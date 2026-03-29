// src/auth/orchestrator.ts
// The multi-channel race engine: coordinates cloud, native, browser, and terminal approval channels.
import net from 'net';
import path from 'path';
import os from 'os';
import { randomUUID } from 'crypto';
import { askNativePopup } from '../ui/native';
import { computeRiskMetadata, type RiskMetadata } from '../context-sniper';
import { scanArgs, scanFilePath, type DlpMatch } from '../dlp';
import { appendHookDebug, appendLocalAudit } from '../audit';
import { getConfig, getCredentials } from '../config';
import { isIgnoredTool, evaluatePolicy } from '../policy';
import {
  checkPause,
  getActiveTrustSession,
  writeTrustSession,
  getPersistentDecision,
} from './state';
import {
  isDaemonRunning,
  getInternalToken,
  registerDaemonEntry,
  waitForDaemonDecision,
  notifyDaemonViewer,
  resolveViaDaemon,
} from './daemon';
import { auditLocalAllow, initNode9SaaS, pollNode9SaaS, resolveNode9SaaS } from './cloud';

export interface AuthResult {
  approved: boolean;
  reason?: string;
  noApprovalMechanism?: boolean;
  blockedByLabel?: string;
  blockedBy?:
    | 'team-policy'
    | 'persistent-deny'
    | 'local-config'
    | 'local-decision'
    | 'no-approval-mechanism'
    | 'timeout';
  changeHint?: string;
  checkedBy?:
    | 'cloud'
    | 'daemon'
    | 'terminal'
    | 'local-policy'
    | 'persistent'
    | 'trust'
    | 'paused'
    | 'audit';
  /** Structured decision source from the winning racer — used for cloud audit reporting. */
  decisionSource?: 'terminal' | 'browser' | 'native' | 'cloud' | 'timeout' | 'local';
}

// ── Flight Recorder — fire-and-forget socket notify ──────────────────────────
const ACTIVITY_SOCKET_PATH =
  process.platform === 'win32'
    ? '\\\\.\\pipe\\node9-activity'
    : path.join(os.tmpdir(), 'node9-activity.sock');

// Returns a Promise so callers can await socket flush before process.exit().
// Without await, process.exit(0) kills the socket mid-connect for fast-passing
// tools (Read, Glob, Grep, etc.), making them invisible in node9 tail.
function notifyActivity(data: {
  id: string;
  ts: number;
  tool: string;
  args?: unknown;
  status: string;
  label?: string;
}): Promise<void> {
  return new Promise<void>((resolve) => {
    try {
      const payload = JSON.stringify(data);
      const sock = net.createConnection(ACTIVITY_SOCKET_PATH);
      sock.on('connect', () => {
        // Attach listeners before calling end() so events fired synchronously
        // on the loopback socket are not missed.
        sock.on('close', resolve);
        sock.end(payload);
      });
      sock.on('error', resolve); // daemon not running — resolve immediately
    } catch {
      resolve();
    }
  });
}

export async function authorizeHeadless(
  toolName: string,
  args: unknown,
  meta?: { agent?: string; mcpServer?: string },
  options?: { calledFromDaemon?: boolean; cwd?: string }
): Promise<AuthResult> {
  // Skip socket notification when called from daemon — daemon already broadcasts via SSE
  if (!options?.calledFromDaemon) {
    const actId = randomUUID();
    const actTs = Date.now();
    await notifyActivity({ id: actId, ts: actTs, tool: toolName, args, status: 'pending' });
    const result = await _authorizeHeadlessCore(toolName, args, meta, {
      ...options,
      activityId: actId,
    });
    // noApprovalMechanism means no channels were available — the CLI will retry
    // after auto-starting the daemon. Don't log a false 'block' to the flight
    // recorder; the retry call will produce the real result notification.
    if (!result.noApprovalMechanism) {
      await notifyActivity({
        id: actId,
        tool: toolName,
        ts: actTs,
        status: result.approved
          ? 'allow'
          : result.blockedByLabel?.includes('DLP')
            ? 'dlp'
            : 'block',
        label: result.blockedByLabel,
      });
    }
    return result;
  }
  return _authorizeHeadlessCore(toolName, args, meta, options);
}

async function _authorizeHeadlessCore(
  toolName: string,
  args: unknown,
  meta?: { agent?: string; mcpServer?: string },
  options?: { calledFromDaemon?: boolean; activityId?: string; cwd?: string }
): Promise<AuthResult> {
  if (process.env.NODE9_PAUSED === '1') return { approved: true, checkedBy: 'paused' };
  const pauseState = checkPause();
  if (pauseState.paused) return { approved: true, checkedBy: 'paused' };

  const creds = getCredentials();
  const config = getConfig(options?.cwd);

  // 1. Check if we are in any kind of test environment (Vitest, CI, or E2E)
  const isTestEnv = !!(
    process.env.VITEST ||
    process.env.NODE_ENV === 'test' ||
    process.env.CI ||
    process.env.NODE9_TESTING === '1'
  );

  // 2. Clone the config object!
  // This prevents us from accidentally mutating the global config cache.
  const approvers = {
    ...(config.settings.approvers || { native: true, browser: true, cloud: true, terminal: true }),
  };

  // 3. THE TEST SILENCER: Hard-disable all physical UIs in test/CI environments.
  // We leave 'cloud' untouched so your SaaS/Cloud tests can still manage it via mock configs.
  if (isTestEnv) {
    approvers.native = false;
    approvers.browser = false;
    approvers.terminal = false;
  }

  if (config.settings.enableHookLogDebug && !isTestEnv) {
    appendHookDebug(toolName, args, meta);
  }

  const isManual = meta?.agent === 'Terminal';

  let explainableLabel = 'Local Config';
  let policyMatchedField: string | undefined;
  let policyMatchedWord: string | undefined;
  let riskMetadata: RiskMetadata | undefined;

  // ── DLP CONTENT SCANNER ───────────────────────────────────────────────────
  // Runs before ignored-tool fast path and audit mode so that a leaked
  // credential is always caught — even for "safe" tools like web_search.
  if (
    config.policy.dlp.enabled &&
    (!isIgnoredTool(toolName) || config.policy.dlp.scanIgnoredTools)
  ) {
    // P1-1/P1-2: Check file path first (blocks read attempts before content is returned,
    // and resolves symlinks to prevent escape attacks).
    const argsObj =
      args && typeof args === 'object' && !Array.isArray(args)
        ? (args as Record<string, unknown>)
        : {};
    const filePath = String(argsObj.file_path ?? argsObj.path ?? argsObj.filename ?? '');
    const dlpMatch: DlpMatch | null = (filePath ? scanFilePath(filePath) : null) ?? scanArgs(args);
    if (dlpMatch) {
      const dlpReason =
        `🚨 DATA LOSS PREVENTION: ${dlpMatch.patternName} detected in ` +
        `field "${dlpMatch.fieldPath}" (${dlpMatch.redactedSample})`;
      if (dlpMatch.severity === 'block') {
        if (!isManual) appendLocalAudit(toolName, args, 'deny', 'dlp-block', meta);
        return {
          approved: false,
          reason: dlpReason,
          blockedBy: 'local-config',
          blockedByLabel: '🚨 Node9 DLP (Secret Detected)',
        };
      }
      // severity === 'review': fall through to the race engine with a DLP label.
      // Write an audit entry now so the DLP flag is traceable even if the race
      // engine later approves the call without recording why it was intercepted.
      if (!isManual) appendLocalAudit(toolName, args, 'allow', 'dlp-review-flagged', meta);
      explainableLabel = '🚨 Node9 DLP (Credential Review)';
    }
  }

  if (config.settings.mode === 'audit') {
    if (!isIgnoredTool(toolName)) {
      const policyResult = await evaluatePolicy(toolName, args, meta?.agent, options?.cwd);
      if (policyResult.decision === 'review') {
        appendLocalAudit(toolName, args, 'allow', 'audit-mode', meta);
        // Must await — process.exit(0) follows immediately and kills any fire-and-forget fetch.
        // Only send to SaaS when cloud is enabled — respects privacy mode (cloud: false).
        if (approvers.cloud && creds?.apiKey) {
          await auditLocalAllow(toolName, args, 'audit-mode', creds, meta);
        }
        // Note: desktop notification intentionally omitted — notify-send routes through
        // the browser on many Linux setups (Firefox as D-Bus handler), causing spurious popups.
      }
    }
    return { approved: true, checkedBy: 'audit' };
  }

  // Fast Paths (Ignore, Trust, Policy Allow)
  if (!isIgnoredTool(toolName)) {
    if (getActiveTrustSession(toolName)) {
      if (approvers.cloud && creds?.apiKey)
        await auditLocalAllow(toolName, args, 'trust', creds, meta);
      if (!isManual) appendLocalAudit(toolName, args, 'allow', 'trust', meta);
      return { approved: true, checkedBy: 'trust' };
    }
    const policyResult = await evaluatePolicy(toolName, args, meta?.agent);
    if (policyResult.decision === 'allow') {
      if (approvers.cloud && creds?.apiKey)
        auditLocalAllow(toolName, args, 'local-policy', creds, meta);
      if (!isManual) appendLocalAudit(toolName, args, 'allow', 'local-policy', meta);
      return { approved: true, checkedBy: 'local-policy' };
    }

    // Hard block from smart rules — skip the race engine entirely
    if (policyResult.decision === 'block') {
      if (!isManual) appendLocalAudit(toolName, args, 'deny', 'smart-rule-block', meta);
      return {
        approved: false,
        reason: policyResult.reason ?? 'Action explicitly blocked by Smart Policy.',
        blockedBy: 'local-config',
        blockedByLabel: policyResult.blockedByLabel,
      };
    }

    explainableLabel = policyResult.blockedByLabel || 'Local Config';
    policyMatchedField = policyResult.matchedField;
    policyMatchedWord = policyResult.matchedWord;
    riskMetadata = computeRiskMetadata(
      args,
      policyResult.tier ?? 6,
      explainableLabel,
      policyMatchedField,
      policyMatchedWord,
      policyResult.ruleName
    );

    const persistent = getPersistentDecision(toolName);
    if (persistent === 'allow') {
      if (approvers.cloud && creds?.apiKey)
        await auditLocalAllow(toolName, args, 'persistent', creds, meta);
      if (!isManual) appendLocalAudit(toolName, args, 'allow', 'persistent', meta);
      return { approved: true, checkedBy: 'persistent' };
    }
    if (persistent === 'deny') {
      if (!isManual) appendLocalAudit(toolName, args, 'deny', 'persistent-deny', meta);
      return {
        approved: false,
        reason: `This tool ("${toolName}") is explicitly listed in your 'Always Deny' list.`,
        blockedBy: 'persistent-deny',
        blockedByLabel: 'Persistent User Rule',
      };
    }
  } else {
    // ignoredTools (read, glob, grep, ls…) fire on every agent operation — too
    // frequent and too noisy to send to the SaaS audit log.
    if (!isManual) appendLocalAudit(toolName, args, 'allow', 'ignored', meta);
    return { approved: true };
  }

  // ── THE HANDSHAKE (Phase 4.1: Cloud Init) ────────────────────────────────
  let cloudRequestId: string | null = null;
  const cloudEnforced = approvers.cloud && !!creds?.apiKey;

  if (cloudEnforced) {
    try {
      const initResult = await initNode9SaaS(toolName, args, creds!, meta, riskMetadata);

      if (!initResult.pending) {
        // Shadow mode: allowed through, but warn the developer passively
        if (initResult.shadowMode) {
          return { approved: true, checkedBy: 'cloud' };
        }
        return {
          approved: !!initResult.approved,
          reason:
            initResult.reason ||
            (initResult.approved ? undefined : 'Action rejected by organization policy.'),
          checkedBy: initResult.approved ? 'cloud' : undefined,
          blockedBy: initResult.approved ? undefined : 'team-policy',
          blockedByLabel: 'Organization Policy (SaaS)',
        };
      }

      cloudRequestId = initResult.requestId || null;
      // remoteApprovalOnly is noted but not enforced — local UI always has control.
      // Hard blocks are handled by Shields before the UI opens.
      explainableLabel = 'Organization Policy (SaaS)';
    } catch {
      // Cloud API handshake failed — fall through to local rules silently
    }
  }

  // ── THE MULTI-CHANNEL RACE ENGINE ──────────────────────────────────────────
  const abortController = new AbortController();
  const { signal } = abortController;
  const racePromises: Promise<AuthResult>[] = [];

  // ⏱️ RACER 0: Approval Timeout
  const approvalTimeoutMs = config.settings.approvalTimeoutMs ?? 0;
  if (approvalTimeoutMs > 0) {
    racePromises.push(
      new Promise<AuthResult>((resolve, reject) => {
        const timer = setTimeout(() => {
          resolve({
            approved: false,
            reason: `No human response within ${approvalTimeoutMs / 1000}s — auto-denied by timeout policy.`,
            blockedBy: 'timeout',
            blockedByLabel: 'Approval Timeout',
          });
        }, approvalTimeoutMs);
        signal.addEventListener('abort', () => {
          clearTimeout(timer);
          reject(new Error('Aborted'));
        });
      })
    );
  }

  let viewerId: string | null = null;
  const internalToken = getInternalToken();

  // Pre-register a daemon entry shared by Racers 3 (browser/terminal) and, when
  // cloudEnforced, by RACER 1 as well (reusing the same card — no duplicate).
  // notifyDaemonViewer is moved here (out of RACER 1) so viewerId is known before
  // the race starts, allowing RACER 3 to use it as its entry ID.
  let daemonEntryId: string | null = null;
  let daemonAllowCount = 1;
  if (
    (approvers.browser || approvers.terminal) &&
    isDaemonRunning() &&
    !options?.calledFromDaemon
  ) {
    if (cloudEnforced && cloudRequestId) {
      // Cloud path: create a single card via notifyDaemonViewer so RACER 3
      // (terminal/browser) shares the same daemon entry — no duplicate card.
      // Local UI always participates in the race regardless of cloud policy.
      const viewer = await notifyDaemonViewer(toolName, args, meta, riskMetadata).catch(() => null);
      viewerId = viewer?.id ?? null;
      daemonEntryId = viewerId;
      if (viewer) daemonAllowCount = viewer.allowCount;
    } else {
      try {
        const entry = await registerDaemonEntry(
          toolName,
          args,
          meta,
          riskMetadata,
          options?.activityId,
          options?.cwd
        );
        daemonEntryId = entry.id;
        daemonAllowCount = entry.allowCount;
      } catch {
        // Daemon unreachable — skip both racers gracefully
      }
    }
  }

  // 🏁 RACER 1: Cloud SaaS Channel (The Poller)
  if (cloudEnforced && cloudRequestId) {
    racePromises.push(
      (async () => {
        try {
          const cloudResult = await pollNode9SaaS(cloudRequestId, creds!, signal);

          return {
            approved: cloudResult.approved,
            reason: cloudResult.approved
              ? undefined
              : cloudResult.reason || 'Action rejected by organization administrator via Slack.',
            checkedBy: cloudResult.approved ? 'cloud' : undefined,
            blockedBy: cloudResult.approved ? undefined : 'team-policy',
            blockedByLabel: 'Organization Policy (SaaS)',
          } as AuthResult;
        } catch (err: unknown) {
          const error = err as Error;
          if (error.name === 'AbortError' || error.message?.includes('Aborted')) throw err;
          throw err;
        }
      })()
    );
  }

  // 🏁 RACER 2: Native OS Popup
  // Skip when called from the daemon's background pipeline — the CLI already
  // launched this popup as part of its own race; firing it a second time from
  // the daemon would show a duplicate popup for the same request.
  if (approvers.native && !isManual && !options?.calledFromDaemon) {
    racePromises.push(
      (async () => {
        const decision = await askNativePopup(
          toolName,
          args,
          meta?.agent,
          explainableLabel,
          false,
          signal,
          policyMatchedField,
          policyMatchedWord,
          daemonAllowCount
        );

        if (decision === 'always_allow') {
          writeTrustSession(toolName, 3600000);
          return { approved: true, checkedBy: 'trust' } as AuthResult;
        }

        const isApproved = decision === 'allow';
        return {
          approved: isApproved,
          reason: isApproved
            ? undefined
            : "The human user clicked 'Block' on the system dialog window.",
          checkedBy: isApproved ? 'daemon' : undefined,
          blockedBy: isApproved ? undefined : 'local-decision',
          blockedByLabel: 'User Decision (Native)',
          decisionSource: 'native',
        } as AuthResult;
      })()
    );
  }

  // 🏁 RACER 3: Browser Dashboard or node9 tail (interactive terminal)
  // Both channels resolve via POST /decision/{id} — same waitForDaemonDecision poll.
  // When cloudEnforced, daemonEntryId == viewerId (same card, no duplicate).
  // Local UI always participates in the race — cloud remoteApprovalOnly is not enforced.
  if (daemonEntryId && (approvers.browser || approvers.terminal)) {
    racePromises.push(
      (async () => {
        const { decision: daemonDecision, source: decisionSource } = await waitForDaemonDecision(
          daemonEntryId!,
          signal
        );
        if (daemonDecision === 'abandoned') throw new Error('Abandoned');

        const isApproved = daemonDecision === 'allow';
        const src: 'terminal' | 'browser' =
          decisionSource === 'terminal' || decisionSource === 'browser'
            ? decisionSource
            : approvers.browser
              ? 'browser'
              : 'terminal';
        const via = src === 'terminal' ? 'Terminal (node9 tail)' : 'Browser Dashboard';
        return {
          approved: isApproved,
          reason: isApproved
            ? undefined
            : `The human user rejected this action via the Node9 ${via}.`,
          checkedBy: isApproved ? 'daemon' : undefined,
          blockedBy: isApproved ? undefined : 'local-decision',
          blockedByLabel: `User Decision (${via})`,
          decisionSource: src,
        } as AuthResult;
      })()
    );
  }

  // 🏆 RESOLVE THE RACE
  if (racePromises.length === 0) {
    return {
      approved: false,
      noApprovalMechanism: true,
      reason:
        `NODE9 SECURITY INTERVENTION: Action blocked by automated policy [${explainableLabel}].\n` +
        `REASON: Action blocked because no approval channels are available. (Native/Browser UI is disabled in config, and this terminal is non-interactive).`,
      blockedBy: 'no-approval-mechanism',
      blockedByLabel: explainableLabel,
    };
  }

  const finalResult = await new Promise<AuthResult>((resolve) => {
    let resolved = false;
    let failures = 0;
    const total = racePromises.length;

    const finish = (res: AuthResult) => {
      if (!resolved) {
        resolved = true;
        abortController.abort(); // KILL THE LOSERS

        // Event Bridge: notify the daemon whenever any channel wins the race.
        // Covers native popup, cloud, and timeout — not just the cloud/Slack path.
        // Browser and terminal racers already go through POST /decision/:id, so
        // calling /resolve/:id afterwards is harmless (entry is gone → 404 ignored).
        if (daemonEntryId && internalToken) {
          resolveViaDaemon(
            daemonEntryId,
            res.approved ? 'allow' : 'deny',
            internalToken,
            res.decisionSource
          ).catch(() => null);
        }

        resolve(res);
      }
    };

    for (const p of racePromises) {
      p.then(finish).catch((err) => {
        if (
          err.name === 'AbortError' ||
          err.message?.includes('canceled') ||
          err.message?.includes('Aborted')
        )
          return;
        // 'Abandoned' means the browser dashboard closed without deciding.
        // Don't silently swallow it — that would leave the race promise hanging
        // forever when the browser racer is the only channel.
        if (err.message === 'Abandoned') {
          finish({
            approved: false,
            reason: 'Browser dashboard closed without making a decision.',
            blockedBy: 'local-decision',
            blockedByLabel: 'Browser Dashboard (Abandoned)',
          });
          return;
        }
        failures++;
        if (failures === total && !resolved) {
          finish({ approved: false, reason: 'All approval channels failed or disconnected.' });
        }
      });
    }
  });

  // If a LOCAL channel (native/browser/terminal) won while the cloud had a
  // pending request open, report the decision back to the SaaS so Mission
  // Control doesn't stay stuck on PENDING forever.
  // We await this (not fire-and-forget) because the CLI process may exit
  // immediately after this function returns, killing any in-flight fetch.
  if (cloudRequestId && creds && finalResult.checkedBy !== 'cloud') {
    await resolveNode9SaaS(
      cloudRequestId,
      creds,
      finalResult.approved,
      finalResult.decisionSource ?? finalResult.checkedBy ?? 'local'
    );
  }

  if (!isManual) {
    appendLocalAudit(
      toolName,
      args,
      finalResult.approved ? 'allow' : 'deny',
      finalResult.checkedBy || finalResult.blockedBy || 'unknown',
      meta
    );
  }

  return finalResult;
}

export async function authorizeAction(toolName: string, args: unknown): Promise<boolean> {
  const result = await authorizeHeadless(toolName, args);
  return result.approved;
}
