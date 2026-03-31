// src/auth/orchestrator.ts
// The multi-channel race engine: coordinates cloud, native, browser, and terminal approval channels.
import { randomUUID } from 'crypto';
import { askNativePopup } from '../ui/native';
import { computeRiskMetadata, type RiskMetadata } from '../context-sniper';
import { scanArgs, scanFilePath, type DlpMatch } from '../dlp';
import { appendHookDebug, appendLocalAudit, appendToLog, HOOK_DEBUG_LOG } from '../audit';
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
  notifyTaint,
  checkTaint,
  notifyActivitySocket,
  checkStatePredicates,
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
  /** Name of the smart rule that fired (for HUD lastRuleHit tracking). */
  ruleHit?: string;
  /** Observe mode: this decision would have been blocked in standard mode. */
  observeWouldBlock?: boolean;
  /** Recovery command to suggest when a stateful rule hard-blocks (e.g. "npm test"). */
  recoveryCommand?: string;
}

// ── Taint helpers ────────────────────────────────────────────────────────────

const WRITE_TOOLS = new Set([
  'write',
  'write_file',
  'create_file',
  'edit',
  'multiedit',
  'str_replace_based_edit_tool',
  'replace',
  'notebook_edit',
  'notebookedit',
]);

function isWriteTool(toolName: string): boolean {
  const t = toolName.toLowerCase().replace(/[^a-z_]/g, '_');
  return WRITE_TOOLS.has(t);
}

/**
 * Extract file paths that a tool might be reading from or uploading.
 * Used to check taint before approving network/shell operations.
 */
function extractFilePaths(toolName: string, args: unknown): string[] {
  const paths: string[] = [];
  if (!args || typeof args !== 'object' || Array.isArray(args)) return paths;
  const a = args as Record<string, unknown>;

  // Structured file path fields
  for (const key of ['file_path', 'path', 'filename', 'source', 'src', 'input']) {
    if (typeof a[key] === 'string' && a[key]) paths.push(a[key] as string);
  }

  // Shell command — extract file references from curl -T, scp, rsync, nc etc.
  const cmd = typeof a.command === 'string' ? a.command : typeof a.cmd === 'string' ? a.cmd : '';
  if (cmd) {
    // curl -T <file> or --data-binary @<file> or --upload-file <file>
    for (const m of cmd.matchAll(/(?:-T|--upload-file|--data(?:-binary)?)\s+@?(\S+)/g)) {
      paths.push(m[1]);
    }
    // scp <file> user@host or rsync <file>
    for (const m of cmd.matchAll(/\b(?:scp|rsync)\s+(?:-\S+\s+)*(\S+)\s+\S+@/g)) {
      paths.push(m[1]);
    }
    // nc / ncat with input redirect: nc host port < file
    for (const m of cmd.matchAll(/<\s*(\S+)/g)) {
      paths.push(m[1]);
    }
  }

  return paths.filter(Boolean);
}

/**
 * Returns true if this is a shell/network tool that could exfiltrate a file.
 * Used to decide whether to run a taint check.
 */
function isNetworkTool(toolName: string, args: unknown): boolean {
  const t = toolName.toLowerCase();
  if (t === 'bash' || t === 'shell' || t === 'run_shell_command' || t === 'terminal.execute') {
    const a = args as Record<string, unknown> | null;
    const cmd =
      typeof a?.command === 'string' ? a.command : typeof a?.cmd === 'string' ? a.cmd : '';
    return /\b(curl|wget|scp|rsync|nc|ncat|netcat|ssh)\b/.test(cmd);
  }
  return false;
}

// ── Flight Recorder — fire-and-forget socket notify ──────────────────────────
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
  ruleHit?: string;
  observeWouldBlock?: boolean;
}): Promise<void> {
  return notifyActivitySocket(data);
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
    // DESIGN NOTE: notifyActivity opens a real Unix socket. The approval timeout
    // racer (setTimeout) is registered inside _authorizeHeadlessCore, which runs
    // AFTER this I/O round-trip completes. This means fake timers cannot be used
    // in tests — vi.advanceTimersByTime fires before the setTimeout is registered.
    // Future refactor: move timeout racer registration to before this call so the
    // clock starts before any I/O side effects, and fake timers become usable.
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
            : result.blockedByLabel?.includes('Taint')
              ? 'taint'
              : 'block',
        label: result.blockedByLabel,
        ruleHit: result.ruleHit,
        observeWouldBlock: result.observeWouldBlock,
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
  const hashAuditArgs = config.settings.auditHashArgs === true;

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
    appendHookDebug(toolName, args, meta, hashAuditArgs);
  }

  const isManual = meta?.agent === 'Terminal';
  const isObserveMode = config.settings.mode === 'observe';

  let explainableLabel = 'Local Config';
  let policyMatchedField: string | undefined;
  let policyMatchedWord: string | undefined;
  let riskMetadata: RiskMetadata | undefined;
  // Set when a stateful block's predicates are NOT met and we fall through to the
  // race engine — passed to registerDaemonEntry so the tail shows the recovery menu.
  let statefulRecoveryCommand: string | undefined;

  // ── TAINT CHECK ───────────────────────────────────────────────────────────
  // Before DLP: if this is a network/upload operation touching a previously
  // tainted file, surface a warning through the race engine — the user decides.
  // Taint is heuristic (a file *may* still be sensitive); hard blocks are
  // reserved for team policy shields.
  let taintWarning: string | null = null;
  if (isNetworkTool(toolName, args)) {
    const filePaths = extractFilePaths(toolName, args);
    if (filePaths.length > 0) {
      const taintResult = await checkTaint(filePaths);
      if (taintResult.tainted && taintResult.record) {
        const { path: taintedPath, source: taintSource } = taintResult.record;
        taintWarning = `⚠️ ${taintedPath} was flagged by ${taintSource} — this file may contain sensitive data`;
      } else if (taintResult.daemonUnavailable) {
        // Taint service is down — cannot confirm files are clean.
        // Treat as a soft taint: the user sees a warning and must explicitly
        // approve. This prevents a daemon crash from silently unblocking
        // exfiltration checks.
        taintWarning = `⚠️ Taint service unavailable — cannot verify if ${filePaths.join(', ')} is clean`;
      }
    }
  }

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
        // Always hash args on DLP blocks — the secret must never appear in the audit log
        if (!isManual)
          appendLocalAudit(
            toolName,
            args,
            'deny',
            isObserveMode ? 'observe-mode-dlp-would-block' : 'dlp-block',
            meta,
            true
          );
        // Taint the destination file so future uploads of it are also blocked.
        if (isWriteTool(toolName) && filePath) {
          await notifyTaint(filePath, `DLP:${dlpMatch.patternName}`);
        }
        if (isObserveMode) {
          return {
            approved: true,
            checkedBy: 'audit',
            observeWouldBlock: true,
            blockedByLabel: '🚨 Node9 DLP (Secret Detected)',
          };
        }
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
      if (!isManual)
        appendLocalAudit(toolName, args, 'allow', 'dlp-review-flagged', meta, hashAuditArgs);
      explainableLabel = '🚨 Node9 DLP (Credential Review)';
    }
  }

  if (isObserveMode) {
    if (!isIgnoredTool(toolName)) {
      const policyResult = await evaluatePolicy(toolName, args, meta?.agent, options?.cwd);
      const wouldBlock = policyResult.decision === 'block';
      if (!isManual)
        appendLocalAudit(
          toolName,
          args,
          'allow',
          wouldBlock ? 'observe-mode-would-block' : 'observe-mode',
          meta,
          hashAuditArgs
        );
      return {
        approved: true,
        checkedBy: 'audit',
        ...(wouldBlock && {
          observeWouldBlock: true,
          blockedByLabel: policyResult.blockedByLabel,
          ruleHit: policyResult.ruleName,
        }),
      };
    }
    return { approved: true, checkedBy: 'audit' };
  }

  if (config.settings.mode === 'audit') {
    if (!isIgnoredTool(toolName)) {
      const policyResult = await evaluatePolicy(toolName, args, meta?.agent, options?.cwd);
      if (policyResult.decision === 'review') {
        appendLocalAudit(toolName, args, 'allow', 'audit-mode', meta, hashAuditArgs);
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
  // Bypassed entirely when a taint warning is active — taint overrides trust
  // sessions and policy allows so the user always gets a chance to review.
  if (!taintWarning && !isIgnoredTool(toolName)) {
    if (getActiveTrustSession(toolName)) {
      if (approvers.cloud && creds?.apiKey)
        await auditLocalAllow(toolName, args, 'trust', creds, meta);
      if (!isManual) appendLocalAudit(toolName, args, 'allow', 'trust', meta, hashAuditArgs);
      return { approved: true, checkedBy: 'trust' };
    }
    const policyResult = await evaluatePolicy(toolName, args, meta?.agent);
    if (policyResult.decision === 'allow') {
      if (approvers.cloud && creds?.apiKey)
        auditLocalAllow(toolName, args, 'local-policy', creds, meta);
      if (!isManual) appendLocalAudit(toolName, args, 'allow', 'local-policy', meta, hashAuditArgs);
      return { approved: true, checkedBy: 'local-policy' };
    }

    // Hard block from smart rules — skip the race engine entirely
    if (policyResult.decision === 'block') {
      // If block has dependsOnState predicates, check them via the daemon.
      // If predicates are not all satisfied (or daemon unreachable), downgrade
      // to review so the user can decide rather than being hard-blocked.
      if (policyResult.dependsOnStatePredicates?.length) {
        const stateResults = await checkStatePredicates(policyResult.dependsOnStatePredicates);
        // Strict === true check: undefined (missing key) and false are both treated
        // as "predicate not satisfied" — both result in fail-open (no recovery card).
        const predicatesMet =
          stateResults !== null &&
          policyResult.dependsOnStatePredicates.every((p) => stateResults[p] === true);

        // Emit an audit entry whenever the state check fails so silent degradation
        // is visible in hook-debug.log. stateResults===null means daemon was
        // unreachable or timed out; a non-null result with any predicate !== true
        // means the block was intentionally skipped (normal operation, not an error).
        if (stateResults === null && !isManual) {
          appendToLog(HOOK_DEBUG_LOG, {
            ts: new Date().toISOString(),
            event: 'state-check-fail-open',
            tool: toolName,
            rule: policyResult.ruleName,
            predicates: policyResult.dependsOnStatePredicates,
            reason:
              'daemon unreachable or /state/check timed out — block rule downgraded to review',
          });
        }

        // Always fall through to the race engine — the human decides via the approvers
        // (tail [1]/[2]/[3], native popup, browser dashboard). When predicates are met,
        // attach the recoveryCommand so the tail can render the STATE GUARD card.
        // When predicates are not met (or daemon unreachable), omit it so the tail
        // shows a standard review card without a recovery-command prompt.
        if (predicatesMet && policyResult.recoveryCommand) {
          statefulRecoveryCommand = policyResult.recoveryCommand;
        }
      } else {
        if (!isManual)
          appendLocalAudit(toolName, args, 'deny', 'smart-rule-block', meta, hashAuditArgs);
        return {
          approved: false,
          reason: policyResult.reason ?? 'Action explicitly blocked by Smart Policy.',
          blockedBy: 'local-config',
          blockedByLabel: policyResult.blockedByLabel,
          ruleHit: policyResult.ruleName,
          ...(policyResult.recoveryCommand && { recoveryCommand: policyResult.recoveryCommand }),
        };
      }
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

    // A persistent allow must never override a smart rule with verdict "review".
    // Smart rules represent explicit user intent; a blanket "allow this tool"
    // should not silently bypass a rule the user wrote (e.g. review-git-push).
    // policyResult.ruleName is set only when a smart rule matched.
    const persistent = policyResult.ruleName ? null : getPersistentDecision(toolName);
    if (persistent === 'allow') {
      if (approvers.cloud && creds?.apiKey)
        await auditLocalAllow(toolName, args, 'persistent', creds, meta);
      if (!isManual) appendLocalAudit(toolName, args, 'allow', 'persistent', meta, hashAuditArgs);
      return { approved: true, checkedBy: 'persistent' };
    }
    if (persistent === 'deny') {
      if (!isManual)
        appendLocalAudit(toolName, args, 'deny', 'persistent-deny', meta, hashAuditArgs);
      return {
        approved: false,
        reason: `This tool ("${toolName}") is explicitly listed in your 'Always Deny' list.`,
        blockedBy: 'persistent-deny',
        blockedByLabel: 'Persistent User Rule',
      };
    }
  } else if (!taintWarning) {
    // ignoredTools (read, glob, grep, ls…) fire on every agent operation — too
    // frequent and too noisy to send to the SaaS audit log.
    if (!isManual) appendLocalAudit(toolName, args, 'allow', 'ignored', meta, hashAuditArgs);
    return { approved: true };
  }

  // Taint warning active — set a high-risk label and fall through to the race engine.
  // The user sees the taint context in the browser dashboard / native popup / Slack.
  if (taintWarning) {
    explainableLabel = '🔴 Node9 Taint (Exfiltration Prevention)';
    // tier 7 = highest valid tier; pass taintWarning as ruleName so all
    // approval channels (terminal card, browser dashboard, Slack) can render it.
    riskMetadata = computeRiskMetadata(
      args,
      7,
      explainableLabel,
      undefined,
      undefined,
      taintWarning
    );
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
      // Don't overwrite the taint label — taint context must stay visible to the user.
      if (!taintWarning) explainableLabel = 'Organization Policy (SaaS)';
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
          options?.cwd,
          statefulRecoveryCommand
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
        const {
          decision: daemonDecision,
          source: decisionSource,
          reason: daemonReason,
        } = await waitForDaemonDecision(daemonEntryId!, signal);
        if (daemonDecision === 'abandoned') throw new Error('Abandoned');

        const isApproved = daemonDecision === 'allow';
        // 'terminal-redirect' = tail choice [2]: AI redirect with a custom reason string
        const isRedirect = decisionSource === 'terminal-redirect';
        const src: 'terminal' | 'browser' =
          decisionSource === 'terminal' ||
          decisionSource === 'terminal-redirect' ||
          decisionSource === 'browser'
            ? decisionSource === 'browser'
              ? 'browser'
              : 'terminal'
            : approvers.browser
              ? 'browser'
              : 'terminal';
        const via = src === 'terminal' ? 'Terminal (node9 tail)' : 'Browser Dashboard';
        return {
          approved: isApproved,
          reason: isApproved
            ? undefined
            : // Use the redirect reason from the tail when choice [2] was selected;
              // otherwise fall back to the generic rejection message.
              (isRedirect && daemonReason) ||
              `The human user rejected this action via the Node9 ${via}.`,
          checkedBy: isApproved ? 'daemon' : undefined,
          blockedBy: isApproved ? undefined : 'local-decision',
          blockedByLabel: isRedirect ? 'Steered Redirect (Terminal)' : `User Decision (${via})`,
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
      meta,
      hashAuditArgs
    );
  }

  return finalResult;
}

export async function authorizeAction(toolName: string, args: unknown): Promise<boolean> {
  const result = await authorizeHeadless(toolName, args);
  return result.approved;
}
