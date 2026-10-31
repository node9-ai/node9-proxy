// src/auth/orchestrator.ts
// The multi-channel race engine: coordinates cloud, native, browser, and terminal approval channels.
import { randomUUID } from 'crypto';
import { resolveLinkedServer } from '../apps/state';
import os from 'os';
import { askNativePopup } from '../ui/native';
import { computeRiskMetadata, type RiskMetadata } from '../context-sniper';
import {
  scanArgumentSecrets,
  scanArgs,
  scanFilePath,
  detectArgsPii,
  matchCanaryArgs,
  type DlpMatch,
} from '../dlp';
import { canaryValues, loadCanaries } from '../canary/registry';
import {
  ssrfDestinationFloor,
  NET_BINARIES,
  sensitivePathMatch,
  analyzeFsOperation,
  isBashTool,
  inspectionLayers,
  resolveShellInput,
  evaluateProtectedFileAccess,
  incompleteFileVerdict,
  catalogSettingsFromConfig,
  type ProtectedFileVerdict,
} from '@node9/policy-engine';
import { prepareFileAccesses, type PreparedFileAccess } from '../policy/file-access';
import { resolveSessionScript, recordSessionWrites, type SessionScript } from './session-script';
import { scanInjection, argumentLeavesText, isRecordOnly } from '@node9/policy-engine';
import {
  extractShellDestinations,
  extractToolDestinations,
  evaluateEgress,
} from '@node9/policy-engine';
import { appendHookDebug, appendLocalAudit, appendToLog, HOOK_DEBUG_LOG } from '../audit';
import {
  extractArgDestinations,
  destinationDomain,
  destinationValue,
  destinationKind,
  isDestructiveToolName,
  isLoopbackHost,
  hostMatches,
  classifyShellExposure,
  fileToolOperation,
  matchesTrustedList,
} from '@node9/policy-engine';
import { knownProjectHosts } from '../exposure/known-hosts';
import { judgeWritesAfterExposure, type WriteHold } from '../exposure/writes';
import { maybeSessionExposed } from '../exposure/marker';
import { toolRole, splitMcpToolName, sourceWord, EXPOSURE_LABEL } from '../exposure/roles';
import { isTrustedRecipient, addTrustedRecipient } from './trusted-recipients';
import { isTrustedHost, matchesTrustedHost } from './trusted-hosts';
import { getConfig, getCredentials } from '../config';
import { forecastRun, noteForecastUnknown } from './forecast-context';
import { isIgnoredTool, evaluatePolicy } from '../policy';
import {
  runStatelessGates,
  combineWithEngine,
  joinPackageReview,
  GATE_LABELS,
} from '../policy/gate-order';
import {
  checkPause,
  getActiveTrustSession,
  writeTrustSession,
  getPersistentDecision,
} from './state';
import {
  isDaemonRunning,
  daemonHasInteractiveApprover,
  getInternalToken,
  registerDaemonEntry,
  waitForDaemonDecision,
  notifyDaemonViewer,
  resolveViaDaemon,
  notifyTaint,
  checkTaint,
  checkSessionTaint,
  checkSessionExposure,
  approveSessionExposure,
  notifyActivitySocket,
  checkStatePredicates,
} from './daemon';
import { initNode9SaaS, pollNode9SaaS, resolveNode9SaaS } from './cloud';
import { recordAndCheck } from '../loop-detector';
import { runPackageCheck } from '../supply-chain/check';
import { readActiveShields } from '../shields';
import { findJailedPath, findJailedPathIn, USER_JAIL_SHIELD } from '../shields/jail';
import { safeMessage } from '../utils/safe-text';
import { asApprovalRequest } from '../policy/negotiation';
import { recordFromLegacyWait, type Channel, type DecidedBy } from './decision-record';
import { approvalUnavailable, authResultFromRecord, recordFromAuthResult } from './card-result';

/** The pattern name the DLP gate gives a sensitive-PATH hit, read off the
 *  engine rather than copied, so a rename there cannot silently skip MSG-1. */
const SENSITIVE_PATH_PATTERN = sensitivePathMatch('').patternName;

/**
 * Is this smart rule a block on a PROTECTED PATH? It decides the message the
 * agent reads (MSG-1): a path block used to reach the agent as "a sensitive
 * credential was found in your arguments ... rotate it", or as a bare
 * "[Smart Rule: block-path-<slug>]". Three families, pinned against the real
 * builders in protected-path-rule.spec.ts:
 *   - the shipped project-jail read blocks, `shield:project-jail:block-read-*`
 *   - what `node9 jail add` installs, `block-path-*` (measured bare names)
 *   - a managed jail's rules, `org:block-path-*`
 * Blocks only: a review goes to the approve/deny prompt, not this message.
 */
export function isProtectedPathRule(ruleName: string | undefined): boolean {
  if (!ruleName) return false;
  return (
    /^(?:org:)?block-path-/.test(ruleName) || /^shield:project-jail:block-read-/.test(ruleName)
  );
}

/** The argument field a path rule matched, from the rule's own name: pathRules
 *  (shields/build.ts) emits one rule per field, suffixed `-anytool` (file_path),
 *  `-anytool-path`, `-anytool-pattern`, or `-bash` (command). Picking the first
 *  non-empty field instead named the wrong path for Glob, which carries the
 *  jailed value in `pattern` and a parent directory in `path` (/code-review). */
function matchedPathField(ruleName: string): string | undefined {
  if (/-anytool-pattern$/.test(ruleName)) return 'pattern';
  if (/-anytool-path$/.test(ruleName)) return 'path';
  if (/-anytool$/.test(ruleName)) return 'file_path';
  return undefined;
}

/** The path a protected-path block was about, for the agent's message. A path
 *  is not a secret. For a shell command the engine's own reader resolves it
 *  (cached, the same call the gate just made). Undefined when nothing names it
 *  reliably: the message then says "This file". */
function protectedPathOf(ruleName: string, toolName: string, args: unknown): string | undefined {
  const a =
    args && typeof args === 'object' && !Array.isArray(args)
      ? (args as Record<string, unknown>)
      : {};
  if (isBashTool(toolName) && typeof a.command === 'string') {
    return analyzeFsOperation(a.command)?.path || undefined;
  }
  const field = matchedPathField(ruleName);
  const order = field ? [field] : ['file_path', 'path', 'filename', 'pattern'];
  for (const k of order) {
    if (typeof a[k] === 'string' && a[k]) return a[k] as string;
  }
  return undefined;
}

/** A path printed into the agent message and onto the developer's terminal is
 *  the agent's own argument: one safe line (safeMessage), and no C1 controls or
 *  bidi overrides, which safeMessage keeps and which can reorder or forge what
 *  the developer sees (/code-review). */
function safePathForDisplay(p: string): string {
  return safeMessage(p).replace(/[\u0080-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, '');
}

/** The two AuthResult fields a protected-path block carries, or nothing.
 *  `credentialInArgs`: the protected-path text says "nothing was exposed",
 *  which is false when the same call ALSO carries a credential (a Write of a
 *  key into .env, `cat .env && curl -H "Authorization: Bearer ..."`). Such a
 *  call keeps the credential or generic text (/code-review). */
function protectedPathFields(
  ruleName: string | undefined,
  toolName: string,
  args: unknown,
  credentialInArgs: boolean
): Pick<AuthResult, 'blockKind' | 'blockedPath'> {
  if (!ruleName || credentialInArgs || !isProtectedPathRule(ruleName)) return {};
  const p = protectedPathOf(ruleName, toolName, args);
  return { blockKind: 'protected-path', blockedPath: p ? safePathForDisplay(p) : undefined };
}

export interface AuthResult {
  approved: boolean;
  /** What was protected, when the block is about a FILE rather than a value in
   *  the arguments. Chooses the agent-facing message (MSG-1); the label, which
   *  the dashboard and telemetry read, is unchanged. */
  blockKind?: 'protected-path';
  /** The path as the agent wrote it, for that message. Not a secret. */
  blockedPath?: string;
  /** Verdict was "review" and the caller opted in via `deferReview`: the caller
   *  (an ask-capable agent's hook) renders the approve/deny prompt itself. The
   *  approver race did NOT run, and no SaaS pending entry was created. */
  review?: boolean;
  reason?: string;
  noApprovalMechanism?: boolean;
  blockedByLabel?: string;
  blockedBy?:
    | 'team-policy'
    | 'persistent-deny'
    | 'local-config'
    | 'local-decision'
    | 'no-approval-mechanism'
    | 'loop-detection'
    | 'timeout';
  changeHint?: string;
  checkedBy?:
    'cloud' | 'daemon' | 'terminal' | 'local-policy' | 'persistent' | 'trust' | 'paused' | 'audit';
  /** Structured decision source from the winning racer — used for cloud audit reporting. */
  decisionSource?: 'terminal' | 'browser' | 'native' | 'cloud' | 'timeout' | 'local';
  /** Who decided an approval (src/auth/decision-record.ts): a person, the
   *  timer, the cloud, a rule, or nobody left. Set on every race result. */
  decidedBy?: DecidedBy;
  /** Where it was decided: node9 tail, node9 monitor, the native popup, the cloud. */
  channel?: Channel;
  /** A person's own instruction to the agent (node9 tail recovery choice [2]). */
  redirect?: string;
  /** Name of the smart rule that fired (for HUD lastRuleHit tracking). */
  ruleHit?: string;
  /** The catalog check behind a policy verdict (`commands.sudo`), when the
   *  engine named one. The other gates name theirs through the audit tag. */
  checkId?: string;
  /** fw#318: the keys an exposure review held, for the inline-ask marker. */
  exposureKeys?: string[];
  /** fw#318 2b: the eid of the read a held send followed (the audit edge). */
  exposureFromEid?: string;
  /** Observe mode: this decision would have been blocked in standard mode. */
  observeWouldBlock?: boolean;
  /** Recovery command to suggest when a stateful rule hard-blocks (e.g. "npm test"). */
  recoveryCommand?: string;
  /** Plain-English description of what triggered this result (from SmartRule.description). */
  ruleDescription?: string;
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

const VERDICT_RANK = { allow: 0, review: 1, block: 2 } as const;
/** A verdict reached through a script the session wrote: its sentences name the script. */
function fromScript<T extends { reason?: string; ruleDescription?: string }>(
  v: T,
  script: string
): T {
  const inScript = (text: string | undefined): string =>
    `In ${script}, a script written this session: ${text ?? 'the shell checks asked for a review'}`;
  return {
    ...v,
    reason: inScript(v.reason),
    ruleDescription: inScript(v.ruleDescription ?? v.reason),
  };
}

function isWriteTool(toolName: string): boolean {
  const t = toolName.toLowerCase().replace(/[^a-z_]/g, '_');
  return WRITE_TOOLS.has(t);
}

/** A namespaced MCP tool as the agent hook forwards it (`mcp__<server>__<tool>`).
 *  Same shape the hook and the gateway use to extract the server name. */
function isMcpToolName(toolName: string): boolean {
  return /^mcp__[^_](?:[^_]|_(?!_))*?__/i.test(toolName);
}

/**
 * Extract file paths that a tool might be reading from or uploading.
 * Used to check taint before approving network/shell operations.
 */
function extractFilePaths(toolName: string, args: unknown, shellCommand?: string): string[] {
  const paths: string[] = [];
  if (!args || typeof args !== 'object' || Array.isArray(args)) return paths;
  const a = args as Record<string, unknown>;

  // Structured file path fields
  for (const key of ['file_path', 'path', 'filename', 'source', 'src', 'input']) {
    if (typeof a[key] === 'string' && a[key]) paths.push(a[key] as string);
  }

  // Shell command — extract file references from curl -T, scp, rsync, nc etc.
  const cmd =
    shellCommand ??
    (typeof a.command === 'string' ? a.command : typeof a.cmd === 'string' ? a.cmd : '');
  if (cmd) {
    // curl -T <file> or --data-binary @<file> or --upload-file <file>
    for (const m of cmd.matchAll(/(?:-T|--upload-file|--data(?:-binary)?)\s+@?(\S+)/g)) {
      paths.push(m[1]);
    }
    // scp <file> user@host or rsync <file>
    for (const m of cmd.matchAll(/\b(?:scp|rsync)\s+(?:-\S+\s+)*(\S+)\s+\S+@/g)) {
      paths.push(m[1]);
    }
    // nc / ncat with input redirect: nc host port < file. Only a single `<`:
    // `<<'EOF'` is a heredoc (its label is no file), `<<<` a here-string,
    // `<&3` an fd and `<(cmd)` a process substitution. `<>file` reads it too.
    for (const m of cmd.matchAll(/(?<!<)<>?(?![<&(])\s*(\S+)/g)) {
      paths.push(m[1]);
    }
  }

  return paths.filter(Boolean);
}

/**
 * Returns true if this is a shell/network tool that could exfiltrate a file.
 * Used to decide whether to run a taint check.
 */
// Built from the engine's NET_BINARIES so this list and the destination
// extractor's cannot drift.
//
// The lookbehind is the whole fix and its SHAPE matters. A bare `\b` matched
// `ssh` INSIDE `.ssh/`, so `cat < ~/.ssh/id_rsa` was classed as a network call,
// entered the taint tier, and with the daemon down came back `ask` ("Taint
// service unavailable") instead of the jail's block. A command-POSITION anchor
// (`^` or whitespace) fixes that but DROPS `/usr/bin/curl`, `sh -c "curl …"`
// and `{curl …;}` -- all matched before, all real network calls, all would
// silently leave the taint tier. The discriminator between the two is a DOT:
// `.ssh` is a dotfile, while a slash or a quote before the name is just a path
// or a payload. Measured over 13 shapes, 2026-09-11.
//
// The lookahead is the same reasoning on the other side: a name followed by a
// slash is a DIRECTORY on a path, not a program (`/etc/ssh/ssh_config`). That
// was the same false entry into the taint tier, through a Python heredoc
// copying `/etc/ssh/ssh_config` with /etc jailed: the daemon-down review came
// back instead of the jail's block. `/usr/bin/curl`, `sh -c "curl …"` and
// `{curl …;}` are not followed by a slash and still match.
const NETWORK_COMMAND_RE = new RegExp(`(?<![.\\w-])(${[...NET_BINARIES].join('|')})\\b(?![/\\\\])`);

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
  agent?: string;
  mcpServer?: string;
  // Agent session identifier (Claude Code / Gemini CLI). Lets `node9 tail`
  // show a session badge so two parallel agent sessions in different
  // terminals don't visually interleave into a single mystery stream.
  sessionId?: string;
}): Promise<boolean> {
  return notifyActivitySocket(data);
}

/**
 * Is a genuine HUMAN approver reachable right now, for the purpose of softening
 * a hard block into a review? (task #17, fail-closed gate.)
 *
 *  - native GUI popup: reachable iff a display is present AND this is the HOOK
 *    process (the daemon's own background pass never opens a dialog, so a
 *    display does not help there).
 *  - terminal (`node9 tail`): reachable iff an input-capable client is connected
 *    to the daemon (asked over HTTP; that call fails closed on error/timeout).
 *
 * Cloud is deliberately NOT a "human" here — it can auto-resolve a client-side
 * shield the SaaS has no rule for. Returns false on any uncertainty so a hard
 * block stays hard rather than becoming an auto-allowable review.
 */
export async function hasReachableHumanApprover(opts: {
  approvers: { native?: boolean; terminal?: boolean };
  calledFromDaemon?: boolean;
}): Promise<boolean> {
  const hasDisplay = !!(process.env.DISPLAY || process.env.WAYLAND_DISPLAY);
  const nativeReachable = !opts.calledFromDaemon && opts.approvers.native !== false && hasDisplay;
  // Short-circuit: only pay the daemon round-trip when native can't reach a human.
  if (nativeReachable) return true;
  return opts.approvers.terminal !== false && (await daemonHasInteractiveApprover());
}

/**
 * Whether a hard block may soften into a review/recovery card.
 *
 * A block softens ONLY when a genuine human approver is reachable (a GUI popup
 * or a connected `node9 tail`). With none — CI, headless, a piped
 * non-interactive agent — it stays hard, so the approver race can never resolve
 * it to allow (a cloud immediate-allow of a client-side shield the SaaS has no
 * rule for). Cloud is deliberately not a "human": it can auto-resolve.
 *
 * `overridable: false` refuses the downgrade outright, whatever else is true.
 * That is the SSRF tier-1 floors, whose reason string already promises the user
 * "This address cannot be allowlisted". Before this, a reachable human turned
 * that promise into a dialog, and on a governed desktop the metadata endpoint
 * was allowed while `node9 explain` still said BLOCK.
 *
 * `!== false` and not `=== true`: every verdict that carries no opinion keeps
 * the previous behaviour. Only an explicit "no one may override this" changes.
 *
 * Pure, and extracted for the same reason resolveNativeDecision is: the live
 * condition includes `isTestEnv`, so a test running under vitest can never
 * observe a downgrade through the real path.
 */
export function mayDowngradeHardBlock(opts: {
  daemonUp: boolean;
  isTestEnv: boolean;
  humanApproverReachable: boolean;
  overridable?: boolean;
}): boolean {
  if (opts.overridable === false) return false;
  return opts.daemonUp && !opts.isTestEnv && opts.humanApproverReachable;
}

export async function authorizeHeadless(
  toolName: string,
  args: unknown,
  meta?: {
    agent?: string;
    mcpServer?: string;
    serverKey?: string;
    sessionId?: string;
    transcriptPath?: string;
  },
  options?: {
    calledFromDaemon?: boolean;
    cwd?: string;
    localSmartRuleMatched?: boolean;
    deferReview?: boolean;
    /** The caller classes this tool as state-changing (the MCP gateway: any
     *  tool the server does not declare `readOnlyHint`), so a tainted session
     *  routes it to review like a write or network call. Left undefined (the
     *  agent hook), a namespaced `mcp__*` tool is gated: fw#344. */
    sessionTaintGated?: boolean;
  }
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
    // Strip ANSI escape sequences — agent / mcpServer come from caller-supplied
    // metadata and may be displayed in a terminal (node9 tail/watch), enabling
    // injection. mcpServer is capped shorter (40 chars) than agent (80).
    const sanitizedAgent = meta?.agent ? safeMessage(meta.agent, 80) : undefined;
    const sanitizedMcpServer = meta?.mcpServer ? safeMessage(meta.mcpServer, 40) : undefined;

    const socketOk = await notifyActivity({
      id: actId,
      ts: actTs,
      tool: toolName,
      args,
      status: 'pending',
      agent: sanitizedAgent,
      mcpServer: sanitizedMcpServer,
      sessionId: meta?.sessionId,
    });
    const result = await _authorizeHeadlessCore(toolName, args, meta, {
      ...options,
      activityId: actId,
      // If socket send failed, tell the daemon NOT to assume we already sent the
      // activity event — it must emit it itself so tail never misses an entry.
      socketActivitySent: socketOk,
    });
    // noApprovalMechanism means no channels were available — the CLI will retry
    // after auto-starting the daemon. Don't log a false 'block' to the flight
    // recorder; the retry call will produce the real result notification.
    if (!result.noApprovalMechanism) {
      await notifyActivity({
        id: actId,
        tool: toolName,
        args,
        ts: actTs,
        status: result.review
          ? 'review'
          : result.approved
            ? 'allow'
            : result.blockedByLabel?.includes('DLP')
              ? 'dlp'
              : result.blockedByLabel?.includes('Taint')
                ? 'taint'
                : 'block',
        label: result.blockedByLabel,
        ruleHit: result.ruleHit,
        observeWouldBlock: result.observeWouldBlock,
        agent: sanitizedAgent,
        mcpServer: sanitizedMcpServer,
        sessionId: meta?.sessionId,
      });
    }
    return result;
  }
  return _authorizeHeadlessCore(toolName, args, meta, options);
}

/** How long the terminal racer waits on /wait. The daemon answers by its
 *  own timer, so the cap only guards against a daemon that never does: a
 *  fixed 120 s cap cut a longer configured timeout short (the abort closes
 *  the long-poll, which removes the card), and a 0 ("no timer") must not be
 *  capped at all. */
export function daemonWaitCapMs(approvalTimeoutMs: number | undefined): number {
  if (approvalTimeoutMs === 0) return 0;
  return Math.max(approvalTimeoutMs ?? 0, 120_000) + 5_000;
}

/**
 * The message shown when the gate asked for approval and nobody answered.
 *
 * Exported so the copy can be asserted directly: the live one is built inside
 * a setTimeout in a promise race, and a test that drove the whole race would
 * be proving the wording by reconstructing the thing that produces it.
 *
 * The second line is the point. This is the moment the product has just cost
 * someone work, which makes it the one place a call to action is welcome
 * rather than an interruption. It names `node9 login`, which with no argument
 * opens the browser and needs nothing prepared -- unlike `node9 connect`,
 * which requires a token minted in the dashboard.
 */
export function approvalTimeoutReason(approvalTimeoutMs: number): string {
  return (
    `No human response within ${approvalTimeoutMs / 1000}s — auto-denied by timeout policy. ` +
    'Approve from your phone next time: run `node9 login`.'
  );
}

export async function _authorizeHeadlessCore(
  toolName: string,
  args: unknown,
  metaArg?: {
    agent?: string;
    mcpServer?: string;
    serverKey?: string;
    sessionId?: string;
    transcriptPath?: string;
    workingDir?: string;
  },
  options?: {
    calledFromDaemon?: boolean;
    activityId?: string;
    cwd?: string;
    localSmartRuleMatched?: boolean;
    socketActivitySent?: boolean;
    deferReview?: boolean;
    sessionTaintGated?: boolean;
  }
): Promise<AuthResult> {
  // Thread the working directory into meta so every audit row written below
  // carries it (the SaaS event-detail Context block reads it). One place,
  // so all decision paths inherit it. See shipper-context-fields.md.
  // `let`, not `const`: the DLP gate widens it with the finding's attribution
  // (dlpPattern / dlpSample) so EVERY later row -- persistent, trust, race
  // outcome, cloud -- says what was found, the way the block row already does.
  let meta:
    | (NonNullable<typeof metaArg> & {
        dlpPattern?: string;
        dlpSample?: string;
        ruleName?: string;
        exposure?: { kind: 'source' | 'logged'; destinations: number };
        exposureFromEid?: string;
      })
    | undefined =
    options?.cwd && !metaArg?.workingDir ? { ...metaArg, workingDir: options.cwd } : metaArg;
  if (process.env.NODE9_PAUSED === '1') return { approved: true, checkedBy: 'paused' };
  const pauseState = checkPause();
  if (pauseState.paused) return { approved: true, checkedBy: 'paused' };

  const creds = getCredentials();
  // A forecast run (forecast.ts) judges under the configuration its caller
  // resolved once per project; everything else below is the live gate.
  const forecast = forecastRun();
  const config = forecast?.config ?? getConfig(options?.cwd);
  // `let`: forced on once the DLP gate flags a credential, so no row written
  // for that call -- flagged, persistent, trust, race outcome, no-channel deny
  // -- carries the args in clear. The block row already forces it (`true`
  // below); a review row passing the config value leaked the credential when
  // auditHashArgs was off and redactSecrets had no label to key on
  // (/code-review, DLP-3).
  let hashAuditArgs = config.settings.auditHashArgs === true;

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
    approvers.terminal = false;
  }
  // Browser approval channel was retired in v3 sprint — always off,
  // regardless of config. The `approvers.browser` field stays in the
  // schema for back-compat with existing user configs; reads just
  // ignore it. Forced false here so any in-memory mutation can't
  // accidentally re-enable the (deleted) channel.
  approvers.browser = false;

  if (config.settings.enableHookLogDebug && !isTestEnv) {
    appendHookDebug(toolName, args, meta, hashAuditArgs);
  }

  const isManual = meta?.agent === 'Terminal';
  // Audit (and `observe`, its older name): nothing is stopped; every check
  // records what it would have done.
  // A forecast reports the enforcing verdict and labels it not enforced
  // itself; the checks run as they would at an enforcing level.
  const isObserveMode = isRecordOnly(config.settings.mode) && !forecast;

  let explainableLabel = 'Local Config';
  let dlpReviewFlagged = false; // a credential was found at DLP 'review' severity
  let packageReview: string | null = null; // the package check asked for review
  let policyMatchedField: string | undefined;
  let policyMatchedWord: string | undefined;
  // The engine verdict behind a review, for the inline-ask result and the
  // forecast: the rule and the catalog check that asked.
  let policyReviewRule: string | undefined;
  let policyReviewCheckId: string | undefined;
  let policyRuleDescription: string | undefined;
  let riskMetadata: RiskMetadata | undefined;
  // Set when a stateful block's predicates are NOT met and we fall through to the
  // race engine — passed to registerDaemonEntry so the tail shows the recovery menu.
  let statefulRecoveryCommand: string | undefined;
  // Set when a local smart rule with verdict "review" matched — prevents cloud's
  // immediate-allow from bypassing the human approval card.
  let localSmartRuleMatched = false;
  // Round-2 F1: set when a hard BLOCK verdict was downgraded to review (a
  // reachable human, or a stateful rule's availability downgrade). Guards the
  // ruleName-less intrinsic blocks (pipe-chain/eval-remote/suspect-binary,
  // tier 3, no ruleName) from being resolved by any non-human channel.
  let hardBlockDowngraded = false;
  // ENG-2: what the block would have said had no human been reachable. When the
  // review a downgrade opened is denied by something other than a person (the
  // daemon's timer, its own background pass), the agent gets this verdict, not
  // a human rejection.
  let downgradedBlock: AuthResult | null = null;

  // The argument scan (bounded decoding views) is the most expensive check on
  // the hot path. Run it at most once per call and hand the result to the
  // engine and every guard that needs it.
  let argScan: DlpMatch | null | undefined;
  const argumentScan = (): DlpMatch | null => (argScan ??= scanArgumentSecrets(args));

  // Resolve once with this request's cwd/config. This floor cannot be skipped
  // by the taint branch, ignored Read, or a trusted-host pipeline.
  let fileAccess: PreparedFileAccess;
  let fileFinding: ProtectedFileVerdict | null;
  try {
    fileAccess = prepareFileAccesses(toolName, args, options?.cwd, inspectionLayers(config.policy));
    fileFinding = isManual
      ? null
      : evaluateProtectedFileAccess(
          fileAccess.accesses,
          fileAccess,
          catalogSettingsFromConfig(config.settings, config.policy)
        );
  } catch (error) {
    // The hook's outer catch fails open. An operand this analysis cannot
    // evaluate is held for approval instead; legacy path DLP stays in force.
    // The message never carries the operand (picomatch reports only lengths).
    try {
      appendToLog(HOOK_DEBUG_LOG, {
        ts: new Date().toISOString(),
        check: 'file-protection',
        tool: toolName,
        message: String((error as Error)?.message ?? error).slice(0, 200),
      });
    } catch {
      /* Logging must not turn a held call into a failure. */
    }
    fileAccess = { cwd: options?.cwd, homeDirs: [], accesses: [], handledPaths: new Set() };
    fileFinding = isManual ? null : incompleteFileVerdict();
  }
  const shellInput = resolveShellInput(toolName, args, inspectionLayers(config.policy));
  // ── A SCRIPT WRITTEN THIS SESSION (fw#372 A3) ─────────────────────────────
  // The files this call writes are recorded with the daemon; a shell command
  // that runs a script the session wrote is judged from the script's content
  // as well, by the file policy here and by the engine in evaluateCurrentPolicy
  // below, the stricter verdict winning. Without it every shell check could be
  // stepped around by writing the command into a file first. Fails open: no
  // daemon, no record, no second judgement.
  if (!isManual) await recordSessionWrites(toolName, args, fileAccess, options?.cwd);
  const sessionScript: SessionScript | null = isManual
    ? null
    : await resolveSessionScript(toolName, args, options?.cwd, inspectionLayers(config.policy));
  if (sessionScript) {
    try {
      const inner = evaluateProtectedFileAccess(
        sessionScript.fileAccess.accesses,
        sessionScript.fileAccess,
        catalogSettingsFromConfig(config.settings, config.policy)
      );
      if (
        inner &&
        (!fileFinding || VERDICT_RANK[inner.decision] > VERDICT_RANK[fileFinding.decision])
      )
        fileFinding = fromScript(inner, sessionScript.path);
    } catch {
      /* An operand the matcher cannot evaluate in the script: the command's own verdict stands. */
    }
  }
  const networkShell = shellInput.kind === 'shell' && NETWORK_COMMAND_RE.test(shellInput.command);
  const shellReview = !isManual && shellInput.kind === 'uninspectable';
  if (shellReview) {
    hashAuditArgs = true;
    explainableLabel = 'Shell inspection incomplete';
    policyRuleDescription =
      'The executable command could not be inspected. Approve this call explicitly.';
  }
  const fileReview = !isObserveMode && fileFinding?.decision === 'review';
  const evaluateCurrentPolicy = async (skipIgnoredFastPath = false) => {
    const own = await evaluatePolicy(toolName, args, meta?.agent, options?.cwd, {
      fileAccess,
      config,
      skipIgnoredFastPath,
      argumentScan: argScan,
      // A server a person linked to an app is judged as that app (fw#390).
      mcpServer: resolveLinkedServer(meta?.mcpServer, {
        serverKey: meta?.serverKey,
        managedLinks: config.policy.appLinks,
        appliedShields: config.policy.appliedShields,
        workspaceGoverned: config.policySource === 'workspace',
      }),
    });
    if (!sessionScript || own.decision === 'block') return own;
    // The script's content, judged as a Bash command of its own; its verdict
    // replaces the command's only when it is stricter.
    const inner = await evaluatePolicy('Bash', sessionScript.args, meta?.agent, options?.cwd, {
      fileAccess: sessionScript.fileAccess,
      config,
      skipIgnoredFastPath,
    });
    if (VERDICT_RANK[inner.decision] <= VERDICT_RANK[own.decision]) return own;
    return fromScript(inner, sessionScript.path);
  };
  if (fileFinding) {
    meta = { ...meta, ruleName: fileFinding.ruleName };
    // The command or edit content may contain credentials; do not log it before DLP runs.
    hashAuditArgs = true;
    const observing = isObserveMode;
    const blocked =
      !observing && (fileFinding.decision === 'block' || (fileReview && config.settings.panicMode));
    appendLocalAudit(
      toolName,
      args,
      blocked ? 'deny' : 'allow',
      observing
        ? 'observe-mode-file-protection'
        : blocked
          ? 'file-protection-block'
          : fileReview
            ? 'file-protection-review'
            : 'file-protection-log',
      meta,
      hashAuditArgs
    );
    if (blocked)
      return {
        approved: false,
        checkedBy: 'local-policy',
        blockedBy: 'local-config',
        reason: fileFinding.reason,
        blockedByLabel: fileFinding.blockedByLabel,
        ruleHit: fileFinding.ruleName,
        ruleDescription: fileFinding.ruleDescription,
        // Only when the arguments carry no credential: the agent must not be
        // told that nothing was exposed while the content holds a key.
        ...(!argumentScan() && {
          blockKind: 'protected-path' as const,
          blockedPath: safePathForDisplay(fileFinding.path),
        }),
      };
    if (fileReview) {
      explainableLabel = fileFinding.blockedByLabel ?? explainableLabel;
      policyRuleDescription = fileFinding.reason;
    }
  }

  // ── TAINT CHECK ───────────────────────────────────────────────────────────
  // Before DLP: if this is a network/upload operation touching a previously
  // tainted file, surface a warning through the race engine — the user decides.
  // Taint is heuristic (a file *may* still be sensitive); hard blocks are
  // reserved for team policy shields.
  let taintWarning: string | null = null;
  if (shellInput.kind === 'shell' && NETWORK_COMMAND_RE.test(shellInput.command)) {
    const filePaths = extractFilePaths(toolName, args, shellInput.command);
    if (filePaths.length > 0) {
      const taintResult = await checkTaint(filePaths);
      if (taintResult.tainted && taintResult.record) {
        const {
          path: taintedPath,
          source: taintSource,
          fromEid: taintFromEid,
        } = taintResult.record;
        taintWarning = `⚠️ ${taintedPath} was flagged by ${taintSource} — this file may contain sensitive data`;

        // ── Phase 4: taint × egress synergy (GAP-5) ──────────────────────────
        // A CONFIRMED-tainted file heading to an UNTRUSTED host is the highest-
        // confidence local exfil signal — upgrade from the soft taint review to
        // a hard block. Only when egress is enabled and the destination isn't on
        // the allow list / private (evaluateEgress returns non-null).
        if (config.policy.egress?.enabled) {
          const dests = extractShellDestinations(shellInput.command);
          const eg = dests.length > 0 ? evaluateEgress(dests, config.policy.egress) : null;
          if (eg) {
            if (!isManual)
              appendLocalAudit(
                toolName,
                args,
                'deny',
                isObserveMode ? 'observe-mode-taint-egress-would-block' : 'taint-egress-block',
                // Phase D2 — the causal taint edge: from the row that created
                // the taint (taintFromEid) to this block row.
                { ...meta, ruleName: `taint-egress:${eg.host}`, taintFromEid, taintSource },
                hashAuditArgs
              );
            if (isObserveMode) {
              return {
                approved: true,
                checkedBy: 'audit',
                observeWouldBlock: true,
                blockedByLabel: '🔴 Node9 Taint+Egress (Exfiltration)',
              };
            }
            return {
              approved: false,
              reason:
                `🔴 EXFILTRATION BLOCKED: the tainted file "${taintedPath}" is being sent to ` +
                `untrusted host "${eg.host}". A flagged file leaving to an unrecognized ` +
                `destination is blocked outright.`,
              blockedBy: 'local-config',
              blockedByLabel: '🔴 Node9 Taint+Egress (Exfiltration Blocked)',
            };
          }
        }
      } else if (taintResult.daemonUnavailable) {
        // Taint service is down — cannot confirm files are clean.
        // Treat as a soft taint: the user sees a warning and must explicitly
        // approve. This prevents a daemon crash from silently unblocking
        // exfiltration checks.
        taintWarning = `⚠️ Taint service unavailable — cannot verify if ${filePaths.join(', ')} is clean`;
      }
    }
  }

  // ── SESSION TAINT (gap1) ──────────────────────────────────────────────────
  // If an earlier tool's OUTPUT in this session was flagged (a secret surfaced;
  // later, an injected instruction), route the session's next high-risk call —
  // network, write or MCP — to human review. Soft (review, not a hard block): tool
  // output containing a secret-shaped string is common and often benign, so we
  // confirm rather than block. `!taintWarning` keeps the file-taint above (with
  // its egress hard-block synergy) as the higher-precedence signal.
  //
  // MCP tools reach here two ways. The gateway forwards BARE names and says
  // itself whether the tool is gated (`sessionTaintGated`, from the server's
  // readOnlyHint). The agent hook forwards `mcp__<server>__<tool>` names and
  // says nothing: the hook never sees a tools/list, so it has no annotations
  // to consult. Until it does, every namespaced MCP tool is gated (fw#344):
  // `mcp__gmail__send_email` after a poisoned email was the one call the
  // taint existed for, and it was the one call the taint never reached.
  const mcpHookTool = options?.sessionTaintGated === undefined && isMcpToolName(toolName);
  // The daemon's answer to "is this session exposed", when the taint round
  // trip below already asked it (fw#318): undefined when it did not run.
  let daemonSaysExposed: boolean | undefined;
  if (
    !taintWarning &&
    meta?.sessionId &&
    (networkShell || isWriteTool(toolName) || options?.sessionTaintGated === true || mcpHookTool)
  ) {
    const sessionTaint = await checkSessionTaint(meta.sessionId);
    if (typeof sessionTaint.exposed === 'boolean') daemonSaysExposed = sessionTaint.exposed;
    if (sessionTaint.tainted && sessionTaint.record) {
      const kind = isWriteTool(toolName)
        ? 'write'
        : networkShell
          ? 'network'
          : mcpHookTool
            ? 'MCP'
            : 'state-changing';
      taintWarning =
        `⚠️ node9 flagged this session — earlier tool output contained ${sessionTaint.record.source}. ` +
        `Approve this ${kind} action before it proceeds.`;
    }
  }

  // ── INJECTED INSTRUCTIONS WRITTEN OR SENT (fw#372 B6) ────────────────────
  // The injection scan reads tool OUTPUT; an injected instruction that the
  // agent then writes into a note or a file, or sends on, persists past the
  // session unseen. With the scan on (injectionScan.enabled, off by default,
  // as the output scan is), the content a write tool or an MCP tool with a
  // destination carries is scanned too, and medium confidence (two signals;
  // arguments have no origin booster) routes the call to review the way a
  // session taint does. Measured: 0 of about 3,500 pre-stage benign rows
  // reach medium.
  if (!taintWarning && config.policy.injectionScan?.enabled && !isManual) {
    const sends = isMcpToolName(toolName) && extractArgDestinations(args).length > 0;
    if (isWriteTool(toolName) || sends) {
      const m = scanInjection(argumentLeavesText(args), { untrusted: false });
      if (m && (m.confidence === 'medium' || m.confidence === 'high')) {
        taintWarning =
          `⚠️ node9: the content this call ${isWriteTool(toolName) ? 'writes' : 'sends'} carries ` +
          `instructions aimed at an AI model (${m.signals.join(', ')}). Approve only if that is what you meant.`;
      }
    }
  }

  // ── SESSION EXPOSURE (fw#318 layer 4) ─────────────────────────────────────
  // The session READ outside content (an email, a web page, an issue): a call
  // that SENDS is judged by where it sends and what it is, not by whether the
  // text looked hostile. Design 5.2. The reason joins callSpecificReview()
  // below, so no standing approval, trust session or policy allow answers it.
  // Fail open like taint: no daemon, no record, no hold.
  let exposureReview: string | null = null;
  let exposureKeys: string[] = [];
  let exposureDestinations: string[] = [];
  let exposureFromEid: string | undefined;
  // The exposure fields of this call's audit rows (fw#318 2b), kept apart
  // from the shared `meta` so a row another gate writes (a DLP block, a
  // package review) never carries them (review F5). Held: the read's eid,
  // on the review's outcome rows. Logged: the count, on the allow row.
  let exposureMeta: {
    exposure?: { kind: 'source' | 'logged'; destinations: number };
    exposureFromEid?: string;
  } = {};
  const ownRowMeta = (approved: boolean) =>
    exposureMeta.exposureFromEid || (approved && exposureMeta.exposure)
      ? { ...meta, ...exposureMeta }
      : meta;
  const ucPolicy = config.policy.untrustedContent;
  if (ucPolicy?.enabled && !taintWarning && meta?.sessionId && !isManual) {
    // MCP actions (the hook's namespaced names, the gateway's flagged bare
    // names) are judged by their argument destinations. A shell command is
    // judged by its AST classification (P3): a SEND (`curl -d`, `git push`,
    // `gh issue comment`, `npm publish`) by the full table; a plain FETCH
    // (`curl https://x`) only when its host appeared in the content read,
    // which is how a query string carries data out. Holding every `curl`
    // after a WebFetch would stop ordinary coding sessions for nothing.
    const role = toolRole(toolName, ucPolicy);
    // The gateway forwards bare names and says itself that the tool acts.
    const acts = role.action || options?.sessionTaintGated === true;
    const shellExp = shellInput.kind === 'shell' ? classifyShellExposure(shellInput.command) : null;
    // P4: a write (a file tool, an MCP file tool by its bare name, or a shell
    // redirect, tee, cp, sed -i) is judged by where it lands and what it
    // carries, never as a send to the URLs its content mentions.
    const bareName = splitMcpToolName(toolName)?.bare;
    const mcpFileWrite = bareName !== undefined && fileToolOperation(bareName, args) === 'write';
    const writes = (
      mcpFileWrite
        ? prepareFileAccesses(bareName!, args, options?.cwd, inspectionLayers(config.policy))
            .accesses
        : fileAccess.accesses
    ).filter((a) => ['write', 'create', 'remove'].includes(a.operation));
    const sendsSomething = (acts && !mcpFileWrite) || !!shellExp?.sends;
    // A call judged only for a write or a plain fetch asks the daemon only
    // when it may be exposed: the hot path of an ordinary session (every
    // edit, every redirect) skips the round trip. The marker file is only a
    // hint: the agent can delete it. So the taint round trip's answer wins
    // when there was one (file tools, network shell, MCP), and a shell write
    // that exposure would hold anyway (outside the project, an instruction
    // file) asks the daemon even without a marker.
    const mayBeExposed =
      daemonSaysExposed ??
      (maybeSessionExposed(meta.sessionId) ||
        (writes.length > 0 &&
          judgeWritesAfterExposure({
            accesses: writes,
            args,
            shellCommand: shellInput.kind === 'shell' ? shellInput.command : null,
            cwd: options?.cwd,
            inContent: new Set(),
            isKnown: () => true,
          }).length > 0));
    const judged = sendsSomething || ((!!shellExp?.fetches || writes.length > 0) && mayBeExposed);
    if (judged) {
      const exposure = await checkSessionExposure(meta.sessionId);
      if (exposure.exposed && exposure.record) {
        const rec = exposure.record;
        // Argument destinations are a SEND only for an MCP action; what a
        // write tool carries in its content is judged by the write rules.
        const dests = new Set<string>(
          acts && !shellExp && !mcpFileWrite ? extractArgDestinations(args) : []
        );
        // Hosts a plain fetch reaches: judged only against the content read.
        const fetchOnly = new Set<string>();
        const projectHosts = shellExp ? knownProjectHosts(options?.cwd) : null;
        // `git push <name>` with a name the repository's config does not
        // hold, when that config lists remotes: nothing to compare, held. With
        // no readable config, the name is taken as the project's own remote.
        let unknownRemote = false;
        if (shellExp) {
          if (shellExp.sends) {
            for (const d of shellExp.destinations) dests.add(d);
            // `git push <remote>`: the repository's own remotes are known.
            // A push with no target ('') goes to the branch's default remote:
            // origin, or else one of the config's own remotes.
            for (const name of shellExp.gitRemotes) {
              const remotes = projectHosts!.remotes;
              const hosts =
                name === ''
                  ? (remotes.get('origin') ?? [...remotes.values()].flat())
                  : remotes.get(name);
              if (hosts) for (const h of hosts) dests.add(h);
              else if (projectHosts!.remotes.size > 0) unknownRemote = true;
            }
          }
          if (shellExp.fetches) {
            for (const h of shellExp.fetchDestinations) if (!dests.has(h)) fetchOnly.add(h);
          }
        }
        const inContent = new Set(rec.destinations);
        const mentioned = new Set(rec.userMentioned);
        const approved = new Set(rec.approved);
        const held: { dest: string; why: string; repo?: string }[] = [];
        const logged: string[] = [];
        const writeProjectHosts = projectHosts ?? knownProjectHosts(options?.cwd);
        // ONE known-destination test for sends, fetches and written content:
        // the organisation, the user's own words, the trusted lists, the
        // egress allow list and the project's own remotes and registries.
        const isKnown = (d: string): boolean => {
          const domain = destinationDomain(d);
          const value = destinationValue(d);
          return (
            (domain !== null && ucPolicy.orgDomains.includes(domain)) ||
            mentioned.has(d) ||
            isTrustedRecipient(d) ||
            matchesTrustedList(d, ucPolicy.trustedRecipients) ||
            (destinationKind(d) === 'host' &&
              (isLoopbackHost(value) ||
                isTrustedHost(value) ||
                (config.policy.trustedHostsManaged &&
                  matchesTrustedHost(value, config.policy.trustedHosts)) ||
                config.policy.egress.allow.some((pat) => hostMatches(value, pat)) ||
                writeProjectHosts.hosts.has(d)))
          );
        };
        const approvedOnce = (key: string) =>
          ucPolicy.afterExposure === 'ask-once' && approved.has(key);
        // On a git host the project uses, the repository decides, not the
        // host: github.com holds the project's origin and an attacker's
        // mirror alike. A repository there is known only when it is one of
        // the project's remotes (or approved once), and its host is not
        // judged. Elsewhere the host is judged as any other destination.
        const repos = (shellExp?.sends ? shellExp.repos : []).filter((r) =>
          writeProjectHosts.hosts.has(`host:${r.split('/')[0]}`)
        );
        const repoHosts = new Set(repos.map((r) => `host:${r.split('/')[0]}`));
        for (const r of repos) {
          if (writeProjectHosts.repos.has(r) || approvedOnce(`${toolName}|repo:${r}`))
            logged.push(`repo:${r}`);
          else held.push({ dest: '', why: 'repository', repo: r });
        }
        // Known wins: a colleague's address is in the email it replies to,
        // and the user's own words, the trusted lists and an earlier
        // approval all outrank "it appeared in the content". For a
        // destination nobody vouched for, appearing in the content is the
        // strongest signal and says so in the prompt.
        for (const d of dests) {
          if (repoHosts.has(d)) continue;
          if (approvedOnce(`${toolName}|${d}`) || isKnown(d)) logged.push(d);
          else if (inContent.has(d)) held.push({ dest: d, why: 'appeared in what was read' });
          else held.push({ dest: d, why: 'not known to this session' });
        }
        // A plain fetch is held only when its host appeared in the content
        // read and nobody vouched for it.
        for (const d of fetchOnly) {
          if (approvedOnce(`${toolName}|${d}`) || isKnown(d) || !inContent.has(d)) logged.push(d);
          else held.push({ dest: d, why: 'appeared in what was read' });
        }
        // A shell send whose destination is built at run time (`curl -d @f
        // "$URL"`) names nothing to compare: after exposure it is held.
        if (
          shellExp?.sends &&
          (shellExp.unresolved ||
            unknownRemote ||
            (shellExp.destinations.length === 0 && shellExp.gitRemotes.length === 0)) &&
          !approvedOnce(`${toolName}|unresolved`)
        ) {
          held.push({ dest: '', why: 'unresolved' });
        }
        // A file write is judged by the write rules below: the reference
        // filesystem server marks write_file destructive (it overwrites).
        const bare = splitMcpToolName(toolName)?.bare ?? toolName;
        if (
          dests.size === 0 &&
          acts &&
          !mcpFileWrite &&
          (role.destructive === true || isDestructiveToolName(bare))
        ) {
          held.push({ dest: '', why: 'destructive' });
        }
        // P4: writes after exposure (design 6). Each hold carries a key so
        // ask-once can clear that path (or that destination) for the session.
        const writeHolds: WriteHold[] =
          writes.length > 0
            ? judgeWritesAfterExposure({
                accesses: writes,
                args,
                shellCommand: shellInput.kind === 'shell' ? shellInput.command : null,
                cwd: options?.cwd,
                inContent,
                isKnown,
              }).filter((h) => {
                const key = `${toolName}|${h.why === 'content-destination' ? h.destination : `path:${h.path}`}`;
                if (ucPolicy.afterExposure === 'ask-once' && approved.has(key)) {
                  logged.push(key);
                  return false;
                }
                return true;
              })
            : [];
        const last = rec.sources[rec.sources.length - 1];
        const readWord = last ? (last.word ?? sourceWord(last.tool)) : 'content';
        const when = last ? new Date(last.at).toTimeString().slice(0, 5) : '';
        const read = last
          ? `${/^[aeiou]/i.test(readWord) ? 'an' : 'a'} ${readWord}` +
            (last.server ? ` through ${last.server}` : '') +
            (when ? ` at ${when}` : '')
          : 'outside content';
        if ((held.length > 0 || writeHolds.length > 0) && ucPolicy.afterExposure !== 'log-only') {
          const noun = (d: string): string => {
            const k = destinationKind(d);
            return k === 'email' ? 'an address' : k === 'host' ? 'a host' : 'an account';
          };
          const parts = held.map((h) =>
            h.dest
              ? `sends to ${destinationValue(h.dest)}, ${
                  h.why === 'appeared in what was read'
                    ? `${noun(h.dest)} that appeared in that ${last ? readWord : 'content'}`
                    : `${noun(h.dest)} this session did not know`
                }`
              : h.why === 'repository'
                ? h.repo!.endsWith('/*')
                  ? `sends to a repository on ${h.repo!.slice(0, -2)} it does not name (a gist, a new repository or an API call)`
                  : `sends to ${h.repo}, a repository that is not one of this project's remotes`
                : h.why === 'unresolved'
                  ? 'sends to a destination this session cannot see (built at run time, or a remote of another repository)'
                  : `is ${bare}, a destructive call, with no known destination`
          );
          const home = os.homedir();
          const short = (p: string) => (p.startsWith(home + '/') ? '~' + p.slice(home.length) : p);
          for (const w of writeHolds) {
            parts.push(
              w.why === 'outside-project'
                ? `writes outside the project, to ${short(w.path)}`
                : w.why === 'agent-instruction'
                  ? `writes to ${short(w.path)}, a file that runs code or instructs the agent`
                  : `writes content carrying ${destinationValue(w.destination ?? '')}, ${noun(w.destination ?? 'host:x')} that appeared in that ${readWord}`
            );
          }
          exposureReview = `🛡️ Node9: this session read ${read}. This call ${parts.join('; and ')}.`;
          // fw#318 2b: the edge from the read to this send, on the rows the
          // review writes (the race outcome, the no-channel deny) and, through
          // the review marker, the inline outcome row.
          exposureFromEid = last?.eid;
          if (exposureFromEid) exposureMeta = { exposureFromEid };
          exposureKeys = [
            ...held
              .filter((h) => h.dest || h.why === 'unresolved' || h.why === 'repository')
              .map((h) =>
                h.why === 'repository'
                  ? `${toolName}|repo:${h.repo}`
                  : `${toolName}|${h.dest || 'unresolved'}`
              ),
            ...writeHolds.map(
              (w) =>
                `${toolName}|${w.why === 'content-destination' ? w.destination : `path:${w.path}`}`
            ),
          ];
          // The destinations ride on the card for "Approve and trust this
          // address" (P5); the inline prompt names the command instead.
          exposureDestinations = held
            .filter((h) => h.dest)
            .map((h) => h.dest)
            .slice(0, 10);
          if (exposureDestinations.length > 0 && options?.deferReview) {
            exposureReview +=
              ` To trust ${exposureDestinations.length === 1 ? 'this address' : 'these addresses'} for good, the user runs: ` +
              exposureDestinations
                .map((d) => `node9 trust recipient add ${destinationValue(d)}`)
                .join('; ') +
              '.';
          }
        } else if (held.length > 0 || writeHolds.length > 0 || logged.length > 0) {
          // Judged and let through. The call's own allow row (written below
          // by whichever path allows it) carries the fact, counts only, never
          // a value (fw#318 2b); the debug log keeps the local detail. No
          // edge to the read: only a send the gate held draws one (review F1).
          exposureMeta = { exposure: { kind: 'logged', destinations: logged.length } };
          appendToLog(HOOK_DEBUG_LOG, {
            ts: new Date().toISOString(),
            event: 'exposure-logged',
            tool: toolName,
            held: held.length + writeHolds.length,
            known: logged.length,
            sessionId: meta.sessionId,
          });
        }
      } else if (exposure.daemonUnavailable) {
        appendToLog(HOOK_DEBUG_LOG, {
          ts: new Date().toISOString(),
          event: 'exposure-unavailable',
          tool: toolName,
        });
      }
    }
  }

  // ── CANARY (DECOY CREDENTIAL) GATE ────────────────────────────────────────
  // A value node9 planted itself has no legitimate path into any tool call.
  // So this runs BEFORE the DLP scanner, independent of dlp.enabled and of the
  // ignored-tool list, and a hit is a hard block even where the regex DLP
  // would only review (design: doc/roadmap/active/canary-design.md; H15, E5).
  // The registry is read per call; a read failure means "no canaries" so the
  // gate can never crash a tool call.
  const canaryVals = safeCanaryValues();
  if (canaryVals.length > 0) {
    const canaryHit = matchCanaryArgs(args, canaryVals);
    if (canaryHit) {
      const rec = canaryRecordById(canaryHit.id);
      // Attribution only: the shape path may have fired on the same value;
      // both attributions ride one row (E1, E6).
      const shape = scanArgs(args);
      const canaryReason =
        `🚨 DECOY CREDENTIAL: the fake ${rec?.kind ?? 'credential'} node9 planted at ` +
        `${rec?.path ?? 'a decoy file'} appeared in field "${canaryHit.fieldPath || 'args'}". ` +
        `Something read that file; nothing legitimate does.`;
      if (!isManual)
        appendLocalAudit(
          toolName,
          args,
          'deny',
          isObserveMode ? 'observe-mode-dlp-canary-would-block' : 'dlp-canary-block',
          {
            ...meta,
            canaryId: canaryHit.id,
            canaryHash: rec?.valueHash,
            canaryKind: rec?.kind,
            canaryPath: rec?.path,
            canaryView: canaryHit.view,
            canaryRetired: canaryHit.retired,
            ...(shape ? { dlpPattern: shape.patternName, dlpSample: shape.redactedSample } : {}),
          },
          true
        );
      if (isObserveMode) {
        return {
          approved: true,
          checkedBy: 'audit',
          observeWouldBlock: true,
          blockedByLabel: '🚨 Node9 DLP (Decoy Credential)',
        };
      }
      return {
        approved: false,
        reason: canaryReason,
        blockedBy: 'local-config',
        blockedByLabel: '🚨 Node9 DLP (Decoy Credential)',
        // The /dev/tty banner renders ruleDescription under "Triggered by".
        // Without it the terminal said only "Decoy Credential" and never named
        // the file, while `node9 canary plant` promises node9 tells you which
        // file was read. Witnessed by canary-block-message.spec.ts, which calls
        // the orchestrator directly: this field never reaches the hook stdout.
        ruleDescription: `The fake credential node9 planted in ${rec?.path ?? 'a decoy file'} just left that file. Nothing legitimate reads it.`,
      };
    }
  }

  // ── SSRF FLOOR, NON-SHELL DESTINATIONS ────────────────────────────────────
  // A tool that fetches a URL itself never produces a shell command, so the
  // floor inside evaluatePolicy cannot see it — and WebFetch, get_*, read_*
  // and list_* are on the ignoredTools list, so it never reaches evaluatePolicy
  // at all. Measured: `curl http://<metadata>/` blocked while the same address
  // through WebFetch was allowed.
  //
  // So this runs here, beside the canary gate and before the ignored-tool fast
  // path, on the same principle: a protected address in a declared destination
  // argument has no legitimate path into a tool call. It calls the SAME engine
  // function evaluatePolicy calls, so the gate and `node9 explain` cannot
  // disagree. A closed list of tool + argument paths, never a scan: see
  // egress/destinations.ts for why that is the only safe shape.
  {
    const dest = ssrfDestinationFloor(toolName, args, {
      ssrfAllow: config.policy.egress?.ssrfAllow,
      ssrfStrict: config.policy.egress?.ssrfStrict,
    });
    if (dest && !isObserveMode) {
      const ssrfRule = `ssrf:${dest.tier}:${toolName}:${dest.host}`;
      if (!isManual)
        appendLocalAudit(
          toolName,
          args,
          'deny',
          'ssrf-destination',
          // The row names the tier and the tool; the host stays in the reason,
          // so a report grouping by rule sees one rule per tier, not per host.
          { ...meta, ruleName: `ssrf:${dest.tier}:${toolName}` },
          hashAuditArgs
        );
      return {
        approved: false,
        checkedBy: 'local-policy',
        blockedByLabel: '🌐 Node9 Egress (Protected Address)',
        reason: dest.reason,
        // AuthResult carries no ruleName; the rule identity the audit row needs
        // travels in ruleHit, as it does for a smart-rule block.
        ruleHit: ssrfRule,
        ruleDescription: dest.reason,
      };
    }
  }

  // ── DLP, PII AND PACKAGE CHECK (the stateless gates) ─────────────────────
  // Their order and their stop/review rules live in policy/gate-order.ts,
  // which `node9 explain` runs too (node9Firewall#405), so the two cannot
  // drift. The scanning, every audit row and every side effect stay here.
  // DLP runs before the ignored-tool fast path and audit mode so that a
  // leaked credential is always caught, even for "safe" tools like
  // web_search. The PII gate is its own control (default 'block'), independent
  // of dlp.enabled. The package check: a known malicious package (OSV MAL-
  // record) blocks with the advisory id; a malicious record with an unknown
  // version, a package published inside policy.packageCheck.maxAgeHours, or
  // an npm install script routes to review. Lookups fail OPEN, and every miss
  // is written to hook-debug.log. Not for manual (Terminal) calls: a human
  // typing an install is the decision this check would otherwise ask them
  // for. `?.`: a config without the key must skip the check, never throw.
  const argsObj =
    args && typeof args === 'object' && !Array.isArray(args)
      ? (args as Record<string, unknown>)
      : {};
  const filePath = String(argsObj.file_path ?? argsObj.path ?? argsObj.filename ?? '');
  const packageCheck = config.policy.packageCheck;
  const gates = await runStatelessGates({
    settings: {
      panicMode: config.settings.panicMode === true,
      dlp: config.policy.dlp,
      toolIgnored: isIgnoredTool(toolName),
    },
    // The file gate was decided above, before the stateful gates.
    // P1-1/P1-2: the file path first (blocks a read before its content comes
    // back, and resolves symlinks), then the arguments.
    dlp: () =>
      (filePath
        ? scanFilePath(filePath, options?.cwd, {
            systemAccessHandled: !isManual && fileAccess.handledPaths.has(filePath),
          })
        : null) ?? argumentScan(),
    pii: () => detectArgsPii(args),
    packageCheck: () =>
      packageCheck?.enabled && !isManual
        ? runPackageCheck(toolName, args, packageCheck, options?.cwd, { offline: !!forecast })
        : Promise.resolve(null),
  });

  const dlpMatch: DlpMatch | null = gates.stop?.dlpMatch ?? gates.reviews.dlp ?? null;
  if (dlpMatch) {
    // Attribution and hashing, ONCE, for both paths below: every row written
    // for this call -- the block row, the flagged row, and every outcome row
    // after it -- names the pattern and carries no credential in its args.
    meta = { ...meta, dlpPattern: dlpMatch.patternName, dlpSample: dlpMatch.redactedSample };
    hashAuditArgs = true;
  }
  if (gates.reviews.dlp) {
    // severity === 'review': fall through to the race engine with a DLP label.
    // Write an audit entry now so the DLP flag is traceable even if the race
    // engine later approves the call without recording why it was intercepted.
    if (!isManual)
      appendLocalAudit(toolName, args, 'allow', 'dlp-review-flagged', meta, hashAuditArgs);
    explainableLabel = GATE_LABELS.dlpReview;
    dlpReviewFlagged = true;
  }
  const pkgResult = gates.packageResult;
  if (pkgResult && pkgResult.misses.length > 0) {
    noteForecastUnknown('package-registry');
    appendToLog(HOOK_DEBUG_LOG, {
      ts: new Date().toISOString(),
      event: 'package-check-miss',
      tool: toolName,
      misses: pkgResult.misses,
    });
  }

  if (gates.stop?.gate === 'dlp' && dlpMatch) {
    // Always hash args on DLP blocks — the secret must never appear in
    // the audit log. The pattern + redacted sample ride on the local row;
    // the outbox shipper carries them to the SaaS (no decision-time
    // network call — that path used to lose events when the hook process
    // exited before the fire-and-forget POST completed).
    // Phase D2 — capture this row's eid so the taint it creates can point
    // back to it (the causal edge source). Undefined under --manual (no row).
    let dlpEid: string | undefined;
    if (!isManual)
      dlpEid = appendLocalAudit(
        toolName,
        args,
        'deny',
        isObserveMode ? 'observe-mode-dlp-would-block' : 'dlp-block',
        meta,
        hashAuditArgs
      );
    // Taint the destination file so future uploads of it are also blocked.
    if (isWriteTool(toolName) && filePath) {
      await notifyTaint(filePath, `DLP:${dlpMatch.patternName}`, dlpEid);
    }
    if (isObserveMode) {
      return {
        approved: true,
        checkedBy: 'audit',
        observeWouldBlock: true,
        blockedByLabel: gates.stop.label,
      };
    }
    return {
      approved: false,
      reason: gates.stop.reason,
      blockedBy: 'local-config',
      blockedByLabel: gates.stop.label,
      // A PATH hit is a protected file, not a secret in the arguments: the
      // agent must not be told to rotate a credential it never saw (MSG-1).
      // Only when the arguments carry no credential: a path match
      // short-circuits the argument scan above (`scanFilePath ?? scanArgs`),
      // so a Write of a real key into .env would otherwise be told "nothing
      // was exposed" (/code-review).
      ...(dlpMatch.patternName === SENSITIVE_PATH_PATTERN &&
        !argumentScan() && {
          blockKind: 'protected-path' as const,
          blockedPath: safePathForDisplay(dlpMatch.redactedSample),
        }),
    };
  }

  if (gates.stop?.gate === 'pii' && gates.stop.pii) {
    // Args are always hashed in the audit row (last arg true) so the PII
    // value never lands in audit.log in clear.
    if (!isManual)
      appendLocalAudit(
        toolName,
        args,
        'deny',
        isObserveMode ? 'observe-mode-pii-would-block' : 'pii-block',
        { ...meta, piiPatterns: gates.stop.pii.join(',') },
        true
      );
    if (isObserveMode) {
      return {
        approved: true,
        checkedBy: 'audit',
        observeWouldBlock: true,
        blockedByLabel: gates.stop.label,
      };
    }
    return {
      approved: false,
      reason: gates.stop.reason,
      blockedBy: 'local-config',
      blockedByLabel: gates.stop.label,
    };
  }

  if (gates.stop?.gate === 'package' && gates.stop.pkg) {
    const advisories = gates.stop.pkg.findings.flatMap((f) => f.advisories ?? []);
    appendLocalAudit(
      toolName,
      args,
      'deny',
      isObserveMode ? 'observe-mode-package-would-block' : 'package-malicious',
      { ...meta, ruleName: `package-check:${advisories.join(',')}` },
      hashAuditArgs
    );
    if (isObserveMode) {
      return {
        approved: true,
        checkedBy: 'audit',
        observeWouldBlock: true,
        blockedByLabel: gates.stop.label,
      };
    }
    return {
      approved: false,
      reason: gates.stop.reason,
      blockedBy: 'local-config',
      blockedByLabel: gates.stop.label,
      ruleHit: `package-check:${advisories.join(',')}`,
      ruleDescription: gates.stop.ruleDescription,
    };
  }

  if (gates.reviews.package?.reason) {
    appendLocalAudit(
      toolName,
      args,
      'allow',
      'package-review-flagged',
      { ...meta, ruleName: 'package-check:review' },
      hashAuditArgs
    );
    packageReview = gates.reviews.package.reason;
    if (!dlpReviewFlagged) explainableLabel = GATE_LABELS.packageReview;
  }

  // ── G10: a tool on the ignored list that DECLARES a destination ──────────
  // WebFetch is on ignoredTools, so with the guards below it never reached
  // evaluatePolicy and the egress policy was shell-only (measured 2026-09-20:
  // curl denied, WebFetch to the same host allowed, under mode:block). When
  // egress is on and the call carries a declared destination (the closed list
  // in egress/destinations.ts, the same one the floor above reads), it is
  // handed to the engine, whose egress verdict is computed BEFORE its ignored
  // fast path and returned there. The ENGINE builds the verdict, so
  // `node9 explain` and this gate cannot disagree.
  //
  // NOT skipIgnoredFastPath. The jail guard needs that door because its rules
  // live after the fast path; egress does not, and passing it opened the whole
  // engine tail to an ignored tool: measured on a strict-mode machine, every
  // ALLOWLISTED WebFetch became a review ("Global Config (Strict Mode
  // Active)") while explain, which passes no flag, still said ALLOW. That is
  // the G8 explain/gate gap, reintroduced by the fix that was meant to close
  // it. The engine's own fast path returns the egress verdict or allow.
  const declaredEgress =
    config.policy.egress?.enabled === true && extractToolDestinations(toolName, args).length > 0;
  const judge =
    !isIgnoredTool(toolName) || declaredEgress || !!fileFinding || shellInput.kind !== 'not-shell';

  if (isObserveMode) {
    if (judge) {
      const policyResult = await evaluateCurrentPolicy();
      const wouldBlock = policyResult.decision === 'block';
      if (!isManual)
        appendLocalAudit(
          toolName,
          args,
          'allow',
          wouldBlock ? 'observe-mode-would-block' : 'observe-mode',
          ownRowMeta(true),
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

  // ── MCP APP PERMISSIONS (P3 Phase 2 — GOVERN) ─────────────────────────────
  // Per-tool block/review for a gatewayed MCP server, keyed by (serverKey,
  // bareTool). Gated on serverKey ALONE — only the mcp-gateway passes it, and
  // there the tools/call name is ALREADY the bare upstream tool name (a stdio
  // gateway wraps one upstream; `write_file` is not namespaced), so mcpServer
  // (extractMcpServer) is undefined for the real path. We still defensively
  // strip an `mcp__<name>__` prefix if a namespaced caller ever appears. bareTool
  // then matches the SEE inventory's bare names — what the dashboard keyed by.
  // Enforced in the standard/strict path only (observe/audit already returned
  // above). Tightening gate: 'allow' is NOT a bypass — it falls through to
  // DLP/egress/smart-rules like an unset tool.
  // `review` routes to the human approver race below. Unlike taintWarning it is
  // a TIGHTENING gate that COMPOSES with policy: it does NOT skip evaluatePolicy,
  // so a shield/smart-rule hard-block still wins (review can add friction, never
  // remove it). `block` (and review under panic mode) hard-denies here.
  let appPermReview: string | null = null;
  let appPermReviewTool: string | null = null; // bareTool — for audit attribution

  /**
   * The review reasons, as two predicates every guard below asks instead of
   * keeping its own hand-written list. fix #3 (app permission) and task #16
   * (taint) each found those lists incomplete, and DLP-3 found the DLP
   * reason in none of them: a credential review was answered by a prior
   * "Always Allow", by the ignored-tools fast path, and by the SaaS's "no org
   * rule matched" allow (doc/roadmap/active/dlp-fixes-design.md, 0). A sixth
   * reason is added HERE and reaches every guard.
   *
   * callSpecificReview: a reason a user's STANDING decision (a prior "Always
   * Allow", a trust session, the ignored-tools fast path, a local policy
   * allow) cannot answer, because it was made before this call existed and
   * these are about THIS call's content or an org's say-so, not the tool. A
   * smart-rule review is deliberately NOT here: a standing decision is
   * exactly how a user pre-answers one ("trust git push for an hour").
   *
   * reviewDemanded: a reason a NON-HUMAN channel (a SaaS auto-allow, a
   * shadowMode answer) cannot answer. That is every reason.
   *
   * Closures, not constants: the reasons are set at different points of the
   * walk (DLP at the gate, app permission after, taint after that), and a
   * guard that runs early must see what is known so far.
   */
  const callSpecificReview = (): boolean =>
    fileReview ||
    shellReview ||
    dlpReviewFlagged ||
    !!appPermReview ||
    !!taintWarning ||
    !!exposureReview ||
    !!packageReview;
  /** A trust session may answer this call. ONE definition for the two places
   *  that must agree: the trust guard that honours a session, and the native
   *  "Always Allow" button that writes one. When they disagreed the button
   *  wrote a session the guard then ignored (fix #5 for app permissions; DLP,
   *  taint and downgraded hard blocks by /code-review, DLP-3). The button is
   *  unreachable under vitest (isTestEnv forces native off), so the trust-guard
   *  rows are its witness through this shared predicate. */
  const standingTrustApplies = (): boolean => !callSpecificReview() && !hardBlockDowngraded;
  const reviewDemanded = (): boolean =>
    callSpecificReview() ||
    localSmartRuleMatched === true ||
    options?.localSmartRuleMatched === true;
  if (meta?.serverKey) {
    const prefix = meta.mcpServer ? `mcp__${meta.mcpServer}__` : '';
    const bareTool =
      prefix && toolName.startsWith(prefix) ? toolName.slice(prefix.length) : toolName;
    const decision = config.policy.appPermissions?.[meta.serverKey]?.[bareTool];
    // Panic mode upgrades review → block, same as the policy-verdict rule below.
    const hardBlock =
      decision === 'block' || (decision === 'review' && config.settings.panicMode === true);
    if (hardBlock) {
      if (!isManual)
        appendLocalAudit(
          toolName,
          args,
          'deny',
          'app-permission-block',
          // ruleName gives the dashboard row its "why" (rule attribution), the
          // same channel shield fires use; mcpServer (in meta) gives the app chip.
          { ...meta, ruleName: `app-permission:${bareTool}` },
          hashAuditArgs
        );
      return {
        approved: false,
        blockedBy: 'local-config',
        reason:
          decision === 'block'
            ? `App permission: "${bareTool}" is set to block by your workspace.`
            : `App permission: "${bareTool}" requires review, and the workspace is in panic mode — all review actions are blocked.`,
        blockedByLabel:
          decision === 'block' ? '🔒 Node9 App Permission (Blocked)' : '🚨 Panic mode (org policy)',
      };
    }
    if (decision === 'review') {
      // Fall through — but through the FULL policy block (fix #3): a hard-block
      // verdict there still wins; only allow/review verdicts reach the race.
      appPermReview = `App permission: "${bareTool}" requires human approval (workspace policy).`;
      appPermReviewTool = bareTool;
    }
  }

  // Fast Paths (Ignore, Trust, Policy Allow)
  // A taint warning overrides trust sessions and policy allows, so the user
  // always gets a chance to review. Neither it nor appPermReview skips this
  // block (fix #3; for taint, the taint-order fix): the policy must run so a
  // hard-block verdict still wins. Before, a taint warning skipped the policy
  // entirely, and with the daemon down ("Taint service unavailable") a jail
  // block, a reverse shell or `curl | sh` on the same call became an
  // approvable question. The ALLOW-returns inside are each guarded by
  // `!callSpecificReview()`, which includes the taint warning.
  if (judge) {
    // ── LOOP DETECTION ────────────────────────────────────────────────────
    // Skipped for an org-set review (re-review regression fix): reopening this
    // block for fix #3 re-enabled loop detection, which would hard-deny a
    // review-marked tool BEFORE its approval card ever shows (an agent retrying
    // after a human deny trips the threshold). A review must always reach the
    // human; the human's own deny is the throttle.
    // G10: and skipped for a tool admitted by `judge` alone. An ignored tool
    // never reached this counter before; arming it because egress is ON turned
    // an agent re-fetching the same page into a hard "Loop Detected" deny
    // (measured: six identical WebFetch calls to an ALLOWLISTED host went
    // allow, allow, allow, allow, deny, deny). Egress judges the destination,
    // not the repetition.
    const ld = config.policy.loopDetection;
    if (ld.enabled && !appPermReview && !taintWarning && !isIgnoredTool(toolName)) {
      const loopResult = recordAndCheck(toolName, args, ld.threshold, ld.windowSeconds * 1000);
      if (loopResult.looping) {
        const reason =
          `It looks like you've called "${toolName}" ${loopResult.count} times with identical arguments ` +
          `in the last ${ld.windowSeconds}s. Are you stuck? Step back and reconsider your approach — ` +
          `what are you actually trying to accomplish, and is there a different way to get there?`;
        // Local row only — the outbox shipper delivers it (the old
        // fire-and-forget POST here died with process.exit, which is why
        // loop counts never reached the dashboard).
        if (!isManual)
          appendLocalAudit(
            toolName,
            args,
            'deny',
            'loop-detected',
            // Phase B — carry the loop magnitude so the SaaS shows "looped Nx".
            { ...meta, loopCount: loopResult.count },
            hashAuditArgs
          );
        return {
          approved: false,
          reason,
          blockedBy: 'loop-detection',
          blockedByLabel: '🔄 Loop Detected',
        };
      }
    }

    let policyResult = await evaluateCurrentPolicy();

    // ── Cloud panic mode ──────────────────────────────────────────────
    // When the workspace admin has flipped panic mode on (via the SaaS
    // dashboard, synced down by daemon/sync.ts to settings.panicMode),
    // every review-verdict is upgraded to a hard block. This is the
    // emergency switch — gives an admin a single toggle to stop all
    // questionable AI actions across their fleet during an incident.
    //
    // Allow-verdicts pass through unaffected (panic mode doesn't fight
    // explicit allow rules — those are typically the ignored-tool fast
    // path or user trust decisions, and breaking them would block reads
    // alongside writes). Block-verdicts also pass through (they're
    // already strictest possible).
    // The engine verdict against the gates' reviews: the shared rules
    // (policy/gate-order.ts). Panic mode upgrades a review to a block; an
    // allow stands only when no gate, stateless or stateful, asked for a
    // review. (`callSpecificReview()`: load-bearing. The engine runs the same
    // scanner and usually reviews whatever the gate flags; the gate's own
    // flags (taint, package, app permission, protected file, uninspectable
    // shell) are not all known to the engine, so the gate keeps the last word.)
    const combined = combineWithEngine(gates, policyResult, {
      panicMode: config.settings.panicMode === true,
      otherReviews: callSpecificReview(),
    });
    if (combined.panicked) {
      policyResult = {
        ...policyResult,
        decision: 'block',
        blockedByLabel: combined.blockedByLabel,
        reason:
          'Workspace is in panic mode — all review-verdict actions are blocked. ' +
          'Contact your admin to disable panic mode in the Node9 dashboard.',
      };
    }

    if (combined.decision === 'allow') {
      // Local row only — the outbox shipper delivers it. Removing the old
      // awaited POST also removes a cloud round-trip from EVERY allowed
      // call (the hot path). Rule attribution rides on the row so the SaaS
      // report classifier keeps its friendly labels.
      if (!isManual)
        appendLocalAudit(
          toolName,
          args,
          'allow',
          'local-policy',
          {
            ...ownRowMeta(true),
            ruleName: policyResult.ruleName,
            checkId: policyResult.checkId,
            logged: policyResult.logged,
          },
          hashAuditArgs
        );
      return {
        approved: true,
        checkedBy: 'local-policy',
        ...(policyResult.logged && {
          ruleHit: policyResult.ruleName,
          checkId: policyResult.checkId,
        }),
      };
    }

    // Hard block from smart rules — skip the race engine entirely
    if (policyResult.decision === 'block') {
      // Round-2 F1: any BLOCK verdict that survives this handler (i.e. was
      // downgraded to a review rather than returned as hardBlock()) must be
      // un-resolvable by every NON-HUMAN channel downstream. The guards there
      // key on ruleName/tier-7 — but the engine's intrinsic AST blocks
      // (pipe-chain exfiltration, eval-remote-exec, suspect-binary) carry NO
      // ruleName at tier 3, which let a prior "Always Allow <tool>" or the
      // cloud no-match immediate-allow silently resolve a hard block. Key the
      // protection on "this was a block", not on how the rule is named.
      hardBlockDowngraded = true;
      // Fail-closed gate for the block→review downgrade below. A hard block may
      // only soften to a review when a genuine HUMAN approver is actually
      // reachable — a GUI popup can be shown, or a `node9 tail` is connected.
      // With NO reachable human (CI, headless, a piped non-interactive agent)
      // the block STAYS a block, so the approver race can never resolve it to
      // allow (e.g. a cloud immediate-allow of a client-side shield the SaaS
      // has no rule for). Cloud is deliberately NOT a "human" here — it can
      // auto-resolve. Fails closed: any uncertainty keeps the hard block.
      const daemonUp = isDaemonRunning();
      let humanApproverReachable = false;
      if (!policyResult.dependsOnStatePredicates?.length && daemonUp && !isTestEnv) {
        humanApproverReachable = await hasReachableHumanApprover({
          approvers,
          calledFromDaemon: options?.calledFromDaemon,
        });
      }
      const mayDowngrade = mayDowngradeHardBlock({
        daemonUp,
        isTestEnv,
        humanApproverReachable,
        overridable: policyResult.overridable,
      });

      // The hard-block result, built before the downgrade below rewrites the label.
      const blocked: AuthResult = {
        approved: false,
        reason: policyResult.reason ?? 'Action explicitly blocked by Smart Policy.',
        blockedBy: 'local-config',
        blockedByLabel: policyResult.blockedByLabel,
        ruleHit: policyResult.ruleName,
        ...(policyResult.checkId && { checkId: policyResult.checkId }),
        ...(policyResult.recoveryCommand && { recoveryCommand: policyResult.recoveryCommand }),
        ...(policyResult.ruleDescription && { ruleDescription: policyResult.ruleDescription }),
        ...protectedPathFields(policyResult.ruleName, toolName, args, dlpReviewFlagged),
      };
      // The audit row + hard-block result, shared by every non-softening path so
      // a fail-closed decision is a single call.
      const hardBlock = (): AuthResult => {
        // Include policyResult.ruleName so the [2] Report SHIELDS panel can
        // attribute this block to its specific shield via the rule→shield map.
        if (!isManual)
          appendLocalAudit(
            toolName,
            args,
            'deny',
            'smart-rule-block',
            { ...meta, ruleName: policyResult.ruleName },
            hashAuditArgs
          );
        return blocked;
      };
      // Both softening paths below open a review in place of this block.
      downgradedBlock = blocked;

      // Stateful (dependsOnState) rules keep their DELIBERATE downgrade-to-review
      // semantics: when predicates are unknown / the daemon can't check them,
      // they soften into the STATE GUARD recovery card rather than hard-blocking
      // a legitimate action (e.g. a deploy) just because state is unavailable —
      // an availability choice for that feature, tested in stateful-rules.spec.
      // The fail-closed human-reachability gate applies to PLAIN blocks only
      // (below). KNOWN RESIDUAL: a stateful block can still soften in a fully
      // non-interactive context — tracked as its own decision (design doc §2b),
      // not ridden onto the shield fix.
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
      } else if (mayDowngrade) {
        // A genuine human approver is reachable (GUI popup or connected tail),
        // so downgrade hard-block to review — the user gets a card and can
        // approve or deny. Without a reachable human this branch is skipped and
        // the block stays hard (the `else` below): never a review a non-human
        // channel could auto-allow. Hard blocks also stay hard in CI/test.
        //
        // Make the downgrade visible. Two changes vs. a regular review:
        //   1. Audit `checkedBy` is 'smart-rule-block-override' — the dashboard
        //      can show "block rule overridden" separately from a hard block.
        //   2. blockedByLabel is prefixed with "⚠️ Override block rule: " so the
        //      popup card / tail row makes it explicit the user is breaking
        //      their own block rule, not approving a routine review.
        if (!isManual)
          appendLocalAudit(
            toolName,
            args,
            'deny',
            'smart-rule-block-override',
            // Same rationale as the smart-rule-block path above —
            // pass the specific rule name so [2] SHIELDS can
            // attribute this override-block to its owning shield.
            { ...meta, ruleName: policyResult.ruleName },
            hashAuditArgs
          );
        // (Cloud delivery: the outbox shipper picks the row up from the
        // local audit log — no decision-time POST.)
        // Mutate the policyResult label so the race engine downstream
        // (line ~570: `explainableLabel = policyResult.blockedByLabel`) picks
        // up the override prefix. Idempotent — never double-prepends.
        const baseLabel = policyResult.blockedByLabel || 'Smart Rule';
        const OVERRIDE_PREFIX = '⚠️ Override block rule: ';
        if (!baseLabel.startsWith(OVERRIDE_PREFIX)) {
          policyResult = {
            ...policyResult,
            blockedByLabel: `${OVERRIDE_PREFIX}${baseLabel}`,
          };
        }
        // Fall through to the race engine with the override label visible.
      } else {
        // No reachable human → the block stays hard (fail closed). Cloud
        // delivery of the deny rides the outbox shipper from the audit row.
        return hardBlock();
      }
    }

    // Fall back to the label already carried, not a literal "Local Config":
    // a gate-only flag (DLP, protected file, uninspectable shell) can review a
    // call the engine ALLOWS, and the literal wiped the DLP label on its way to
    // the approver (/code-review, DLP-3). The engine now receives the gate's
    // config, so the two no longer read different files. When the engine names its own label (a smart-rule review), that
    // label replaces the DLP one, as before; combining the two, the way the
    // app-permission branch does, is not done here.
    explainableLabel = policyResult.blockedByLabel || explainableLabel;
    if (policyResult.decision === 'review' && explainableLabel === policyResult.blockedByLabel) {
      policyReviewRule = policyResult.ruleName;
      policyReviewCheckId = policyResult.checkId;
    }
    policyMatchedField = policyResult.matchedField;
    policyMatchedWord = policyResult.matchedWord;
    // B1 (#6): the tier-7 strict fallback reviews with NO ruleName (it is a
    // mode, not a rule) — keying this guard on ruleName alone let the SaaS
    // gate's immediate-allow for an unmatched tool ("no org rule matched",
    // NOT an approval) resolve the call, silently bypassing a cloud-managed
    // Block all (the old strict). It says "unmatched requires a human"; cloud's no-match
    // allow must never pre-empt that.
    // Deliberately tier-7-only: other rule-less reviews (e.g. dangerous-word)
    // stay cloud-resolvable — pinned by core.test.ts ("calls cloud API and
    // returns approved:true") and a semantics change that wide needs its own
    // decision, not a rider on this fix.
    // (The name `localSmartRuleMatched` is kept — it crosses the daemon HTTP
    // boundary (auth/daemon.ts → daemon/server.ts) and renaming the wire field
    // would silently drop the guard on a hook↔daemon version skew.)
    // Round-2 F1: `hardBlockDowngraded` joins the guard — a downgraded block
    // is always a local match, whether or not the verdict carries a ruleName.
    if (policyResult.ruleName || policyResult.tier === 7 || hardBlockDowngraded)
      localSmartRuleMatched = true;
    // Capture the human-readable description so it survives through the race
    // engine and appears in sendBlock even when the user denies at the daemon.
    if (policyResult.ruleDescription) policyRuleDescription = policyResult.ruleDescription;
    else if (policyResult.reason) policyRuleDescription = policyResult.reason;
    riskMetadata = computeRiskMetadata(
      args,
      policyResult.tier ?? 6,
      explainableLabel,
      policyMatchedField,
      policyMatchedWord,
      policyResult.ruleName
    );
    // Truncate to 200 chars — descriptions come from local config but are
    // forwarded to the SaaS; cap length to prevent oversized payloads.
    // MSG-5: a softened block shows its rule's sentence on an approval card, so
    // "Reading .env files is blocked" sat above "Enter = Allow". The card asks;
    // the agent-facing reason (policyRuleDescription) keeps the block wording.
    if (policyRuleDescription)
      riskMetadata.ruleDescription = (
        hardBlockDowngraded ? asApprovalRequest(policyRuleDescription) : policyRuleDescription
      ).slice(0, 200);

    // A persistent allow must never override a smart rule with verdict "review".
    // Smart rules represent explicit user intent; a blanket "allow this tool"
    // should not silently bypass a rule the user wrote (e.g. review-git-push).
    // policyResult.ruleName is set only when a smart rule matched.
    //
    // KNOWN GAP (roadmap): persistent approvals are keyed by tool name only.
    // For shell tools (Bash), "Always Allow" approves the entire tool even for
    // commands not covered by a smart rule. Future work: key by command-level
    // pattern (e.g. first command token) so approvals are narrowly scoped.
    // See: doc/roadmap.md "Command-Scoped Persistent Approvals".
    //
    // B1 (#6): tier-7 strict reviews skip the consult too — same key-on-
    // ruleName defect as the cloud guard above. An "Always Allow" clicked
    // BEFORE the org mandated strict would permanently exempt that tool, and
    // the call never reaches the cloud, so the BE floor can't compensate.
    // Rule-less sub-tier-7 reviews (dangerous-word) stay persistent-resolvable.
    // Round-2 F1: a downgraded hard block also skips the consult — a blanket
    // "Always Allow Bash" must never resolve an intrinsic exfil/RCE block.
    const persistent =
      policyResult.ruleName || policyResult.tier === 7 || hardBlockDowngraded
        ? null
        : getPersistentDecision(toolName);
    // `!appPermReview`: a prior "Always Allow" must not bypass an org-set review
    // (fix #3). A persistent DENY still short-circuits (tightening is fine).
    if (persistent === 'allow' && !callSpecificReview()) {
      // Local row only — cloud delivery via the outbox shipper.
      if (!isManual)
        appendLocalAudit(toolName, args, 'allow', 'persistent', ownRowMeta(true), hashAuditArgs);
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
  } else if (!callSpecificReview()) {
    // DLP-3: a flagged ignored tool (`Read` with a credential in an argument,
    // scanIgnoredTools on) used to fall into this branch and return a bare
    // {approved:true}; it now falls through to the race like a tainted one.
    // Jail guard (task #20): when a jail shield is armed, Read/Grep/Glob calls
    // that target a jailed or sensitive path must NOT take the ignoredTools
    // fast path — the jail's whole point is stopping file-tool reads.
    //
    // History: this guard used to check ONLY 'project-jail' while `jail add`
    // enables 'user-jail' (shields/jail.ts USER_JAIL_SHIELD), and its inner
    // test was scanFilePath — which knows built-in DLP paths, never user-added
    // jail paths. Net effect: the jail blocked Bash but was INERT for the file
    // tools (the primary way an agent reads a file), while `jail add` printed
    // "reads now BLOCK". Found by the jail gauntlet on its first probe.
    const toolLower = toolName.toLowerCase();
    const isFileTool =
      toolLower === 'read' ||
      toolLower === 'grep' ||
      toolLower === 'glob' ||
      toolLower === 'read_file' ||
      toolLower === 'grep_search' ||
      toolLower === 'list_files';
    // PR-2 §0.4 — arm from the CONFIG'S OWN TESTIMONY of what is running
    // (policy.appliedShields, the N6 resolver output), never the local
    // shields.json: a keyed machine ignores that file, and arming from it
    // left cloud-mandated jail shields unarmed — Read/Grep/Glob of jailed
    // paths took the ignoredTools fast path (the task-#20 bypass reborn).
    // Fallback to the file only when the config predates appliedShields.
    const activeShields = isFileTool ? (config.policy.appliedShields ?? readActiveShields()) : [];
    // Task #22: an ORG-managed jail (managedConfig.jailPaths) enables no shield
    // — it only injects org:-prefixed rules — so arming on shields alone let
    // the managed route keep task #20's bypass. Arm on the managed paths too.
    const managedJail = isFileTool ? (config.policy.managedJailPaths ?? []) : [];
    if (
      isFileTool &&
      (activeShields.includes('project-jail') ||
        activeShields.includes(USER_JAIL_SHIELD) ||
        managedJail.length > 0)
    ) {
      const argsObj =
        args && typeof args === 'object' && !Array.isArray(args)
          ? (args as Record<string, unknown>)
          : {};
      // ALL candidate fields, not the first non-empty one: Grep sends the
      // jailed directory in `path` while `pattern` also exists, Glob the
      // reverse — a first-match pick can check the wrong field.
      const candidates = ['file_path', 'path', 'pattern', 'filename']
        .map((k) => argsObj[k])
        .filter((v): v is string => typeof v === 'string' && v.length > 0);
      const jailHit =
        (candidates.map(findJailedPath).find(Boolean) ??
          candidates.map((c) => findJailedPathIn(c, managedJail)).find(Boolean)) ||
        null;
      const sensitiveHit = candidates.some((c) =>
        scanFilePath(c, options?.cwd, {
          systemAccessHandled: !isManual && fileAccess.handledPaths.has(c),
        })
      );
      if (jailHit || sensitiveHit) {
        // Let THE ENGINE decide — the shield's own rules carry the verdict and
        // the rule name (one matcher, one decision-maker; no guard-local
        // verdict logic to drift out of sync). skipIgnoredFastPath: without it
        // the engine's tier-1 ignored fast path returns 'allow' before the
        // shield's `tool:'*'` rules are consulted (the second half of #20).
        const policyResult = await evaluateCurrentPolicy(true);
        if (policyResult.decision === 'block') {
          // Mirror the branch-1 hardBlock() shape so the block row is
          // attributed to its rule (Report SHIELDS panel keys on ruleName).
          if (!isManual)
            appendLocalAudit(
              toolName,
              args,
              'deny',
              'smart-rule-block',
              { ...meta, ruleName: policyResult.ruleName },
              hashAuditArgs
            );
          return {
            approved: false,
            reason: policyResult.reason ?? 'Action explicitly blocked by Smart Policy.',
            blockedBy: 'local-config',
            blockedByLabel: policyResult.blockedByLabel,
            ruleHit: policyResult.ruleName,
            ...protectedPathFields(policyResult.ruleName, toolName, args, dlpReviewFlagged),
          };
        }
        // Review verdict, or a hit the engine has no matching rule for (e.g. a
        // filename-only hit, or a pre-fix user-jail.json not yet regenerated
        // with path/pattern rules): fall through to the approver race — fail
        // toward a human, never to allow.
      } else {
        if (!isManual)
          appendLocalAudit(toolName, args, 'allow', 'ignored', ownRowMeta(true), hashAuditArgs);
        return { approved: true };
      }
    } else {
      // ignoredTools (read, glob, grep, ls…) fire on every agent operation — too
      // frequent and too noisy to send to the SaaS audit log.
      if (!isManual)
        appendLocalAudit(toolName, args, 'allow', 'ignored', ownRowMeta(true), hashAuditArgs);
      return { approved: true };
    }
  }

  if (standingTrustApplies() && getActiveTrustSession(toolName, args)) {
    // Local row only — cloud delivery via the outbox shipper.
    if (!isManual)
      appendLocalAudit(toolName, args, 'allow', 'trust', ownRowMeta(true), hashAuditArgs);
    return { approved: true, checkedBy: 'trust' };
  }

  // Taint warning active — set a high-risk label and fall through to the race engine.
  // The user sees the taint context in the browser dashboard / native popup / Slack.
  if (taintWarning && hardBlockDowngraded && riskMetadata) {
    // A policy block softened to a review (a human approver is reachable)
    // keeps its own rule and label, so the audit row and the report attribute
    // it to the rule that blocked; the taint warning is added to what the
    // approver reads, not put in its place.
    riskMetadata.ruleDescription = [taintWarning, riskMetadata.ruleDescription, appPermReview]
      .filter((c): c is string => !!c)
      .join('\n')
      .slice(0, 1024);
  } else if (taintWarning) {
    explainableLabel = '🔴 Node9 Taint (Exfiltration Prevention)';
    // tier 7 = highest valid tier; pass taintWarning as ruleName so all
    // approval channels (terminal card, browser dashboard, Slack) can render it.
    // fix #7: when an app-perm review ALSO applies, append it to the ruleName so
    // the approver is told BOTH concerns — the review requirement isn't dropped.
    riskMetadata = computeRiskMetadata(
      args,
      7,
      explainableLabel,
      undefined,
      undefined,
      appPermReview ? `${taintWarning}\n${appPermReview}` : taintWarning
    );
    // The policy runs under a taint warning now: when it also reviewed the
    // call, its rule and check stay on the result (the report counts the
    // check that matched) and its description joins the taint warning, so the
    // reason, the rule and the description describe the same review.
    if (policyReviewRule || policyReviewCheckId) {
      policyRuleDescription = [taintWarning, policyRuleDescription]
        .filter((c): c is string => !!c)
        .join('\n')
        .slice(0, 1024);
      riskMetadata.ruleDescription = policyRuleDescription;
    }
  } else if (exposureReview) {
    // fw#318: a send after the session read outside content. Same
    // fall-through-to-race shape as taint. The rule name is the stable
    // `exposure` (catalog lookup, reports); the sentence rides as
    // ruleDescription, the field every approval surface shows (tail, the
    // native popup, Mission Control, Slack), so each says what was read and
    // where this sends.
    explainableLabel = EXPOSURE_LABEL;
    riskMetadata = computeRiskMetadata(args, 6, explainableLabel, undefined, undefined, 'exposure');
    riskMetadata.ruleDescription = (
      appPermReview ? `${exposureReview}\n${appPermReview}` : exposureReview
    ).slice(0, 1024);
    if (exposureDestinations.length > 0) riskMetadata.exposureDestinations = exposureDestinations;
  } else if (appPermReview) {
    // Org-set per-tool review (MCP app permission) — same fall-through-to-race
    // shape as taint, at elevated (not maximum) tier. The reason string rides as
    // ruleName so every approval surface says WHICH tool needs sign-off.
    // Re-review fix: when a DLP credential-review ALSO applies, combine (don't
    // overwrite) so the approver still sees the secret context — same pattern as
    // fix #7 (taint+review).
    if (dlpReviewFlagged) {
      explainableLabel = '🚨 Node9 DLP (Credential Review) + 🔒 App Permission (Review)';
      riskMetadata = computeRiskMetadata(
        args,
        6,
        explainableLabel,
        undefined,
        undefined,
        `A credential was detected in this call (DLP review).\n${appPermReview}`
      );
    } else {
      explainableLabel = '🔒 Node9 App Permission (Review)';
      riskMetadata = computeRiskMetadata(
        args,
        5,
        explainableLabel,
        undefined,
        undefined,
        appPermReview
      );
    }
  } else if (packageReview) {
    // The package check's findings ride as the rule text so every approval
    // surface says WHICH package and why. A policy label set above (a smart
    // rule that also reviewed) is kept; the findings still reach the card.
    policyRuleDescription = joinPackageReview(
      policyRuleDescription,
      explainableLabel,
      packageReview
    );
    riskMetadata = computeRiskMetadata(
      args,
      5,
      explainableLabel,
      undefined,
      undefined,
      packageReview
    );
  }

  // ── INLINE-ASK DEFER (review → caller renders the prompt) ────────────────
  // When the caller opts in (check.ts, for an ask-capable agent), a `review`
  // verdict short-circuits HERE — before the SaaS handshake below — so no
  // /intercept pending entry is ever created (which would orphan in the
  // dashboard/Slack). The caller turns this result into the agent's native
  // `permissionDecision:"ask"` prompt.
  //
  // v2 (review-ask-inline-v2-spec.md): block = stop, review = THE DEV DECIDES,
  // inline is the dev's seat. Every review verdict defers — smart-rule, taint,
  // DLP credential-review — with EXACTLY ONE exclusion. (App-permission
  // reviews are inline-eligible in PRINCIPLE only: serverKey comes solely from
  // the mcp-gateway, which passes no deferReview — JSON-RPC has no ask channel
  // — so in production they always take the race below.)
  //   - a DOWNGRADED HARD BLOCK (F1d): an intrinsic block (pipe-chain exfil /
  //     eval-remote) softened to review only because a human is reachable is
  //     NOT an admin-chosen review verdict — "block = stop" keeps it on the
  //     routed approver, the channel node9 controls and the agent can't spoof.
  // The v1 cloud-enforced carve-out is deleted: cloud is the RECORD, not a
  // gate — the inline outcome ships to the SaaS as audit (checkedBy
  // 'inline-review' via log.ts); an admin who wants routed approvals sets
  // managed reviewChannel:'approver' (workspace, one click).
  // Set by check.ts (`deferReview: askMode`) for ask-capable agents (Claude
  // Code / Copilot), default-on.
  // A forecast ends here too: the handshake, the card and the race are the
  // consequences it must not have. Nothing downgrades a block in a forecast:
  // isDaemonRunning() is false there, so `hardBlockDowngraded` is never set.
  if (forecast && approvers.cloud && !!creds?.apiKey) noteForecastUnknown('cloud-gate');
  if ((options?.deferReview && !hardBlockDowngraded) || forecast) {
    return {
      approved: false,
      review: true,
      // The prompt must say WHY: the taint sentence beats the bare label so
      // the dev sees the actual risk context inline. (No appPermReview term:
      // deferReview and serverKey never co-occur in production — see above.)
      reason:
        taintWarning ||
        packageReview ||
        exposureReview ||
        explainableLabel ||
        'Node9 flagged this action for review.',
      ...(exposureReview && exposureKeys.length > 0 ? { exposureKeys } : {}),
      ...(exposureReview && exposureFromEid ? { exposureFromEid } : {}),
      ...(policyReviewRule && { ruleHit: policyReviewRule }),
      ...(policyReviewCheckId && { checkId: policyReviewCheckId }),
      ruleDescription: policyRuleDescription,
      blockedByLabel: explainableLabel,
    };
  }

  // ── THE HANDSHAKE (Phase 4.1: Cloud Init) ────────────────────────────────
  let cloudRequestId: string | null = null;
  const cloudEnforced = approvers.cloud && !!creds?.apiKey;

  // Always notify SaaS when cloud is enforced so the request appears in the
  // dashboard / Slack channel even when a local smart rule triggered review.
  // TRUST MODEL: when forceReview=true, the SaaS must create a genuine PENDING
  // entry requiring a human click — cloud cannot auto-resolve it. Local racers
  // (terminal card, native popup) run in parallel so the user can still deny
  // locally before cloud resolves. If the SaaS is compromised, cloud approvals
  // are already untrusted regardless — this is not a regression from prior state.
  // Explicit boolean cast: localSmartRuleMatched is always a boolean, but
  // options?.localSmartRuleMatched is boolean|undefined — coerce to true/undefined
  // with a strict boolean check to avoid JS truthiness surprises across the API
  // boundary.
  // Every review reason, from the one predicate (reviewDemanded). Task #16
  // vector C stated the principle for taint: a client-side finding the SaaS
  // has no rule for needs a GENUINE pending entry, or its checkRule answers
  // "no org rule matched" → {approved:true}, which is not a human approving
  // anything. Measured against the live BE: {approved:true} without this flag,
  // {pending:true} with it. DLP-3 found the DLP reason missing here.
  const forceReview = reviewDemanded() || undefined;
  // Round-3 F1e: a DOWNGRADED HARD BLOCK must not be resolvable by the cloud
  // racer. This is the sixth non-human channel — rows B/D/E/F of
  // shield-block-downgrade-realgate.spec.ts closed persistent, trust,
  // shadowMode and the inline prompt, and the immediate-allow guard below
  // closed the !pending branch. The pending branch stayed open: the poller was
  // enrolled unconditionally, and the SaaS resolved it with nobody clicking.
  // Measured 2026-08-31: 143 real deny→allow pairs on the founder's machine.
  //
  // Deliberately keyed on `hardBlockDowngraded` and NOT on `forceReview`.
  // They are boolean-equivalent for the block case but mean opposite things:
  // forceReview asks the SaaS to create a genuine PENDING entry so a HUMAN
  // must click, which is a legitimate cloud channel for an admin-chosen review
  // (app-permission, taint). Gating on it removed that human path and broke
  // two app-permission rows. Only node9's own floor — a block softened solely
  // because a human happened to be reachable — is off-limits to the cloud, per
  // the `mayDowngrade` comment above: "Cloud is deliberately NOT a 'human'
  // here — it can auto-resolve. Fails closed."
  //
  // Gates the VOTE only. `cloudRequestId` is still assigned, because two other
  // consumers need it: resolveNode9SaaS (so Mission Control does not sit on
  // PENDING forever) and the audit row's BE linkage (so the shipper enriches
  // the existing row instead of inserting a duplicate).
  const cloudMayVote = !hardBlockDowngraded;
  if (cloudEnforced) {
    try {
      const initResult = await initNode9SaaS(
        toolName,
        args,
        creds!,
        meta,
        riskMetadata,
        config.settings.agentPolicy,
        forceReview
      );

      if (!initResult.pending) {
        // Shadow mode: allowed through, but warn the developer passively.
        // fix #2: an org-set app-perm review WINS over shadow mode (an explicit
        // per-tool decision beats a global observe toggle) — and this also closes
        // a stale/compromised-BE bypass (a BE answering shadowMode to skip the
        // review). Fall through to the race instead of auto-allowing.
        // Round-3 F1c: mirror the immediate-allow guard below — a local review
        // match (incl. a downgraded hard block, which sets localSmartRuleMatched
        // via hardBlockDowngraded) means forceReview was sent; a shadowMode
        // response must not resolve it. Without this, a shadow/observe org (or a
        // stale BE ignoring forceReview) auto-allows a downgraded intrinsic block.
        // `!taintWarning` (task #16 vector C): a taint review is in exactly the
        // class this guard already protects — we now send forceReview for it, so
        // a shadowMode answer (from a shadow/observe org, or a stale BE ignoring
        // that flag) must not resolve an exfiltration review either.
        if (initResult.shadowMode && !reviewDemanded()) {
          return { approved: true, checkedBy: 'cloud' };
        }
        // A local smart rule with verdict "review" represents explicit user intent
        // (e.g. require-approval-before-push). Cloud's immediate-allow must not
        // bypass it — fall through to the race engine so the user sees an approval card.
        // Also respect the flag when called from the daemon's background auth pass.
        // appPermReview: never accept a cloud immediate-allow — a stale/older BE
        // that ignores forceReview must not bypass an org-set review. Fall
        // through to the race so a genuine human decision is required.
        // `!taintWarning` (task #16 vector C): never accept a cloud
        // immediate-allow for an exfiltration review either — same reasoning as
        // appPermReview above, and it also covers a stale/older BE that ignores
        // the forceReview flag we now send.
        // `!forceReview` is exactly the four-term condition this guard used to
        // restate inline (localSmartRuleMatched / options.localSmartRuleMatched
        // / appPermReview / taintWarning) — forceReview is built from the same
        // four a few lines above, so deriving it here removes the duplicate
        // without changing behaviour. NOT `cloudMayVote`: that one is narrower
        // (downgraded hard blocks only) and using it here would let a cloud
        // immediate-allow through for app-permission and taint reviews.
        if (!forceReview) {
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
        // Smart rule active — fall through to race engine; cloud still joins as a racer
        // via cloudRequestId if the SaaS returned a pending request.
      }

      // Only set cloudRequestId when the SaaS created a genuine PENDING entry.
      // Never assign from a pending:false response — the SaaS may have already
      // auto-resolved it, and polling would return that stale auto-decision
      // without a real human click, bypassing local smart-rule review intent.
      if (initResult.pending) cloudRequestId = initResult.requestId || null;
      // remoteApprovalOnly is noted but not enforced — local UI always has control.
      // Hard blocks are handled by Shields before the UI opens.
      // Don't overwrite the taint label — taint context must stay visible to the user.
      // ...nor the DLP one (DLP-3): the approver, and the final deny when no
      // channel answers, must still say a credential was found.
      // callSpecificReview, not reviewDemanded (which the design first named):
      // a smart-rule label was overwritten here before this fix too, and
      // widening the term would change labels on calls DLP-3 is not about.
      // MSG-5 widens it to reviewDemanded: a local rule (a smart-rule review, a
      // softened block such as the project jail) asked for this review, and the
      // card said "Organization Policy (SaaS)" above it. Only a review no local
      // rule asked for is the organisation's.
      if (!reviewDemanded()) explainableLabel = 'Organization Policy (SaaS)';
    } catch {
      // Cloud API handshake failed — fall through to local rules silently
    }
  }

  // ── THE MULTI-CHANNEL RACE ENGINE ──────────────────────────────────────────
  const abortController = new AbortController();
  const { signal } = abortController;
  const racePromises: Promise<AuthResult>[] = [];

  // ⏱️ RACER 0 (the approval timeout) is armed after the card below.
  const approvalTimeoutMs = config.settings.approvalTimeoutMs ?? 0;

  let viewerId: string | null = null;
  const internalToken = getInternalToken();

  // Pre-register a daemon entry shared by RACER 3 (terminal popup) and,
  // when cloudEnforced, by RACER 1 as well (reusing the same card — no
  // duplicate). notifyDaemonViewer is moved here (out of RACER 1) so
  // viewerId is known before the race starts.
  //
  // The browser approval channel was retired in the v3 sprint — RACER 3
  // is now terminal-only.
  let daemonEntryId: string | null = null;
  let daemonAllowCount = 1;
  /** The card's deadline from a protocol-2 daemon (null: no timer);
   *  undefined when the daemon is older than the card protocol. */
  let cardDeadline: number | null | undefined;
  // Who may answer the card: the daemon's own UIs, and the hook's racers it
  // cannot see. A card only the UIs can answer is the one abandoned when
  // node9 tail closes.
  const cardOptions = {
    channels: [
      'terminal',
      'monitor',
      // Only when the popup can show: a card listing a channel nobody can
      // use is never abandoned when node9 tail closes, and waits unanswered.
      ...(approvers.native &&
      !isManual &&
      !options?.calledFromDaemon &&
      (process.platform === 'darwin' ||
        process.platform === 'win32' ||
        !!(process.env.DISPLAY || process.env.WAYLAND_DISPLAY))
        ? ['native']
        : []),
      ...(cloudEnforced && cloudRequestId && cloudMayVote ? ['cloud'] : []),
    ] as Channel[],
    timeoutMs: approvalTimeoutMs,
  };
  if (approvers.terminal && isDaemonRunning() && !options?.calledFromDaemon) {
    if (cloudEnforced && cloudRequestId) {
      // Cloud path: create a single card via notifyDaemonViewer so RACER 3
      // (terminal/browser) shares the same daemon entry — no duplicate card.
      // Local UI always participates in the race regardless of cloud policy.
      // Pass activityId + socketActivitySent so the daemon skips its own
      // 'activity' broadcast and reuses the CLI's id — without these,
      // every cloud-enforced command produced two 'activity' SSE events.
      const viewer = await notifyDaemonViewer(
        toolName,
        args,
        meta,
        riskMetadata,
        options?.activityId,
        options?.socketActivitySent,
        {
          cwd: options?.cwd,
          recoveryCommand: statefulRecoveryCommand,
          sessionId: meta?.sessionId,
          card: cardOptions,
        }
      ).catch(() => null);
      viewerId = viewer?.id ?? null;
      daemonEntryId = viewerId;
      if (viewer) {
        daemonAllowCount = viewer.allowCount;
        cardDeadline = viewer.deadline;
      }
    } else {
      try {
        const entry = await registerDaemonEntry(
          toolName,
          args,
          meta,
          riskMetadata,
          options?.activityId,
          options?.cwd,
          statefulRecoveryCommand,
          // fix #1: for an app-perm review, tell the daemon NOT to run its own
          // background authorizeHeadless — it re-auths WITHOUT serverKey (meta
          // carries no serverKey), skips the app-perm gate, and silently
          // auto-allows. This process (the long-running gateway — appPermReview
          // only ever happens here) stays alive to run its own racers, so the
          // daemon just holds the card and waits for the human decision.
          // fw#318 P1.1: the same for every call-specific review (exposure,
          // session taint, DLP, file review): the re-run carries no session id
          // and cannot see these reasons, so it must never answer the card.
          appPermReview || callSpecificReview() ? true : undefined,
          undefined,
          localSmartRuleMatched || options?.localSmartRuleMatched,
          options?.socketActivitySent,
          meta?.sessionId,
          cardOptions
        );
        daemonEntryId = entry.id;
        daemonAllowCount = entry.allowCount;
        cardDeadline = entry.deadline;
      } catch {
        // Daemon unreachable — skip both racers gracefully
      }
    }
  }

  // ⏱️ RACER 0: Approval Timeout
  // One timer per approval (approval-card design): a protocol-2 card carries
  // its own deadline, set from this timeout, and the daemon decides it there
  // (decidedBy 'timer'). The hook arms its own timer only without such a
  // card: no daemon, no terminal approver, or a daemon older than the card
  // protocol.
  if (approvalTimeoutMs > 0 && cardDeadline === undefined) {
    racePromises.push(
      new Promise<AuthResult>((resolve, reject) => {
        const timer = setTimeout(() => {
          resolve({
            approved: false,
            reason: approvalTimeoutReason(approvalTimeoutMs),
            blockedBy: 'timeout',
            blockedByLabel: 'Approval Timeout',
            decidedBy: 'timer',
          });
        }, approvalTimeoutMs);
        signal.addEventListener('abort', () => {
          clearTimeout(timer);
          reject(new Error('Aborted'));
        });
      })
    );
  }

  // 🏁 RACER 1: Cloud SaaS Channel (The Poller)
  // Cloud is a valid racer even for local smart rule matches — with forceReview,
  // the SaaS always creates a PENDING entry requiring a real human click in
  // Mission Control, so an approval there is a genuine human decision.
  if (cloudEnforced && cloudRequestId && cloudMayVote) {
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
            decidedBy: 'cloud',
            channel: 'cloud',
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
  // Note: localSmartRuleMatched does NOT skip the native popup — zenity requires
  // explicit user click (approve/deny), it never auto-resolves. Cloud is skipped
  // when localSmartRuleMatched to prevent SaaS auto-allow from bypassing human review,
  // but the native popup is a valid human approval channel even for smart rule matches.
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
          daemonAllowCount,
          riskMetadata?.ruleDescription,
          exposureDestinations
        );

        if (decision === 'trust_recipients') {
          // fw#318 P5: allow this call and trust its destinations for good,
          // unless the machine's policy is the workspace's (the list is then
          // the organisation's; the call is still allowed once).
          if (config.policySource !== 'workspace') {
            for (const d of exposureDestinations) addTrustedRecipient(d, 'approval');
          }
          return {
            approved: true,
            checkedBy: 'daemon',
            decisionSource: 'native',
            decidedBy: 'person',
            channel: 'native',
          } as AuthResult;
        }

        if (decision === 'always_allow') {
          // fix #5 (behavioral half): for an app-perm review, do NOT persist a
          // trust session — fix #3 guards trust off for review-marked tools, so a
          // "1h trust" would silently no-op (the button would lie). Grant this
          // call once instead; the human is re-asked next time (correct for an
          // org-mandated review). Hiding the button on the card = fast follow.
          // standingTrustApplies, the trust guard's own predicate: a session
          // the guard would ignore must not be written (/code-review, DLP-3).
          if (standingTrustApplies()) {
            writeTrustSession(toolName, 3600000, args);
            return {
              approved: true,
              checkedBy: 'trust',
              decidedBy: 'person',
              channel: 'native',
            } as AuthResult;
          }
          return {
            approved: true,
            checkedBy: 'daemon',
            decisionSource: 'native',
            decidedBy: 'person',
            channel: 'native',
          } as AuthResult;
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
          decidedBy: 'person',
          channel: 'native',
        } as AuthResult;
      })()
    );
  }

  /** Results that came from the card itself (the terminal racer): the card
   *  already holds their decision. */
  const fromCard = new WeakSet<AuthResult>();
  const timeoutReason =
    approvalTimeoutMs > 0 ? approvalTimeoutReason(approvalTimeoutMs) : undefined;

  // 🏁 RACER 3: node9 tail (interactive terminal)
  // Resolves via POST /decision/{id} — same waitForDaemonDecision poll.
  // When cloudEnforced, daemonEntryId == viewerId (same card, no duplicate).
  // Local UI always participates in the race — cloud remoteApprovalOnly is not enforced.
  //
  // Browser channel was retired in the v3 sprint. decisionSource may
  // still arrive as 'browser' from third-party clients posting to
  // /decision; we coerce to 'terminal' for label purposes.
  if (daemonEntryId && approvers.terminal) {
    racePromises.push(
      (async () => {
        // A protocol-2 daemon names the card's deadline: wait until a little
        // after it (none for no timer). An older daemon: the old cap.
        const cap =
          cardDeadline === undefined
            ? daemonWaitCapMs(config.settings.approvalTimeoutMs)
            : cardDeadline === null
              ? 0
              : Math.max(cardDeadline - Date.now(), 0) + 5_000;
        const outcome = await waitForDaemonDecision(daemonEntryId!, signal, cap);
        // Who decided, from the card's record (an older daemon: from its
        // one-word source). No decider at all: /wait failed.
        const legacy = !outcome.record;
        const record = outcome.record ?? recordFromLegacyWait(outcome);
        // A softened block whose card gave no person's answer (the wait
        // failed; an older daemon's own check blocked it) reports the rule's
        // block, as the call would have been without the review.
        if (
          downgradedBlock &&
          (!record || (legacy && record.decidedBy === 'policy' && record.decision === 'deny'))
        ) {
          const softened = { ...downgradedBlock, blockedBy: 'local-config' } as AuthResult;
          fromCard.add(softened);
          return softened;
        }
        if (!record) return approvalUnavailable(outcome.reason);
        // An older daemon's own check names no rule: the review's label does.
        if (legacy && record.decidedBy === 'policy') record.label = explainableLabel;
        const result = authResultFromRecord(record, { downgradedBlock, timeoutReason });
        fromCard.add(result);
        return result;
      })()
    );
  }

  // 🏆 RESOLVE THE RACE
  if (racePromises.length === 0) {
    // fix #4: a review deny with no approval channels used to write NO audit row
    // (the gate no longer writes an upfront review-deny row), so the deny was
    // invisible to the dashboard. Write one, with app-perm attribution.
    if (!isManual && appPermReview)
      appendLocalAudit(
        toolName,
        args,
        'deny',
        'app-permission-review',
        { ...ownRowMeta(false), ruleName: `app-permission:${appPermReviewTool}` },
        hashAuditArgs
      );
    else if (!isManual && exposureReview)
      appendLocalAudit(
        toolName,
        args,
        'deny',
        'no-approval-mechanism',
        { ...ownRowMeta(false), ruleName: 'exposure' },
        hashAuditArgs
      );
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

  const raceResult = await new Promise<AuthResult>((resolve) => {
    let resolved = false;
    let failures = 0;
    const total = racePromises.length;

    const finish = (res: AuthResult) => {
      if (!resolved) {
        resolved = true;
        abortController.abort(); // KILL THE LOSERS

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
        failures++;
        if (failures === total && !resolved) {
          finish(approvalUnavailable('All approval channels failed or disconnected.'));
        }
      });
    }
  });

  // The card decides once (src/daemon/cards.ts). A winner the card does not
  // know yet (native popup, cloud poller, the hook's timer) is reported to it,
  // awaited: if a person decided in node9 tail a moment earlier, the card
  // keeps theirs and the hook reports that one, so the agent, the audit row
  // and the daemon always agree.
  let finalResult = raceResult;
  if (daemonEntryId && internalToken && !fromCard.has(raceResult)) {
    const reply = await resolveViaDaemon(
      daemonEntryId,
      raceResult.approved ? 'allow' : 'deny',
      internalToken,
      raceResult.decisionSource,
      recordFromAuthResult(raceResult)
    ).catch(() => null);
    if (reply && !reply.won)
      finalResult = authResultFromRecord(reply.record, { downgradedBlock, timeoutReason });
  }

  // If a LOCAL channel (native/browser/terminal) won while the cloud had a
  // pending request open, report the decision back to the SaaS so Mission
  // Control doesn't stay stuck on PENDING forever.
  // We await this (not fire-and-forget) because the CLI process may exit
  // immediately after this function returns, killing any in-flight fetch.
  // fw#318 ask-once: a human allow clears this call's destinations for the
  // session (never the whole record). Awaited: the hook process exits right
  // after this function returns, and an unawaited POST would be lost.
  if (
    finalResult.approved &&
    exposureKeys.length > 0 &&
    meta?.sessionId &&
    ucPolicy?.afterExposure === 'ask-once'
  ) {
    await approveSessionExposure(meta.sessionId, exposureKeys);
  }

  // Not for a cloud decision: the cloud made it (a cloud deny has no
  // checkedBy, and used to be PATCHed back as decidedBy "local").
  if (
    cloudRequestId &&
    creds &&
    finalResult.checkedBy !== 'cloud' &&
    finalResult.decidedBy !== 'cloud'
  ) {
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
      // cloudRequestId links this row to the BE-origin AuditLog row the
      // /intercept handshake created — the shipper hands it to the SaaS so
      // the BE enriches that row instead of inserting a duplicate. Matters
      // for EVERY racer outcome, not just cloud wins: a native-popup
      // decision on a cloud-pending request would otherwise count twice.
      // fix #6: carry app-perm attribution so a race-resolved approve/deny isn't
      // anonymous on the dashboard (matches the block row's ruleName).
      {
        ...ownRowMeta(finalResult.approved),
        ...(cloudRequestId && { cloudRequestId }),
        ...(appPermReview && { ruleName: `app-permission:${appPermReviewTool}` }),
        // Who decided, from the decision record, and the card: the daemon
        // writes its own row for the same card, and the report counts one.
        ...(finalResult.decidedBy && { decidedBy: finalResult.decidedBy }),
        ...(finalResult.channel && { channel: finalResult.channel }),
        ...(daemonEntryId && { cardId: daemonEntryId }),
      },
      hashAuditArgs
    );
  }

  // Inject the human-readable rule description into denied results so check.ts
  // can display it via sendBlock. The race resolvers (daemon, browser, native)
  // don't carry this field — we re-attach it here from the policy evaluation.
  const enrichedResult =
    !finalResult.approved && policyRuleDescription && !finalResult.ruleDescription
      ? { ...finalResult, ruleDescription: policyRuleDescription }
      : finalResult;

  return enrichedResult;
}

export async function authorizeAction(toolName: string, args: unknown): Promise<boolean> {
  const result = await authorizeHeadless(toolName, args);
  return result.approved;
}

// ── Canary registry access for the gate ─────────────────────────────────────
/** A registry read failure means "no canaries": the gate must never throw into a tool call. */
function safeCanaryValues() {
  try {
    return canaryValues();
  } catch {
    return [];
  }
}
function canaryRecordById(id: string) {
  try {
    return loadCanaries().find((r) => r.id === id) ?? null;
  } catch {
    return null;
  }
}
