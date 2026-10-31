import type { InspectionInput, InspectionLayers, DlpMatch } from '@node9/policy-engine';
import { reviewsEveryInline, isBlockAll, checkValue } from '@node9/policy-engine';
// src/policy/index.ts
// Host wrapper around @node9/policy-engine.
//
// The policy waterfall (DLP, smart rules, eval detection, pipe-chain,
// provenance, sandbox, dangerous-words, strict mode) lives in the engine.
// This file:
//   - calls getConfig() / getActiveEnvironment() / readActiveShields()
//   - injects checkProvenance + isTrustedHost as host hooks
//   - keeps the explainPolicy waterfall (heavy fs/os/process I/O)

import fs from 'fs';
import { readCappedText } from '../utils/read-capped';
import path from 'path';
import os from 'os';
import { scanArgumentSecrets, scanFilePath, detectArgsPii } from '../dlp';
import {
  runStatelessGates,
  combineWithEngine,
  GATE_LABELS,
  PRE_ENGINE_GATES,
  type PreEngineGate,
  type StatelessGates,
} from './gate-order';
import { prepareFileAccesses, type PreparedFileAccess } from './file-access';
import { runPackageCheck } from '../supply-chain/check';
import { configuredRegistryHosts } from '../supply-chain/registries';
import { getConfig, getActiveEnvironment } from '../config';
import { checkProvenance } from '../utils/provenance.js';
import { matchesTrustedHost, isTrustedHost } from '../auth/trusted-hosts.js';
import {
  evaluatePolicy as engineEvaluatePolicy,
  isIgnoredTool as engineIsIgnoredTool,
  matchesPattern,
  getNestedValue,
  evaluateSmartConditions,
  detectDangerousShellExec,
  analyzeShellCommand,
  resolveShellInput,
  shellRuleArgs,
  inspectionEntry,
  inspectionLayers,
  evaluateProtectedFileAccess,
  catalogSettingsFromConfig,
  type PolicyVerdict,
} from '@node9/policy-engine';

export {
  matchesPattern,
  evaluateSmartConditions,
  normalizeCommandForPolicy,
  detectDangerousShellExec,
  detectDangerousEval,
  checkDangerousSql,
  detectInlineExec,
} from '@node9/policy-engine';
import {
  detectInlineExec,
  inlineExecReview,
  inlineExecReason,
  inlineExecDescription,
  toolMatchesRule,
} from '@node9/policy-engine';

// ── evaluatePolicy — host wrapper that injects config + I/O hooks ───────────

export async function evaluatePolicy(
  toolName: string,
  args?: unknown,
  agent?: string,
  cwd?: string,
  // Task #20: the orchestrator's jail guard needs the engine to evaluate the
  // full rule chain for a file tool that would otherwise take the ignored
  // fast path (it has already found a jailed/sensitive path in the args).
  opts?: {
    skipIgnoredFastPath?: boolean;
    fileAccess?: PreparedFileAccess;
    config?: ReturnType<typeof getConfig>;
    /** The gate's scanArgumentSecrets(args) for these arguments, when already computed. */
    argumentScan?: DlpMatch | null;
    /** The MCP server label the caller resolved (gateway or hook), for rules
     *  scoped to a server (node9Firewall#390). */
    mcpServer?: string;
  }
): Promise<PolicyVerdict> {
  const config = opts?.config ?? getConfig(cwd);
  const prepared =
    opts?.fileAccess ?? prepareFileAccesses(toolName, args, cwd, inspectionLayers(config.policy));
  const activeEnvironment = getActiveEnvironment(config) ?? undefined;
  return engineEvaluatePolicy(
    config,
    toolName,
    args,
    {
      ...prepared,
      agent,
      cwd: prepared.cwd,
      activeEnvironment,
      skipIgnoredFastPath: opts?.skipIgnoredFastPath,
      argumentScan: opts?.argumentScan,
      mcpServer: opts?.mcpServer,
    },
    {
      checkProvenance,
      // Managed → match against the org list (frozen with the rest of managed
      // config; changes arrive via cloud sync). Unmanaged → the local file via
      // getCachedHosts (5s TTL + mtime), so a `node9 trust add/remove` still
      // reaches a long-lived in-process authorizer (the gateway) within seconds.
      isTrustedHost: config.policy.trustedHostsManaged
        ? (host: string) => matchesTrustedHost(host, config.policy.trustedHosts)
        : isTrustedHost,
      readAgentSettings,
      isConfiguredRegistry: (host: string, at?: string) => configuredRegistryHosts(at).has(host),
    }
  );
}

/** The most an agent settings file is read for the hooks comparison. */
const MAX_AGENT_SETTINGS_BYTES = 256 * 1024;

/**
 * The agent settings file as it is on disk now, for the hooks comparison of
 * files.agent-instructions (node9Firewall#413 part 4). A regular file within
 * the cap, read as UTF-8; anything else is null and the engine falls back to
 * "any mention of hooks in the new text is a change". Never throws.
 */
export function readAgentSettings(absPath: string): string | null {
  // Type and size come from the open descriptor, not a prior stat of the
  // path (CodeQL js/file-system-race); O_NONBLOCK keeps a FIFO at the path
  // from hanging the gate on open.
  const r = readCappedText(
    absPath,
    MAX_AGENT_SETTINGS_BYTES,
    fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK ?? 0)
  );
  return r && !r.truncated ? r.text : null;
}

/** Returns true when toolName matches an ignoredTools pattern (fast-path, silent allow). */
export function isIgnoredTool(toolName: string): boolean {
  return engineIsIgnoredTool(toolName, getConfig());
}

// ── explainPolicy — diagnostic waterfall (heavy I/O, host-only) ─────────────

export interface ExplainStep {
  name: string;
  outcome: 'checked' | 'allow' | 'review' | 'block' | 'skip';
  detail: string;
  isFinal?: boolean;
}

export interface WaterfallTier {
  tier: number;
  label: string;
  status: 'active' | 'missing' | 'env';
  path?: string;
  note?: string;
}

export interface ExplainResult {
  tool: string;
  args: unknown;
  waterfall: WaterfallTier[];
  steps: ExplainStep[];
  decision: 'allow' | 'review' | 'block';
  blockedByLabel?: string;
  matchedToken?: string;
  ruleDescription?: string;
}

function tokenize(toolName: string): string[] {
  return toolName
    .toLowerCase()
    .split(/[_.\-\s]+/)
    .filter(Boolean);
}

function explainExtractShellCommand(
  toolName: string,
  args: unknown,
  toolInspection: InspectionLayers
): { command: string | null; matchingPattern: string | undefined; fieldName: string } {
  const shell = resolveShellInput(toolName, args, toolInspection);
  const matchingPattern = [
    ...Object.keys(toolInspection.trusted),
    ...Object.keys(toolInspection.project ?? {}),
  ].find((p) => matchesPattern(toolName, p));
  // Legacy non-shell mappings (notably SQL) still supply tokens for explain.
  // Do not use this fallback for an ambiguous or malformed shell invocation.
  const entry = inspectionEntry(toolName, toolInspection);
  const legacyValue =
    shell.kind === 'not-shell' && typeof entry === 'string' ? getNestedValue(args, entry) : null;
  return {
    command:
      shell.kind === 'shell' ? shell.command : typeof legacyValue === 'string' ? legacyValue : null,
    matchingPattern,
    fieldName:
      shell.kind === 'shell' ? shell.fieldPath : typeof entry === 'string' ? entry : 'command',
  };
}

function explainIsSqlTool(toolName: string, toolInspection: InspectionInput): boolean {
  const fieldName = inspectionEntry(toolName, toolInspection);
  return fieldName === 'sql' || fieldName === 'query';
}

const SQL_DML_KEYWORDS = new Set(['select', 'insert', 'update', 'delete', 'merge', 'upsert']);

// Non-Terminal sentinel: explain previews how node9 treats an AGENT tool call
// (node9's threat model). The engine's bash-AST gates only run for a non-Terminal
// agent, so explain MUST simulate one — passing 'Terminal' here would reproduce
// the very drift this function exists to kill.
const EXPLAIN_AGENT = 'agent';

/**
 * Diagnostic preview of how node9 would treat a tool call.
 *
 * The hook's stateless gates (protected file, DLP, PII, package check) run
 * first, through the same module the hook uses (`policy/gate-order.ts`,
 * node9Firewall#405): same order, same stop and review rules. A gate that
 * stops the call ends the preview there, as the hook returns there. Then the
 * DECISION is taken from the real engine (`evaluatePolicy`) so explain can
 * never under-report what the live hook enforces. The step-by-step trace is
 * the human-readable re-derivation in `deriveExplainTrace`. When the two
 * disagree the engine wins and an authoritative step states the real verdict,
 * plus a NODE9_DEBUG drift canary. Last, the gates' reviews meet the engine's
 * verdict through the hook's combination rules.
 *
 * Not modelled: the gates that depend on the running session (file taint,
 * session taint, outside content, canaries, app permissions, approvals).
 */
export async function explainPolicy(
  toolName: string,
  args?: unknown,
  agent: string = EXPLAIN_AGENT
): Promise<ExplainResult> {
  const config = getConfig();
  const prepared = prepareFileAccesses(
    toolName,
    args,
    process.cwd(),
    inspectionLayers(config.policy)
  );
  // The hook skips the file gate and the package check for a manual (Terminal) call.
  const manual = agent === 'Terminal';
  const cfg = config.policy.packageCheck;
  const panicMode = config.settings.panicMode === true;
  const gates = await runStatelessGates({
    settings: { panicMode, dlp: config.policy.dlp, toolIgnored: isIgnoredTool(toolName) },
    // Omitted for a manual call, as the hook skips the gate: no step is shown.
    file: manual
      ? undefined
      : () =>
          evaluateProtectedFileAccess(
            prepared.accesses,
            prepared,
            catalogSettingsFromConfig(config.settings, config.policy)
          ),
    dlp: () => explainDlpMatch(args, prepared),
    pii: () => detectArgsPii(args),
    packageCheck: () =>
      manual || !cfg?.enabled
        ? Promise.resolve(null)
        : runPackageCheck(toolName, args, cfg, prepared.cwd),
  });
  const gateSteps = explainGateSteps(gates, { manual, packageOn: cfg?.enabled === true });
  const waterfall = explainWaterfall(config);

  if (gates.stop) {
    // The hook returns here, so the engine never runs.
    const { stop } = gates;
    return {
      tool: toolName,
      args,
      waterfall,
      steps: [
        ...gateSteps,
        {
          name: ENGINE_STEP,
          outcome: 'skip',
          detail: `Not reached: ${GATE_PLAIN[stop.gate]} blocks before the policy engine runs`,
          isFinal: false,
        },
      ],
      decision: 'block',
      blockedByLabel: stop.label,
      ruleDescription: stop.ruleDescription ?? stop.reason,
    };
  }

  const { result } = await explainEngineVerdict(toolName, args, agent, config, prepared);
  const combined = combineWithEngine(
    gates,
    {
      decision: result.decision,
      blockedByLabel: result.blockedByLabel,
      ruleDescription: result.ruleDescription,
    },
    { panicMode }
  );
  let steps: ExplainStep[] = [...gateSteps, ...result.steps];
  if (combined.panicked) {
    steps = [
      ...steps.map((s) => (s.isFinal ? { ...s, isFinal: false } : s)),
      {
        name: 'Panic mode',
        outcome: 'block',
        detail: 'Workspace is in panic mode: every review is a block',
        isFinal: true,
      },
    ];
  } else if (combined.decision !== result.decision) {
    // A gate's review holds a call the engine allowed: the gate step is the stop.
    const stopName = explainReviewStopName(gates);
    steps = steps.map((s) =>
      s.name === stopName ? { ...s, isFinal: true } : s.isFinal ? { ...s, isFinal: false } : s
    );
  }
  return {
    ...result,
    waterfall,
    steps,
    decision: combined.decision,
    blockedByLabel: combined.blockedByLabel ?? result.blockedByLabel,
    ruleDescription: combined.ruleDescription ?? result.ruleDescription,
  };
}

const PACKAGE_STEP = 'Package check';
const ENGINE_STEP = 'Engine verdict (authoritative)';

/** The step name of each gate, as the preview prints it. */
const GATE_STEP: Record<PreEngineGate, string> = {
  file: 'Protected file gate',
  dlp: 'DLP Content Scanner',
  pii: 'PII gate',
  package: PACKAGE_STEP,
};
const GATE_PLAIN: Record<PreEngineGate, string> = {
  file: 'the protected-file check',
  dlp: 'the DLP scanner',
  pii: 'the PII gate',
  package: 'the package check',
};

/** The same DLP inputs the hook scans: the file path first, then the arguments. */
function explainDlpMatch(args: unknown, prepared: PreparedFileAccess): DlpMatch | null {
  const argsObj =
    args && typeof args === 'object' && !Array.isArray(args)
      ? (args as Record<string, unknown>)
      : {};
  const filePath = String(argsObj.file_path ?? argsObj.path ?? argsObj.filename ?? '');
  return (
    (filePath
      ? scanFilePath(filePath, prepared.cwd, {
          systemAccessHandled: prepared.handledPaths.has(filePath),
        })
      : null) ?? (args !== undefined ? scanArgumentSecrets(args) : null)
  );
}

/** The gates as steps, in gate order; the gates after a stop are "not reached". */
function explainGateSteps(
  gates: StatelessGates,
  opts: { manual: boolean; packageOn: boolean }
): ExplainStep[] {
  const steps: ExplainStep[] = [];
  const pkg = gates.packageResult;
  const failed = pkg?.misses.join('; ') ?? '';
  const misses =
    !pkg || pkg.misses.length === 0
      ? ''
      : pkg.verdict === 'block'
        ? ` Some lookups failed: ${failed}`
        : ` Some lookups failed, and a failed lookup does not stop the call: ${failed}`;
  for (const run of gates.ran) {
    const name = GATE_STEP[run.gate];
    if (run.gate === 'package') {
      if (opts.manual) continue;
      if (!opts.packageOn) {
        steps.push({
          name,
          outcome: 'skip',
          detail: 'Package check is off (policy.packageCheck.enabled is false)',
        });
        continue;
      }
      const outcome: ExplainStep['outcome'] =
        run.outcome === 'stop'
          ? 'block'
          : run.outcome === 'review'
            ? 'review'
            : pkg && pkg.checked > 0
              ? 'checked'
              : 'skip';
      steps.push({ name, outcome, detail: run.detail + misses, isFinal: run.outcome === 'stop' });
      continue;
    }
    if (run.gate === 'file' && run.outcome === 'skip') continue;
    const outcome: ExplainStep['outcome'] =
      run.outcome === 'stop'
        ? 'block'
        : run.outcome === 'review'
          ? 'review'
          : run.outcome === 'skip'
            ? 'skip'
            : 'checked';
    steps.push({ name, outcome, detail: run.detail, isFinal: run.outcome === 'stop' });
  }
  if (gates.stop) {
    const after = PRE_ENGINE_GATES.slice(PRE_ENGINE_GATES.indexOf(gates.stop.gate) + 1);
    for (const gate of after) {
      if (gate === 'package' && opts.manual) continue;
      steps.push({
        name: GATE_STEP[gate],
        outcome: 'skip',
        detail: `Not reached: ${GATE_PLAIN[gates.stop.gate]} blocks first`,
      });
    }
  }
  return steps;
}

/** The gate whose review holds the call, by the label the hook carries. */
function explainReviewStopName(gates: StatelessGates): string {
  if (gates.label === GATE_LABELS.dlpReview) return GATE_STEP.dlp;
  if (gates.label === GATE_LABELS.packageReview) return GATE_STEP.package;
  if (gates.reviews.file || gates.reviews.fileIncomplete) return GATE_STEP.file;
  if (gates.reviews.dlp) return GATE_STEP.dlp;
  return GATE_STEP.package;
}

/** The engine verdict, reconciled with the human-readable trace. */
async function explainEngineVerdict(
  toolName: string,
  args: unknown,
  agent: string,
  config: ReturnType<typeof getConfig>,
  prepared: PreparedFileAccess
): Promise<{ result: ExplainResult; engine: PolicyVerdict }> {
  const derived = await deriveExplainTrace(toolName, args);
  const engine = await evaluatePolicy(toolName, args, agent, prepared.cwd, {
    fileAccess: prepared,
    config,
  });
  const fileVerdict = engine.checkId?.startsWith('files.');
  if (derived.decision === engine.decision && !fileVerdict) return { result: derived, engine };

  // Drift canary — a gate the engine runs (and the re-derivation models
  // differently) decided this. Loud in debug so the next added gate can't
  // silently re-widen the gap.
  if (process.env.NODE9_DEBUG) {
    console.error(
      `[node9 explain] decision drift: trace=${derived.decision} engine=${engine.decision} ` +
        `for ${toolName} — engine wins (${engine.blockedByLabel ?? 'engine'}).`
    );
  }

  const engineStep: ExplainStep = {
    name: fileVerdict ? 'Protected file access' : ENGINE_STEP,
    outcome: engine.decision,
    detail: fileVerdict
      ? (engine.reason ?? engine.ruleDescription ?? 'Protected file access')
      : `${engine.blockedByLabel ?? 'policy engine'}` +
        `${engine.reason ? `: ${engine.reason}` : ''} — this is the verdict the live hook actually ` +
        `enforces. It differs from the preview trace above, which models the policy tiers separately ` +
        `and can drift; the engine is authoritative.`,
    isFinal: true,
  };

  return {
    engine,
    result: {
      ...derived,
      // One stop per preview: the trace's own final step yields to the engine's.
      steps: [...derived.steps.map((s) => (s.isFinal ? { ...s, isFinal: false } : s)), engineStep],
      decision: engine.decision,
      blockedByLabel: engine.blockedByLabel ?? derived.blockedByLabel,
      ruleDescription: engine.ruleDescription ?? derived.ruleDescription,
    },
  };
}

/** The config sources, as the preview lists them. */
function explainWaterfall(config: ReturnType<typeof getConfig>): WaterfallTier[] {
  const globalPath = path.join(os.homedir(), '.node9', 'config.json');
  const projectPath = path.join(process.cwd(), 'node9.config.json');
  const credsPath = path.join(os.homedir(), '.node9', 'credentials.json');

  // I4: the waterfall must tell the PR-2 truth. On a workspace-governed
  // machine the local tiers exist on disk but are inert for policy, and the
  // env-var mode override is ignored too — labeling them 'active' would
  // describe a merge that no longer happens.
  const wsGoverned = config.policySource === 'workspace';

  // ── Waterfall tiers ───────────────────────────────────────────────────────
  const waterfall: WaterfallTier[] = [
    {
      tier: 1,
      label: 'Env vars',
      status: 'env',
      note: process.env.NODE9_MODE
        ? wsGoverned
          ? `NODE9_MODE=${process.env.NODE9_MODE} — ignored (workspace config controls mode)`
          : `NODE9_MODE=${process.env.NODE9_MODE}`
        : 'not set',
    },
    {
      tier: 2,
      label: wsGoverned ? 'Workspace config' : 'Cloud policy',
      status: fs.existsSync(credsPath) ? 'active' : 'missing',
      note: fs.existsSync(credsPath)
        ? wsGoverned
          ? 'authoritative — this machine follows the workspace configuration (app.node9.ai)'
          : 'credentials found (not evaluated in explain mode)'
        : 'not connected — run: node9 login',
    },
    {
      tier: 3,
      label: 'Project config',
      status: fs.existsSync(projectPath) ? 'active' : 'missing',
      path: projectPath,
      ...(wsGoverned && fs.existsSync(projectPath)
        ? { note: 'present — ignored (workspace config governs policy)' }
        : {}),
    },
    {
      tier: 4,
      label: 'Global config',
      status: fs.existsSync(globalPath) ? 'active' : 'missing',
      path: globalPath,
      ...(wsGoverned && fs.existsSync(globalPath)
        ? { note: 'present — ignored (workspace config governs policy)' }
        : {}),
    },
    {
      tier: 5,
      label: 'Defaults',
      status: 'active',
      note: 'always active',
    },
  ];

  return waterfall;
}

async function deriveExplainTrace(toolName: string, args: unknown): Promise<ExplainResult> {
  const steps: ExplainStep[] = [];

  const config = getConfig();
  const layers = inspectionLayers(config.policy);
  const waterfall = explainWaterfall(config);
  const wouldBeIgnored = matchesPattern(toolName, config.policy.ignoredTools);

  // ── 1. Ignored tools ──────────────────────────────────────────────────────
  if (wouldBeIgnored) {
    steps.push({
      name: 'Ignored tools',
      outcome: 'allow',
      detail: `"${toolName}" matches ignoredTools pattern → fast-path allow`,
      isFinal: true,
    });
    return { tool: toolName, args, waterfall, steps, decision: 'allow' };
  }
  steps.push({
    name: 'Ignored tools',
    outcome: 'checked',
    detail: `"${toolName}" not in ignoredTools list`,
  });

  // ── 2. Smart Rules ────────────────────────────────────────────────────────
  if (config.policy.smartRules.length > 0) {
    // Same matcher as the gate (toolMatchesRule), including the shell-shape
    // alias. A raw matchesPattern here printed 'No smart rule matched "shell"'
    // for every shell-shaped spelling the gate actually reviews — explain
    // contradicting the gate is worse than explain being silent, because it
    // teaches the user the gate is wrong (/code-review round 3).
    const matchedRule = config.policy.smartRules.find(
      (rule) =>
        toolMatchesRule(toolName, rule.tool, layers) &&
        evaluateSmartConditions(shellRuleArgs(toolName, args, rule.tool, layers), rule)
    );
    if (matchedRule) {
      const label = `Smart Rule: ${matchedRule.name ?? matchedRule.tool}`;
      if (matchedRule.verdict === 'allow') {
        steps.push({
          name: 'Smart rules',
          outcome: 'allow',
          detail: `${label} → allow`,
          isFinal: true,
        });
        return { tool: toolName, args, waterfall, steps, decision: 'allow' };
      }
      steps.push({
        name: 'Smart rules',
        outcome: matchedRule.verdict,
        detail: `${label} → ${matchedRule.verdict}${matchedRule.reason ? `: ${matchedRule.reason}` : ''}`,
        isFinal: true,
      });
      return {
        tool: toolName,
        args,
        waterfall,
        steps,
        decision: matchedRule.verdict,
        blockedByLabel: label,
      };
    }
    steps.push({
      name: 'Smart rules',
      outcome: 'checked',
      detail: `No smart rule matched "${toolName}"`,
    });
  } else {
    steps.push({ name: 'Smart rules', outcome: 'skip', detail: 'No smart rules configured' });
  }

  // ── 3. Input parsing ──────────────────────────────────────────────────────
  let allTokens: string[] = [];
  let pathTokens: string[] = [];

  const {
    command: shellCommand,
    matchingPattern,
    fieldName,
  } = explainExtractShellCommand(toolName, args, layers);
  if (shellCommand) {
    const analyzed = analyzeShellCommand(shellCommand);
    allTokens = analyzed.allTokens;
    pathTokens = analyzed.paths;

    steps.push({
      name: 'Input parsing',
      outcome: 'checked',
      detail: `Shell command via toolInspection["${matchingPattern ?? toolName}"] → field "${fieldName}": "${shellCommand}"`,
    });

    // ── 3. Inline exec ────────────────────────────────────────────────────
    // Uses the SAME detector as the gate. explain previously carried its own
    // ^-anchored regex, so it reported "no inline execution" for every wrapped,
    // piped, heredoc or non-python spelling the gate reviews — anyone debugging
    // a prompt with `node9 explain` got the wrong answer (/code-review
    // 2026-08-13). Drift here is worse than a miss: it teaches the user the
    // gate is wrong.
    // fw#385: Strict and Block all ask on every inline call; every other
    // level asks when the code does something dangerous or cannot be read.
    const everyInline = reviewsEveryInline(config.settings.mode);
    const strictInline = everyInline && detectInlineExec(shellCommand);
    const inline = everyInline ? null : inlineExecReview(shellCommand);
    // The check's value in force, as the engine reads it: `off` skips the
    // check, `log` records the finding and lets the call through (Soft).
    const inlineValue = checkValue(
      catalogSettingsFromConfig(config.settings, config.policy),
      'commands.inline-exec'
    );
    if ((strictInline || inline) && inlineValue === 'off') {
      steps.push({
        name: 'Inline execution',
        outcome: 'skip',
        detail: 'Inline code detected; the check is off (commands.inline-exec: off)',
      });
    } else if ((strictInline || inline) && inlineValue === 'log') {
      steps.push({
        name: 'Inline execution',
        outcome: 'allow',
        detail: `${inline ? inlineExecReason(inline) : 'Inline code execution detected'} — logged, not held at this level (commands.inline-exec: log)`,
      });
    } else if (strictInline || inline) {
      const reason = inline ? inlineExecReason(inline) : undefined;
      const outcome = inlineValue === 'block' ? 'block' : 'review';
      steps.push({
        name: 'Inline execution',
        outcome,
        detail: reason ?? 'Inline code execution detected — this level reviews every inline call',
        isFinal: true,
      });
      return {
        tool: toolName,
        args,
        waterfall,
        steps,
        decision: outcome,
        blockedByLabel: 'Node9 Standard (Inline Execution)',
        ...(reason ? { reason } : {}),
        ruleDescription: inlineExecDescription(inline),
      };
    } else {
      steps.push({
        name: 'Inline execution',
        outcome: 'checked',
        detail: detectInlineExec(shellCommand)
          ? 'Inline code that does nothing dangerous'
          : 'No inline execution pattern detected',
      });
    }

    // ── 3b. AST eval detection ────────────────────────────────────────────
    const evalVerdict = detectDangerousShellExec(shellCommand);
    if (evalVerdict) {
      const label =
        evalVerdict === 'block' ? 'Node9: Eval Remote Execution' : 'Node9: Eval Dynamic Content';
      const detail =
        evalVerdict === 'block'
          ? 'eval of remote download (curl/wget) — near-certain supply-chain attack'
          : 'eval of dynamic content (variable or subshell expansion) — requires approval';
      steps.push({ name: 'AST eval detection', outcome: evalVerdict, detail, isFinal: true });
      return {
        tool: toolName,
        args,
        waterfall,
        steps,
        decision: evalVerdict,
        blockedByLabel: label,
      };
    }
    steps.push({
      name: 'AST eval detection',
      outcome: 'checked',
      detail: 'No dangerous eval detected',
    });

    // ── 4. SQL DML keyword stripping ──────────────────────────────────────
    if (explainIsSqlTool(toolName, layers)) {
      allTokens = allTokens.filter((t) => !SQL_DML_KEYWORDS.has(t.toLowerCase()));
      steps.push({
        name: 'SQL token stripping',
        outcome: 'checked',
        detail: 'DML keywords stripped from tokens (SQL safety handled by smart rules)',
      });
    }
  } else {
    allTokens = tokenize(toolName);
    let detail = `No toolInspection match for "${toolName}" — tokens: [${allTokens.join(', ')}]`;
    if (args && typeof args === 'object') {
      const flattenedArgs = JSON.stringify(args).toLowerCase();
      const extraTokens = flattenedArgs.split(/[^a-zA-Z0-9]+/).filter((t) => t.length > 1);
      allTokens.push(...extraTokens);
      const preview = extraTokens.slice(0, 8).join(', ') + (extraTokens.length > 8 ? '…' : '');
      detail += ` + deep scan of args: [${preview}]`;
    }
    steps.push({ name: 'Input parsing', outcome: 'checked', detail });
  }

  // ── 4. Tokens ─────────────────────────────────────────────────────────────
  const uniqueTokens = [...new Set(allTokens)];
  steps.push({
    name: 'Tokens scanned',
    outcome: 'checked',
    detail: `[${uniqueTokens.join(', ')}]`,
  });

  // ── 5. Sandbox paths ──────────────────────────────────────────────────────
  if (pathTokens.length > 0 && config.policy.sandboxPaths.length > 0) {
    const allInSandbox = pathTokens.every((p) => matchesPattern(p, config.policy.sandboxPaths));
    if (allInSandbox) {
      steps.push({
        name: 'Sandbox paths',
        outcome: 'allow',
        detail: `[${pathTokens.join(', ')}] all match sandbox patterns → auto-allow`,
        isFinal: true,
      });
      return { tool: toolName, args, waterfall, steps, decision: 'allow' };
    }
    const unmatched = pathTokens.filter((p) => !matchesPattern(p, config.policy.sandboxPaths));
    steps.push({
      name: 'Sandbox paths',
      outcome: 'checked',
      detail: `[${unmatched.join(', ')}] not in sandbox — not auto-allowed`,
    });
  } else {
    steps.push({
      name: 'Sandbox paths',
      outcome: 'skip',
      detail:
        pathTokens.length === 0 ? 'No path tokens found in input' : 'No sandbox paths configured',
    });
  }

  // ── 6. Dangerous words ────────────────────────────────────────────────────
  let matchedDangerousWord: string | undefined;
  const isDangerous = uniqueTokens.some((token) =>
    config.policy.dangerousWords.some((word) => {
      const w = word.toLowerCase();
      const hit =
        token === w ||
        (() => {
          try {
            return new RegExp(`\\b${w}\\b`, 'i').test(token);
          } catch {
            return false;
          }
        })();
      if (hit && !matchedDangerousWord) matchedDangerousWord = word;
      return hit;
    })
  );
  if (isDangerous) {
    steps.push({
      name: 'Dangerous words',
      outcome: 'review',
      detail: `"${matchedDangerousWord}" found in token list`,
      isFinal: true,
    });
    return {
      tool: toolName,
      args,
      waterfall,
      steps,
      decision: 'review',
      blockedByLabel: `Project/Global Config — dangerous word: "${matchedDangerousWord}"`,
      matchedToken: matchedDangerousWord,
      ruleDescription: `This command contains a flagged keyword ("${matchedDangerousWord}") from your node9 config. Review it before allowing.`,
    };
  }
  steps.push({
    name: 'Dangerous words',
    outcome: 'checked',
    detail: `No dangerous words matched`,
  });

  // ── 8. Block all: the catch-all ───────────────────────────────────────────
  if (isBlockAll(config.settings.mode)) {
    steps.push({
      name: 'Block all',
      outcome: 'review',
      detail: 'Level is "block-all" — all tools require approval unless explicitly allowed',
      isFinal: true,
    });
    return {
      tool: toolName,
      args,
      waterfall,
      steps,
      decision: 'review',
      blockedByLabel: 'Global Config (Strict Mode Active)',
    };
  }
  steps.push({
    name: 'Block all',
    outcome: 'skip',
    detail: `Level is "${config.settings.mode}" — no catch-all review`,
  });

  return { tool: toolName, args, waterfall, steps, decision: 'allow' };
}
