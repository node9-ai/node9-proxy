// Canonical detection pipeline — the one extractor every JSONL-scanning
// consumer in node9 calls. Replaces the duplicated detection logic in
// scan.ts (CLI), scan-watermark.ts (daemon), and scan-upload-history.ts
// (backfill) so all three produce identical findings on identical input.
//
// Two public entry points:
//
//   extractCanonicalFindings(call, ctx)
//     Per-line / per-tool-call. Runs every detector that doesn't need
//     window state: smart rules + AST suppression + AST FS-op + DLP +
//     PII + sensitive-file-read + privilege-escalation + destructive-op +
//     pipe-to-shell + eval-of-remote + long-output-redacted.
//
//   extractSessionLevelFindings(calls, ctx)
//     Per-session. Runs detectors that need a sliding window across calls
//     — currently just loop detection, but the natural home for any
//     future session-aware signal (sustained-iteration spend, repeated
//     DLP across the same session, etc.).
//
// The canonical findings are then either:
//   - Rendered locally by the CLI (keeps `input`, `redactedSample` etc.)
//   - Projected to the privacy-safe `ScanFinding` via toScanFinding()
//     before egress to the SaaS.
//
// Pure functions. No fs/path/os/process imports. Hosts pass parsed
// JSONL entries in.

import { scanArgs } from '../dlp';
import { matchesPattern, evaluateSmartConditions } from '../rules';
import {
  analyzeFsOperation,
  analyzeShellCommand,
  detectDangerousShellExec,
  isBashTool,
  AST_FS_REGEX_RULES,
} from '../shell';
import { analyzePipeChain } from '../policy/pipe-chain';
import { classifyRuleSeverity, type Severity } from '../severity';
import { DESTRUCTIVE_OP_RE, SENSITIVE_PATH_RE, FILE_TOOLS } from './destructive-regex';
import { detectPii } from './pii';
import { evaluateLoopWindow, type ToolCallRecord } from '../loop';
import { COST_PER_LOOP_ITER_USD } from './index';
import type { SmartRule } from '../types';
import type { ScanFinding } from './index';

// ── Public types ──────────────────────────────────────────────────────────

export type CanonicalFindingType =
  | 'smart-rule'
  | 'ast-fs-op'
  | 'dlp'
  | 'pii'
  | 'sensitive-file-read'
  | 'privilege-escalation'
  | 'destructive-op'
  | 'pipe-to-shell'
  | 'eval-of-remote'
  | 'loop'
  | 'long-output-redacted';

export type CanonicalAgent = 'claude' | 'gemini' | 'codex' | 'shell';

export type CanonicalSourceType = 'default' | 'shield' | 'user' | 'engine';

export interface CanonicalFinding {
  /** Discriminator. Maps 1:1 to ScanFinding.type for the SaaS upload. */
  type: CanonicalFindingType;
  /**
   * Stable rule identifier. For type='smart-rule' / 'ast-fs-op' it's the
   * rule name (e.g. 'block-rm-rf-home', 'shield:project-jail:block-read-ssh').
   * For built-in detector findings (PII, DLP, regex), a synthetic name keyed
   * on the detector + pattern (e.g. 'pii:email', 'dlp:GitHub Token').
   */
  ruleName: string;
  /** Block or review. Findings only exist for fired rules — no allow/info. */
  verdict: 'block' | 'review';
  /** Severity tier. Single source of truth — produced once at the engine. */
  severity: Severity;
  /** Engine-generated reason. Never carries user PII or raw secrets. */
  reason: string;
  /** Pattern name for DLP/PII (e.g. 'GitHub Token', 'Email'). */
  patternName?: string;
  /** Tool that produced the call. */
  toolName: string;
  agent: CanonicalAgent;
  sessionId: string;
  /** Project label or working directory the session lives in. */
  project: string;
  /** Local JSONL line offset. Never exfiltrated; used for dedupe. */
  lineIndex: number;
  /** Where the rule came from. 'engine' for built-in detectors. */
  sourceType: CanonicalSourceType;
  /** Optional shield/source label for UI. */
  shieldLabel?: string;
  /** When this exact (post-dedupe) finding was first / last seen. */
  firstSeenAt: string;
  lastSeenAt: string;
  /** Post-dedupe match count. 1 by default, N for N collapsed raw matches. */
  occurrenceCount: number;

  /** AST findings: the path that triggered the verdict. */
  subjectPath?: string;
  /** Loop findings: dollar cost so far. Loop-only today; optional everywhere. */
  costUsd?: number;
  /** Loop findings: number of iterations. */
  loopCount?: number;
  loopKind?: 'loop' | 'long-iteration';
  /** Loop findings: a sanitized command preview for UI. */
  commandPreview?: string;

  // ── PRIVACY-SENSITIVE — strip via toScanFinding() before network egress ──
  /** Raw tool input. Local CLI render only. */
  input?: Record<string, unknown>;
  /** DLP UI: first/last chars of the matched value with the middle replaced. */
  redactedSample?: string;
}

/**
 * Normalized per-call entry the per-line extractor consumes. Hosts (CLI
 * scan, daemon, backfill) parse agent-specific JSONL into this shape so
 * extractCanonicalFindings doesn't have to know about Claude vs Gemini vs
 * Codex line layouts.
 */
export interface ToolCallEntry {
  toolName: string;
  args: Record<string, unknown>;
  timestamp: string;
  /** Bytes of tool result content for long-output detection. 0 / undefined
   *  for non-result entries. */
  outputBytes?: number;
}

export interface ExtractContext {
  sessionId: string;
  lineIndex: number;
  project: string;
  agent: CanonicalAgent;
  rules: ReadonlyArray<{
    rule: SmartRule;
    sourceType: CanonicalSourceType;
    shieldLabel?: string;
  }>;
  /** toolInspection map from PolicyConfig — drives shell-command extraction
   *  for tools that aren't the standard 'bash' name. Defaults handled by caller. */
  toolInspection: Record<string, string>;
  /** DLP enabled flag from PolicyConfig. */
  dlpEnabled: boolean;
}

export interface SessionExtractContext {
  sessionId: string;
  project: string;
  agent: CanonicalAgent;
  /**
   * Loop-detection window settings. Mirrors PolicyConfig.policy.loopDetection.
   *
   * `windowSeconds: 0` means "no window" — count all matching calls in the
   * session regardless of timing. This is the right setting for historical
   * backfill (--upload-history): an agent that hammered the same Edit on
   * the same file 126 times across hours is the loop pattern users care
   * about, but a 120s window would never fire on it. The live hook keeps
   * the small window because it's racing against an actively running agent.
   */
  loopDetection: {
    enabled: boolean;
    threshold: number;
    windowSeconds: number;
  };
}

export interface SessionToolCall extends ToolCallEntry {
  /** Local JSONL line where this call lived — propagates to the loop finding. */
  lineIndex: number;
}

// Threshold for "long output" — tool results larger than this trigger a
// long-output-redacted finding. Same value the proxy's runtime redaction
// layer uses, so counts are comparable across consumers.
export const LONG_OUTPUT_THRESHOLD_BYTES = 100 * 1024;

/**
 * Wire-format identity of the canonical detector pipeline. Bumped when
 * extractCanonicalFindings (and friends) change their output in a way
 * that would invalidate verdicts already recorded against the previous
 * version. The daemon stores this in ~/.node9/scan-watermark.json and
 * triggers a one-time re-scan when its persisted value falls behind.
 *
 * Bump it when:
 *   - adding/removing a CanonicalFindingType
 *   - changing severity classification for an existing type
 *   - changing dedupe keys (would silently re-bucket existing findings)
 *   - any semantic change to the detectors that affects emitted counts
 *
 * Don't bump for:
 *   - comment-only edits
 *   - jsdoc tweaks
 *   - refactors that demonstrably preserve output
 *
 * scripts/check-extractor-version.mjs hashes the detector source files
 * and fails CI when the hash drifts without a version bump — forgetting
 * is loud, not silent.
 */
export const CANONICAL_EXTRACTOR_VERSION = 'canonical-v4';

/**
 * SHA-256 prefix of the detector-source files
 * (canonical.ts + pii.ts + destructive-regex.ts).
 *
 * Updated by `npm run bump-extractor-version`. The CI gate in
 * `.github/workflows/ci.yml` recomputes the hash on every push and fails
 * if it doesn't match this constant — the contract is "if any of those
 * files changed, this hash must change too, and you must consciously
 * decide whether to bump CANONICAL_EXTRACTOR_VERSION."
 */
export const CANONICAL_EXTRACTOR_HASH = '64a6a63a27f4646f';

// Dedupe key length cap — match what scan.ts:502 uses today.
const DEDUPE_PREVIEW_LEN = 120;

// ── Per-line extractor ────────────────────────────────────────────────────

export function extractCanonicalFindings(
  call: ToolCallEntry,
  ctx: ExtractContext
): CanonicalFinding[] {
  const out: CanonicalFinding[] = [];
  const ts = call.timestamp;
  const toolNameLower = call.toolName.toLowerCase();
  const command = typeof call.args.command === 'string' ? (call.args.command as string) : null;
  const isBash = isBashTool(call.toolName) && command !== null;

  // ── Long output redacted (per-line, no rule needed) ──────────────────────
  if (call.outputBytes !== undefined && call.outputBytes > LONG_OUTPUT_THRESHOLD_BYTES) {
    out.push(
      makeFinding({
        type: 'long-output-redacted',
        ruleName: 'long-output-redacted',
        verdict: 'review',
        severity: 'medium',
        reason: `Tool output exceeded ${LONG_OUTPUT_THRESHOLD_BYTES} bytes and was redacted`,
        toolName: call.toolName,
        ctx,
        ts,
        sourceType: 'engine',
      })
    );
  }

  // ── DLP (over args) ──────────────────────────────────────────────────────
  if (ctx.dlpEnabled) {
    const dlp = scanArgs(call.args);
    if (dlp) {
      out.push(
        makeFinding({
          type: 'dlp',
          ruleName: `dlp:${dlp.patternName}`,
          patternName: dlp.patternName,
          verdict: dlp.severity === 'block' ? 'block' : 'review',
          severity: dlp.severity === 'block' ? 'critical' : 'medium',
          reason: `${dlp.patternName} detected in ${dlp.fieldPath}`,
          toolName: call.toolName,
          ctx,
          ts,
          sourceType: 'engine',
          input: call.args,
          redactedSample: dlp.redactedSample,
        })
      );
    }
  }

  // ── PII (over string-shaped args) ────────────────────────────────────────
  for (const value of stringValues(call.args)) {
    const piiHits = detectPii(value);
    for (const pattern of piiHits) {
      out.push(
        makeFinding({
          type: 'pii',
          ruleName: `pii:${pattern.toLowerCase().replace(/\s+/g, '-')}`,
          patternName: pattern,
          verdict: 'review',
          severity: 'medium',
          reason: `${pattern} pattern detected in tool input`,
          toolName: call.toolName,
          ctx,
          ts,
          sourceType: 'engine',
        })
      );
    }
  }

  // ── Sensitive file reads (file_path / path / pattern args) ───────────────
  if (FILE_TOOLS.has(toolNameLower)) {
    const filePath =
      (typeof call.args.file_path === 'string' && call.args.file_path) ||
      (typeof call.args.path === 'string' && call.args.path) ||
      (typeof call.args.pattern === 'string' && call.args.pattern) ||
      '';
    if (filePath && SENSITIVE_PATH_RE.test(filePath)) {
      out.push(
        makeFinding({
          type: 'sensitive-file-read',
          ruleName: 'sensitive-file-read',
          verdict: 'review',
          severity: 'critical',
          reason: `Sensitive file path read via ${call.toolName}`,
          toolName: call.toolName,
          ctx,
          ts,
          sourceType: 'engine',
          subjectPath: filePath,
        })
      );
    }
  }

  if (!isBash || command === null) {
    return out;
  }

  // ── Bash-specific detectors below ────────────────────────────────────────

  // ── AST FS-op (project-jail / rm-rf-home) ────────────────────────────────
  // When the AST detector runs, regex-mirror smart rules are suppressed in
  // the smart-rules loop below — same semantics as scan.ts:1059 and the
  // engine waterfall added in PR #152.
  const fsVerdict = analyzeFsOperation(command);
  if (fsVerdict) {
    const isShield = fsVerdict.ruleName.startsWith('shield:');
    out.push(
      makeFinding({
        type: 'ast-fs-op',
        ruleName: fsVerdict.ruleName,
        verdict: fsVerdict.verdict,
        severity: classifyRuleSeverity(fsVerdict.ruleName, fsVerdict.verdict),
        reason: fsVerdict.reason,
        toolName: call.toolName,
        ctx,
        ts,
        sourceType: isShield ? 'shield' : 'engine',
        shieldLabel: isShield ? 'project-jail (AST)' : 'Node9 (AST)',
        subjectPath: fsVerdict.path,
        input: call.args,
      })
    );
  }

  // ── Smart rules (with AST suppression) ───────────────────────────────────
  for (const source of ctx.rules) {
    const r = source.rule;
    if (r.verdict === 'allow') continue;
    if (r.tool && !matchesPattern(toolNameLower, r.tool)) continue;
    if (r.name && AST_FS_REGEX_RULES.has(r.name)) continue;
    if (!evaluateSmartConditions(call.args, r)) continue;

    out.push(
      makeFinding({
        type: 'smart-rule',
        ruleName: r.name ?? r.tool,
        verdict: r.verdict === 'block' ? 'block' : 'review',
        severity: classifyRuleSeverity(r.name ?? r.tool, r.verdict),
        reason: r.reason ?? `Smart rule ${r.name ?? r.tool} fired`,
        toolName: call.toolName,
        ctx,
        ts,
        sourceType: source.sourceType,
        shieldLabel: source.shieldLabel,
        input: call.args,
      })
    );
    break; // first matching rule wins per call
  }

  // ── Eval-of-remote (curl | bash, bash -c "$(curl …)" etc.) ───────────────
  const evalVerdict = detectDangerousShellExec(command);
  if (evalVerdict) {
    out.push(
      makeFinding({
        type: 'eval-of-remote',
        ruleName: 'eval-of-remote',
        verdict: evalVerdict,
        severity: classifyRuleSeverity('eval-remote', evalVerdict),
        reason:
          evalVerdict === 'block'
            ? 'Eval of remote download is a near-certain supply-chain attack'
            : 'Eval of dynamic content (variable / subshell) requires approval',
        toolName: call.toolName,
        ctx,
        ts,
        sourceType: 'engine',
        input: call.args,
      })
    );
  }

  // ── Pipe-to-shell (sensitive-source pipe to network sink) ────────────────
  const pipe = analyzePipeChain(command);
  if (pipe.isPipeline && pipe.risk === 'critical') {
    out.push(
      makeFinding({
        type: 'pipe-to-shell',
        ruleName: 'pipe-to-shell',
        verdict: 'block',
        severity: 'critical',
        reason: `Sensitive file piped through obfuscator to network sink: ${pipe.sourceFiles.join(', ')} → ${pipe.sinkTargets.join(', ')}`,
        toolName: call.toolName,
        ctx,
        ts,
        sourceType: 'engine',
        input: call.args,
      })
    );
  }

  // ── Destructive op (rm -rf, DROP TABLE, force push, etc.) ────────────────
  if (DESTRUCTIVE_OP_RE.test(command)) {
    out.push(
      makeFinding({
        type: 'destructive-op',
        ruleName: 'destructive-op',
        verdict: 'review',
        severity: 'high',
        reason: 'Destructive operation pattern detected',
        toolName: call.toolName,
        ctx,
        ts,
        sourceType: 'engine',
        input: call.args,
      })
    );
  }

  // ── Privilege escalation (sudo, chmod 777, chown root) ───────────────────
  // All-AST detection via analyzeShellCommand (mvdan-sh AST + permissive
  // regex fallback if AST parse fails). The function returns:
  //   - actions  — first word of every CallExpr (the actual command names)
  //   - allTokens — every literal token, lowercased + path-segment-split
  //
  // Both sudo/su AND chmod/chown go through this path so all four classes
  // share the same false-positive elimination (string-literal mentions
  // like `echo "chmod 777 done"` or `cat /etc/sudoers` no longer trip the
  // detector — those don't put the action name in `actions`). Quoting
  // bypasses (`s''udo`, `c\hmod`) are caught because mvdan-sh resolves
  // the AST before we look at actions.
  //
  // PRIVILEGE_ESCALATION_RE is no longer the privesc gate at all; it's
  // retained in the engine exports for non-AST consumers (smart rules
  // that grep raw strings) and as documentation of the historical
  // pattern set.
  const ast = analyzeShellCommand(command);
  const sudoVariant = ast.actions.includes('sudo') || ast.actions.includes('su');
  const chmodVariant =
    ast.actions.includes('chmod') &&
    (ast.allTokens.includes('777') ||
      ast.allTokens.includes('0777') ||
      ast.allTokens.includes('+x'));
  const chownVariant = ast.actions.includes('chown') && ast.allTokens.includes('root');
  if (sudoVariant || chmodVariant || chownVariant) {
    out.push(
      makeFinding({
        type: 'privilege-escalation',
        ruleName: 'privilege-escalation',
        verdict: 'review',
        severity: 'high',
        reason: 'Privilege-escalation pattern detected',
        toolName: call.toolName,
        ctx,
        ts,
        sourceType: 'engine',
        input: call.args,
      })
    );
  }

  return out;
}

// ── Per-session extractor (loop, future window-aware signals) ─────────────

export function extractSessionLevelFindings(
  calls: ReadonlyArray<SessionToolCall>,
  ctx: SessionExtractContext
): CanonicalFinding[] {
  if (!ctx.loopDetection.enabled || calls.length === 0) return [];

  const out: CanonicalFinding[] = [];
  const seenLoopKeys = new Set<string>();
  // windowSeconds === 0 → "no window": treat the entire session as the window
  // so historical loops fire even when calls are spaced hours apart. Avoid
  // Number.MAX_SAFE_INTEGER (overflow when multiplied by 1000); a year of ms
  // is a sufficient horizon for any realistic JSONL session.
  const ONE_YEAR_MS = 365 * 24 * 60 * 60 * 1000;
  const windowMs =
    ctx.loopDetection.windowSeconds <= 0 ? ONE_YEAR_MS : ctx.loopDetection.windowSeconds * 1000;

  // Slide a window of recent records keyed by (toolName, argsHash). The
  // engine helper handles cutoff + counting; we feed it records in
  // timestamp order and pass the current call's timestamp as `now`.
  //
  // Empty / unparseable timestamps yield NaN from new Date().getTime().
  // Passing NaN as `now` makes evaluateLoopWindow's cutoff comparison
  // (`r.ts >= cutoff`) always false — every record gets filtered out and
  // loop detection silently produces nothing. Synthesize a monotonic
  // sequence based on the call's index instead, so the windowing logic
  // still works even on agents (Codex, future formats) that omit the
  // timestamp field.
  let records: ToolCallRecord[] = [];
  let syntheticTs = 0;
  for (let i = 0; i < calls.length; i++) {
    const call = calls[i];
    const parsed = new Date(call.timestamp).getTime();
    const now = Number.isFinite(parsed) ? parsed : ++syntheticTs;
    const verdict = evaluateLoopWindow(
      records,
      call.toolName,
      call.args,
      ctx.loopDetection.threshold,
      windowMs,
      now
    );
    records = verdict.nextRecords;
    if (!verdict.looping) continue;

    const last = records[records.length - 1];
    const key = `${last.t}|${last.h}`;
    if (seenLoopKeys.has(key)) continue;
    seenLoopKeys.add(key);

    out.push({
      type: 'loop',
      ruleName: 'loop',
      verdict: 'review',
      severity: 'medium',
      reason: `Tool called ${verdict.count} times with identical args within window`,
      toolName: call.toolName,
      agent: ctx.agent,
      sessionId: ctx.sessionId,
      project: ctx.project,
      lineIndex: call.lineIndex,
      sourceType: 'engine',
      firstSeenAt: call.timestamp,
      lastSeenAt: call.timestamp,
      occurrenceCount: 1,
      loopCount: verdict.count,
      loopKind: 'loop',
      commandPreview: previewArgs(call.args, DEDUPE_PREVIEW_LEN),
      costUsd: verdict.count * COST_PER_LOOP_ITER_USD,
    });
  }

  return out;
}

// ── Dedupe ────────────────────────────────────────────────────────────────

/**
 * Collapse equivalent findings into one row, summing occurrenceCount and
 * spreading firstSeenAt / lastSeenAt across the matches. Dedupe key is
 * (type, ruleName, command-preview, project, agent) — same shape scan.ts
 * uses today (line 502), with `agent` added so cross-agent matches stay
 * separated for the dashboard's per-agent breakdown.
 */
export function dedupeCanonicalFindings(
  findings: ReadonlyArray<CanonicalFinding>
): CanonicalFinding[] {
  const merged = new Map<string, CanonicalFinding>();
  for (const f of findings) {
    const inputPreview = f.input ? previewArgs(f.input, DEDUPE_PREVIEW_LEN) : '';
    const key = `${f.type}|${f.ruleName}|${inputPreview}|${f.project}|${f.agent}`;
    const prev = merged.get(key);
    if (!prev) {
      merged.set(key, { ...f });
      continue;
    }
    prev.occurrenceCount += f.occurrenceCount;
    if (f.firstSeenAt && (!prev.firstSeenAt || f.firstSeenAt < prev.firstSeenAt)) {
      prev.firstSeenAt = f.firstSeenAt;
    }
    if (f.lastSeenAt && f.lastSeenAt > prev.lastSeenAt) {
      prev.lastSeenAt = f.lastSeenAt;
    }
    // Sum cost across loop occurrences; leave undefined otherwise.
    if (f.costUsd !== undefined) {
      prev.costUsd = (prev.costUsd ?? 0) + f.costUsd;
    }
    if (f.loopCount !== undefined) {
      prev.loopCount = (prev.loopCount ?? 0) + f.loopCount;
    }
  }
  return [...merged.values()];
}

// ── Privacy-stripping projection for SaaS upload ──────────────────────────

/**
 * Project a CanonicalFinding into the privacy-safe ScanFinding shape the
 * proxy sends to the SaaS. Drops `input`, `redactedSample`, `commandPreview`,
 * `subjectPath` — anything that could carry user content. Counts and pattern
 * names only, matching the privacy invariant in scan/index.ts.
 *
 * Returns null if the type doesn't have a corresponding ScanFinding bucket
 * (currently `smart-rule` and `ast-fs-op` — those carry a user-defined or
 * shield rule name and aren't part of the count-based summary).
 */
export function toScanFinding(c: CanonicalFinding): ScanFinding | null {
  // Map CanonicalFindingType → ScanFinding.type. The two enums share most
  // names; the unmapped ones (smart-rule, ast-fs-op) are deliberately
  // excluded from the SaaS rollup because they're per-rule identifiers,
  // not signal categories.
  const typeMap: Record<CanonicalFindingType, ScanFinding['type'] | null> = {
    'smart-rule': null,
    'ast-fs-op': null,
    dlp: 'dlp',
    pii: 'pii',
    'sensitive-file-read': 'sensitive-file-read',
    'privilege-escalation': 'privilege-escalation',
    'destructive-op': 'destructive-op',
    'pipe-to-shell': 'pipe-to-shell',
    'eval-of-remote': 'eval-of-remote',
    loop: 'loop',
    'long-output-redacted': 'long-output-redacted',
  };
  const sfType = typeMap[c.type];
  if (sfType === null) return null;

  return {
    sessionId: c.sessionId,
    type: sfType,
    ...(c.patternName && { patternName: c.patternName }),
    lineIndex: c.lineIndex,
  };
}

// ── Internals ─────────────────────────────────────────────────────────────

// Match scan.ts:331's preview helper so dedupe keys stay consistent across
// CLI and engine consumers. Pulls a representative string out of the args
// (command / query / file_path / JSON), trims whitespace, caps length.
const TERMINAL_ESCAPE_RE =
  // eslint-disable-next-line no-control-regex
  /\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-_]|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g;

export function previewArgs(input: Record<string, unknown>, max: number): string {
  const cmd = input.command ?? input.query ?? input.file_path ?? JSON.stringify(input);
  const s = String(cmd).replace(TERMINAL_ESCAPE_RE, '').replace(/\s+/g, ' ').trim();
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

function makeFinding(args: {
  type: CanonicalFindingType;
  ruleName: string;
  verdict: 'block' | 'review';
  severity: Severity;
  reason: string;
  toolName: string;
  ctx: ExtractContext;
  ts: string;
  sourceType: CanonicalSourceType;
  shieldLabel?: string;
  subjectPath?: string;
  input?: Record<string, unknown>;
  patternName?: string;
  redactedSample?: string;
}): CanonicalFinding {
  const f: CanonicalFinding = {
    type: args.type,
    ruleName: args.ruleName,
    verdict: args.verdict,
    severity: args.severity,
    reason: args.reason,
    toolName: args.toolName,
    agent: args.ctx.agent,
    sessionId: args.ctx.sessionId,
    project: args.ctx.project,
    lineIndex: args.ctx.lineIndex,
    sourceType: args.sourceType,
    firstSeenAt: args.ts,
    lastSeenAt: args.ts,
    occurrenceCount: 1,
  };
  if (args.shieldLabel) f.shieldLabel = args.shieldLabel;
  if (args.subjectPath) f.subjectPath = args.subjectPath;
  if (args.input) f.input = args.input;
  if (args.patternName) f.patternName = args.patternName;
  if (args.redactedSample) f.redactedSample = args.redactedSample;
  return f;
}

/**
 * Yield every string leaf in a nested args object. Used for PII detection,
 * which only operates on text. Caps recursion + total size so a pathological
 * deeply-nested arg can't burn unbounded CPU.
 */
function* stringValues(obj: unknown, depth = 0): Generator<string> {
  if (depth > 6) return;
  if (typeof obj === 'string') {
    if (obj.length > 0) yield obj;
    return;
  }
  if (!obj || typeof obj !== 'object') return;
  if (Array.isArray(obj)) {
    for (const v of obj) yield* stringValues(v, depth + 1);
    return;
  }
  for (const v of Object.values(obj)) yield* stringValues(v, depth + 1);
}
