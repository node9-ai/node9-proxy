// src/policy/gate-order.ts
// One source for the order and the combination rules of the hook's stateless
// pre-engine gates (node9Firewall#405). The hook (auth/orchestrator.ts) and
// `node9 explain` (policy/index.ts) both run the gates through this module,
// so a change to the order, to what stops a call, or to how a gate's review
// meets the engine's verdict happens in one place and reaches both.
//
// This module owns no I/O: the caller supplies the scanners (`GateIo`) and
// writes its own audit rows from the result. The stateful gates (file taint,
// session taint, exposure, canary, app permissions) are not here; they need
// the daemon and the session and run in the hook only.

import type { DlpMatch, PolicyVerdict, ProtectedFileVerdict } from '@node9/policy-engine';
import type { PackageCheckResult } from '../supply-chain/check';

/** The stateless gates, in the order the hook runs them before the engine. */
export const PRE_ENGINE_GATES = ['file', 'dlp', 'pii', 'package'] as const;
export type PreEngineGate = (typeof PRE_ENGINE_GATES)[number];

export const GATE_LABELS = {
  dlpBlock: '🚨 Node9 DLP (Secret Detected)',
  dlpReview: '🚨 Node9 DLP (Credential Review)',
  pii: '🔒 Node9 PII (Detected)',
  packageBlock: '📦 Node9 Package Check (Malicious)',
  packageReview: '📦 Node9 Package Check (Review)',
} as const;

/** The settings the gate rules read. */
export interface GateSettings {
  panicMode: boolean;
  dlp: {
    enabled: boolean;
    reviewAction?: string;
    pii?: string;
    scanIgnoredTools?: boolean;
  };
  /** The tool is on the ignored list (read, grep, ls ...). */
  toolIgnored: boolean;
}

/**
 * What each gate scans, supplied by the caller. A gate whose function is
 * omitted is recorded as decided elsewhere (the hook decides the file gate
 * before the stateful gates and passes only its review flag here).
 */
export interface GateIo {
  settings: GateSettings;
  /** The protected-file verdict; a throw is held as an incomplete analysis. */
  file?: () => ProtectedFileVerdict | null;
  /** The DLP match: the file path scan, then the argument scan. */
  dlp: () => DlpMatch | null;
  /** The PII patterns found in the arguments. */
  pii: () => string[];
  /** The package check; `null` when the check is off or the call is manual. */
  packageCheck: () => Promise<PackageCheckResult | null>;
}

export type GateOutcome = 'stop' | 'review' | 'pass' | 'skip';

export interface GateRun {
  gate: PreEngineGate;
  outcome: GateOutcome;
  detail: string;
}

export interface GateStop {
  gate: PreEngineGate;
  label: string;
  reason: string;
  ruleName?: string;
  ruleDescription?: string;
  /** What the stopping gate found, for the caller's audit row and side effects. */
  dlpMatch?: DlpMatch;
  pii?: string[];
  pkg?: PackageCheckResult;
}

export interface StatelessGates {
  /** The first gate that stops the call; the later gates did not run. */
  stop?: GateStop;
  reviews: {
    file?: ProtectedFileVerdict;
    /** The file analysis threw: the call is held for approval. */
    fileIncomplete?: boolean;
    dlp?: DlpMatch;
    package?: PackageCheckResult;
  };
  /** The label the hook carries into the engine stage (DLP before package). */
  label?: string;
  /** The package check's result when it ran, for the caller's bookkeeping. */
  packageResult?: PackageCheckResult;
  ran: GateRun[];
}

// ── The rules, one per gate ─────────────────────────────────────────────────

/** A block stops; a review stops under panic mode and is a review otherwise. */
export function fileGateOutcome(
  file: ProtectedFileVerdict | null,
  panicMode: boolean
): 'stop' | 'review' | null {
  if (!file) return null;
  if (file.decision === 'block') return 'stop';
  if (file.decision === 'review') return panicMode ? 'stop' : 'review';
  return null;
}

export function dlpGateApplies(s: GateSettings): boolean {
  return s.dlp.enabled && (!s.toolIgnored || s.dlp.scanIgnoredTools === true);
}

/** Block severity, or the admin's `reviewAction: 'block'`, stops the call. */
export function dlpStops(match: DlpMatch, s: GateSettings): boolean {
  return match.severity === 'block' || s.dlp.reviewAction === 'block';
}

export function piiGateApplies(s: GateSettings): boolean {
  return s.dlp.pii === 'block' && (!s.toolIgnored || s.dlp.scanIgnoredTools === true);
}

export function packageGateOutcome(pkg: PackageCheckResult): 'stop' | 'review' | null {
  if (pkg.verdict === 'block' && pkg.reason) return 'stop';
  if (pkg.verdict === 'review' && pkg.reason) return 'review';
  return null;
}

export function dlpReason(match: DlpMatch): string {
  return (
    `🚨 DATA LOSS PREVENTION: ${match.patternName} detected in ` +
    `field "${match.fieldPath}" (${match.redactedSample})`
  );
}

export function piiReason(found: string[]): string {
  return (
    `🔒 PII DETECTED: ${found.join(', ')} found in tool arguments. ` +
    `Remove or tokenize personal data before passing it to a tool.`
  );
}

// ── The runner ──────────────────────────────────────────────────────────────

/**
 * Run the stateless gates in order and stop at the first that stops the
 * call. Reviews are collected for the engine stage; the caller writes its
 * audit rows and side effects from `stop`, `reviews` and `packageResult`.
 */
export async function runStatelessGates(io: GateIo): Promise<StatelessGates> {
  const out: StatelessGates = { reviews: {}, ran: [] };
  const s = io.settings;
  for (const gate of PRE_ENGINE_GATES) {
    switch (gate) {
      case 'file': {
        if (!io.file) {
          out.ran.push({ gate, outcome: 'skip', detail: 'decided by the caller' });
          break;
        }
        let file: ProtectedFileVerdict | null;
        try {
          file = io.file();
        } catch {
          out.reviews.fileIncomplete = true;
          out.ran.push({
            gate,
            outcome: 'review',
            detail: 'The file analysis could not finish; the call is held for approval',
          });
          break;
        }
        const outcome = fileGateOutcome(file, s.panicMode);
        if (outcome === 'stop' && file) {
          out.stop = {
            gate,
            label: file.blockedByLabel ?? 'Protected file',
            reason: file.reason ?? 'Protected file access',
            ruleName: file.ruleName,
            ruleDescription: file.ruleDescription,
          };
          out.ran.push({ gate, outcome: 'stop', detail: out.stop.reason });
          return out;
        }
        if (outcome === 'review' && file) {
          out.reviews.file = file;
          out.label = file.blockedByLabel ?? out.label;
          out.ran.push({ gate, outcome: 'review', detail: file.reason ?? 'Protected file access' });
          break;
        }
        out.ran.push({ gate, outcome: 'pass', detail: 'No protected file in this call' });
        break;
      }
      case 'dlp': {
        if (!dlpGateApplies(s)) {
          out.ran.push({
            gate,
            outcome: 'skip',
            detail: s.dlp.enabled
              ? 'Ignored tool, and dlp.scanIgnoredTools is off'
              : 'DLP is off (policy.dlp.enabled is false)',
          });
          break;
        }
        const match = io.dlp();
        if (!match) {
          out.ran.push({
            gate,
            outcome: 'pass',
            detail: 'No sensitive credentials detected in args',
          });
          break;
        }
        const detail = `🚨 ${match.patternName} detected in ${match.fieldPath} — sample: ${match.redactedSample}`;
        if (dlpStops(match, s)) {
          out.stop = {
            gate,
            label: GATE_LABELS.dlpBlock,
            reason: dlpReason(match),
            dlpMatch: match,
          };
          out.ran.push({ gate, outcome: 'stop', detail });
          return out;
        }
        out.reviews.dlp = match;
        out.label = GATE_LABELS.dlpReview;
        out.ran.push({ gate, outcome: 'review', detail });
        break;
      }
      case 'pii': {
        if (!piiGateApplies(s)) {
          out.ran.push({
            gate,
            outcome: 'skip',
            detail:
              s.dlp.pii === 'block'
                ? 'Ignored tool, and dlp.scanIgnoredTools is off'
                : 'PII gate is off (policy.dlp.pii is not "block")',
          });
          break;
        }
        const found = io.pii();
        if (found.length === 0) {
          out.ran.push({ gate, outcome: 'pass', detail: 'No personal data detected in args' });
          break;
        }
        out.stop = { gate, label: GATE_LABELS.pii, reason: piiReason(found), pii: found };
        out.ran.push({
          gate,
          outcome: 'stop',
          detail: `🔒 ${found.join(', ')} found in tool arguments`,
        });
        return out;
      }
      case 'package': {
        const pkg = await io.packageCheck();
        if (!pkg) {
          out.ran.push({ gate, outcome: 'skip', detail: 'Package check did not run' });
          break;
        }
        out.packageResult = pkg;
        const outcome = packageGateOutcome(pkg);
        if (outcome === 'stop') {
          out.stop = {
            gate,
            label: GATE_LABELS.packageBlock,
            reason: pkg.reason ?? '',
            ruleDescription: pkg.reason,
            pkg,
          };
          out.ran.push({ gate, outcome: 'stop', detail: pkg.reason ?? '' });
          return out;
        }
        if (outcome === 'review') {
          out.reviews.package = pkg;
          // A DLP review already set the label the approver reads first.
          if (!out.reviews.dlp) out.label = GATE_LABELS.packageReview;
          out.ran.push({ gate, outcome: 'review', detail: pkg.reason ?? '' });
          break;
        }
        out.ran.push({
          gate,
          outcome: 'pass',
          detail:
            pkg.checked === 0
              ? 'No package install or run in this command.'
              : `${pkg.checked} package${pkg.checked === 1 ? '' : 's'} checked, no findings.`,
        });
        break;
      }
    }
  }
  return out;
}

// ── The engine stage ────────────────────────────────────────────────────────

export interface EngineSide {
  decision: PolicyVerdict['decision'];
  blockedByLabel?: string;
  ruleDescription?: string;
  reason?: string;
}

export interface Combined {
  decision: PolicyVerdict['decision'];
  blockedByLabel?: string;
  ruleDescription?: string;
  /** Panic mode turned the engine's review into a block. */
  panicked: boolean;
}

/**
 * Join the package review's text to a description the way the hook does:
 * the package text replaces an empty description or one that is itself the
 * package label's, and is appended to any other.
 */
export function joinPackageReview(
  description: string | undefined,
  label: string | undefined,
  packageReview: string
): string {
  return label === GATE_LABELS.packageReview || !description
    ? packageReview
    : `${description}\n${packageReview}`;
}

/**
 * The engine's verdict against the gates' reviews, the hook's rules:
 * panic mode turns an engine review into a block; an engine block wins; an
 * engine review stands and gains the package text; an engine allow becomes
 * a review when any gate (or the caller's own flags) asked for one, under
 * the engine's label if it set one, else the gates' label.
 */
export function combineWithEngine(
  gates: StatelessGates,
  engine: EngineSide,
  opts: { panicMode: boolean; otherReviews?: boolean } = { panicMode: false }
): Combined {
  const packageReview = gates.reviews.package?.reason;
  if (opts.panicMode && engine.decision === 'review') {
    return {
      decision: 'block',
      blockedByLabel: '🚨 Panic mode (org policy)',
      ruleDescription: engine.ruleDescription,
      panicked: true,
    };
  }
  if (engine.decision === 'block') {
    return {
      decision: 'block',
      blockedByLabel: engine.blockedByLabel,
      ruleDescription: engine.ruleDescription,
      panicked: false,
    };
  }
  const gateReview =
    !!gates.reviews.file ||
    !!gates.reviews.fileIncomplete ||
    !!gates.reviews.dlp ||
    !!gates.reviews.package ||
    opts.otherReviews === true;
  if (engine.decision === 'review') {
    const label = engine.blockedByLabel ?? gates.label;
    return {
      decision: 'review',
      blockedByLabel: label,
      ruleDescription: packageReview
        ? joinPackageReview(engine.ruleDescription, label, packageReview)
        : engine.ruleDescription,
      panicked: false,
    };
  }
  if (!gateReview) return { decision: 'allow', panicked: false };
  return {
    decision: 'review',
    blockedByLabel: engine.blockedByLabel ?? gates.label,
    ruleDescription: packageReview ?? gates.reviews.file?.reason ?? engine.ruleDescription,
    panicked: false,
  };
}
