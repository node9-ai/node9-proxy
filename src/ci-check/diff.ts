// src/ci-check/diff.ts
// CI-5 — classify a HEAD scan against a BASE scan: what did THIS change introduce?
//
// Every other check answers "what is wrong with this repo". A reviewer opening a pull
// request is asking a different question, and answering the first one instead is why a
// gate gets switched off on day one: a repo that has been accumulating agent config for
// two years goes red on a PR that touched none of it.
//
// Pure and platform-agnostic on purpose. The identity of a finding is derived from repo
// content ONLY (rule + path + a semantic locator) — never from a blob SHA, a PR number
// or a run id, so it survives a rebase and ports to any host that can give us two trees.

import { createHash } from 'node:crypto';
import type {
  BaseState,
  CiFinding,
  EscalatedFinding,
  ScanDiff,
  ScanResult,
  Severity,
} from './types';
import { SEVERITY_RANK } from './types';

/** The stable identity of a finding across two scans.
 *
 *  Deliberately EXCLUDES: severity and title (so a re-worded or re-graded finding is the
 *  same finding), and the line number (which moves whenever anything above it is edited —
 *  including it would report every finding in an edited file as new). */
export function fingerprintOf(f: CiFinding): string {
  const key = JSON.stringify([f.rule, f.file, f.locator ?? '', f.ordinal ?? 0]);
  return createHash('sha256').update(key).digest('hex').slice(0, 16);
}

/** Assign `ordinal` to findings that are otherwise identical within one scan, so two
 *  genuinely separate occurrences (the same hook command registered twice) do not collapse
 *  into one key and silently drop from the diff. Mutates in emission order — deterministic
 *  because the file order is. */
export function assignOrdinals(findings: CiFinding[]): CiFinding[] {
  const seen = new Map<string, number>();
  for (const f of findings) {
    const key = JSON.stringify([f.rule, f.file, f.locator ?? '']);
    const n = seen.get(key) ?? 0;
    if (n > 0) f.ordinal = n;
    seen.set(key, n + 1);
  }
  return findings;
}

function worstOf(severities: Severity[]): Severity | null {
  let worst: Severity | null = null;
  for (const s of severities) {
    if (!worst || SEVERITY_RANK[s] > SEVERITY_RANK[worst]) worst = s;
  }
  return worst;
}

/** Is the base side trustworthy enough to subtract from the head?
 *
 *  A base scan that could not read every file makes each unseen finding look introduced —
 *  the mirror image of the failure this file exists to prevent. Both untrustworthy states
 *  are named rather than collapsed into a boolean, so a consumer cannot mistake "we could
 *  not compare" for "nothing new". */
function baseStateOf(base: ScanResult | null | undefined): BaseState {
  if (!base) return 'did-not-run';
  return base.incomplete ? 'incomplete' : 'ok';
}

/**
 * Classify `head` against `base`.
 *
 * When the base is not trustworthy the diff DEGRADES TO THE ABSOLUTE ANSWER: nothing is
 * claimed as introduced, every head finding is reported, and `worstIntroduced` becomes the
 * head's own worst severity. A caller that gates on `worstIntroduced` therefore gets the
 * old, strict behaviour when the comparison was impossible — never a false all-clear.
 */
export function diffScans(base: ScanResult | null | undefined, head: ScanResult): ScanDiff {
  const state = baseStateOf(base);

  if (state !== 'ok' || !base) {
    return {
      base: state,
      added: [],
      removed: [],
      unchanged: [...head.findings],
      escalated: [],
      worstIntroduced: head.worst,
    };
  }

  const baseByFp = new Map<string, CiFinding>();
  for (const f of base.findings) baseByFp.set(fingerprintOf(f), f);

  const added: CiFinding[] = [];
  const unchanged: CiFinding[] = [];
  const escalated: EscalatedFinding[] = [];
  const matched = new Set<string>();

  for (const f of head.findings) {
    const fp = fingerprintOf(f);
    const prior = baseByFp.get(fp);
    if (!prior) {
      added.push(f);
      continue;
    }
    matched.add(fp);
    // A finding that already existed and got WORSE is guardrail erosion (a deny backstop
    // deleted, a mitigation removed). It is not new, and calling it "unchanged" would let
    // the removal merge silently — so it is its own class, and it counts as introduced.
    if (SEVERITY_RANK[f.severity] > SEVERITY_RANK[prior.severity]) {
      escalated.push({ finding: f, from: prior.severity, to: f.severity });
    } else {
      // Equal, or IMPROVED. A de-escalation is a fix in progress, never an introduction.
      unchanged.push(f);
    }
  }

  const removed = base.findings.filter((f) => !matched.has(fingerprintOf(f)));

  return {
    base: state,
    added,
    removed,
    unchanged,
    escalated,
    worstIntroduced: worstOf([...added.map((f) => f.severity), ...escalated.map((e) => e.to)]),
  };
}
