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
const NOT_HONOURED_NEW =
  'this finding is new: a suppression cannot accept a finding in the same change that introduces it — merge it, then suppress it in a separate reviewed change';
const BASE_UNREADABLE =
  'the base could not be read, so no suppression can be shown to predate this change — not honoured';
const notHonouredEscalated = (from: Severity) =>
  `this finding was accepted at ${from} and this change makes it worse — the suppression does not cover the new severity`;
const NOT_HONOURED_EVIDENCE =
  'the evidence changed in this change (the finding now matches something different) — the suppression covered the old evidence, not this';

/** Same evidence: what the finding matched and why it is graded as it is. `line` is not
 *  evidence — moving a finding must not end its suppression. */
function sameEvidence(a: CiFinding, b: CiFinding): boolean {
  return (
    JSON.stringify(a.signals) === JSON.stringify(b.signals) &&
    JSON.stringify(a.mitigations ?? []) === JSON.stringify(b.mitigations ?? [])
  );
}

/** A copy with its suppression dropped and the reason named. `diffScans` never mutates the
 *  head it was given: calling it twice must not double a signal, and the head must stay what
 *  scanTree returned. */
function unhonour(f: CiFinding, why: string): CiFinding {
  const { suppressed: _dropped, ...rest } = f;
  void _dropped;
  return { ...rest, signals: [...f.signals, why] };
}

function worstUnsuppressed(findings: CiFinding[]): Severity | null {
  return worstOf(findings.filter((f) => !f.suppressed).map((f) => f.severity));
}

export function diffScans(base: ScanResult | null | undefined, head: ScanResult): ScanDiff {
  const state = baseStateOf(base);

  if (state !== 'ok' || !base) {
    // Nobody can tell which suppressions are new when the base could not be read, so none is
    // honoured in the gate: degrade strict, never open — the same law as the rest of CI-5.
    const honoured = head.findings.map((f) => (f.suppressed ? unhonour(f, BASE_UNREADABLE) : f));
    const worstAll = worstUnsuppressed(honoured);
    return {
      base: state,
      added: [],
      removed: [],
      unchanged: honoured,
      escalated: [],
      worstIntroduced: worstAll,
      honoured,
      worstAll,
      incomplete: true,
    };
  }

  // THE suppression property. A `.node9-ignore.json` is committed, so whoever can add a
  // finding can add its suppression in the same commit; applied blindly that PR is green.
  // A suppression that did not exist in the base does not apply to a finding this change
  // introduced or escalated — in EITHER gate. Silencing something costs a separate,
  // reviewable commit. A pre-existing finding suppressed by this change is the legitimate
  // workflow and stays honoured.
  const baseByFp = new Map<string, CiFinding>();
  for (const f of base.findings) baseByFp.set(fingerprintOf(f), f);

  const added: CiFinding[] = [];
  const unchanged: CiFinding[] = [];
  const escalated: EscalatedFinding[] = [];
  const honoured: CiFinding[] = [];
  const matched = new Set<string>();

  for (const raw of head.findings) {
    const fp = fingerprintOf(raw);
    const prior = baseByFp.get(fp);
    // A finding that already existed and got WORSE is guardrail erosion (a deny backstop
    // deleted, a mitigation removed). It is not new, and calling it "unchanged" would let
    // the removal merge silently — so it is its own class, and it counts as introduced.
    const isEscalation = !!prior && SEVERITY_RANK[raw.severity] > SEVERITY_RANK[prior.severity];
    // THE honour rule (review H.2–H.4, 2026-09-27): a head finding keeps its suppression only
    // if the SAME finding existed in the base, no worse, with the same evidence. That keeps
    // the legitimate workflow — a change that only suppresses an unchanged pre-existing
    // finding — and refuses: a new finding (even under a wide base entry), an escalation of
    // an accepted finding, and a suppressed finding whose content was swapped.
    const why = !raw.suppressed
      ? null
      : !prior
        ? NOT_HONOURED_NEW
        : isEscalation
          ? notHonouredEscalated(prior.severity)
          : !sameEvidence(raw, prior)
            ? NOT_HONOURED_EVIDENCE
            : null;
    const f = why ? unhonour(raw, why) : raw;
    honoured.push(f);
    if (!prior) {
      added.push(f);
      continue;
    }
    matched.add(fp);
    if (isEscalation) escalated.push({ finding: f, from: prior.severity, to: f.severity });
    // Equal, or IMPROVED. A de-escalation is a fix in progress, never an introduction.
    else unchanged.push(f);
  }

  const removed = base.findings.filter((f) => !matched.has(fingerprintOf(f)));

  return {
    base: state,
    added,
    removed,
    unchanged,
    escalated,
    worstIntroduced: worstUnsuppressed([...added, ...escalated.map((e) => e.finding)]),
    honoured,
    worstAll: worstUnsuppressed(honoured),
    // The head side of the same guard: a scan that could not read every file has not
    // earned the word "clean", however trustworthy the base was.
    incomplete: head.incomplete,
  };
}
