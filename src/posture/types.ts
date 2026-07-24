// src/posture/types.ts
// Shared types for `node9 posture` — the agent-security scorecard.
//
// A check is a function `(ctx) => Finding[]` (sync or async). It is read-only
// or classification-only: it never executes a payload, never mutates state,
// and never emits a secret value (only the secret *type* + location).

export type Severity = 'critical' | 'high' | 'medium' | 'advisory';

/** Whose job it is to fix a finding. `node9` = there's a lever (a command);
 *  `os` = node9 can only detect it, the fix is your OS/infra. */
export type Owner = 'node9' | 'os';

/** node9's relationship to a finding — is it already enforcing a mitigation? */
export type CoverageState = 'covered' | 'partial' | 'open' | 'cant-fix';

export interface Coverage {
  state: CoverageState;
  /** Strength when covered/partial — from the real gate verdict. */
  level?: 'block' | 'review';
  /** What's enforcing it, e.g. 'project-jail shield', 'node9 DLP'. */
  via?: string;
}

/**
 * How a check declares its coverage test, run by `annotateCoverage` at the
 * REAL gating layer (DLP for file reads, policy for commands) — never trusted
 * from a single tier. Internal: not rendered, not shipped.
 */
export type CoverageProbe =
  | { kind: 'fileRead'; paths: string[] } // → scanFilePath (DLP layer)
  | { kind: 'command'; command: string } // → evaluatePolicy (policy layer)
  | { kind: 'egress' } // → config.policy.egress
  | { kind: 'cantFix' }; // → always advisory (OS/infra)

export interface Finding {
  /** Scorecard row this finding belongs to, e.g. 'Secrets'. */
  category: string;
  severity: Severity;
  /** One-line headline, e.g. '3 plaintext secrets on disk'. */
  title: string;
  /** Plain language, shown under the title for OPEN findings (Phase B). */
  what?: string; // what this means, in everyday terms
  why?: string; // why you have it
  who?: string; // what could go wrong / who's affected
  /** Specifics — secret *types* + locations, never values. */
  detail: string[];
  /** Whose job it is to fix this. node9 (a command) or os (your infra).
   *  Unset → treated as 'os' (don't falsely claim node9 can fix it). */
  owner?: Owner;
  /** node9 has an ADJACENT lever that reduces this risk, even though fully
   *  closing it stays the user's job (owner remains 'os'). Renders under the
   *  🔒 "AVAILABLE — turn on to harden" tier — between 🔧 and 🧱. Distinct from
   *  coverage: coverage = in-path enforcement of THIS finding; node9Reduces = a
   *  separate shield/command that shrinks the blast radius (sandbox/project-jail
   *  for isolation, db-shields for an exposed Postgres/Redis). */
  node9Reduces?: boolean;
  /** Points this finding deducts from 100 while OPEN — used ONLY for the
   *  hardening opportunities node9 offers (Isolation, db-shields), which the
   *  severity-bucket score intentionally ignores. Genuine exposures leave this
   *  unset and are scored by severity instead. The number doubles as the "+N"
   *  the AVAILABLE tier shows ("enable this → +N to your score"). */
  scoreWeight?: number;
  /** The flexibility tradeoff of the primary fix, rendered as gain/cost lines
   *  so the security↔flexibility cost is explicit, not just asserted. */
  gain?: string;
  cost?: string;
  /** The enforcement bridge: what node9 can do about it (the free→paid hook). */
  fix?: string;
  /** Set by `annotateCoverage` — node9's enforcement relationship to this finding. */
  coverage?: Coverage;
  /** How to assess coverage for this finding (internal; not shipped — render
   *  may read `kind` for phrasing, e.g. "reads of" on fileRead). */
  coverageProbe?: CoverageProbe;
  /** Internal: this finding is only OPEN because node9 isn't enforcing — the
   *  Coverage check already reports that gap, so drop it when open to avoid
   *  double-surfacing the same root cause. (e.g. egress locked but not wired.) */
  redundantWhenOpen?: boolean;
}

export interface CheckContext {
  /** Home directory to inspect (agent config locations). */
  home: string;
  /** Working directory for config resolution + the gate self-test. */
  cwd: string;
  /** Optional agent name, threaded into the policy evaluation. */
  agent?: string;
}

export interface PostureCheck {
  /** Scorecard row label. */
  category: string;
  run: (ctx: CheckContext) => Finding[] | Promise<Finding[]>;
}

export interface PostureResult {
  agent: string;
  findings: Finding[];
  /** Categories that ran clean (no findings) — shown as ✅ rows. */
  passedCategories: string[];
  /** Categories whose check threw — shown as a muted "could not be checked"
   *  row, excluded from the score so a tool error never skews the verdict. */
  erroredCategories: string[];
  /** The single scariest true story + the one next step, or null when clean. */
  headline: Headline | null;
  score: number;
  tier: 'good' | 'at-risk' | 'critical';
  /** Number of checks evaluated — the score denominator. */
  checksRun: number;
}

export interface Headline {
  /** The attack narrative — the one risk that matters most, in plain English. */
  risk: string;
  /** The single highest-leverage next step (self-contained, names node9 where it can act). */
  action: string;
}
