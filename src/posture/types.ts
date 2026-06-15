// src/posture/types.ts
// Shared types for `node9 posture` — the agent-security scorecard.
//
// A check is a function `(ctx) => Finding[]` (sync or async). It is read-only
// or classification-only: it never executes a payload, never mutates state,
// and never emits a secret value (only the secret *type* + location).

export type Severity = 'critical' | 'high' | 'medium' | 'advisory';

export interface Finding {
  /** Scorecard row this finding belongs to, e.g. 'Secrets'. */
  category: string;
  severity: Severity;
  /** One-line headline, e.g. '3 plaintext secrets on disk'. */
  title: string;
  /** Specifics — secret *types* + locations, never values. */
  detail: string[];
  /** The enforcement bridge: what node9 can do about it (the free→paid hook). */
  fix?: string;
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
  score: number;
  tier: 'good' | 'at-risk' | 'critical';
  /** Number of checks evaluated — the score denominator. */
  checksRun: number;
}
