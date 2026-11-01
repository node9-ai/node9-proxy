// src/protection.ts
//
// Neutral home for the snapshot shapes the TUI dashboard (monitor) reads:
// the blast facts (reachable paths, env findings) and the posture score.
//
// Until fw#421 this module also held the "exposure × protection" math
// (`computeProtection`: the blast score discounted by active shields). That
// was a third machine score beside blast and posture; the posture score is
// now the one number every surface shows, so the math is gone and the blast
// snapshot carries facts only.
//
// Pure module: no fs, no network, no React/Ink imports. Safe to import
// from any layer.

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface BlastPathInfo {
  /** Short, display-ready path label (e.g. "~/.ssh/id_rsa"). */
  label: string;
  /** Human description from blast.ts (e.g. "RSA private key — SSH server access").
   *  Empty string if unavailable. */
  description: string;
}

export interface BlastSnapshot {
  /** Top reachable sensitive paths. The Risk panel uses .length only;
   *  the Report [2] BlastRadius panel renders label + description per row. */
  paths: BlastPathInfo[];
  envFindings: number;
}

/** Shield-config snapshot — names of shields registered (builtin + user)
 *  vs the names actually active in ~/.node9/shields.json. */
export interface ShieldStatus {
  active: string[];
  inactive: string[];
}

/** Shields that stop reads of the files blast lists (today: project-jail).
 *  Scan's SHIELDS panel ranks these first and recommends the first one that
 *  is off; no score arithmetic hangs off this any more. */
export const PROTECTIVE_SHIELDS: ReadonlySet<string> = new Set(['project-jail']);

export function isProtectiveShield(name: string): boolean {
  return PROTECTIVE_SHIELDS.has(name);
}

/** The posture score as the monitor shows it: the same number `node9
 *  posture` prints, with its first action and the hardening headroom. */
export interface PostureSnapshot {
  score: number;
  tier: 'good' | 'at-risk' | 'critical';
  /** The headline's "do this first", or null when the scorecard is clean. */
  action: string | null;
  /** Σ scoreWeight of open hardening findings: points the user can close. */
  headroom: number;
  /** ms epoch of the run. */
  at: number;
}
