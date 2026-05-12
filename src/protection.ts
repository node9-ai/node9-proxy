// src/protection.ts
//
// Neutral home for the "exposure × protection" math used by both the
// TUI dashboard (monitor) and the CLI scan command.
//
// Lifted out of src/tui/dashboard/{types,data}.ts on 2026-05-12 so that
// the CLI scan renderer can compute "+N pts if you enable project-jail"
// without taking a layering inversion through tui/dashboard/*. The old
// locations re-export from here so existing monitor imports keep
// working without any call-site churn.
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
  /** Points deducted from the security score for this path being readable. */
  score: number;
}

export interface BlastSnapshot {
  score: number;
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

/** Composite "what's my real risk" summary — combines blast exposure
 *  (static FS reachability) with shield protection (runtime defense)
 *  into a single effective score, plus the most useful action the
 *  user could take to improve it. Pure function over BlastSnapshot
 *  and ShieldStatus — see computeProtection below. */
export interface ProtectionSummary {
  /** Points deducted from the perfect 100 by blast findings. Always
   *  >= 0; equals (100 - blast.score). */
  exposed: number;
  /** Points given back by active protective shields. Always >= 0;
   *  capped at `exposed` so effective never exceeds 100. */
  protect: number;
  /** Final score the user sees in the RISK box. exposed - protect
   *  flipped to score-out-of-100. */
  effective: number;
  /** Inactive protective shield whose enablement would give the
   *  biggest bonus. Null when no protective shield is inactive or
   *  when effective is already maxed. */
  suggestedShield: string | null;
  /** Bonus the suggested shield would add, in score points (0-100). */
  suggestedBonus: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Per-shield discount fraction applied to blast deductions when the
 *  shield is active. Discounts overlap (multiple protective shields
 *  on isn't additive) so computeProtection() uses the *max* of active
 *  discounts, not a sum. Names match the SHIELDS registry exactly.
 *
 *  Current entries:
 *  - project-jail: blocks reads of `.ssh/`, `.aws/`, `.env`,
 *    `credentials.json`, `.netrc`, `.npmrc`, `.docker/config.json`,
 *    `gcloud/credentials`, `.kube/config`. Two rule families:
 *    (a) bash-tool rules matching on `command` (cat / less / vim / etc.)
 *    (b) tool=* rules matching on `file_path` (Read / Edit / Write /
 *    MultiEdit / future MCP file tools).
 *    0.7 reflects "covers bash AND tool-mediated reads"; the
 *    remaining 30% is symlink dodge, dynamic-path construction,
 *    Glob enumeration, and tools using non-`file_path` arg names.
 *
 *  NOT in this table (and why):
 *  - filesystem (builtin shield): reviews chmod 777 and writes to
 *    /etc/. Destructive-write protection, NOT blast-path defense.
 *    Removed from this table on 2026-05-12 — was a dead typo entry
 *    (`filesystem-jail`) that never matched anyway.
 *  - dlp / bash-safe / block-rm-rf / aws / docker / github / postgres
 *    / mongodb / redis / k8s: defend different risk surfaces (live
 *    findings, destructive ops, domain-specific concerns), don't
 *    reduce static blast-path exposure. */
export const PROTECTIVE_SHIELD_DISCOUNTS: Readonly<Record<string, number>> = {
  'project-jail': 0.7,
};

// ---------------------------------------------------------------------------
// computeProtection
// ---------------------------------------------------------------------------

/**
 * Pure function: combine blast exposure with active-shield protection
 * into a single effective score plus an actionable suggestion. Drives
 * the RISK box in the idle Notification slot, the secure / at-risk
 * threshold in the header health badge, and (soon) the SHIELDS
 * recommendation panel in `node9 scan` default view.
 *
 * Math:
 *   exposed   = 100 - blast.score  (points lost to reachable paths)
 *   protect   = round(exposed × max-discount-of-active-protective-shields)
 *   effective = clamp(100 - exposed + protect, 0, 100)
 *
 * The discount uses MAX (not sum) across active protective shields
 * because the jails overlap — multiple read-blockers active isn't
 * meaningfully more protection than just the broadest one. v2 may
 * add finer per-path attribution if shields start carving disjoint
 * coverage areas.
 *
 * `suggestedShield` is the highest-value INACTIVE protective shield;
 * suggestedBonus is the protection points that enabling it would add.
 * Null when nothing's left to enable or effective is already maxed.
 */
export function computeProtection(
  blast: BlastSnapshot | null,
  shieldStatus: ShieldStatus | null
): ProtectionSummary {
  const score = blast?.score ?? 100;
  const exposed = Math.max(0, 100 - score);
  const active = shieldStatus?.active ?? [];
  const inactive = shieldStatus?.inactive ?? [];
  // Use MAX of active shield discounts — overlapping protections
  // (multiple read-blockers covering the same paths) don't double
  // the defense; the broader shield already covers what the narrower
  // one does. Today there's only one entry (`project-jail` at 0.7)
  // so the reduce trivially returns it when active. When additional
  // protective shields land, the max-of-discounts logic earns its keep.
  const activeDiscount = active.reduce((max, name) => {
    const d = PROTECTIVE_SHIELD_DISCOUNTS[name] ?? 0;
    return d > max ? d : max;
  }, 0);
  const protect = Math.round(exposed * activeDiscount);
  const effective = Math.max(0, Math.min(100, 100 - exposed + protect));

  // Suggest the inactive shield whose discount-DELTA over the current
  // best gives the biggest bonus. With one protective shield in the
  // map today, this either suggests project-jail (when inactive and
  // exposed > 0) or returns null. After additional protective shields
  // ship, this picks the highest-value upgrade from the user's
  // current state.
  let suggestedShield: string | null = null;
  let suggestedBonus = 0;
  if (exposed > 0) {
    for (const name of inactive) {
      const d = PROTECTIVE_SHIELD_DISCOUNTS[name] ?? 0;
      const delta = d - activeDiscount;
      if (delta > 0) {
        const bonus = Math.round(exposed * delta);
        if (bonus > suggestedBonus) {
          suggestedShield = name;
          suggestedBonus = bonus;
        }
      }
    }
  }
  return { exposed, protect, effective, suggestedShield, suggestedBonus };
}
