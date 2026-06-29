// Managed-config (MDM M2) apply helpers — the baseline+lock merge model.
//
// The dashboard sets a managed value; the proxy applies it as a FLOOR that a
// developer can only make stricter locally — unless an admin locked the field,
// in which case the cloud value wins outright. A managed value never makes a
// machine *weaker* than the developer chose (that's the whole point: gate, not
// cage). shadowMode/panicMode remain absolute overrides applied above this.

// `mode` strictness, weakest → strictest. observe/audit only log; standard and
// strict actually enforce (strict being the most aggressive).
export const MODE_ORDER = ['observe', 'audit', 'standard', 'strict'] as const;

/** Strictness rank of a mode (higher = stricter). -1 for an unknown value. */
export function modeRank(mode: string): number {
  return MODE_ORDER.indexOf(mode as (typeof MODE_ORDER)[number]);
}

/**
 * Resolve the effective `mode` given the local value, the cloud-managed floor,
 * and whether the admin locked it.
 *  - locked  → cloud wins outright.
 *  - else    → keep local only if it's STRICTER than the cloud floor; otherwise
 *              raise it to the floor.
 * An unknown/unrankable cloud value is ignored (returns local) so a bad managed
 * value can never weaken or break enforcement.
 */
export function resolveManagedMode(local: string, cloud: string, locked: boolean): string {
  if (modeRank(cloud) === -1) return local; // never apply junk
  if (locked) return cloud;
  return modeRank(local) > modeRank(cloud) ? local : cloud;
}
