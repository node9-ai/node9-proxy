// Managed-config (MDM M2) apply helpers — the baseline+lock merge model.
//
// The dashboard sets a managed value; the proxy applies it as a FLOOR that a
// developer can only make stricter locally — unless an admin locked the field,
// in which case the cloud value wins outright. A managed value never makes a
// machine *weaker* than the developer chose (that's the whole point: gate, not
// cage). shadowMode/panicMode remain absolute overrides applied above this.

// Strictness orderings, weakest → strictest.
// mode: observe/audit only log; standard/strict enforce (strict most aggressive).
export const MODE_ORDER = ['observe', 'audit', 'standard', 'strict'] as const;
// egress mode: the verdict for an unknown host. off = no gate, block = strictest.
export const EGRESS_MODE_ORDER = ['off', 'review', 'block'] as const;

/** Rank of a value within an order (higher = stricter). -1 if unknown. */
function rankIn(order: readonly string[], value: string): number {
  return order.indexOf(value);
}

/**
 * Baseline+lock for an ORDERED enum (mode, egress.mode):
 *  - locked → cloud wins outright.
 *  - else   → keep local only if STRICTER than the cloud floor; otherwise raise.
 * An unrankable cloud value is ignored (returns local) so junk never weakens or
 * breaks enforcement.
 */
export function resolveByOrder(
  order: readonly string[],
  local: string,
  cloud: string,
  locked: boolean
): string {
  if (rankIn(order, cloud) === -1) return local; // never apply junk
  if (locked) return cloud;
  return rankIn(order, local) > rankIn(order, cloud) ? local : cloud;
}

/** Strictness rank of a mode (kept for callers/tests). -1 for unknown. */
export function modeRank(mode: string): number {
  return rankIn(MODE_ORDER, mode);
}

/** Resolve the effective `mode` (baseline+lock). */
export function resolveManagedMode(local: string, cloud: string, locked: boolean): string {
  return resolveByOrder(MODE_ORDER, local, cloud, locked);
}

// The managed-egress fields the proxy applies (M2b). `enabled` is force-on only
// (false is the weakest, so it's never a meaningful floor); `mode` is ordered.
// The allowlist is intentionally NOT managed here — it LOOSENS access (adds
// reachable hosts), which doesn't fit "baseline = only tighten"; deferred.
export interface ManagedEgress {
  enabled?: boolean;
  mode?: string;
}
/**
 * Apply managed egress to the machine's local egress object (baseline+lock).
 *  - enabled: force-on — locked → cloud value; else `local || cloud` (a managed
 *    `true` turns egress on; a dev can't turn a managed-on egress off).
 *  - mode: resolveByOrder over off<review<block.
 * Generic over the local egress type so the precise caller type is preserved.
 * Returns a NEW object; untouched local fields (allow/deny/allowPrivate) carry
 * through unchanged.
 */
export function applyManagedEgress<T extends { enabled: boolean; mode: string }>(
  local: T,
  managed: ManagedEgress,
  locked: string[]
): T {
  const next: T = { ...local };
  if (typeof managed.enabled === 'boolean') {
    next.enabled = locked.includes('egressEnabled')
      ? managed.enabled
      : local.enabled || managed.enabled;
  }
  if (typeof managed.mode === 'string') {
    next.mode = resolveByOrder(
      EGRESS_MODE_ORDER,
      local.mode,
      managed.mode,
      locked.includes('egressMode')
    ) as T['mode'];
  }
  return next;
}

// Managed DLP fields (M2c). `enabled` is force-on; `pii` gates SSN/credit-card in
// tool args (off = detect-only, block = deny in realtime), ordered off<block.
export const DLP_PII_ORDER = ['off', 'block'] as const;
export interface ManagedDlp {
  enabled?: boolean;
  pii?: string;
}

/**
 * Apply managed DLP to the machine's local dlp object (baseline+lock), same
 * model as egress: `enabled` force-on, `pii` a floor over off<block. Generic so
 * the precise caller type is preserved; untouched fields (scanIgnoredTools)
 * carry through.
 */
export function applyManagedDlp<T extends { enabled: boolean; pii?: string }>(
  local: T,
  managed: ManagedDlp,
  locked: string[]
): T {
  const next: T = { ...local };
  if (typeof managed.enabled === 'boolean') {
    next.enabled = locked.includes('dlpEnabled')
      ? managed.enabled
      : local.enabled || managed.enabled;
  }
  if (typeof managed.pii === 'string') {
    next.pii = resolveByOrder(
      DLP_PII_ORDER,
      local.pii ?? 'off',
      managed.pii,
      locked.includes('dlpPii')
    ) as T['pii'];
  }
  return next;
}
