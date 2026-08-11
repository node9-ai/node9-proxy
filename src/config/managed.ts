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

// The managed-egress fields the proxy applies (M2b + Step 2 lists). `enabled` is
// force-on; `mode` is ordered; `allow` REPLACES the local allowlist (the org owns
// it — a dev can't widen past it); `deny` UNIONS with local (only tightens);
// `allowPrivate` is a floor boolean (managed `false` forces private nets off).
export interface ManagedEgress {
  enabled?: boolean;
  mode?: string;
  allow?: string[];
  deny?: string[];
  allowPrivate?: boolean;
}
/**
 * Apply managed egress to the machine's local egress object (baseline+lock).
 *  - enabled: force-on — locked → cloud value; else `local || cloud` (a managed
 *    `true` turns egress on; a dev can't turn a managed-on egress off).
 *  - mode: resolveByOrder over off<review<block.
 *  - allow: managed list, when non-empty, REPLACES local (org owns the allowlist).
 *  - deny: union of local + managed (always tightens).
 *  - allowPrivate: locked → cloud; else `local && managed` so a managed `false`
 *    forces private access off, while `true` leaves the dev's stricter choice.
 * Generic over the local egress type so the precise caller type is preserved.
 */
export function applyManagedEgress<
  T extends {
    enabled: boolean;
    mode: string;
    allow?: string[];
    deny?: string[];
    allowPrivate?: boolean;
  },
>(local: T, managed: ManagedEgress, locked: string[]): T {
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
  if (Array.isArray(managed.allow) && managed.allow.length > 0) {
    next.allow = [...managed.allow] as T['allow'];
  }
  if (Array.isArray(managed.deny) && managed.deny.length > 0) {
    next.deny = [...new Set([...(local.deny ?? []), ...managed.deny])] as T['deny'];
  }
  if (typeof managed.allowPrivate === 'boolean') {
    next.allowPrivate = (
      locked.includes('egressAllowPrivate')
        ? managed.allowPrivate
        : (local.allowPrivate ?? true) && managed.allowPrivate
    ) as T['allowPrivate'];
  }
  return next;
}

// Managed DLP fields (M2c). `enabled` is force-on; `pii` gates SSN/credit-card in
// tool args (off = detect-only, block = deny in realtime), ordered off<block.
// `reviewAction` (inline-ask v2) upgrades review-severity matches to a hard
// block, ordered review<block — a floor, so a member may tighten but the org's
// 'block' can never be loosened locally.
export const DLP_PII_ORDER = ['off', 'block'] as const;
export const DLP_REVIEW_ACTION_ORDER = ['review', 'block'] as const;
export interface ManagedDlp {
  enabled?: boolean;
  pii?: string;
  reviewAction?: string;
}

/**
 * Apply managed DLP to the machine's local dlp object (baseline+lock), same
 * model as egress: `enabled` force-on, `pii` a floor over off<block,
 * `reviewAction` a floor over review<block. Generic so the precise caller type
 * is preserved; untouched fields (scanIgnoredTools) carry through.
 */
export function applyManagedDlp<
  T extends { enabled: boolean; pii?: string; reviewAction?: string; scanIgnoredTools?: boolean },
>(local: T, managed: ManagedDlp, locked: string[]): T {
  const next: T = { ...local };
  if (typeof managed.enabled === 'boolean') {
    next.enabled = locked.includes('dlpEnabled')
      ? managed.enabled
      : local.enabled || managed.enabled;
  }
  // Task #23: when the org turns DLP ON, a local `scanIgnoredTools:false` must
  // not switch it back off for the whole ignoredTools class (read/grep/glob/ls
  // — the most common agent operations). That is a LOOSENING, and the
  // config-home law lets local config only tighten. The org cannot express this
  // knob at all (ResolvedManagedConfig.dlp carries only enabled/pii/
  // reviewAction), so without this floor the local value always won and the
  // mandate was silently hollow. Measured exposure: secret-in-args for ignored
  // tools; path-based sensitive reads stayed covered by the project-jail shield.
  if (managed.enabled === true) {
    next.scanIgnoredTools = true;
  }
  if (typeof managed.pii === 'string') {
    next.pii = resolveByOrder(
      DLP_PII_ORDER,
      local.pii ?? 'off',
      managed.pii,
      locked.includes('dlpPii')
    ) as T['pii'];
  }
  if (typeof managed.reviewAction === 'string') {
    next.reviewAction = resolveByOrder(
      DLP_REVIEW_ACTION_ORDER,
      local.reviewAction ?? 'review',
      managed.reviewAction,
      locked.includes('dlpReviewAction')
    ) as T['reviewAction'];
  }
  return next;
}

// Command-checks governance (command-checks-governance-spec.md). Every key is
// a floor over off<review<block (member may tighten, the org's value can't be
// loosened locally); per-key lock `commandChecks<Key>` forces the exact value.
// Class-B keys (evalDynamic, pipeChainHigh) are validated upstream to the
// 2-value set — the order still ranks them correctly here.
export const COMMAND_CHECK_ORDER = ['off', 'review', 'block'] as const;
export const COMMAND_CHECK_KEYS = [
  'inlineExec',
  'rmAdvisory',
  'chmod',
  'sqlDdl',
  'evalDynamic',
  'pipeChainHigh',
] as const;
export type CommandCheckKey = (typeof COMMAND_CHECK_KEYS)[number];
export type ManagedCommandChecks = Partial<Record<CommandCheckKey, string>>;

export function applyManagedCommandChecks<T extends Partial<Record<CommandCheckKey, string>>>(
  local: T,
  managed: ManagedCommandChecks,
  locked: string[]
): T {
  const next: T = { ...local };
  for (const key of COMMAND_CHECK_KEYS) {
    const m = managed[key];
    if (typeof m !== 'string') continue;
    const lockKey = `commandChecks${key[0].toUpperCase()}${key.slice(1)}`;
    const localValue = local[key];
    // NO local opinion → the org's value applies verbatim. The floor compares
    // an admin value against a DEV'S CHOICE; treating an absent choice as the
    // default 'review' made the default masquerade as a deliberate local
    // setting, and since off < review the floor silently discarded every
    // admin 'off' (founder QA 2026-07-26: dashboard said off, gate stayed
    // review). Only dlp.pii escaped this because its default is the WEAKEST
    // value, so an absent local could never out-rank the managed one.
    const resolved =
      localValue === undefined
        ? m
        : resolveByOrder(
            COMMAND_CHECK_ORDER as unknown as string[],
            localValue,
            m,
            locked.includes(lockKey)
          );
    // Class-B safety: never store 'off' for tighten-only keys even if a
    // hostile/buggy cloud value slips past upstream validation.
    if ((key === 'evalDynamic' || key === 'pipeChainHigh') && resolved === 'off') continue;
    next[key] = resolved as T[CommandCheckKey];
  }
  return next;
}

// Managed approver surfaces (Preferences v1). The org owns WHERE approvals happen
// (force cloud, forbid terminal self-approve), so a present managed value
// REPLACES the local one per-field.
export interface ManagedApprovers {
  native?: boolean;
  browser?: boolean;
  cloud?: boolean;
  terminal?: boolean;
}
export function applyManagedApprovers<
  T extends { native: boolean; browser: boolean; cloud: boolean; terminal: boolean },
>(local: T, managed: ManagedApprovers): T {
  return {
    ...local,
    native: typeof managed.native === 'boolean' ? managed.native : local.native,
    browser: typeof managed.browser === 'boolean' ? managed.browser : local.browser,
    cloud: typeof managed.cloud === 'boolean' ? managed.cloud : local.cloud,
    terminal: typeof managed.terminal === 'boolean' ? managed.terminal : local.terminal,
  };
}
