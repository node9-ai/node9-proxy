// src/config/v2.ts
// The v2 config file: the shape `node9 checks` prints, keyed by catalog ids.
//
//   { "version": "2", "mode", "checks", "tuning", "approvals", "rules",
//     "tools", "device", "environments" }
//
// This module is pure: it translates between the v2 file and the legacy file
// shape the loader has always merged (settings / policy / environments), both
// ways, and strips values that equal the shipped defaults. The loader reads a
// v2 file by translating it to legacy first, so every consumer of the merged
// Config keeps working while the engine learns to read `policy.checks`
// directly. Design: "Controls catalog", section "Phase 2".

import {
  CHECK_BY_ID,
  CHECK_VERDICT_RANK,
  isVerdict,
  isLockedCheck,
  checksFromLegacyPolicy,
  checkToLegacyPolicy,
  tuningFromLegacyPolicy,
  tuningToLegacyPolicy,
  configurableValues,
  isKnobGoverned,
  CONFIGURABLE_CHECK_IDS,
  TUNING_FIELDS,
  type Verdict,
  type CheckDef,
} from '@node9/policy-engine';

export { configurableValues } from '@node9/policy-engine';
import type { z } from 'zod';
import type { ConfigFileSchema } from '../config-schema';
import { DEFAULT_CONFIG, type SmartRule } from './index';

export type LegacyFile = z.infer<typeof ConfigFileSchema>;
type LegacySettings = NonNullable<LegacyFile['settings']>;
type LegacyPolicy = NonNullable<LegacyFile['policy']>;

export const CONFIG_FILE_VERSION_2 = '2';

export interface ConfigFileV2 {
  version: '2';
  mode?: 'standard' | 'strict' | 'audit' | 'observe';
  /** Catalog id → value. Only what departs from the default is written. */
  checks?: Record<string, Verdict>;
  /** Catalog id → that check's settings (lists, thresholds). */
  tuning?: Record<string, Record<string, unknown>>;
  approvals?: {
    channels?: string[];
    timeoutSeconds?: number;
    reviewPrompt?: 'inline' | 'approver';
  };
  /** The user's own smart rules, unchanged from the legacy shape. */
  rules?: SmartRule[];
  tools?: {
    ignored?: string[];
    inspection?: Record<string, string>;
    sandboxPaths?: string[];
    dangerousWords?: string[];
  };
  /** Operational settings that are not policy: daemon, sync, shipper, debug. */
  device?: Record<string, unknown>;
  environments?: LegacyFile['environments'];
}

export function isV2File(raw: unknown): raw is Record<string, unknown> & { version: '2' } {
  return (
    !!raw &&
    typeof raw === 'object' &&
    !Array.isArray(raw) &&
    // "2" or 2: a hand-written file may use either, and a v2 file mistaken for
    // legacy would fail the loader's major-version check and drop everything.
    String((raw as Record<string, unknown>).version) === CONFIG_FILE_VERSION_2
  );
}

// ── Settings keys that are not policy ────────────────────────────────────────

/** Legacy `settings` keys with a home of their own in v2; everything else
 *  under `settings` is a device setting and passes through unchanged. */
const SETTINGS_WITH_A_HOME = new Set([
  'mode',
  'approvers',
  'approvalTimeoutMs',
  'approvalTimeoutSeconds',
  'reviewChannel',
]);

const APPROVER_CHANNELS = ['native', 'terminal', 'cloud', 'browser'] as const;
type Obj = Record<string, unknown>;

// ── v2 → legacy ──────────────────────────────────────────────────────────────

export interface V2Translation {
  legacy: LegacyFile;
  /**
   * The entries for `policy.checks`: only checks whose detector reads the map
   * (and pack rows). A knob-governed check is carried by its legacy knob
   * instead, so managed floors and the old gates see one value.
   */
  checks: Record<string, Verdict>;
  /** Every check the file stated and was accepted, for `node9 checks` and so
   *  a writer keeps a stated value even when it equals the default. */
  stated: Record<string, Verdict>;
  warnings: string[];
}

export interface V2Options {
  /** A repository file: agent-writable, so it may only tighten. A
   *  knob-governed check below its catalog default is refused. */
  project?: boolean;
}

const KNOWN_V2_KEYS = new Set([
  'version',
  'mode',
  'checks',
  'tuning',
  'approvals',
  'rules',
  'tools',
  'device',
  'environments',
]);

/**
 * Translate a v2 file to the legacy file shape plus the explicit checks map.
 * Unknown ids, values a row does not offer, locked rows and pack rows are
 * reported and dropped; nothing throws, a config file must never break a
 * tool call.
 */
export function v2ToLegacy(raw: Record<string, unknown>, options: V2Options = {}): V2Translation {
  const warnings: string[] = [];
  const v2 = raw as Partial<ConfigFileV2>;
  const settings: Obj = {};
  const policy: Obj = {};
  const checks: Record<string, Verdict> = {};
  const stated: Record<string, Verdict> = {};

  for (const key of Object.keys(raw)) {
    if (KNOWN_V2_KEYS.has(key)) continue;
    warnings.push(
      key === 'packs'
        ? 'packs: not read from the file yet; enable a pack with `node9 shield enable <name>`'
        : `${key}: not a v2 config key; ignored`
    );
  }

  if (typeof v2.mode === 'string') settings.mode = v2.mode;

  for (const [key, value] of Object.entries(v2.device ?? {})) {
    if (SETTINGS_WITH_A_HOME.has(key)) {
      warnings.push(`device.${key} is not a device setting; use its own key`);
      continue;
    }
    settings[key] = value;
  }

  const ap = v2.approvals;
  if (ap) {
    if (Array.isArray(ap.channels)) {
      const approvers: Record<string, boolean> = {};
      for (const ch of APPROVER_CHANNELS) approvers[ch] = ap.channels.includes(ch);
      settings.approvers = approvers;
    }
    if (typeof ap.timeoutSeconds === 'number')
      settings.approvalTimeoutMs = ap.timeoutSeconds * 1000;
    if (ap.reviewPrompt === 'inline') settings.reviewChannel = 'ask';
    else if (ap.reviewPrompt === 'approver') settings.reviewChannel = 'approver';
  }

  if (Array.isArray(v2.rules)) policy.smartRules = v2.rules;
  const tools = v2.tools ?? {};
  if (tools.ignored) policy.ignoredTools = tools.ignored;
  if (tools.inspection) policy.toolInspection = tools.inspection;
  if (tools.sandboxPaths) policy.sandboxPaths = tools.sandboxPaths;
  if (tools.dangerousWords) policy.dangerousWords = tools.dangerousWords;

  for (const [id, value] of Object.entries(v2.checks ?? {})) {
    const def = CHECK_BY_ID.get(id);
    if (!def) {
      warnings.push(`checks.${id}: no such check (see node9 checks)`);
      continue;
    }
    if (!isVerdict(value)) {
      warnings.push(`checks.${id}: "${String(value)}" is not one of off, log, review, block`);
      continue;
    }
    if (isLockedCheck(def)) {
      warnings.push(`checks.${id}: this check is locked and always blocks`);
      continue;
    }
    if (id === 'commands.unknown') {
      warnings.push(`checks.${id}: set "mode": "strict" instead`);
      continue;
    }
    const allowed = configurableValues(id);
    if (allowed.length === 0) {
      warnings.push(`checks.${id}: this check cannot be set from a file yet`);
      continue;
    }
    if (!allowed.includes(value)) {
      warnings.push(`checks.${id}: accepts ${allowed.join(', ')} today; "${value}" ignored`);
      continue;
    }
    const knobGoverned = isKnobGoverned(id);
    if (
      options.project &&
      knobGoverned &&
      CHECK_VERDICT_RANK[value] < CHECK_VERDICT_RANK[def.defaultValue]
    ) {
      warnings.push(`checks.${id}: a project file may only tighten; "${value}" ignored`);
      continue;
    }
    stated[id] = value;
    if (knobGoverned) checkToLegacyPolicy(policy, id, value);
    else checks[id] = value;
  }

  for (const id of Object.keys(v2.tuning ?? {})) {
    if (!CHECK_BY_ID.has(id)) warnings.push(`tuning.${id}: no such check`);
  }
  for (const pair of tuningToLegacyPolicy(policy, v2.tuning ?? {})) {
    const [id] = pair.split('.', 1);
    if (CHECK_BY_ID.has(id)) warnings.push(`tuning.${pair}: no such setting`);
  }

  const legacy: LegacyFile = { version: '1.0' };
  if (Object.keys(settings).length) legacy.settings = settings as LegacySettings;
  if (Object.keys(policy).length) legacy.policy = policy as LegacyPolicy;
  if (v2.environments) legacy.environments = v2.environments;
  return { legacy, checks, stated, warnings };
}

// ── legacy → v2 ──────────────────────────────────────────────────────────────

const TUNING_FIELDS_BY_NAME = new Map(TUNING_FIELDS.map((f) => [`${f.checkId}.${f.name}`, f]));

function sameValue(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

/**
 * Translate a legacy file to v2, keeping only what departs from the shipped
 * defaults. `node9 init` wrote every default to disk as an explicit value;
 * carrying those over would pin each user to today's defaults forever.
 */
export function legacyToV2(
  file: LegacyFile,
  /** Explicit checks a v2 file already stated (a writer round-trips them):
   *  an id a legacy knob also carries takes the knob's value, the rest ride
   *  through unchanged, since the legacy shape cannot express them. */
  explicitChecks: Readonly<Record<string, Verdict>> = {}
): ConfigFileV2 {
  const out: ConfigFileV2 = { version: '2' };
  const settings = (file.settings ?? {}) as Obj;
  const policy = (file.policy ?? {}) as LegacyPolicy;
  const dSettings = DEFAULT_CONFIG.settings as unknown as Obj;
  const dPolicy = DEFAULT_CONFIG.policy as unknown as Obj;

  if (typeof settings.mode === 'string' && settings.mode !== DEFAULT_CONFIG.settings.mode)
    out.mode = settings.mode as ConfigFileV2['mode'];

  const device: Obj = {};
  for (const [key, value] of Object.entries(settings)) {
    if (SETTINGS_WITH_A_HOME.has(key)) continue;
    if (sameValue(value, dSettings[key])) continue;
    device[key] = value;
  }
  if (Object.keys(device).length) out.device = device;

  const approvals: NonNullable<ConfigFileV2['approvals']> = {};
  const approvers = settings.approvers as Record<string, boolean> | undefined;
  if (approvers) {
    const channels = APPROVER_CHANNELS.filter((ch) => approvers[ch] === true);
    const dChannels = APPROVER_CHANNELS.filter(
      (ch) => (DEFAULT_CONFIG.settings.approvers as Record<string, boolean>)[ch] === true
    );
    if (!sameValue(channels, dChannels)) approvals.channels = channels;
  }
  const timeoutSeconds =
    typeof settings.approvalTimeoutSeconds === 'number'
      ? settings.approvalTimeoutSeconds
      : typeof settings.approvalTimeoutMs === 'number'
        ? settings.approvalTimeoutMs / 1000
        : undefined;
  if (
    timeoutSeconds !== undefined &&
    timeoutSeconds * 1000 !== DEFAULT_CONFIG.settings.approvalTimeoutMs
  )
    approvals.timeoutSeconds = timeoutSeconds;
  if (settings.reviewChannel === 'ask') approvals.reviewPrompt = 'inline';
  else if (settings.reviewChannel === 'approver') approvals.reviewPrompt = 'approver';
  if (Object.keys(approvals).length) out.approvals = approvals;

  const fromKnobs = checksFromLegacyPolicy(
    policy,
    typeof settings.mode === 'string' ? settings.mode : undefined
  );
  delete fromKnobs['commands.unknown']; // carried by `mode`
  const checks: Record<string, Verdict> = { ...explicitChecks, ...fromKnobs };
  const kept: Record<string, Verdict> = {};
  for (const [id, v] of Object.entries(checks)) {
    const def = CHECK_BY_ID.get(id) as CheckDef;
    if (v !== def.defaultValue || explicitChecks[id] === v) kept[id] = v;
  }
  if (Object.keys(kept).length) out.checks = kept;

  const tuning: Record<string, Obj> = {};
  for (const [id, fields] of Object.entries(tuningFromLegacyPolicy(policy))) {
    for (const [name, value] of Object.entries(fields)) {
      const field = TUNING_FIELDS_BY_NAME.get(`${id}.${name}`);
      if (!field) continue;
      const [block, key] = field.legacy;
      if (sameValue(value, (dPolicy[block] as Obj | undefined)?.[key])) continue;
      (tuning[id] ??= {})[name] = value;
    }
  }
  if (Object.keys(tuning).length) out.tuning = tuning;

  // `node9 init` wrote the shipped rules into the file too. A rule that is
  // byte-for-byte a shipped one is not the user's; a same-named rule the user
  // changed is kept (it replaces the shipped one at load, as it always did).
  const shipped = new Map(
    DEFAULT_CONFIG.policy.smartRules.map((r) => [r.name, JSON.stringify(r)] as const)
  );
  const userRules = (policy.smartRules ?? []).filter(
    (r) => !(r.name && shipped.get(r.name) === JSON.stringify(r))
  );
  if (userRules.length) out.rules = userRules as SmartRule[];

  const tools: NonNullable<ConfigFileV2['tools']> = {};
  if (policy.ignoredTools && !sameValue(policy.ignoredTools, dPolicy.ignoredTools))
    tools.ignored = policy.ignoredTools;
  if (policy.toolInspection && !sameValue(policy.toolInspection, dPolicy.toolInspection))
    tools.inspection = policy.toolInspection;
  if (policy.sandboxPaths && !sameValue(policy.sandboxPaths, dPolicy.sandboxPaths))
    tools.sandboxPaths = policy.sandboxPaths;
  if (policy.dangerousWords && !sameValue(policy.dangerousWords, dPolicy.dangerousWords))
    tools.dangerousWords = policy.dangerousWords;
  if (Object.keys(tools).length) out.tools = tools;

  if (file.environments && Object.keys(file.environments).length)
    out.environments = file.environments;
  return out;
}

/** The ids a v2 file can state today. */
export const FILE_CHECK_IDS: readonly string[] = CONFIGURABLE_CHECK_IDS;
