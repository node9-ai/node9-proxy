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
  CHECKS,
  CHECK_BY_ID,
  CHECK_VERDICT_RANK,
  isVerdict,
  isLockedCheck,
  type Verdict,
  type CheckDef,
} from '@node9/policy-engine';
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

// ── Tuning: legacy policy fields that are a check's settings ─────────────────

interface TuningField {
  checkId: string;
  /** Field name in the v2 tuning object. */
  name: string;
  /** Path under legacy `policy`. */
  legacy: [keyof LegacyPolicy, string];
}

const TUNING_FIELDS: TuningField[] = [
  { checkId: 'network.unknown-host', name: 'allow', legacy: ['egress', 'allow'] },
  { checkId: 'network.unknown-host', name: 'deny', legacy: ['egress', 'deny'] },
  { checkId: 'network.unknown-host', name: 'allowPrivate', legacy: ['egress', 'allowPrivate'] },
  { checkId: 'network.internal-addresses', name: 'exemptions', legacy: ['egress', 'ssrfAllow'] },
  { checkId: 'data.secrets', name: 'scanIgnoredTools', legacy: ['dlp', 'scanIgnoredTools'] },
  { checkId: 'behavior.loops', name: 'threshold', legacy: ['loopDetection', 'threshold'] },
  { checkId: 'behavior.loops', name: 'windowSeconds', legacy: ['loopDetection', 'windowSeconds'] },
  {
    checkId: 'behavior.prompt-injection',
    name: 'minConfidence',
    legacy: ['injectionScan', 'minConfidence'],
  },
  { checkId: 'behavior.prompt-injection', name: 'exemptTools', legacy: ['injectionScan', 'allow'] },
  { checkId: 'loading.skill-tamper', name: 'roots', legacy: ['skillPinning', 'roots'] },
  {
    checkId: 'loading.malicious-package',
    name: 'registrySignals',
    legacy: ['packageCheck', 'registrySignals'],
  },
  {
    checkId: 'loading.malicious-package',
    name: 'maxAgeHours',
    legacy: ['packageCheck', 'maxAgeHours'],
  },
  {
    checkId: 'loading.malicious-package',
    name: 'onlineFallback',
    legacy: ['packageCheck', 'onlineFallback'],
  },
  { checkId: 'loading.malicious-package', name: 'allow', legacy: ['packageCheck', 'allow'] },
];

// ── Checks: legacy knobs ↔ catalog ids ───────────────────────────────────────

type Obj = Record<string, unknown>;

/** Read the checks a legacy policy block states explicitly. */
function checksFromLegacy(policy: LegacyPolicy, mode: string | undefined): Record<string, Verdict> {
  const out: Record<string, Verdict> = {};
  const cc = policy.commandChecks ?? {};
  const put = (id: string, v: string | undefined) => {
    if (isVerdict(v)) out[id] = v;
  };
  put('commands.inline-exec', cc.inlineExec);
  put('commands.rm', cc.rmAdvisory);
  put('commands.chmod', cc.chmod);
  put('commands.sql-ddl', cc.sqlDdl);
  put('commands.eval-dynamic', cc.evalDynamic);
  put('data.pipe-chain', cc.pipeChainHigh);

  const dlp = policy.dlp;
  if (dlp?.enabled === false) {
    // The weak-credential row follows: DLP off turns both off.
    out['data.secrets'] = 'off';
  } else {
    if (dlp?.enabled === true) out['data.secrets'] = 'block';
    if (dlp?.reviewAction) out['data.secrets-weak'] = dlp.reviewAction;
  }
  if (dlp?.pii) out['data.pii'] = dlp.pii;

  const eg = policy.egress;
  if (eg?.enabled === false) out['network.unknown-host'] = 'off';
  else if (eg?.enabled === true) out['network.unknown-host'] = eg.mode ?? 'review';
  if (eg?.ssrfStrict !== undefined)
    out['network.internal-addresses'] = eg.ssrfStrict ? 'block' : 'off';

  const loop = policy.loopDetection;
  if (loop?.enabled !== undefined) out['behavior.loops'] = loop.enabled ? 'block' : 'off';

  const inj = policy.injectionScan;
  if (inj?.enabled !== undefined) out['behavior.prompt-injection'] = inj.enabled ? 'log' : 'off';

  const skill = policy.skillPinning;
  if (skill?.enabled === false) out['loading.skill-tamper'] = 'off';
  else if (skill?.enabled === true)
    out['loading.skill-tamper'] = skill.mode === 'block' ? 'block' : 'log';

  const pkg = policy.packageCheck;
  if (pkg?.enabled === false) out['loading.malicious-package'] = 'off';
  else if (pkg?.enabled === true)
    out['loading.malicious-package'] = pkg.onMalicious === 'review' ? 'review' : 'block';

  if (mode === 'strict') out['commands.unknown'] = 'review';
  return out;
}

/**
 * Write one check's value into a legacy policy block. Returns false when the
 * legacy shape cannot carry the value; the caller keeps the value in
 * `policy.checks`, which the engine reads directly, so nothing is lost for a
 * check the engine governs through the map. The legacy knobs only exist for
 * the gates that still read them (DLP, PII, egress, loops, pins, packages).
 */
function checkToLegacy(policy: Obj, id: string, v: Verdict): boolean {
  const obj = (key: string): Obj => {
    if (!policy[key] || typeof policy[key] !== 'object') policy[key] = {};
    return policy[key] as Obj;
  };
  const offOr = (key: string, on: () => void): boolean => {
    if (v === 'off') obj(key).enabled = false;
    else {
      obj(key).enabled = true;
      on();
    }
    return true;
  };
  switch (id) {
    case 'commands.inline-exec':
      if (v === 'log') return false;
      obj('commandChecks').inlineExec = v;
      return true;
    case 'commands.rm':
      if (v === 'log') return false;
      obj('commandChecks').rmAdvisory = v;
      return true;
    case 'commands.chmod':
      if (v === 'log') return false;
      obj('commandChecks').chmod = v;
      return true;
    case 'commands.sql-ddl':
      if (v === 'log') return false;
      obj('commandChecks').sqlDdl = v;
      return true;
    case 'commands.eval-dynamic':
      if (v !== 'review' && v !== 'block') return false;
      obj('commandChecks').evalDynamic = v;
      return true;
    case 'data.pipe-chain':
      if (v !== 'review' && v !== 'block') return false;
      obj('commandChecks').pipeChainHigh = v;
      return true;
    case 'data.secrets':
      if (v === 'off') obj('dlp').enabled = false;
      else if (v === 'block') obj('dlp').enabled = true;
      else return false;
      return true;
    case 'data.secrets-weak':
      if (v !== 'review' && v !== 'block') return false;
      obj('dlp').reviewAction = v;
      return true;
    case 'data.pii':
      if (v !== 'off' && v !== 'block') return false;
      obj('dlp').pii = v;
      return true;
    case 'network.unknown-host':
      if (v === 'log') return false;
      return offOr('egress', () => {
        obj('egress').mode = v;
      });
    case 'network.internal-addresses':
      if (v !== 'off' && v !== 'block') return false;
      obj('egress').ssrfStrict = v === 'block';
      return true;
    case 'behavior.loops':
      if (v !== 'off' && v !== 'block') return false;
      obj('loopDetection').enabled = v === 'block';
      return true;
    case 'behavior.prompt-injection':
      if (v !== 'off' && v !== 'log') return false;
      obj('injectionScan').enabled = v === 'log';
      return true;
    case 'loading.skill-tamper':
      if (v === 'review') return false;
      return offOr('skillPinning', () => {
        obj('skillPinning').mode = v === 'block' ? 'block' : 'warn';
      });
    case 'loading.malicious-package':
      if (v === 'log') return false;
      return offOr('packageCheck', () => {
        obj('packageCheck').onMalicious = v === 'review' ? 'review' : 'block';
      });
    default:
      return false;
  }
}

// ── What a file may set today ────────────────────────────────────────────────

/**
 * Checks whose detector reads the resolved `policy.checks` map: every value
 * the catalog row offers works. Pack rows (`packs.*`) qualify too.
 */
const MAP_GOVERNED = new Set([
  'commands.inline-exec',
  'commands.eval-dynamic',
  'commands.curl-pipe-shell',
  'commands.rm',
  'commands.chmod',
  'commands.sudo',
  'commands.git-destructive',
  'commands.sql-ddl',
  'commands.sql-no-where',
  'commands.temp-binary',
  'commands.disk-destroy',
  'commands.dangerous-word',
  'data.pipe-chain',
]);

/**
 * Checks whose gate still reads a legacy knob (the orchestrator's DLP, PII,
 * egress, loop, pin and package gates): only the values that knob can carry.
 */
const KNOB_GOVERNED: Record<string, readonly Verdict[]> = {
  'data.secrets': ['off', 'block'],
  'data.secrets-weak': ['review', 'block'],
  'data.pii': ['off', 'block'],
  'network.unknown-host': ['off', 'review', 'block'],
  'network.internal-addresses': ['off', 'block'],
  'behavior.loops': ['off', 'block'],
  'behavior.prompt-injection': ['off', 'log'],
  'loading.skill-tamper': ['off', 'log', 'block'],
  'loading.malicious-package': ['off', 'review', 'block'],
};

/**
 * The values a config file may set for a check TODAY. Empty for a check
 * whose detector reads neither the map nor a knob yet (the canary, the
 * credential-file and taint gates, MCP pins, the jail): stating it in a file
 * would change nothing, and `node9 checks` would then report a value that is
 * not in force. Those rows are shown as "not configurable yet".
 */
export function configurableValues(id: string): readonly Verdict[] {
  const def = CHECK_BY_ID.get(id);
  if (!def || isLockedCheck(def) || id === 'commands.unknown') return [];
  if (def.pack || MAP_GOVERNED.has(id)) return def.values;
  return KNOB_GOVERNED[id] ?? [];
}

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
    const knobGoverned = id in KNOB_GOVERNED;
    if (
      options.project &&
      knobGoverned &&
      CHECK_VERDICT_RANK[value] < CHECK_VERDICT_RANK[def.defaultValue]
    ) {
      warnings.push(`checks.${id}: a project file may only tighten; "${value}" ignored`);
      continue;
    }
    stated[id] = value;
    if (knobGoverned) checkToLegacy(policy, id, value);
    else checks[id] = value;
  }

  for (const [id, fields] of Object.entries(v2.tuning ?? {})) {
    if (!CHECK_BY_ID.has(id)) {
      warnings.push(`tuning.${id}: no such check`);
      continue;
    }
    if (!fields || typeof fields !== 'object') continue;
    for (const [name, value] of Object.entries(fields)) {
      const field = TUNING_FIELDS.find((f) => f.checkId === id && f.name === name);
      if (!field) {
        warnings.push(`tuning.${id}.${name}: no such setting`);
        continue;
      }
      const [block, key] = field.legacy;
      if (!policy[block] || typeof policy[block] !== 'object') policy[block] = {};
      (policy[block] as Obj)[key] = value;
    }
  }

  const legacy: LegacyFile = { version: '1.0' };
  if (Object.keys(settings).length) legacy.settings = settings as LegacySettings;
  if (Object.keys(policy).length) legacy.policy = policy as LegacyPolicy;
  if (v2.environments) legacy.environments = v2.environments;
  return { legacy, checks, stated, warnings };
}

// ── legacy → v2 ──────────────────────────────────────────────────────────────

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

  const fromKnobs = checksFromLegacy(
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
  for (const f of TUNING_FIELDS) {
    const [block, key] = f.legacy;
    const value = (policy[block] as Obj | undefined)?.[key];
    if (value === undefined) continue;
    const dValue = (dPolicy[block] as Obj | undefined)?.[key];
    if (sameValue(value, dValue)) continue;
    (tuning[f.checkId] ??= {})[f.name] = value;
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
export const FILE_CHECK_IDS: readonly string[] = CHECKS.filter(
  (c) => configurableValues(c.id).length > 0
).map((c) => c.id);
