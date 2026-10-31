// The bridge between the catalog and the legacy policy knobs.
//
// Some gates still read the legacy shape (`dlp.enabled`, `egress.mode`,
// `loopDetection.enabled`, ...). Until they read the checks map, a check that
// one of those knobs governs is carried BY the knob, both in the proxy's
// config file and in the workspace config the dashboard syncs. This module
// is the one translation table, in both directions, shared by the proxy and
// the dashboard backend so the two can never disagree on what a knob means.

import { CHECKS, CHECK_BY_ID, isVerdict, isLockedCheck, type Verdict } from './catalog';
import { isBlockAll } from './levels';

type Obj = Record<string, unknown>;

/** The legacy policy knobs, loosely typed: a config file, a managed config
 *  row and a merged Config all satisfy it. */
export interface LegacyPolicyKnobs {
  commandChecks?: Record<string, string | undefined>;
  dlp?: { enabled?: boolean; pii?: string; reviewAction?: string; scanIgnoredTools?: boolean };
  egress?: {
    enabled?: boolean;
    mode?: string;
    ssrfStrict?: boolean;
    allow?: string[];
    deny?: string[];
    allowPrivate?: boolean;
    ssrfAllow?: string[];
  };
  loopDetection?: { enabled?: boolean; threshold?: number; windowSeconds?: number };
  injectionScan?: { enabled?: boolean; minConfidence?: string; allow?: string[] };
  skillPinning?: { enabled?: boolean; mode?: string; roots?: string[] };
  packageCheck?: {
    enabled?: boolean;
    onMalicious?: string;
    /** 2.27.0: one boolean for both signals. Read, never written. */
    registrySignals?: boolean;
    newPackage?: string;
    installScript?: string;
    maxAgeHours?: number;
    onlineFallback?: boolean;
    allow?: string[];
  };
  untrustedContent?: {
    enabled?: boolean;
    spotlight?: boolean;
    afterExposure?: string;
    orgDomains?: string[];
  };
}

// ── Tuning: legacy policy fields that are a check's settings ─────────────────

export interface TuningField {
  checkId: string;
  /** Field name in the v2 tuning object. */
  name: string;
  /** Path under the legacy policy block. */
  legacy: readonly [block: string, key: string];
}

export const TUNING_FIELDS: readonly TuningField[] = [
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
    name: 'newPackage',
    legacy: ['packageCheck', 'newPackage'],
  },
  {
    checkId: 'loading.malicious-package',
    name: 'maxAgeHours',
    legacy: ['packageCheck', 'maxAgeHours'],
  },
  {
    checkId: 'loading.malicious-package',
    name: 'installScript',
    legacy: ['packageCheck', 'installScript'],
  },
  {
    checkId: 'loading.malicious-package',
    name: 'onlineFallback',
    legacy: ['packageCheck', 'onlineFallback'],
  },
  { checkId: 'loading.malicious-package', name: 'allow', legacy: ['packageCheck', 'allow'] },
  // fw#318: the verdict carries off / log (log-only) / review; the tuning
  // carries whether a review asks once per destination or every time, the
  // frame around outside content, and the organisation's own domains.
  {
    checkId: 'behavior.untrusted-content',
    name: 'afterExposure',
    legacy: ['untrustedContent', 'afterExposure'],
  },
  {
    checkId: 'behavior.untrusted-content',
    name: 'spotlight',
    legacy: ['untrustedContent', 'spotlight'],
  },
  {
    checkId: 'behavior.untrusted-content',
    name: 'orgDomains',
    legacy: ['untrustedContent', 'orgDomains'],
  },
];

/** Every tuning field a legacy policy block states, as `{ checkId: { name: value } }`. */
export function tuningFromLegacyPolicy(policy: LegacyPolicyKnobs): Record<string, Obj> {
  const out: Record<string, Obj> = {};
  const p = policy as Obj;
  // The 2.27.0 `registrySignals: false` reads as both new fields off, unless
  // the block states them itself (the loop below then overwrites).
  if (policy.packageCheck?.registrySignals === false) {
    out['loading.malicious-package'] = { newPackage: 'off', installScript: 'off' };
  }
  for (const f of TUNING_FIELDS) {
    const [block, key] = f.legacy;
    const value = (p[block] as Obj | undefined)?.[key];
    if (value === undefined) continue;
    (out[f.checkId] ??= {})[f.name] = value;
  }
  return out;
}

/** Write a tuning map into a legacy policy block. Returns the unknown
 *  `checkId.name` pairs it could not place. */
export function tuningToLegacyPolicy(policy: Obj, tuning: Record<string, unknown>): string[] {
  const unknown: string[] = [];
  for (const [id, fields] of Object.entries(tuning)) {
    if (!fields || typeof fields !== 'object') continue;
    const normalized = { ...(fields as Obj) };
    if (id === 'loading.malicious-package') {
      if (normalized.registrySignals === false) {
        normalized.newPackage ??= 'off';
        normalized.installScript ??= 'off';
      }
      delete normalized.registrySignals;
    }
    for (const [name, value] of Object.entries(normalized)) {
      const field = TUNING_FIELDS.find((f) => f.checkId === id && f.name === name);
      if (!field) {
        unknown.push(`${id}.${name}`);
        continue;
      }
      const [block, key] = field.legacy;
      if (!policy[block] || typeof policy[block] !== 'object') policy[block] = {};
      (policy[block] as Obj)[key] = value;
    }
  }
  return unknown;
}

// ── Checks: legacy knobs ↔ catalog ids ───────────────────────────────────────

/** Read the checks a legacy policy block states explicitly. */
export function checksFromLegacyPolicy(
  policy: LegacyPolicyKnobs,
  mode?: string
): Record<string, Verdict> {
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
    put('data.secrets-weak', dlp?.reviewAction);
  }
  put('data.pii', dlp?.pii);

  const eg = policy.egress;
  if (eg?.enabled === false) out['network.unknown-host'] = 'off';
  else if (eg?.enabled === true)
    out['network.unknown-host'] = isVerdict(eg.mode) ? eg.mode : 'review';
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

  const uc = policy.untrustedContent;
  if (uc?.enabled === false) out['behavior.untrusted-content'] = 'off';
  else if (uc?.enabled === true)
    out['behavior.untrusted-content'] = uc.afterExposure === 'log-only' ? 'log' : 'review';

  if (isBlockAll(mode)) out['commands.unknown'] = 'review';
  return out;
}

/**
 * Write one check's value into a legacy policy block. Returns false when the
 * legacy shape cannot carry the value.
 */
export function checkToLegacyPolicy(policy: Obj, id: string, v: Verdict): boolean {
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
    case 'behavior.untrusted-content':
      if (v !== 'off' && v !== 'log' && v !== 'review') return false;
      return offOr('untrustedContent', () => {
        const uc = obj('untrustedContent');
        // `review` keeps a stated ask-every-time; anything else asks once.
        if (v === 'log') uc.afterExposure = 'log-only';
        else if (uc.afterExposure !== 'ask-every-time') uc.afterExposure = 'ask-once';
      });
    default:
      return false;
  }
}

/**
 * The knob-governed checks a legacy policy block STATES: it sets the field
 * that picks the check's value. Presence, not value, decides, so a level
 * (levels.ts) leaves the check alone. A field that turns a check on without
 * choosing between its on values (`dlp.enabled: true` for the weak-credential
 * row, `untrustedContent.enabled: true`) does not pin it: older `node9 init`
 * runs wrote those into every config file.
 */
export function knobStatedChecks(policy: LegacyPolicyKnobs): Set<string> {
  const out = new Set<string>();
  const has = (o: object | undefined, key: string) =>
    !!o && typeof o === 'object' && (o as Obj)[key] !== undefined;
  const { dlp, egress, loopDetection, injectionScan, skillPinning, packageCheck } = policy;
  const uc = policy.untrustedContent;
  if (has(dlp, 'enabled')) out.add('data.secrets');
  if (has(dlp, 'reviewAction') || dlp?.enabled === false) out.add('data.secrets-weak');
  if (has(dlp, 'pii')) out.add('data.pii');
  if (has(egress, 'enabled') || has(egress, 'mode')) out.add('network.unknown-host');
  if (has(egress, 'ssrfStrict')) out.add('network.internal-addresses');
  if (has(loopDetection, 'enabled')) out.add('behavior.loops');
  if (has(injectionScan, 'enabled')) out.add('behavior.prompt-injection');
  if (has(skillPinning, 'enabled') || has(skillPinning, 'mode')) out.add('loading.skill-tamper');
  if (has(packageCheck, 'enabled') || has(packageCheck, 'onMalicious'))
    out.add('loading.malicious-package');
  if (uc && typeof uc === 'object' && (uc.enabled === false || has(uc, 'afterExposure')))
    out.add('behavior.untrusted-content');
  return out;
}

// ── What a file or a workspace may set today ─────────────────────────────────

/**
 * Checks whose detector reads the resolved checks map: every value the
 * catalog row offers works. Pack rows (`packs.*`) qualify too.
 */
export const MAP_GOVERNED: ReadonlySet<string> = new Set([
  'files.shell-startup',
  'files.password-hashes',
  'files.system-dirs',
  'files.agent-instructions',
  'commands.inline-exec',
  'commands.eval-dynamic',
  'commands.curl-pipe-shell',
  'commands.rm',
  'commands.chmod',
  'commands.sudo',
  'commands.git-destructive',
  'commands.git-hooks-bypass',
  'commands.git-stage-all',
  'commands.sql-ddl',
  'commands.sql-no-where',
  'commands.temp-binary',
  'commands.disk-destroy',
  'commands.dangerous-word',
  'commands.node9-disarm',
  'commands.reverse-shell',
  'data.pipe-chain',
  'data.env-exfil',
  'loading.unknown-registry',
  // The general action checks (node9Firewall#390): smart rules the map governs.
  'actions.money',
  'actions.access',
  'actions.publish',
  'actions.settings',
  'actions.protected-branch',
]);

/**
 * Checks whose gate still reads a legacy knob: only the values that knob
 * can carry.
 */
export const KNOB_GOVERNED: Readonly<Record<string, readonly Verdict[]>> = {
  'data.secrets': ['off', 'block'],
  'data.secrets-weak': ['review', 'block'],
  'data.pii': ['off', 'block'],
  'network.unknown-host': ['off', 'review', 'block'],
  'network.internal-addresses': ['off', 'block'],
  'behavior.loops': ['off', 'block'],
  'behavior.prompt-injection': ['off', 'log'],
  'loading.skill-tamper': ['off', 'log', 'block'],
  'loading.malicious-package': ['off', 'review', 'block'],
  'behavior.untrusted-content': ['off', 'log', 'review'],
};

export function isKnobGoverned(id: string): boolean {
  return id in KNOB_GOVERNED;
}

/**
 * The values a config file or a workspace may set for a check TODAY. Empty
 * for a check whose detector reads neither the map nor a knob yet (the
 * canary, the credential-file and taint gates, MCP pins, the jail): stating
 * it would change nothing, and a screen would then show a value that is not
 * in force. Those rows are "not configurable yet".
 */
export function configurableValues(id: string): readonly Verdict[] {
  const def = CHECK_BY_ID.get(id);
  if (!def || isLockedCheck(def) || id === 'commands.unknown') return [];
  if (def.pack || MAP_GOVERNED.has(id)) return def.values;
  return KNOB_GOVERNED[id] ?? [];
}

/** The ids a config file or a workspace can state today. */
export const CONFIGURABLE_CHECK_IDS: readonly string[] = CHECKS.filter(
  (c) => configurableValues(c.id).length > 0
).map((c) => c.id);
