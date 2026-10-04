// ONE list of everything node9 checks.
//
// Every verdict the engine or the host returns that is not `allow` names a
// check from this list by `checkId`. The dashboard screen, the local config
// file, `node9 checks` and the per-check audit counts are derived from here;
// nothing about a check is declared twice.
//
// Phase 1 (this file): the catalog, a resolver that reads TODAY's config shape
// (commandChecks, dlp, egress, mode, ...) and a translation table from the rule
// names and labels the code emits today. No behaviour changes: the resolver
// answers what the existing knobs already say, and `checkIdForRule` lets the
// audit log and the explain trace name the check without touching detectors
// that still emit a legacy label.
//
// Design: "Controls catalog: design and architecture" (2026-10-03).

import { BUILTIN_SHIELDS } from './shields';
import { isStrictGatedTier, type SsrfTier } from './egress/ssrf';
import { CHECK_TEXT } from './catalog-text';

// ── Vocabulary ────────────────────────────────────────────────────────────────

/** The one value set every check uses. `log` runs the check and records the
 *  finding without stopping the call; it replaces skill pinning's `warn` and
 *  the per-check meaning of the global observe mode. */
export type Verdict = 'off' | 'log' | 'review' | 'block';

export const VERDICTS: readonly Verdict[] = ['off', 'log', 'review', 'block'];

export const CHECK_VERDICT_RANK: Record<Verdict, number> = { off: 0, log: 1, review: 2, block: 3 };

export function isVerdict(v: unknown): v is Verdict {
  return v === 'off' || v === 'log' || v === 'review' || v === 'block';
}

/** Groups are by what the user fears, not by the mechanism that catches it. */
export type CheckGroup = 'commands' | 'data' | 'network' | 'files' | 'behavior' | 'loading';

export const CHECK_GROUPS: readonly { id: CheckGroup; title: string }[] = [
  { id: 'commands', title: 'Commands' },
  { id: 'data', title: 'Secrets and data' },
  { id: 'network', title: 'Network' },
  { id: 'files', title: 'Files' },
  { id: 'behavior', title: 'Agent behavior' },
  { id: 'loading', title: 'What the agent loads' },
];

export interface CheckDef {
  /** `group.name`, stable forever: audit rows and config files key on it. */
  id: string;
  group: CheckGroup;
  title: string;
  /** One line, shown under the title: what the check catches. */
  catches: string;
  /** What a user may pick, in order. */
  values: readonly Verdict[];
  defaultValue: Verdict;
  /** Lowest value a user may pick. `block` means the check is locked. */
  floor?: Verdict;
  /** Set on a row a pack (a builtin shield) contributes; the row only exists
   *  while that pack is on. */
  pack?: string;
  /** Rule names and labels the code emits today for this check. Exact
   *  matches only; prefixed families are handled in `checkIdForRule`. */
  legacy?: readonly string[];
  /** Plain-language explanation (catalog-text.ts). */
  plain?: string;
  /** One concrete thing an agent might do that this check catches. */
  example?: string;
  /** When to change the default, and to what. */
  advice?: string;
}

const ALL: readonly Verdict[] = VERDICTS;

/** Words in the product's own dangerous-word list. Shields add their own. */
export const BUILTIN_DANGEROUS_WORDS: readonly string[] = ['mkfs', 'shred'];

// ── The catalog ───────────────────────────────────────────────────────────────
//
// Defaults are what the shipped code does today, so wiring the catalog in
// changes no verdict. Three checks are locked (`floor: 'block'`): each is a
// complete compromise if an agent that can edit the config turns it off, and
// none produces false positives.

const PRODUCT_CHECKS: readonly CheckDef[] = [
  // ── Commands ────────────────────────────────────────────────────────────
  {
    id: 'commands.inline-exec',
    group: 'commands',
    title: 'Inline code execution',
    catches: 'node -e, python -c, bash -c, a heredoc into an interpreter',
    values: ALL,
    defaultValue: 'review',
    legacy: ['Node9 Standard (Inline Execution)'],
  },
  {
    id: 'commands.eval-dynamic',
    group: 'commands',
    title: 'Eval of dynamic content',
    catches: 'a variable or a subshell inside eval or a -c payload',
    values: ALL,
    defaultValue: 'review',
    legacy: ['Node9: Eval Dynamic Content'],
  },
  {
    id: 'commands.eval-remote',
    group: 'commands',
    title: 'Eval of a remote download',
    catches: 'eval or sh over the output of curl or wget',
    values: ['block'],
    defaultValue: 'block',
    floor: 'block',
    legacy: ['Node9: Eval Remote Execution'],
  },
  {
    id: 'commands.curl-pipe-shell',
    group: 'commands',
    title: 'Remote script piped into a shell',
    catches: 'curl or wget piped into sh, bash, zsh or PowerShell',
    values: ALL,
    defaultValue: 'block',
    legacy: ['review-curl-pipe-shell'],
  },
  {
    id: 'commands.rm',
    group: 'commands',
    title: 'Delete files',
    catches: 'rm outside the known build-artifact paths',
    values: ALL,
    defaultValue: 'review',
    legacy: ['review-rm', 'allow-rm-safe-paths'],
  },
  {
    id: 'commands.rm-home',
    group: 'commands',
    title: 'Recursive delete of the home directory',
    catches: 'rm -rf on ~, $HOME, /home or /',
    values: ['block'],
    defaultValue: 'block',
    floor: 'block',
    legacy: ['block-rm-rf-home'],
  },
  {
    id: 'commands.chmod',
    group: 'commands',
    title: 'World-writable permissions',
    catches: 'chmod 777, 0777 or a+rwx',
    values: ALL,
    defaultValue: 'review',
    legacy: ['shield:filesystem:review-chmod-777'],
  },
  {
    id: 'commands.sudo',
    group: 'commands',
    title: 'Elevated privileges',
    catches: 'a command run through sudo',
    values: ALL,
    defaultValue: 'review',
    legacy: ['review-sudo'],
  },
  {
    id: 'commands.git-destructive',
    group: 'commands',
    title: 'Destructive git operation',
    catches: 'force push, reset --hard, clean, rebase, branch or tag delete',
    values: ALL,
    defaultValue: 'review',
    legacy: ['review-force-push', 'review-git-destructive'],
  },
  {
    id: 'commands.sql-ddl',
    group: 'commands',
    title: 'Drop or truncate',
    catches: 'DROP or TRUNCATE through a database CLI or a database tool',
    values: ALL,
    defaultValue: 'review',
    legacy: [
      'review-drop-truncate-shell',
      'review-drop-table-sql',
      'review-truncate-sql',
      'review-drop-column-sql',
    ],
  },
  {
    id: 'commands.sql-no-where',
    group: 'commands',
    title: 'Unscoped SQL mutation',
    catches: 'DELETE or UPDATE without a WHERE clause',
    values: ALL,
    defaultValue: 'review',
    legacy: ['no-delete-without-where'],
  },
  {
    id: 'commands.temp-binary',
    group: 'commands',
    title: 'Binary from a temp directory',
    catches: 'an absolute path under /tmp, /var/tmp, /dev/shm or a world-writable file',
    values: ALL,
    defaultValue: 'review',
    legacy: ['Node9: Suspect Binary', 'Node9: Unknown Binary (strict mode)'],
  },
  {
    id: 'commands.disk-destroy',
    group: 'commands',
    title: 'Disk or filesystem destruction',
    catches: 'mkfs, shred, dd and the manual-terminal disaster list',
    values: ALL,
    defaultValue: 'review',
    legacy: ['Manual Nuclear Protection'],
  },
  {
    id: 'commands.dangerous-word',
    group: 'commands',
    title: 'Dangerous word',
    catches: 'a word from a pack or from the config dangerousWords list',
    values: ALL,
    defaultValue: 'review',
  },
  {
    id: 'commands.unanalysable',
    group: 'commands',
    title: 'Command too nested to analyse',
    catches: 'wrappers nested past the depth the shell parser follows',
    values: ALL,
    defaultValue: 'review',
    legacy: ['review-unanalysable-nesting'],
  },
  {
    id: 'commands.unknown',
    group: 'commands',
    title: 'Any command no check recognised',
    catches: 'the strict-mode catch-all',
    values: ['off', 'review'],
    defaultValue: 'off',
    legacy: ['Global Config (Strict Mode Active)'],
  },

  // ── Secrets and data ────────────────────────────────────────────────────
  {
    id: 'data.secrets',
    group: 'data',
    title: 'Secret in arguments',
    catches: 'an API key, token or private key matching one of the DLP patterns',
    values: ALL,
    defaultValue: 'block',
    legacy: ['🚨 Node9 DLP (Secret Detected)'],
  },
  {
    id: 'data.secrets-weak',
    group: 'data',
    title: 'Weak credential in arguments',
    catches: 'a JWT or a bearer token',
    values: ALL,
    defaultValue: 'review',
    legacy: ['🚨 Node9 DLP (Credential Review)'],
  },
  {
    id: 'data.pii',
    group: 'data',
    title: 'Personal data in arguments',
    catches: 'a social security number or a credit card number',
    values: ALL,
    defaultValue: 'block',
    legacy: ['🔒 Node9 PII (Detected)'],
  },
  {
    id: 'data.credential-files',
    group: 'data',
    title: 'Credential file read',
    catches: '~/.ssh, ~/.aws and .env files, through any reader or any file tool',
    values: ALL,
    defaultValue: 'block',
  },
  {
    id: 'data.credential-files-other',
    group: 'data',
    title: 'Other credential file',
    catches: '.netrc, .npmrc, kube and docker config, and a copy of any credential file',
    values: ALL,
    defaultValue: 'review',
  },
  {
    id: 'data.pipe-chain',
    group: 'data',
    title: 'Sensitive file piped to the network',
    catches: 'a credential file read and piped into curl, nc or ssh',
    values: ALL,
    defaultValue: 'review',
    legacy: ['Node9: Pipe-Chain Exfiltration (high)', 'Node9: Pipe-Chain to Trusted Host'],
  },
  {
    id: 'data.pipe-chain-obfuscated',
    group: 'data',
    title: 'Obfuscated exfiltration',
    catches: 'a sensitive file encoded or compressed on its way to the network',
    values: ALL,
    defaultValue: 'block',
    legacy: [
      'Node9: Pipe-Chain Exfiltration (critical)',
      'Node9: Pipe-Chain to Trusted Host (obfuscated)',
    ],
  },
  {
    id: 'data.output-secrets',
    group: 'data',
    title: 'Secret in tool output',
    catches: 'a credential a tool returned; the session is tainted, nothing is stopped',
    values: ['off', 'log'],
    defaultValue: 'log',
  },
  {
    id: 'data.prompt-secrets',
    group: 'data',
    title: 'Secret in the prompt',
    catches: 'a credential pasted into the conversation',
    values: ALL,
    defaultValue: 'block',
  },
  {
    id: 'data.canary',
    group: 'data',
    title: 'Decoy credential used',
    catches: 'a planted decoy value appears in a tool call',
    values: ALL,
    defaultValue: 'block',
    legacy: ['🚨 Node9 DLP (Decoy Credential)'],
  },

  // ── Network ─────────────────────────────────────────────────────────────
  {
    id: 'network.unknown-host',
    group: 'network',
    title: 'Unknown host',
    catches: 'a destination on neither the allowlist nor the builtin list',
    values: ['off', 'review', 'block'],
    defaultValue: 'off',
    legacy: ['🌐 Node9 Egress (Review)', '🌐 Node9 Egress (Blocked)'],
  },
  {
    id: 'network.internal-addresses',
    group: 'network',
    title: 'Internal address',
    catches: 'loopback, the RFC 1918 ranges and carrier-grade NAT',
    values: ['off', 'block'],
    defaultValue: 'off',
  },
  {
    id: 'network.metadata',
    group: 'network',
    title: 'Cloud metadata address',
    catches: '169.254.169.254 and its peers, link-local and multicast',
    values: ['block'],
    defaultValue: 'block',
    floor: 'block',
    legacy: ['🌐 Node9 Egress (Protected Address)'],
  },
  {
    id: 'network.taint-egress',
    group: 'network',
    title: 'Tainted data sent out',
    catches:
      'a file or an output flagged earlier in the session reaches a host not on the allowlist',
    values: ALL,
    defaultValue: 'block',
    legacy: [
      '🔴 Node9 Taint+Egress (Exfiltration)',
      '🔴 Node9 Taint+Egress (Exfiltration Blocked)',
    ],
  },

  // ── Files ───────────────────────────────────────────────────────────────
  {
    id: 'files.jail',
    group: 'files',
    title: 'Jailed path',
    catches: 'a path the workspace or the developer added to the jail',
    values: ALL,
    defaultValue: 'review',
  },

  // ── Agent behavior ──────────────────────────────────────────────────────
  {
    id: 'behavior.loops',
    group: 'behavior',
    title: 'Runaway loop',
    catches: 'the same tool call repeated past the threshold inside the window',
    values: ['off', 'block'],
    defaultValue: 'block',
    legacy: ['🔄 Loop Detected'],
  },
  {
    id: 'behavior.prompt-injection',
    group: 'behavior',
    title: 'Prompt injection in tool output',
    catches: 'instructions aimed at the model inside content a tool returned',
    values: ['off', 'log'],
    defaultValue: 'off',
  },
  {
    id: 'behavior.session-taint',
    group: 'behavior',
    title: 'Action after tainted output',
    catches: 'a network call or a write after a flagged file or a flagged tool output',
    values: ALL,
    defaultValue: 'review',
    legacy: ['🔴 Node9 Taint (Exfiltration Prevention)'],
  },

  // ── What the agent loads ────────────────────────────────────────────────
  {
    id: 'loading.skill-tamper',
    group: 'loading',
    title: 'Skill file changed',
    catches: 'a skill or plugin file whose hash differs from the one approved',
    values: ['off', 'log', 'block'],
    defaultValue: 'off',
    legacy: ['Skill Pin Quarantine'],
  },
  {
    id: 'loading.mcp-tamper',
    group: 'loading',
    title: 'MCP server changed',
    catches: 'tool definitions that differ from the pinned ones',
    values: ALL,
    defaultValue: 'block',
    legacy: ['MCP tool definitions changed (possible rug pull)'],
  },
  {
    id: 'loading.malicious-package',
    group: 'loading',
    title: 'Malicious package',
    catches: 'an install of a package the index flags',
    values: ALL,
    defaultValue: 'block',
    legacy: ['📦 Node9 Package Check (Malicious)', '📦 Node9 Package Check (Review)'],
  },
];

// ── Pack rows ─────────────────────────────────────────────────────────────────
//
// A builtin shield is a pack: turning it on adds its rules as rows. Two
// shields are not packs: project-jail's rules ARE the credential-file checks
// above (the AST emits them with or without the shield), and filesystem's
// chmod rule is `commands.chmod`.

const SHIELD_RULE_NAME = /^shield:([^:]+):(block|review|allow)-(.+)$/;

/** Rows that keep their product check id even though a shield spells them. */
const SHIELD_RULES_FOLDED_INTO_PRODUCT: Record<string, string> = {
  'shield:filesystem:review-chmod-777': 'commands.chmod',
};

function packRowId(shield: string, ruleName: string): string | undefined {
  const m = SHIELD_RULE_NAME.exec(ruleName);
  if (!m || m[1] !== shield) return undefined;
  return `packs.${shield}.${m[3]}`;
}

function packRows(): CheckDef[] {
  const rows: CheckDef[] = [];
  for (const shield of Object.values(BUILTIN_SHIELDS)) {
    if (shield.name === 'project-jail') continue;
    for (const rule of shield.smartRules) {
      if (!rule.name || SHIELD_RULES_FOLDED_INTO_PRODUCT[rule.name]) continue;
      const id = packRowId(shield.name, rule.name);
      if (!id) continue;
      rows.push({
        id,
        group: 'commands',
        title: rule.name.replace(SHIELD_RULE_NAME, '$3').replace(/-/g, ' '),
        catches: rule.description ?? rule.reason ?? '',
        values: ALL,
        defaultValue: rule.verdict === 'allow' ? 'off' : rule.verdict,
        pack: shield.name,
        legacy: [rule.name],
      });
    }
  }
  return rows;
}

/** Attach the plain-language text (catalog-text.ts). A pack row reuses its
 *  shield rule's description. */
function withText(def: CheckDef): CheckDef {
  const text = CHECK_TEXT[def.id];
  if (text) return { ...def, ...text };
  if (def.pack)
    return {
      ...def,
      plain: def.catches,
      advice: `Part of the ${def.pack} pack, turned on from the Apps page.`,
    };
  return def;
}

export const CHECKS: readonly CheckDef[] = [...PRODUCT_CHECKS, ...packRows()].map(withText);

export const CHECK_BY_ID: ReadonlyMap<string, CheckDef> = new Map(CHECKS.map((c) => [c.id, c]));

export function getCheck(id: string): CheckDef | undefined {
  return CHECK_BY_ID.get(id);
}

export function isLockedCheck(def: CheckDef): boolean {
  return def.floor === 'block';
}

// ── Translation from today's rule names and labels ───────────────────────────

const LEGACY_TO_ID: ReadonlyMap<string, string> = new Map(
  CHECKS.flatMap((c) => (c.legacy ?? []).map((l) => [l, c.id] as const))
);

/** Which check an SSRF floor hit belongs to: the strict-gated tiers are the
 *  internal-address check, the rest are the locked metadata check. */
export function ssrfCheckId(tier: SsrfTier): string {
  return isStrictGatedTier(tier) ? 'network.internal-addresses' : 'network.metadata';
}

const PROJECT_JAIL_BLOCK_READ = /^shield:project-jail:block-read-(ssh|aws|env)(-any-tool)?$/;

/**
 * The check behind a rule name or a verdict label the code emits today.
 * Undefined for a user or organisation rule (`org:` and unnamed rules are
 * rules, not checks) and for a label no check claims.
 */
const OVERRIDE_PREFIX = 'Override block rule:';
const LABEL_WRAPPERS = ['Smart Rule:', 'Node9 (AST):', 'project-jail (AST):'] as const;

/** The rule name inside a wrapping label, or undefined when `s` is not one. */
function unwrapRuleLabel(s: string): string | undefined {
  let rest = s;
  const override = rest.lastIndexOf(OVERRIDE_PREFIX);
  if (override >= 0) rest = rest.slice(override + OVERRIDE_PREFIX.length).trimStart();
  for (const wrapper of LABEL_WRAPPERS) {
    if (!rest.startsWith(wrapper)) continue;
    const inner = rest.slice(wrapper.length).trim();
    return inner.length > 0 ? inner : undefined;
  }
  return undefined;
}

export function checkIdForRule(nameOrLabel: string | undefined): string | undefined {
  if (!nameOrLabel) return undefined;
  const s = nameOrLabel.trim();
  const exact = LEGACY_TO_ID.get(s);
  if (exact) return exact;

  // Labels that wrap a rule name: "Smart Rule: review-sudo",
  // "Node9 (AST): block-rm-rf-home", "project-jail (AST): shield:...",
  // "⚠️ Override block rule: Smart Rule: ...". Plain string work, not a
  // regex: the old pattern backtracked polynomially on a label with a long
  // run of spaces after the prefix (CodeQL js/polynomial-redos).
  const unwrapped = unwrapRuleLabel(s);
  if (unwrapped !== undefined) return checkIdForRule(unwrapped);

  if (s.startsWith('shield:project-jail:')) {
    return PROJECT_JAIL_BLOCK_READ.test(s)
      ? 'data.credential-files'
      : 'data.credential-files-other';
  }
  const folded = SHIELD_RULES_FOLDED_INTO_PRODUCT[s];
  if (folded) return folded;
  const shieldRule = SHIELD_RULE_NAME.exec(s);
  if (shieldRule) return `packs.${shieldRule[1]}.${shieldRule[3]}`;

  if (s.startsWith('egress:')) return 'network.unknown-host';
  const ssrf = /^ssrf:([a-z-]+):/.exec(s);
  if (ssrf) return ssrfCheckId(ssrf[1] as SsrfTier);
  if (s.startsWith('DLP: ')) return 'data.secrets';
  if (s.startsWith('package-check:')) return 'loading.malicious-package';
  if (s.startsWith('Project/Global Config') && s.includes('dangerous word'))
    return 'commands.dangerous-word';
  return undefined;
}

/** The check behind an audit row's `checkedBy` tag, for rows whose verdict
 *  carried no rule name (the DLP, PII, loop and taint gates). */
export function checkIdForCheckedBy(checkedBy: string | undefined): string | undefined {
  if (!checkedBy) return undefined;
  const tag = checkedBy.replace(/^observe-mode-/, '').replace(/-would-block$/, '');
  switch (tag) {
    case 'dlp-block':
    case 'dlp':
      return 'data.secrets';
    case 'dlp-review-flagged':
      return 'data.secrets-weak';
    case 'dlp-canary-block':
    case 'dlp-canary':
      return 'data.canary';
    case 'pii-block':
    case 'pii':
      return 'data.pii';
    case 'loop-detected':
    case 'loop-detection':
      return 'behavior.loops';
    case 'taint-egress-block':
    case 'taint-egress':
      return 'network.taint-egress';
    case 'taint':
      return 'behavior.session-taint';
    case 'package-malicious':
    case 'package':
      return 'loading.malicious-package';
    case 'ssrf-destination':
      return 'network.metadata';
    default:
      return undefined;
  }
}

// ── Resolver over today's config shape ───────────────────────────────────────

/** The slice of the host config the resolver reads. The proxy's `Config`
 *  satisfies it structurally; the dashboard backend builds it from a row. */
export interface CatalogSettings {
  mode?: string;
  commandChecks?: {
    inlineExec?: string;
    rmAdvisory?: string;
    chmod?: string;
    sqlDdl?: string;
    evalDynamic?: string;
    pipeChainHigh?: string;
  };
  dlp?: { enabled?: boolean; reviewAction?: string; pii?: string };
  egress?: { enabled?: boolean; mode?: string; ssrfStrict?: boolean };
  loopDetection?: { enabled?: boolean };
  injectionScan?: { enabled?: boolean };
  skillPinning?: { enabled?: boolean; mode?: string };
  packageCheck?: { enabled?: boolean; onMalicious?: string };
  /** Shields the host actually injected (`policy.appliedShields`). */
  appliedShields?: readonly string[];
  /**
   * Explicit per-check values, keyed by check id: the v2 config file's
   * `checks` map, or the host's resolved map. Wins over the legacy knobs
   * above; a value below a row's floor is raised to the floor.
   */
  checks?: Readonly<Record<string, string>>;
}

/** Where a value came from. `configured` means it departs from the shipped
 *  default: the merged config carries every default as an explicit value, so
 *  "set" and "unset" cannot be told apart, and the departure is what a reader
 *  wants to know. A pack row never claims a source; its value says whether the
 *  pack is on. */
/**
 * The ONE projection from a host config (`settings` + `policy`) to what the
 * resolver reads. The engine and the proxy both call it, so a new knob is
 * threaded through once.
 */
export function catalogSettingsFromConfig(
  settings: { mode?: string },
  policy: Omit<CatalogSettings, 'mode'>
): CatalogSettings {
  return {
    mode: settings.mode,
    commandChecks: policy.commandChecks,
    dlp: policy.dlp,
    egress: policy.egress,
    loopDetection: policy.loopDetection,
    injectionScan: policy.injectionScan,
    skillPinning: policy.skillPinning,
    packageCheck: policy.packageCheck,
    appliedShields: policy.appliedShields ?? [],
    checks: policy.checks,
  };
}

export type CheckSource = 'default' | 'configured' | 'locked' | 'local' | 'project' | 'workspace';

export interface ResolvedCheck {
  id: string;
  value: Verdict;
  source: CheckSource;
}

/** A knob's explicit value, or undefined when the config does not set it. */
type LegacyReader = (s: CatalogSettings) => Verdict | undefined;

function knob(v: string | undefined, fallbackOff = false): Verdict | undefined {
  if (v === undefined) return undefined;
  if (isVerdict(v)) return v;
  return fallbackOff ? 'off' : undefined;
}

function enabledOr(enabled: boolean | undefined, on: Verdict): Verdict | undefined {
  if (enabled === undefined) return undefined;
  return enabled ? on : 'off';
}

const LEGACY_READERS: Record<string, LegacyReader> = {
  'commands.inline-exec': (s) => knob(s.commandChecks?.inlineExec),
  'commands.eval-dynamic': (s) => knob(s.commandChecks?.evalDynamic),
  'commands.rm': (s) => knob(s.commandChecks?.rmAdvisory),
  'commands.chmod': (s) => knob(s.commandChecks?.chmod),
  'commands.sql-ddl': (s) => knob(s.commandChecks?.sqlDdl),
  'commands.unknown': (s) =>
    s.mode === undefined ? undefined : s.mode === 'strict' ? 'review' : 'off',
  'data.secrets': (s) => enabledOr(s.dlp?.enabled, 'block'),
  'data.secrets-weak': (s) => {
    if (s.dlp?.enabled === false) return 'off';
    const action = s.dlp?.reviewAction;
    if (action === undefined) return s.dlp?.enabled === undefined ? undefined : 'review';
    return action === 'block' ? 'block' : 'review';
  },
  'data.pii': (s) =>
    s.dlp?.pii === undefined ? undefined : s.dlp.pii === 'block' ? 'block' : 'off',
  'data.pipe-chain': (s) => knob(s.commandChecks?.pipeChainHigh),
  'network.unknown-host': (s) => {
    if (s.egress?.enabled === undefined && s.egress?.mode === undefined) return undefined;
    if (!s.egress?.enabled) return 'off';
    return s.egress.mode === 'block' ? 'block' : s.egress.mode === 'off' ? 'off' : 'review';
  },
  'network.internal-addresses': (s) =>
    s.egress?.ssrfStrict === undefined ? undefined : s.egress.ssrfStrict ? 'block' : 'off',
  'behavior.loops': (s) => enabledOr(s.loopDetection?.enabled, 'block'),
  'behavior.prompt-injection': (s) => enabledOr(s.injectionScan?.enabled, 'log'),
  'loading.skill-tamper': (s) => {
    if (s.skillPinning?.enabled === undefined) return undefined;
    if (!s.skillPinning.enabled) return 'off';
    return s.skillPinning.mode === 'block' ? 'block' : 'log';
  },
  'loading.malicious-package': (s) => {
    if (s.packageCheck?.enabled === undefined) return undefined;
    if (!s.packageCheck.enabled) return 'off';
    return s.packageCheck.onMalicious === 'review' ? 'review' : 'block';
  },
};

/**
 * The value in force for one check, read from today's config shape, and
 * where it came from. A locked check always answers its floor. A pack row is
 * `off` unless its pack is applied. Anything the config does not set is the
 * catalog default.
 */
export function resolveCheck(settings: CatalogSettings, id: string): ResolvedCheck | undefined {
  const def = CHECK_BY_ID.get(id);
  if (!def) return undefined;
  if (isLockedCheck(def)) return { id, value: 'block', source: 'locked' };
  const floor = def.floor ? CHECK_VERDICT_RANK[def.floor] : 0;
  // An explicit entry (a v2 file, or the host's resolved map) wins.
  const explicit = settings.checks?.[id];
  if (isVerdict(explicit)) {
    const value = CHECK_VERDICT_RANK[explicit] < floor ? def.floor! : explicit;
    return { id, value, source: value === def.defaultValue ? 'default' : 'configured' };
  }
  if (def.pack) {
    const on = settings.appliedShields?.includes(def.pack) ?? false;
    return { id, value: on ? def.defaultValue : 'off', source: 'default' };
  }
  const read = LEGACY_READERS[id]?.(settings);
  if (read === undefined) return { id, value: def.defaultValue, source: 'default' };
  const value = CHECK_VERDICT_RANK[read] < floor ? def.floor! : read;
  return { id, value, source: value === def.defaultValue ? 'default' : 'configured' };
}

/** Every check resolved, in catalog order. */
export function resolveAllChecks(settings: CatalogSettings): ResolvedCheck[] {
  return CHECKS.map((c) => resolveCheck(settings, c.id)!);
}

/**
 * The value a detector should act on: an explicit `checks[id]` entry when
 * the settings carry one (raised to the row's floor), else the legacy
 * resolution. Detectors call this and nothing else, so a check's value is
 * decided in one place whatever file or payload it came from.
 */
export function checkValue(settings: CatalogSettings, id: string): Verdict {
  return resolveCheck(settings, id)?.value ?? 'off';
}

/** Resolve every check the way `checkValue` would, as one map. The host
 *  stores this on its config so every reader sees the same answers. */
export function resolveCheckMap(settings: CatalogSettings): Record<string, Verdict> {
  const out: Record<string, Verdict> = {};
  for (const c of CHECKS) out[c.id] = checkValue(settings, c.id);
  return out;
}
