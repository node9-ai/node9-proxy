// src/config/index.ts
// Config types, constants, and runtime config loading.
// Kept separate from core.ts policy logic so tests can import config types
// without pulling in the full authorization stack.
import fs from 'fs';
import path from 'path';
import os from 'os';
import { sanitizeConfig } from '../config-schema';
import { readActiveShields, readShieldOverrides, getShield } from '../shields';
import {
  resolveManagedMode,
  applyManagedEgress,
  applyManagedDlp,
  applyManagedApprovers,
} from './managed';
import { pathRules } from '../shields/build';
import { normalizeHost } from '../auth/trusted-hosts';

// SmartCondition + SmartRule are now defined in @node9/policy-engine.
// Re-exported here so existing import paths (`from '../config'`) keep
// working unchanged across the codebase. The local `import type` lets
// the rest of this file reference SmartRule by bare name.
export type { SmartCondition, SmartRule } from '@node9/policy-engine';
import type { SmartRule } from '@node9/policy-engine';
// The trusted shield catalog. A cloud-mandated shield resolves its body from
// here directly, never a user ~/.node9/shields/<name>.json that shadows the
// builtin (B1: a mandate's rules must come from the fleet, not the dev's file).
import { BUILTIN_SHIELDS } from '@node9/policy-engine';

export interface EnvironmentConfig {
  requireApproval?: boolean;
}

export interface Config {
  version?: string;
  settings: {
    mode: string;
    autoStartDaemon?: boolean;
    enableUndo?: boolean;
    enableHookLogDebug?: boolean;
    approvalTimeoutMs?: number;
    approvalTimeoutSeconds?: number;
    flightRecorder?: boolean;
    auditHashArgs?: boolean;
    approvers: { native: boolean; browser: boolean; cloud: boolean; terminal: boolean };
    environment?: string;
    agentPolicy?: 'require_approval' | 'block_on_rules';
    /** Review-prompt delivery: 'ask' = agent's inline prompt, 'approver' = node9's
     *  own approver. Unset → smart default (see resolveAskMode in check.ts). */
    reviewChannel?: 'ask' | 'approver';
    /** When true, agents may call weakening MCP tools (shield_disable, approver_set).
     *  Default (unset): those tools refuse over MCP — a human runs them from the CLI. */
    mcpAllowWeakening?: boolean;
    cloudSyncIntervalHours?: number;
    /** Auto-wire reconciler (P3 2.6): when true, a newly-detected ungoverned MCP
     *  server is auto-wrapped through the gateway; default (false) = nudge only. */
    mcpAutoWrap?: boolean;
    /** Reconcile scan cadence in minutes (default 60, clamp 5-1440). A managed
     *  value from the dashboard overrides this. */
    mcpReconcileIntervalMinutes?: number;
    /** Days before an orphaned MCP pin is auto-removed (default 7, 0 = never). */
    mcpStaleAfterDays?: number;
    /** Outbox shipper (audit.log → SaaS batch ingest). */
    shipper: { enabled: boolean; intervalSeconds: number };
    hud?: {
      showEnvironmentCounts?: boolean;
    };
    /**
     * Cloud-pushed panic switch. When true, all review-verdict actions
     * are upgraded to block. Set by SaaS workspace's `isPanicMode` flag,
     * synced to the local cache, and applied in the orchestrator.
     * Never set by local user config — read-only from cloud.
     */
    panicMode?: boolean;
  };
  policy: {
    sandboxPaths: string[];
    dangerousWords: string[];
    ignoredTools: string[];
    toolInspection: Record<string, string>;
    smartRules: SmartRule[];
    snapshot: {
      tools: string[];
      onlyPaths: string[];
      ignorePaths: string[];
    };
    dlp: {
      enabled: boolean;
      scanIgnoredTools: boolean;
      // Realtime PII gating for high-signal PII (SSN, Credit Card) in tool args.
      // 'off' (default): detect-only via the offline scan, never blocks.
      // 'block': deny the tool call in realtime when SSN/Credit Card appears.
      // Opt-in by design — defaulting to 'off' changes no existing behaviour and
      // avoids false-positive blocks for orgs that legitimately handle PII.
      pii?: 'off' | 'block';
    };
    // Egress / destination control (GAP-5). Gates WHERE network tools send data
    // (curl/wget/scp/ssh/nc). Opt-in: enabled=false by default. `mode` is the
    // verdict for an unknown host; allow/deny are host globs ("*.github.com").
    egress: {
      enabled: boolean;
      mode: 'off' | 'review' | 'block';
      allow: string[];
      deny: string[];
      allowPrivate: boolean;
    };
    loopDetection: {
      enabled: boolean;
      threshold: number;
      windowSeconds: number;
    };
    // Indirect-prompt-injection scanning of TOOL OUTPUT (gap1 v2). Opt-in:
    // enabled=false by default — shipping it changes no behavior until a user
    // turns it on. `minConfidence` is the actionable threshold (low is by
    // design never actionable, so it is not a valid gate). `allow` exempts
    // specific canonical tool names whose output should never be scanned.
    injectionScan: {
      enabled: boolean;
      minConfidence: 'medium' | 'high';
      allow: string[];
    };
    skillPinning: {
      enabled: boolean;
      mode: 'warn' | 'block';
      roots: string[];
    };
    // Pipe-chain trusted hosts — downgrades secret|curl-host exfil verdicts.
    // ONLY the managed source populates this list; when unmanaged, the policy
    // hook reads the local file directly via the fresh (TTL+mtime) getCachedHosts
    // path, so a `node9 trust add/remove` still propagates to long-lived
    // authorizers (the gateway) within seconds. trustedHostsManaged flags which
    // source is live so an empty managed list can CLEAR (not just no-op).
    trustedHosts: string[];
    trustedHostsManaged: boolean;
    // Managed MCP per-tool permissions { serverKey: { bareTool: allow|review|block } }.
    // Applied from the managed cache; enforced in the gateway authorize path.
    appPermissions: Record<string, Record<string, 'allow' | 'review' | 'block'>>;
  };
  environments: Record<string, EnvironmentConfig>;
}

// Default Enterprise Posture
/*
export const DANGEROUS_WORDS = [
  'delete',
  'drop',
  'remove',
  'terminate',
  'refund',
  'write',
  'update',
  'destroy',
  'rm',
  'rmdir',
  'purge',
  'format',
];
*/
// Intentionally minimal — only words that are catastrophic AND never appear
// in legitimate code/content. Everything else is handled by smart rules,
// which can scope to specific tool fields and avoid false positives.
export const DANGEROUS_WORDS = [
  'mkfs', // formats/wipes a filesystem partition
  'shred', // permanently overwrites file contents (unrecoverable)
];

// 2. The Master Default Config
export const DEFAULT_CONFIG: Config = {
  version: '1.0',
  settings: {
    mode: 'standard',
    autoStartDaemon: true,
    enableUndo: true, // 🔥 ALWAYS TRUE BY DEFAULT for the safety net
    enableHookLogDebug: true,
    approvalTimeoutMs: 120_000, // 120-second auto-deny timeout
    flightRecorder: true,
    auditHashArgs: true,
    approvers: { native: true, browser: false, cloud: false, terminal: true },
    cloudSyncIntervalHours: 5,
    shipper: { enabled: true, intervalSeconds: 20 },
  },
  policy: {
    sandboxPaths: ['/tmp/**', '**/sandbox/**', '**/test-results/**'],
    dangerousWords: DANGEROUS_WORDS,
    ignoredTools: [
      'list_*',
      'get_*',
      'read_*',
      'describe_*',
      'read',
      'glob',
      'grep',
      'ls',
      'notebookread',
      'notebookedit',
      'webfetch',
      'websearch',
      'exitplanmode',
      'askuserquestion',
      'agent',
      'task*',
      'toolsearch',
      'mcp__ide__*',
      'getDiagnostics',
    ],
    toolInspection: {
      bash: 'command',
      shell: 'command',
      run_shell_command: 'command',
      'terminal.execute': 'command',
      'postgres:query': 'sql',
    },
    snapshot: {
      tools: [
        'str_replace_based_edit_tool',
        'write_file',
        'edit_file',
        'create_file',
        'edit',
        'replace',
        // Claude / canonicalised Hermes — shouldSnapshot lowercases the
        // incoming name before set-membership, so we list the lowercase
        // forms of `Bash`/`Write`/`Edit`/`MultiEdit`. Without these,
        // post-canonicalisation Hermes `patch` / `write_file` (which now
        // arrive as `Edit` / `Write`) silently skipped snapshotting.
        'write',
        'multiedit',
      ],
      onlyPaths: [],
      ignorePaths: ['**/node_modules/**', 'dist/**', 'build/**', '.next/**', '**/*.log'],
    },
    smartRules: [
      // ── rm safety (critical — always evaluated first) ──────────────────────
      {
        name: 'block-rm-rf-home',
        tool: 'bash',
        conditionMode: 'all',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            // Anchor rm as a shell command (not inside a string arg like a git commit message).
            value: '(^|&&|\\|\\||;)\\s*rm\\b[^;&|]*\\s(-[rRfF]*[rR][rRfF]*|--recursive)(\\s|$)',
          },
          {
            field: 'command',
            op: 'matches',
            value: '(~|\\/root(\\/|$)|\\$HOME|\\/home\\/)',
          },
        ],
        verdict: 'block',
        reason: 'Recursive delete of home directory is irreversible',
        description:
          'The AI wants to recursively delete your home directory. This will permanently destroy all your personal files and cannot be undone.',
      },
      // ── SQL safety ────────────────────────────────────────────────────────
      {
        name: 'no-delete-without-where',
        tool: '*',
        conditions: [
          { field: 'sql', op: 'matches', value: '^(DELETE|UPDATE)\\s', flags: 'i' },
          { field: 'sql', op: 'notMatches', value: '\\bWHERE\\b', flags: 'i' },
        ],
        conditionMode: 'all',
        verdict: 'review',
        reason: 'DELETE/UPDATE without WHERE clause — would affect every row in the table',
        description:
          'The AI is running a SQL statement that will modify every row in the table — no WHERE filter was found. This could wipe or corrupt all your data.',
      },
      {
        name: 'review-drop-truncate-shell',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            // Require a DB CLI in the command so grep/cat/echo of SQL strings don't trigger.
            value:
              '(^|&&|\\|\\||;|\\|)\\s*(psql|mysql|sqlite3|sqlplus|cockroach|clickhouse-client|mongo)\\b',
            flags: 'i',
          },
          {
            field: 'command',
            op: 'matches',
            value: '\\b(DROP|TRUNCATE)\\s+(TABLE|DATABASE|SCHEMA|INDEX)',
            flags: 'i',
          },
        ],
        conditionMode: 'all',
        verdict: 'review',
        reason: 'SQL DDL destructive statement inside a shell command',
        description:
          'The AI wants to drop or truncate a database table via the shell. This permanently deletes the table structure or all its data.',
      },
      // ── Git safety ────────────────────────────────────────────────────────
      {
        name: 'review-force-push',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            // Anchor git as a shell command so node -e / python -c scripts containing
            // "git push --force" as a string don't false-positive.
            value: '(^|&&|\\|\\||;)\\s*git\\s+push[^;&|]*(--force|--force-with-lease|-f\\b)',
            flags: 'i',
          },
        ],
        conditionMode: 'all',
        verdict: 'review',
        reason: 'Force push rewrites remote history — confirm this is intentional',
        description:
          'The AI wants to force push to a remote git branch. This rewrites shared history and can permanently destroy commits that teammates have already pulled.',
      },
      {
        name: 'review-git-destructive',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            // Anchor git as a shell command so node -e / python -c scripts containing
            // "git reset --hard" as a string don't false-positive.
            value:
              '(^|&&|\\|\\||;)\\s*git\\s+(reset\\s+--hard|clean\\s+-[fdxX]|rebase\\b|tag\\s+-d|branch\\s+-[dD])',
            flags: 'i',
          },
          {
            field: 'command',
            op: 'notMatches',
            // Exclude recovery ops and routine branch-surgery (--onto) — these are not destructive.
            value: '\\bgit\\s+rebase\\s+--(abort|continue|skip|onto)\\b',
            flags: 'i',
          },
        ],
        conditionMode: 'all',
        verdict: 'review',
        reason: 'Destructive git operation — discards history or working-tree changes',
        description:
          'The AI wants to run a destructive git operation (reset, rebase, clean, or branch delete) that can permanently discard commits or uncommitted work.',
      },
      // ── Shell safety ──────────────────────────────────────────────────────
      {
        name: 'review-sudo',
        tool: 'bash',
        conditions: [{ field: 'command', op: 'matches', value: '\\bsudo\\s', flags: 'i' }],
        conditionMode: 'all',
        verdict: 'review',
        reason: 'Command requires elevated privileges',
        description:
          'The AI wants to run a command as root (sudo). Commands with root access can modify system files, install software, or change security settings.',
      },
      {
        name: 'review-curl-pipe-shell',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            // Anchor curl/wget as a shell command so node -e scripts testing this
            // regex pattern don't self-match as a false positive.
            value: '(^|&&|\\|\\||;)\\s*(curl|wget)[^|]*\\|\\s*(ba|z|da|fi|c|k)?sh',
            flags: 'i',
          },
        ],
        conditionMode: 'all',
        verdict: 'block',
        reason: 'Piping remote script into a shell is a supply-chain attack vector',
        description:
          'The AI wants to download a script from the internet and run it immediately, without you seeing what it contains. This is one of the most common ways malware gets installed.',
      },
    ],
    dlp: { enabled: true, scanIgnoredTools: true, pii: 'off' },
    egress: { enabled: false, mode: 'review', allow: [], deny: [], allowPrivate: true },
    loopDetection: { enabled: true, threshold: 5, windowSeconds: 120 },
    injectionScan: { enabled: false, minConfidence: 'medium', allow: [] },
    skillPinning: { enabled: false, mode: 'warn', roots: [] },
    trustedHosts: [],
    trustedHostsManaged: false,
    appPermissions: {},
  },
  environments: {},
};

// Advisory rules — appended LAST in getConfig() so user-defined smart rules
// (project/global/shield) are evaluated first and can override them.
// This is the "Safe by Default" safety net: operations that are dangerous enough
// to require human review out-of-the-box, but where shields can upgrade the
// verdict to 'block' for teams that want stricter enforcement.
const ADVISORY_SMART_RULES: SmartRule[] = [
  // ── rm safety ─────────────────────────────────────────────────────────────
  // tool: '*' so they cover bash, shell, run_shell_command, and Gemini's Shell.
  // Pattern '(^|&&|\|\||;)\s*rm\b' matches rm as a shell command (including in
  // chained commands like 'cat foo && rm bar') but avoids false-positives on 'docker rm'.
  {
    name: 'allow-rm-safe-paths',
    tool: '*',
    conditionMode: 'all',
    conditions: [
      { field: 'command', op: 'matches', value: '(^|&&|\\|\\||;)\\s*rm\\b' },
      {
        field: 'command',
        op: 'matches',
        // Matches known-safe build artifact paths in the command.
        value:
          '(node_modules|\\bdist\\b|\\.next|\\bcoverage\\b|\\.cache|\\btmp\\b|\\btemp\\b|\\.DS_Store)(\\/|\\s|$)',
      },
    ],
    verdict: 'allow',
    reason: 'Deleting a known-safe build artifact path',
  },
  {
    name: 'review-rm',
    tool: '*',
    conditions: [{ field: 'command', op: 'matches', value: '(^|&&|\\|\\||;)\\s*rm\\b' }],
    verdict: 'review',
    reason: 'rm can permanently delete files — confirm the target path',
    description:
      'The AI wants to delete files. Unlike moving to trash, rm is permanent — the files cannot be recovered without a backup.',
  },
  // ── SQL safety (Safe by Default) ──────────────────────────────────────────
  // These rules fire when an AI calls a database tool directly (e.g. MCP postgres,
  // mcp__postgres__query) with a destructive SQL statement in the 'sql' field.
  // The postgres shield upgrades these from 'review' → 'block' for stricter teams;
  // without a shield, users still get a human-approval gate on every destructive op.
  {
    name: 'review-drop-table-sql',
    tool: '*',
    conditions: [{ field: 'sql', op: 'matches', value: 'DROP\\s+TABLE', flags: 'i' }],
    verdict: 'review',
    reason: 'DROP TABLE is irreversible — enable the postgres shield to block instead',
    description:
      'The AI wants to drop a database table. This permanently deletes the table and all its data — there is no undo.',
  },
  {
    name: 'review-truncate-sql',
    tool: '*',
    conditions: [{ field: 'sql', op: 'matches', value: 'TRUNCATE\\s+TABLE', flags: 'i' }],
    verdict: 'review',
    reason: 'TRUNCATE removes all rows — enable the postgres shield to block instead',
    description:
      'The AI wants to truncate a database table, which instantly deletes every row. The table structure remains but all data is gone.',
  },
  {
    name: 'review-drop-column-sql',
    tool: '*',
    conditions: [
      { field: 'sql', op: 'matches', value: 'ALTER\\s+TABLE.*DROP\\s+COLUMN', flags: 'i' },
    ],
    verdict: 'review',
    reason: 'DROP COLUMN is irreversible — enable the postgres shield to block instead',
    description:
      'The AI wants to drop a column from a database table. This permanently removes the column and all its data from every row.',
  },
];

let cachedConfig: Config | null = null;

export function _resetConfigCache(): void {
  cachedConfig = null;
}

/**
 * Reads settings from the global config (~/.node9/config.json) only.
 * Intentionally does NOT merge project config — these are machine-level
 * preferences, not project policies.
 */
export function getGlobalSettings(): {
  mode: string;
  autoStartDaemon: boolean;
  slackEnabled: boolean;
  enableTrustSessions: boolean;
  allowGlobalPause: boolean;
} {
  try {
    const globalConfigPath = path.join(os.homedir(), '.node9', 'config.json');
    if (fs.existsSync(globalConfigPath)) {
      const parsed = JSON.parse(fs.readFileSync(globalConfigPath, 'utf-8')) as Record<
        string,
        unknown
      >;
      const settings = (parsed.settings as Record<string, unknown>) || {};
      return {
        mode: (settings.mode as string) || 'audit',
        autoStartDaemon: settings.autoStartDaemon !== false,
        slackEnabled: settings.slackEnabled !== false,
        enableTrustSessions: settings.enableTrustSessions === true,
        allowGlobalPause: settings.allowGlobalPause !== false,
      };
    }
  } catch {}
  return {
    mode: 'audit',
    autoStartDaemon: true,
    slackEnabled: true,
    enableTrustSessions: false,
    allowGlobalPause: true,
  };
}

export function getCredentials() {
  const DEFAULT_API_URL = 'https://api.node9.ai/api/v1/intercept';
  if (process.env.NODE9_API_KEY) {
    return {
      apiKey: process.env.NODE9_API_KEY,
      apiUrl: process.env.NODE9_API_URL || DEFAULT_API_URL,
    };
  }
  try {
    const credPath = path.join(os.homedir(), '.node9', 'credentials.json');
    if (fs.existsSync(credPath)) {
      const creds = JSON.parse(fs.readFileSync(credPath, 'utf-8')) as Record<string, unknown>;
      const profileName = process.env.NODE9_PROFILE || 'default';
      const profile = creds[profileName] as Record<string, unknown> | undefined;

      if (profile?.apiKey) {
        return {
          apiKey: profile.apiKey as string,
          apiUrl: (profile.apiUrl as string) || DEFAULT_API_URL,
        };
      }
      if (creds.apiKey) {
        return {
          apiKey: creds.apiKey as string,
          apiUrl: (creds.apiUrl as string) || DEFAULT_API_URL,
        };
      }
    }
  } catch {}
  return null;
}

/**
 * Returns true when a Slack API key is stored AND Slack is enabled in config.
 * Slack is the approval authority when this is true.
 */
export function hasSlack(): boolean {
  const creds = getCredentials();
  if (!creds?.apiKey) return false;
  return getGlobalSettings().slackEnabled;
}

/**
 * Returns the names of all saved profiles in ~/.node9/credentials.json.
 * Returns [] when the file doesn't exist or uses the legacy flat format.
 */
export function listCredentialProfiles(): string[] {
  try {
    const credPath = path.join(os.homedir(), '.node9', 'credentials.json');
    if (!fs.existsSync(credPath)) return [];
    const creds = JSON.parse(fs.readFileSync(credPath, 'utf-8')) as Record<string, unknown>;
    if (!creds.apiKey) return Object.keys(creds).filter((k) => typeof creds[k] === 'object');
  } catch {}
  return [];
}

export function getActiveEnvironment(config: Config): EnvironmentConfig | null {
  const env = config.settings.environment || process.env.NODE_ENV || 'development';
  return config.environments[env] ?? null;
}

let cacheReadFailureLogged = false;

/**
 * Read + parse rules-cache.json defensively.
 *
 * The daemon rewrites this file on every policy change (sync.ts writeCache).
 * A hook's getConfig() reading it concurrently used to `JSON.parse` a single
 * `readFileSync` inside a fail-OPEN catch: a torn/partial read threw and the
 * catch silently dropped ALL cloud enforcement (shields, managed mode) for
 * that call — a non-deterministic fail-open. `writeCache` is now atomic
 * (temp+rename), so a reader never sees a partial file; this reader adds
 * defense in depth: retry a torn read (belt-and-suspenders for any other
 * writer), distinguish an ABSENT cache (no cloud policy — normal) from a
 * PRESENT-but-corrupt one, and never drop enforcement without a trace.
 *
 * Returns the parsed object, or `{}` when there is nothing usable — callers
 * guard every field (`Array.isArray(raw.rules)` etc.), so `{}` is a safe
 * "no cloud layer" without special-casing.
 */
export function readRulesCacheResilient(cacheFile: string): Record<string, unknown> {
  let existed = false;
  for (let attempt = 0; attempt < 3; attempt++) {
    let content: string;
    try {
      content = fs.readFileSync(cacheFile, 'utf-8');
      existed = true;
    } catch (err) {
      // ENOENT = no cloud policy configured — normal, not an error.
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return {};
      continue; // transient FS error — retry
    }
    try {
      return JSON.parse(content) as Record<string, unknown>;
    } catch {
      /* partial/torn read — retry; atomic writeCache means the next read is whole */
    }
  }
  // Present but unparseable after retries: cloud enforcement is EXPECTED (the
  // file exists) yet unreadable. Never let that vanish silently — log once.
  // We still fall back rather than hard-block every call; fail-closed-on-corrupt
  // is a separate policy decision (see daemon-enforcement-nondeterminism-design).
  if (existed && !cacheReadFailureLogged) {
    cacheReadFailureLogged = true;
    try {
      fs.appendFileSync(
        path.join(os.homedir(), '.node9', 'hook-debug.log'),
        `[${new Date().toISOString()}] RULES_CACHE_UNREADABLE ${cacheFile} — cloud enforcement skipped this read\n`
      );
    } catch {
      /* logging is best-effort — never break config loading */
    }
  }
  return {};
}

export function getConfig(cwd?: string): Config {
  // When an explicit cwd is provided (hook commands passing payload.cwd), skip
  // the cache entirely — each project directory may have its own node9.config.json,
  // and we must not pollute the ambient cache used by the interactive CLI.
  if (!cwd && cachedConfig) return cachedConfig;

  const globalPath = path.join(os.homedir(), '.node9', 'config.json');
  // If cwd doesn't exist on disk, tryLoadConfig returns null and the project
  // config layer is simply skipped — global config + defaults are used instead.
  // This is intentional: a nonexistent cwd (e.g. deleted project, stale hook)
  // must not crash; it falls back gracefully to the global config.
  const projectPath = path.join(cwd ?? process.cwd(), 'node9.config.json');

  const globalConfig = tryLoadConfig(globalPath);
  const projectConfig = tryLoadConfig(projectPath);

  const mergedSettings = {
    ...DEFAULT_CONFIG.settings,
    approvers: { ...DEFAULT_CONFIG.settings.approvers },
    shipper: { ...DEFAULT_CONFIG.settings.shipper },
  };
  const mergedPolicy = {
    sandboxPaths: [...DEFAULT_CONFIG.policy.sandboxPaths],
    dangerousWords: [...DEFAULT_CONFIG.policy.dangerousWords],
    ignoredTools: [...DEFAULT_CONFIG.policy.ignoredTools],
    toolInspection: { ...DEFAULT_CONFIG.policy.toolInspection },
    smartRules: [...DEFAULT_CONFIG.policy.smartRules],
    snapshot: {
      tools: [...DEFAULT_CONFIG.policy.snapshot.tools],
      onlyPaths: [...DEFAULT_CONFIG.policy.snapshot.onlyPaths],
      ignorePaths: [...DEFAULT_CONFIG.policy.snapshot.ignorePaths],
    },
    dlp: { ...DEFAULT_CONFIG.policy.dlp },
    egress: {
      ...DEFAULT_CONFIG.policy.egress,
      allow: [...DEFAULT_CONFIG.policy.egress.allow],
      deny: [...DEFAULT_CONFIG.policy.egress.deny],
    },
    loopDetection: { ...DEFAULT_CONFIG.policy.loopDetection },
    injectionScan: {
      ...DEFAULT_CONFIG.policy.injectionScan,
      allow: [...DEFAULT_CONFIG.policy.injectionScan.allow],
    },
    skillPinning: {
      ...DEFAULT_CONFIG.policy.skillPinning,
      roots: [...DEFAULT_CONFIG.policy.skillPinning.roots],
    },
    // Left empty on purpose: the local file is read fresh at policy-eval time
    // (getCachedHosts via isTrustedHost), NOT snapshotted into the frozen config
    // here. A managed list fills this below and flips trustedHostsManaged.
    trustedHosts: [] as string[],
    trustedHostsManaged: false,
    appPermissions: {},
  };
  const mergedEnvironments: Record<string, EnvironmentConfig> = { ...DEFAULT_CONFIG.environments };

  const applyLayer = (source: Record<string, unknown> | null) => {
    if (!source) return;
    const s = (source.settings || {}) as Partial<Config['settings']>;
    const p = (source.policy || {}) as Partial<Config['policy']>;

    if (s.mode !== undefined) mergedSettings.mode = s.mode;
    if (s.autoStartDaemon !== undefined) mergedSettings.autoStartDaemon = s.autoStartDaemon;
    if (s.enableUndo !== undefined) mergedSettings.enableUndo = s.enableUndo;
    if (s.enableHookLogDebug !== undefined)
      mergedSettings.enableHookLogDebug = s.enableHookLogDebug;
    if (s.approvers) mergedSettings.approvers = { ...mergedSettings.approvers, ...s.approvers };
    if (s.shipper) mergedSettings.shipper = { ...mergedSettings.shipper, ...s.shipper };
    if (s.approvalTimeoutMs !== undefined) mergedSettings.approvalTimeoutMs = s.approvalTimeoutMs;
    // approvalTimeoutSeconds is the user-facing alias; convert to ms.
    // approvalTimeoutMs takes precedence if both are present.
    if (s.approvalTimeoutSeconds !== undefined && s.approvalTimeoutMs === undefined)
      mergedSettings.approvalTimeoutMs = s.approvalTimeoutSeconds * 1000;
    if (s.environment !== undefined) mergedSettings.environment = s.environment;
    if (s.reviewChannel !== undefined) mergedSettings.reviewChannel = s.reviewChannel;
    if (s.mcpAllowWeakening !== undefined) mergedSettings.mcpAllowWeakening = s.mcpAllowWeakening;
    if (s.cloudSyncIntervalHours !== undefined)
      mergedSettings.cloudSyncIntervalHours = s.cloudSyncIntervalHours;
    if (s.mcpAutoWrap !== undefined) mergedSettings.mcpAutoWrap = s.mcpAutoWrap === true;
    if (s.mcpReconcileIntervalMinutes !== undefined)
      mergedSettings.mcpReconcileIntervalMinutes = s.mcpReconcileIntervalMinutes;
    if (s.mcpStaleAfterDays !== undefined) mergedSettings.mcpStaleAfterDays = s.mcpStaleAfterDays;
    if (s.hud !== undefined) mergedSettings.hud = { ...mergedSettings.hud, ...s.hud };

    if (p.sandboxPaths) mergedPolicy.sandboxPaths.push(...p.sandboxPaths);
    if (p.ignoredTools) mergedPolicy.ignoredTools.push(...p.ignoredTools);
    // This allows a project to relax global restrictions.
    if (p.dangerousWords) mergedPolicy.dangerousWords = [...p.dangerousWords];

    if (p.toolInspection)
      mergedPolicy.toolInspection = { ...mergedPolicy.toolInspection, ...p.toolInspection };
    // Project rules are inserted between default block rules and default review/allow rules.
    // This gives project rules priority over built-in review rules (e.g. a stateful block
    // rule fires before the default review-git-push) while preserving the Layer 1 invariant:
    // built-in block rules (rm-rf-home, force-push) always fire first and cannot be
    // bypassed by a project allow rule.
    if (p.smartRules) {
      const defaultBlocks = mergedPolicy.smartRules.filter((r) => r.verdict === 'block');
      const defaultNonBlocks = mergedPolicy.smartRules.filter((r) => r.verdict !== 'block');
      // Deduplicate by name: user-config rules with the same name as a default rule
      // override the default (user rule wins), rather than stacking on top of it.
      // This prevents rules 1-N in DEFAULT_CONFIG from appearing twice when a user's
      // config.json was seeded with the same rule names.
      // B1 (#3): local rules may never be `pinned` — pinning is a
      // cloud-mandate-only property (a pinned local `allow` would compete with a
      // cloud rule in the engine's resolvePinned). zod already drops the unknown
      // key in sanitizeConfig, but strip it explicitly so this security property
      // survives a future schema change (a `.passthrough()` or an added field).
      const localRules = p.smartRules.map(({ pinned: _pinned, ...r }) => r);
      const userRuleNames = new Set(localRules.filter((r) => r.name).map((r) => r.name));
      const filteredBlocks = defaultBlocks.filter((r) => !r.name || !userRuleNames.has(r.name));
      const filteredNonBlocks = defaultNonBlocks.filter(
        (r) => !r.name || !userRuleNames.has(r.name)
      );
      mergedPolicy.smartRules = [...filteredBlocks, ...localRules, ...filteredNonBlocks];
    }
    if (p.snapshot) {
      const s = p.snapshot as Partial<Config['policy']['snapshot']>;
      if (s.tools) mergedPolicy.snapshot.tools.push(...s.tools);
      if (s.onlyPaths) mergedPolicy.snapshot.onlyPaths.push(...s.onlyPaths);
      if (s.ignorePaths) mergedPolicy.snapshot.ignorePaths.push(...s.ignorePaths);
    }
    if (p.dlp) {
      const d = p.dlp as Partial<Config['policy']['dlp']>;
      if (d.enabled !== undefined) mergedPolicy.dlp.enabled = d.enabled;
      if (d.scanIgnoredTools !== undefined) mergedPolicy.dlp.scanIgnoredTools = d.scanIgnoredTools;
      if (d.pii !== undefined) mergedPolicy.dlp.pii = d.pii;
    }
    if (p.egress) {
      const e = p.egress as Partial<Config['policy']['egress']>;
      if (e.enabled !== undefined) mergedPolicy.egress.enabled = e.enabled;
      if (e.mode !== undefined) mergedPolicy.egress.mode = e.mode;
      if (Array.isArray(e.allow)) mergedPolicy.egress.allow.push(...e.allow);
      if (Array.isArray(e.deny)) mergedPolicy.egress.deny.push(...e.deny);
      if (e.allowPrivate !== undefined) mergedPolicy.egress.allowPrivate = e.allowPrivate;
    }
    if (p.loopDetection) {
      const ld = p.loopDetection as Partial<Config['policy']['loopDetection']>;
      if (ld.enabled !== undefined) mergedPolicy.loopDetection.enabled = ld.enabled;
      if (ld.threshold !== undefined) mergedPolicy.loopDetection.threshold = ld.threshold;
      if (ld.windowSeconds !== undefined)
        mergedPolicy.loopDetection.windowSeconds = ld.windowSeconds;
    }
    if (p.injectionScan && typeof p.injectionScan === 'object') {
      const is = p.injectionScan as Partial<Config['policy']['injectionScan']>;
      if (is.enabled !== undefined) mergedPolicy.injectionScan.enabled = is.enabled;
      if (is.minConfidence !== undefined)
        mergedPolicy.injectionScan.minConfidence = is.minConfidence;
      if (Array.isArray(is.allow)) {
        for (const t of is.allow) {
          if (typeof t === 'string' && t.length > 0) mergedPolicy.injectionScan.allow.push(t);
        }
      }
    }
    if (p.skillPinning && typeof p.skillPinning === 'object') {
      const sp = p.skillPinning as Partial<Config['policy']['skillPinning']>;
      if (sp.enabled !== undefined) mergedPolicy.skillPinning.enabled = sp.enabled;
      if (sp.mode !== undefined) mergedPolicy.skillPinning.mode = sp.mode;
      if (Array.isArray(sp.roots)) {
        for (const r of sp.roots) {
          if (typeof r === 'string' && r.length > 0) mergedPolicy.skillPinning.roots.push(r);
        }
      }
    }

    const envs = (source.environments || {}) as Record<string, unknown>;
    for (const [envName, envConfig] of Object.entries(envs)) {
      if (envConfig && typeof envConfig === 'object') {
        const ec = envConfig as Record<string, unknown>;
        mergedEnvironments[envName] = {
          ...mergedEnvironments[envName],
          // Validate field types before merging — do not blindly spread user input
          ...(typeof ec.requireApproval === 'boolean'
            ? { requireApproval: ec.requireApproval }
            : {}),
        };
      }
    }
  };

  applyLayer(globalConfig);
  applyLayer(projectConfig);

  // ── Cloud rules cache layer ───────────────────────────────────────────────
  // Rules synced from the cloud dashboard are applied after local config so
  // admin-defined policy takes precedence over per-user overrides.
  // Shields still apply last and cannot be overridden by cloud rules.
  //
  // The cache also carries two workspace-level switches that control the
  // proxy's runtime behavior:
  //   - panicMode: every review-verdict becomes block (admin emergency switch).
  //                Stored on `mergedSettings.panicMode` and applied in the
  //                orchestrator after the engine returns its verdict.
  //   - shadowMode: forces `mergedSettings.mode = 'observe'` so all blocks
  //                 become "would-block" log entries instead of real blocks.
  //                 Useful for staging a policy rollout without breaking
  //                 anyone's workflow. Local user config can still set mode
  //                 explicitly — but if the user hasn't, cloud takes effect.
  // Shields the dashboard enforces fleet-wide (Managed Config M1). Captured from
  // the rules-cache here and unioned with local shields in the shield layer
  // below — additive/on: a developer can add more locally, never weaken these.
  // Enforced at the override loop below (`cloudManagedSet`), where a local
  // per-rule override is skipped for any shield in this set (B1).
  let cloudManagedShields: string[] = [];
  // B1 (#1): true once the cloud has SET or LOCKED the mode. When true, the
  // NODE9_MODE env var (applied last, below) must not override it — otherwise a
  // single `NODE9_MODE=observe` defeats a `locked:['mode']` mandate and turns
  // every block into a would-block. Where the cloud hasn't spoken, the env var
  // stays a dev convenience.
  let modeCloudControlled = false;
  // B1 (#1): true when the CLOUD chose observe (shadowMode staged rollout). A
  // shield mandate floors LOCAL observe/audit to standard, but honors a cloud
  // staged observe — the fleet chose that.
  let modeCloudStaged = false;
  {
    const cacheFile = path.join(os.homedir(), '.node9', 'rules-cache.json');
    try {
      // Resilient read: retries a torn read and, on a present-but-corrupt
      // cache, logs instead of silently dropping cloud enforcement (fail-open).
      const raw = readRulesCacheResilient(cacheFile);
      if (Array.isArray(raw.rules) && raw.rules.length > 0) {
        applyLayer({ policy: { smartRules: raw.rules } });
      }
      if (Array.isArray(raw.shields)) {
        cloudManagedShields = raw.shields.filter((s): s is string => typeof s === 'string');
      }
      // Managed settings (M2, baseline+lock) — applied as a floor a dev can only
      // tighten, unless the admin locked it. Runs BEFORE the shadow/panic
      // overrides below so those stay absolute.
      if (raw.managedConfig && typeof raw.managedConfig === 'object') {
        const mc = raw.managedConfig as {
          mode?: unknown;
          egress?: {
            enabled?: unknown;
            mode?: unknown;
            allow?: unknown;
            deny?: unknown;
            allowPrivate?: unknown;
          };
          dlp?: { enabled?: unknown; pii?: unknown };
          approvers?: {
            native?: unknown;
            browser?: unknown;
            cloud?: unknown;
            terminal?: unknown;
          };
          reviewChannel?: unknown;
          approvalTimeoutMs?: unknown;
          injectionScan?: {
            enabled?: unknown;
            minConfidence?: unknown;
            allow?: unknown;
          };
          loopDetection?: {
            enabled?: unknown;
            threshold?: unknown;
            windowSeconds?: unknown;
          };
          skillPinning?: { enabled?: unknown; mode?: unknown; roots?: unknown };
          jailPaths?: { path?: unknown; verdict?: unknown }[];
          trustedHosts?: unknown;
          appPermissions?: unknown;
          locked?: unknown;
        };
        const locked: string[] = Array.isArray(mc.locked)
          ? mc.locked.filter((f): f is string => typeof f === 'string')
          : [];
        // M2a: settings.mode.
        if (typeof mc.mode === 'string') {
          mergedSettings.mode = resolveManagedMode(
            mergedSettings.mode,
            mc.mode,
            locked.includes('mode')
          );
        }
        // The cloud has spoken about mode iff it set one or locked it — NODE9_MODE
        // must not override either (B1 #1).
        if (typeof mc.mode === 'string' || locked.includes('mode')) {
          modeCloudControlled = true;
        }
        // M2b + Step 2: policy.egress. enabled force-on; mode off<review<block;
        // allow replaces local; deny unions; allowPrivate floor boolean.
        if (mc.egress && typeof mc.egress === 'object') {
          const hosts = (v: unknown): string[] | undefined =>
            Array.isArray(v) ? v.filter((h): h is string => typeof h === 'string') : undefined;
          mergedPolicy.egress = applyManagedEgress(
            mergedPolicy.egress,
            {
              enabled: typeof mc.egress.enabled === 'boolean' ? mc.egress.enabled : undefined,
              mode: typeof mc.egress.mode === 'string' ? mc.egress.mode : undefined,
              allow: hosts(mc.egress.allow),
              deny: hosts(mc.egress.deny),
              allowPrivate:
                typeof mc.egress.allowPrivate === 'boolean' ? mc.egress.allowPrivate : undefined,
            },
            locked
          );
        }
        // M2c: policy.dlp. enabled force-on; pii floor over off<block.
        if (mc.dlp && typeof mc.dlp === 'object') {
          mergedPolicy.dlp = applyManagedDlp(
            mergedPolicy.dlp,
            {
              enabled: typeof mc.dlp.enabled === 'boolean' ? mc.dlp.enabled : undefined,
              pii: typeof mc.dlp.pii === 'string' ? mc.dlp.pii : undefined,
            },
            locked
          );
        }
        // Preferences: settings.approvers — the org owns where approvals happen,
        // so a managed value replaces the local surface per-field.
        if (mc.approvers && typeof mc.approvers === 'object') {
          const bool = (v: unknown): boolean | undefined =>
            typeof v === 'boolean' ? v : undefined;
          mergedSettings.approvers = applyManagedApprovers(mergedSettings.approvers, {
            native: bool(mc.approvers.native),
            browser: bool(mc.approvers.browser),
            cloud: bool(mc.approvers.cloud),
            terminal: bool(mc.approvers.terminal),
          });
        }
        // Preferences v2: reviewChannel + approvalTimeoutMs — plain scalars, the
        // org's value replaces local when set (admin owns these approval knobs).
        if (mc.reviewChannel === 'ask' || mc.reviewChannel === 'approver') {
          mergedSettings.reviewChannel = mc.reviewChannel;
        }
        // Require a POSITIVE timeout. 0 is rejected (not "wait forever"): the
        // daemon's pending-card timer is `setTimeout(deny, ms ?? DEFAULT)`, so a
        // stored 0 would auto-deny every card instantly (0 ?? DEFAULT === 0).
        // Unset → daemon uses its default; a disabled timeout isn't org-settable.
        if (typeof mc.approvalTimeoutMs === 'number' && mc.approvalTimeoutMs > 0) {
          mergedSettings.approvalTimeoutMs = mc.approvalTimeoutMs;
        }
        // Detection: injectionScan replaces the local config per-field (the org
        // owns which protections run).
        if (mc.injectionScan && typeof mc.injectionScan === 'object') {
          const i = mc.injectionScan;
          const cur = mergedPolicy.injectionScan;
          mergedPolicy.injectionScan = {
            enabled: typeof i.enabled === 'boolean' ? i.enabled : cur.enabled,
            minConfidence:
              i.minConfidence === 'high' || i.minConfidence === 'medium'
                ? i.minConfidence
                : cur.minConfidence,
            allow: Array.isArray(i.allow)
              ? i.allow.filter((x): x is string => typeof x === 'string')
              : cur.allow,
          };
        }
        if (mc.loopDetection && typeof mc.loopDetection === 'object') {
          const l = mc.loopDetection;
          const cur = mergedPolicy.loopDetection;
          mergedPolicy.loopDetection = {
            enabled: typeof l.enabled === 'boolean' ? l.enabled : cur.enabled,
            threshold:
              typeof l.threshold === 'number' && Number.isFinite(l.threshold)
                ? l.threshold
                : cur.threshold,
            windowSeconds:
              typeof l.windowSeconds === 'number' && Number.isFinite(l.windowSeconds)
                ? l.windowSeconds
                : cur.windowSeconds,
          };
        }
        if (mc.skillPinning && typeof mc.skillPinning === 'object') {
          const sk = mc.skillPinning;
          const cur = mergedPolicy.skillPinning;
          mergedPolicy.skillPinning = {
            enabled: typeof sk.enabled === 'boolean' ? sk.enabled : cur.enabled,
            mode: sk.mode === 'block' || sk.mode === 'warn' ? sk.mode : cur.mode,
            roots: Array.isArray(sk.roots)
              ? sk.roots.filter((x): x is string => typeof x === 'string')
              : cur.roots,
          };
        }
        // Managed credential-jail paths → synthesized smartRules (org:-prefixed
        // for attribution + to avoid colliding with the local user-jail shield).
        if (Array.isArray(mc.jailPaths)) {
          for (const jp of mc.jailPaths) {
            const path = typeof jp?.path === 'string' ? jp.path.trim() : '';
            if (!path) continue;
            const verdict = jp?.verdict === 'review' ? 'review' : 'block';
            for (const r of pathRules(path, verdict, 'org-managed jail')) {
              mergedPolicy.smartRules.push({ ...r, name: `org:${r.name}` });
            }
          }
        }
        // Managed trusted hosts REPLACE the local list (the org owns the
        // pipe-chain trust set — a dev can't silently widen it). Present-but-empty
        // is a valid REPLACE: it CLEARS all host trust fleet-wide (hence the
        // `Array.isArray` check, not `.length`, + the managed flag). Entries are
        // normalized (scheme/port/path stripped) so a dashboard value like
        // "https://api.co:443" actually matches the bare host at eval time.
        if (Array.isArray(mc.trustedHosts)) {
          mergedPolicy.trustedHostsManaged = true;
          mergedPolicy.trustedHosts = mc.trustedHosts
            .filter((h): h is string => typeof h === 'string')
            .map((h) => normalizeHost(h));
        }
        // Managed MCP app permissions REPLACE the local map (coerced to known
        // decisions). Enforced by the gateway authorize path.
        if (
          mc.appPermissions &&
          typeof mc.appPermissions === 'object' &&
          !Array.isArray(mc.appPermissions)
        ) {
          const coerced: Record<string, Record<string, 'allow' | 'review' | 'block'>> = {};
          for (const [srv, tools] of Object.entries(mc.appPermissions)) {
            if (!tools || typeof tools !== 'object' || Array.isArray(tools)) continue;
            const m: Record<string, 'allow' | 'review' | 'block'> = {};
            for (const [tool, d] of Object.entries(tools as Record<string, unknown>)) {
              if (d === 'allow' || d === 'review' || d === 'block') m[tool] = d;
            }
            if (Object.keys(m).length) coerced[srv] = m;
          }
          mergedPolicy.appPermissions = coerced;
        }
      }
      if (raw.panicMode === true) {
        mergedSettings.panicMode = true;
      }
      if (raw.shadowMode === true) {
        // shadowMode acts as the cloud-driven equivalent of running the
        // proxy in observe mode locally — admin can flip it without each
        // user editing their config.
        mergedSettings.mode = 'observe';
        modeCloudStaged = true; // cloud chose observe — a shield mandate honors it
      }
    } catch {
      /* malformed field shape within an otherwise-valid cache — skip cloud
         layer. (Absent/corrupt FILE is handled by readRulesCacheResilient.) */
    }
  }

  // ── Shield layer ──────────────────────────────────────────────────────────
  // Shields are applied after user config so they cannot be overridden locally.
  // Rules are sourced from the in-memory catalog, not from config.json — so
  // enabling a shield never mutates the user's config file.
  // Per-rule verdict overrides (from `node9 shield set`) are applied here.
  const shieldOverrides = readShieldOverrides();
  // Local shields ∪ cloud-managed shields (M1). Deduped so a shield enabled both
  // locally and from the dashboard is applied once.
  const activeShieldNames = [...new Set([...readActiveShields(), ...cloudManagedShields])];
  // B1: a cloud-mandated shield is enforced EXACTLY as the cloud defines it —
  // local per-rule overrides (`node9 shield set`) do not apply to it, weakening
  // OR tightening. This is what the comment above the union has always promised
  // ("a developer can add more locally, never weaken these") and, until this
  // set existed, did not enforce: the override loop below applied to every
  // shield in the union, so `node9 shield set redis <rule> allow` weakened a
  // fleet-mandated redis shield. A shield that is both locally-enabled AND
  // cloud-mandated resolves to cloud — a mandate is not opt-out-able by having
  // enabled the same shield first.
  const cloudManagedSet = new Set(cloudManagedShields);
  for (const shieldName of activeShieldNames) {
    const isCloudMandated = cloudManagedSet.has(shieldName);
    // B1 (#2): a cloud-mandated shield resolves its BODY from the trusted
    // builtin catalog ONLY — never getShield(), which returns a user
    // ~/.node9/shields/<name>.json shadowing the same name (its rules could be
    // empty or all-allow). A mandated name absent from the catalog fails CLOSED
    // (dropped) rather than falling back to a shadowable local body — no trusted
    // body means don't pretend to enforce. A local/self-enabled shield keeps
    // full user-shadow power (power-user customisation); only a mandate is
    // locked to the fleet.
    const shield = isCloudMandated ? BUILTIN_SHIELDS[shieldName] : getShield(shieldName);
    if (!shield) continue;
    // Deduplicate smartRules by name — prevents duplicates if the user also
    // has the same rule name in their config.
    const existingRuleNames = new Set(mergedPolicy.smartRules.map((r) => r.name));
    const ruleOverrides = isCloudMandated ? {} : (shieldOverrides[shieldName] ?? {});
    for (const rule of shield.smartRules) {
      const collides = rule.name ? existingRuleNames.has(rule.name) : false;
      if (isCloudMandated) {
        // A mandate is un-weakenable. Its rule WINS a name collision (part 2 —
        // a config.json twin of `node9 shield set`, and worse because a cloned
        // repo can carry it) AND is PINNED (#1): the engine's resolvePinned
        // makes the strictest pinned verdict win regardless of array order, so
        // a DIFFERENTLY-named local `allow` rule sitting earlier in smartRules
        // can no longer out-precede the shield's `block` (the first-match hole
        // the earlier B1 review wrongly believed closed).
        if (collides) {
          mergedPolicy.smartRules = mergedPolicy.smartRules.filter((r) => r.name !== rule.name);
        }
        mergedPolicy.smartRules.push({ ...rule, pinned: true });
      } else if (!collides) {
        const overrideVerdict = rule.name ? ruleOverrides[rule.name] : undefined;
        mergedPolicy.smartRules.push(
          overrideVerdict !== undefined ? { ...rule, verdict: overrideVerdict } : rule
        );
      }
    }
    const existingWords = new Set(mergedPolicy.dangerousWords);
    for (const word of shield.dangerousWords) {
      if (!existingWords.has(word)) mergedPolicy.dangerousWords.push(word);
    }
  }

  // Advisory rm rules are always appended last so user-defined rules (project/global/shield)
  // are evaluated first and can override default rm behaviour.
  const existingAdvisoryNames = new Set(mergedPolicy.smartRules.map((r) => r.name));
  for (const rule of ADVISORY_SMART_RULES) {
    if (!existingAdvisoryNames.has(rule.name)) mergedPolicy.smartRules.push(rule);
  }

  // NODE9_MODE is a local dev convenience — honoured only when the cloud hasn't
  // set/locked the mode (B1 #1), and only for a valid value (a garbage value was
  // previously stored verbatim and then enforced).
  const envMode = process.env.NODE9_MODE;
  if (
    envMode &&
    !modeCloudControlled &&
    (['observe', 'audit', 'standard', 'strict'] as const).includes(envMode as never)
  ) {
    mergedSettings.mode = envMode;
  }

  // B1 (#1): a mandated shield must actually enforce. observe and audit modes
  // make the orchestrator return approved:true for every call (no enforcement),
  // so a LOCAL observe/audit (from config.json settings.mode OR NODE9_MODE)
  // would disable every mandated shield. Under a mandate, floor it to standard.
  // A CLOUD staged observe (shadowMode) or a cloud-controlled/locked mode is
  // left alone — the fleet chose that. Floor to standard, not strict: enough to
  // enforce, no over-tightening.
  if (
    cloudManagedShields.length > 0 &&
    !modeCloudControlled &&
    !modeCloudStaged &&
    (mergedSettings.mode === 'observe' || mergedSettings.mode === 'audit')
  ) {
    mergedSettings.mode = 'standard';
  }

  // B1 (#3/#5/#6): local ignoredTools / sandboxPaths must not fast-path a tool
  // to allow BEFORE a mandated shield runs (the engine's ignored-tool and
  // sandbox short-circuits return allow ahead of the smart-rule tier). When the
  // fleet mandates shields, discard local (global + repo-carried) additions and
  // keep only the safe read-only defaults — a coarse but absolute guard, matching
  // the mandate-is-not-opt-out-able principle. A dev loses custom local ignores
  // ONLY while their org mandates shields.
  if (cloudManagedShields.length > 0) {
    mergedPolicy.ignoredTools = [...DEFAULT_CONFIG.policy.ignoredTools];
    mergedPolicy.sandboxPaths = [...DEFAULT_CONFIG.policy.sandboxPaths];
  }

  mergedPolicy.sandboxPaths = [...new Set(mergedPolicy.sandboxPaths)];
  mergedPolicy.dangerousWords = [...new Set(mergedPolicy.dangerousWords)];
  mergedPolicy.ignoredTools = [...new Set(mergedPolicy.ignoredTools)];
  mergedPolicy.skillPinning.roots = [...new Set(mergedPolicy.skillPinning.roots)];
  mergedPolicy.snapshot.tools = [...new Set(mergedPolicy.snapshot.tools)];
  mergedPolicy.snapshot.onlyPaths = [...new Set(mergedPolicy.snapshot.onlyPaths)];
  mergedPolicy.snapshot.ignorePaths = [...new Set(mergedPolicy.snapshot.ignorePaths)];

  const result: Config = {
    settings: mergedSettings,
    policy: mergedPolicy,
    environments: mergedEnvironments,
  };

  // Only populate the cache when using the ambient cwd — explicit cwd calls are
  // per-project and must not overwrite the cached interactive-CLI config.
  if (!cwd) cachedConfig = result;

  return result;
}

function tryLoadConfig(filePath: string): Record<string, unknown> | null {
  if (!fs.existsSync(filePath)) return null;
  let raw: unknown;
  try {
    raw = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(
      `\n⚠️  Node9: Failed to parse ${filePath}\n   ${msg}\n   → Using default config\n\n`
    );
    return null;
  }
  const SUPPORTED_VERSION = '1.0';
  const SUPPORTED_MAJOR = SUPPORTED_VERSION.split('.')[0];
  const fileVersion = (raw as Record<string, unknown>)?.version;
  if (fileVersion !== undefined) {
    const vStr = String(fileVersion);
    const fileMajor = vStr.split('.')[0];
    if (fileMajor !== SUPPORTED_MAJOR) {
      process.stderr.write(
        `\n❌  Node9: Config at ${filePath} has version "${vStr}" — major version is incompatible with this release (expected "${SUPPORTED_VERSION}"). Config will not be loaded.\n\n`
      );
      return null;
    } else if (vStr !== SUPPORTED_VERSION) {
      process.stderr.write(
        `\n⚠️  Node9: Config at ${filePath} declares version "${vStr}" — expected "${SUPPORTED_VERSION}". Continuing with best-effort parsing.\n\n`
      );
    }
  }

  const { sanitized, error } = sanitizeConfig(raw);
  if (error) {
    process.stderr.write(
      `\n⚠️  Node9: Invalid config at ${filePath}:\n${error.replace('Invalid config:\n', '')}\n   → Invalid fields ignored, using defaults for those keys\n\n`
    );
  }
  return sanitized;
}
