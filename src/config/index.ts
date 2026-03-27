// src/config/index.ts
// Config types, constants, and runtime config loading.
// Kept separate from core.ts policy logic so tests can import config types
// without pulling in the full authorization stack.
import fs from 'fs';
import path from 'path';
import os from 'os';
import { sanitizeConfig } from '../config-schema';
import { readActiveShields, readShieldOverrides, getShield } from '../shields';

export interface SmartCondition {
  field: string;
  op:
    | 'matches'
    | 'notMatches'
    | 'contains'
    | 'notContains'
    | 'exists'
    | 'notExists'
    | 'matchesGlob'
    | 'notMatchesGlob';
  value?: string;
  flags?: string;
}

export interface SmartRule {
  name?: string;
  tool: string;
  conditions: SmartCondition[];
  conditionMode?: 'all' | 'any';
  verdict: 'allow' | 'review' | 'block';
  reason?: string;
}

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
    approvers: { native: boolean; browser: boolean; cloud: boolean; terminal: boolean };
    environment?: string;
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
    };
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
    mode: 'audit',
    autoStartDaemon: true,
    enableUndo: true, // 🔥 ALWAYS TRUE BY DEFAULT for the safety net
    enableHookLogDebug: true,
    approvalTimeoutMs: 120_000, // 120-second auto-deny timeout
    flightRecorder: true,
    approvers: { native: true, browser: true, cloud: false, terminal: true },
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
            value: 'rm\\b.*(-[rRfF]*[rR][rRfF]*|--recursive)',
          },
          {
            field: 'command',
            op: 'matches',
            value: '(~|\\/root(\\/|$)|\\$HOME|\\/home\\/)',
          },
        ],
        verdict: 'block',
        reason: 'Recursive delete of home directory is irreversible',
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
      },
      {
        name: 'review-drop-truncate-shell',
        tool: 'bash',
        conditions: [
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
      },
      // ── Git safety ────────────────────────────────────────────────────────
      {
        name: 'block-force-push',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            value: '^\\s*git\\b.*\\bpush\\b.*(--force|--force-with-lease|-f\\b)',
            flags: 'i',
          },
        ],
        conditionMode: 'all',
        verdict: 'block',
        reason: 'Force push overwrites remote history and cannot be undone',
      },
      {
        name: 'review-git-push',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            value: '^\\s*git\\b.*\\bpush\\b(?!.*(-f\\b|--force|--force-with-lease))',
            flags: 'i',
          },
        ],
        conditionMode: 'all',
        verdict: 'review',
        reason: 'git push sends changes to a shared remote',
      },
      {
        name: 'review-git-destructive',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            value:
              '^\\s*git\\b.*(reset\\s+--hard|clean\\s+-[fdxX]|\\brebase\\b|tag\\s+-d|branch\\s+-[dD])',
            flags: 'i',
          },
        ],
        conditionMode: 'all',
        verdict: 'review',
        reason: 'Destructive git operation — discards history or working-tree changes',
      },
      // ── Shell safety ──────────────────────────────────────────────────────
      {
        name: 'review-sudo',
        tool: 'bash',
        conditions: [{ field: 'command', op: 'matches', value: '^\\s*sudo\\s', flags: 'i' }],
        conditionMode: 'all',
        verdict: 'review',
        reason: 'Command requires elevated privileges',
      },
      {
        name: 'review-curl-pipe-shell',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            value: '(curl|wget)[^|]*\\|\\s*(ba|z|da|fi|c|k)?sh',
            flags: 'i',
          },
        ],
        conditionMode: 'all',
        verdict: 'block',
        reason: 'Piping remote script into a shell is a supply-chain attack vector',
      },
    ],
    dlp: { enabled: true, scanIgnoredTools: true },
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
  },
  {
    name: 'review-truncate-sql',
    tool: '*',
    conditions: [{ field: 'sql', op: 'matches', value: 'TRUNCATE\\s+TABLE', flags: 'i' }],
    verdict: 'review',
    reason: 'TRUNCATE removes all rows — enable the postgres shield to block instead',
  },
  {
    name: 'review-drop-column-sql',
    tool: '*',
    conditions: [
      { field: 'sql', op: 'matches', value: 'ALTER\\s+TABLE.*DROP\\s+COLUMN', flags: 'i' },
    ],
    verdict: 'review',
    reason: 'DROP COLUMN is irreversible — enable the postgres shield to block instead',
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
    if (s.approvalTimeoutMs !== undefined) mergedSettings.approvalTimeoutMs = s.approvalTimeoutMs;
    // approvalTimeoutSeconds is the user-facing alias; convert to ms.
    // approvalTimeoutMs takes precedence if both are present.
    if (s.approvalTimeoutSeconds !== undefined && s.approvalTimeoutMs === undefined)
      mergedSettings.approvalTimeoutMs = s.approvalTimeoutSeconds * 1000;
    if (s.environment !== undefined) mergedSettings.environment = s.environment;

    if (p.sandboxPaths) mergedPolicy.sandboxPaths.push(...p.sandboxPaths);
    if (p.ignoredTools) mergedPolicy.ignoredTools.push(...p.ignoredTools);
    // This allows a project to relax global restrictions.
    if (p.dangerousWords) mergedPolicy.dangerousWords = [...p.dangerousWords];

    if (p.toolInspection)
      mergedPolicy.toolInspection = { ...mergedPolicy.toolInspection, ...p.toolInspection };
    if (p.smartRules) mergedPolicy.smartRules.push(...p.smartRules);
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

  // ── Shield layer ──────────────────────────────────────────────────────────
  // Shields are applied after user config so they cannot be overridden locally.
  // Rules are sourced from the in-memory catalog, not from config.json — so
  // enabling a shield never mutates the user's config file.
  // Per-rule verdict overrides (from `node9 shield set`) are applied here.
  const shieldOverrides = readShieldOverrides();
  for (const shieldName of readActiveShields()) {
    const shield = getShield(shieldName);
    if (!shield) continue;
    // Deduplicate smartRules by name — prevents duplicates if the user also
    // has the same rule name in their config (shouldn't happen, but be safe).
    const existingRuleNames = new Set(mergedPolicy.smartRules.map((r) => r.name));
    const ruleOverrides = shieldOverrides[shieldName] ?? {};
    for (const rule of shield.smartRules) {
      if (!existingRuleNames.has(rule.name)) {
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

  if (process.env.NODE9_MODE) mergedSettings.mode = process.env.NODE9_MODE as string;

  mergedPolicy.sandboxPaths = [...new Set(mergedPolicy.sandboxPaths)];
  mergedPolicy.dangerousWords = [...new Set(mergedPolicy.dangerousWords)];
  mergedPolicy.ignoredTools = [...new Set(mergedPolicy.ignoredTools)];
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
