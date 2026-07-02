// src/agent-wiring.ts
// Single source of truth for "is node9 wired into agent X?" — used by
// `node9 doctor` (and intended for `node9 status` to adopt, replacing its
// hand-rolled per-agent checks). Previously doctor checked only 3 agents and
// status checked a different 6; this registry stops them drifting.
//
// Each agent has a genuinely different wiring contract (matcher vs flat hook
// arrays, JSON vs YAML, settings path) and most also expose an MCP surface
// node9 can wrap. The registry encodes the contract per agent and exposes one
// uniform result shape covering BOTH hooks and MCP.
import fs from 'fs';
import path from 'path';
import os from 'os';
import * as yaml from 'yaml';
import { parse as parseToml } from 'smol-toml';
import { isNode9Hook, hermesConfigPath, detectAgents, opencodeConfigDir } from './setup';

// ── Low-level detectors (this module is now the shared home for them) ─────────

function readJson<T>(filePath: string): T | null | 'invalid' {
  if (!fs.existsSync(filePath)) return null;
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf-8')) as T;
  } catch {
    return 'invalid';
  }
}

type HookEntry = { command?: string };
type HookMatcher = { hooks?: HookEntry[] };

// True if any matcher in the list carries a node9 hook. Guards against
// hand-edited/foreign files where `hooks` is missing or not an array.
function matchersHaveNode9Hook(matchers: HookMatcher[] | undefined): boolean {
  return (matchers ?? []).some((m) => (m.hooks ?? []).some((h) => isNode9Hook(h.command)));
}

// Flat-array variant for agents (Copilot, Cursor, Hermes) whose hooks have no
// matcher level. Array.isArray guards a config where the event key is a non-array.
function flatHaveNode9Hook(entries: HookEntry[] | undefined): boolean {
  return (Array.isArray(entries) ? entries : []).some((h) => isNode9Hook(h.command));
}

// ── Hook-file model ───────────────────────────────────────────────────────────

type HookFormat = 'matcher' | 'flat' | 'yaml';
type HookRoot = Record<string, unknown> | 'absent' | 'invalid';

interface HookEvent {
  key: string; // the settings key, e.g. 'PreToolUse' / 'pre_tool_call'
  kind: 'check' | 'log'; // guards (check) vs records (log) the tool call
}

// Read an agent's hook file and return its `hooks` root, or a sentinel.
function readHookRoot(filePath: string, format: HookFormat): HookRoot {
  if (!fs.existsSync(filePath)) return 'absent';
  let raw: string;
  try {
    raw = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return 'absent'; // unreadable (perms) — treat as not present
  }
  try {
    const parsed = (format === 'yaml' ? yaml.parse(raw) : JSON.parse(raw)) as {
      hooks?: Record<string, unknown>;
    } | null;
    return (parsed?.hooks ?? {}) as Record<string, unknown>;
  } catch {
    return 'invalid';
  }
}

// Is node9 wired into a specific event within an already-read hook root?
function eventWired(root: Record<string, unknown>, ev: HookEvent, format: HookFormat): boolean {
  const arr = root[ev.key];
  if (format === 'matcher') return matchersHaveNode9Hook(arr as HookMatcher[] | undefined);
  return flatHaveNode9Hook(arr as HookEntry[] | undefined); // flat + yaml are both flat-of-{command}
}

// ── MCP-surface model ─────────────────────────────────────────────────────────

export interface McpServer {
  command?: string;
  args?: string[];
}

export type McpFormat = 'json' | 'toml';

// node9 wraps an upstream server as { command: 'node9', args: [...] } and also
// installs a standalone { command: 'node9', args: ['mcp-server'] } entry — both
// have command 'node9'. `present` = any node9-owned entry; `wrapped` = the
// human-readable list ("name → args") shown by status.
function detectMcp(servers: Record<string, McpServer> | undefined): {
  wrapped: string[];
  present: boolean;
} {
  const entries = Object.entries(servers ?? {});
  const present = entries.some(([, s]) => s?.command === 'node9');
  const wrapped = entries
    .filter(([, s]) => s?.command === 'node9' && Array.isArray(s.args) && s.args.length > 0)
    .map(([name, s]) => `${name} → ${(s.args as string[]).join(' ')}`);
  return { wrapped, present };
}

// Raw MCP server map for the reconciler (name → {command,args,...}), across both
// formats. Malformed/absent → {}. The reconciler classifies + wraps these.
export function readMcpServers(filePath: string, format: McpFormat): Record<string, McpServer> {
  if (!fs.existsSync(filePath)) return {};
  try {
    if (format === 'toml') {
      const parsed = parseToml(fs.readFileSync(filePath, 'utf-8')) as {
        mcp_servers?: Record<string, McpServer>;
      };
      return parsed?.mcp_servers ?? {};
    }
    const parsed = readJson<{ mcpServers?: Record<string, McpServer> }>(filePath);
    if (parsed === null || parsed === 'invalid') return {};
    return parsed.mcpServers ?? {};
  } catch {
    return {};
  }
}

// Reads an agent's MCP config. JSON agents key it under `mcpServers`; Codex
// uses TOML (`config.toml`) keyed under `mcp_servers`. Malformed/absent → none.
function readMcp(filePath: string, format: McpFormat): { wrapped: string[]; present: boolean } {
  if (!fs.existsSync(filePath)) return { wrapped: [], present: false };
  try {
    if (format === 'toml') {
      const parsed = parseToml(fs.readFileSync(filePath, 'utf-8')) as {
        mcp_servers?: Record<string, McpServer>;
      };
      return detectMcp(parsed?.mcp_servers);
    }
    const parsed = readJson<{ mcpServers?: Record<string, McpServer> }>(filePath);
    if (parsed === null || parsed === 'invalid') return { wrapped: [], present: false };
    return detectMcp(parsed.mcpServers);
  } catch {
    return { wrapped: [], present: false };
  }
}

// ── Registry ──────────────────────────────────────────────────────────────────

interface AgentSpec {
  id: keyof ReturnType<typeof detectAgents>;
  label: string;
  setupCommand: string;
  // Absent for MCP-only agents (Cursor) that node9 protects via MCP, not hooks.
  hookFile?: (home: string) => string;
  hookFormat: HookFormat;
  hookEvents: HookEvent[];
  // Present → the agent has an MCP surface node9 can wrap (path to its config).
  mcpFile?: (home: string) => string;
  mcpFormat?: McpFormat; // defaults to 'json'; Codex is 'toml'
  // Plugin-shim agents (OpenCode, Pi) — node9 protects them via a node9-authored
  // plugin/extension file rather than hooks or MCP. Presence of this file = wired.
  shimFile?: (home: string) => string;
  // Deterministic "this agent has a footprint on the machine" — a config file
  // or install dir, NOT a $PATH probe. Drives whether `status` shows the agent.
  present: (home: string) => boolean;
  // Column width the event keys are padded to so the "(node9 …)" suffixes align
  // in status. Defaults to DEFAULT_LABEL_PAD; Hermes' longer keys need more.
  labelPad?: number;
}

const exists = (p: string): boolean => {
  try {
    return fs.existsSync(p);
  } catch {
    return false;
  }
};

const ck = (key: string): HookEvent => ({ key, kind: 'check' });
const lg = (key: string): HookEvent => ({ key, kind: 'log' });

// Hook-row labels are computed (key padded to labelPad, then the suffix) rather
// than stored with literal trailing spaces — robust against formatters.
const DEFAULT_LABEL_PAD = 11; // width of 'PostToolUse'
const hookLabelOf = (ev: HookEvent, pad: number): string =>
  `${ev.key.padEnd(pad)} (node9 ${ev.kind})`;

// All nine supported agents. Most are hook-wired; Cursor is MCP-only;
// OpenCode and Pi are plugin-shim agents (wired = a node9-authored file exists).
//
// Cursor is MCP-ONLY: node9 does NOT wire it via hooks (setup.ts:1334 —
// "Cursor does not yet support a pre-execution hooks file"); its protection is
// the MCP surface. It has no hookFile, so `isProtected` comes from MCP alone.
export const AGENT_SPECS: AgentSpec[] = [
  {
    id: 'claude',
    label: 'Claude Code',
    setupCommand: 'node9 agents add claude',
    hookFile: (h) => path.join(h, '.claude', 'settings.json'),
    hookFormat: 'matcher',
    hookEvents: [ck('PreToolUse'), lg('PostToolUse')],
    mcpFile: (h) => path.join(h, '.claude.json'),
    present: (h) =>
      exists(path.join(h, '.claude', 'settings.json')) || exists(path.join(h, '.claude.json')),
  },
  {
    id: 'gemini',
    label: 'Gemini CLI',
    setupCommand: 'node9 agents add gemini',
    hookFile: (h) => path.join(h, '.gemini', 'settings.json'),
    hookFormat: 'matcher',
    hookEvents: [ck('BeforeTool'), lg('AfterTool')],
    mcpFile: (h) => path.join(h, '.gemini', 'settings.json'),
    present: (h) => exists(path.join(h, '.gemini', 'settings.json')),
  },
  {
    id: 'codex',
    label: 'Codex',
    setupCommand: 'node9 agents add codex',
    hookFile: (h) => path.join(h, '.codex', 'hooks.json'),
    hookFormat: 'matcher',
    hookEvents: [ck('PreToolUse'), ck('UserPromptSubmit')],
    mcpFile: (h) => path.join(h, '.codex', 'config.toml'),
    mcpFormat: 'toml',
    present: (h) => exists(path.join(h, '.codex')),
  },
  {
    id: 'antigravity',
    label: 'Antigravity',
    setupCommand: 'node9 agents add antigravity',
    hookFile: (h) => path.join(h, '.gemini', 'config', 'hooks.json'),
    hookFormat: 'matcher',
    hookEvents: [ck('PreToolUse'), lg('PostToolUse')],
    mcpFile: (h) => path.join(h, '.gemini', 'config', 'mcp_config.json'),
    present: (h) =>
      exists(path.join(h, '.gemini', 'config', 'hooks.json')) ||
      exists(path.join(h, '.gemini', 'antigravity-cli')) ||
      exists(path.join(h, '.gemini', 'antigravity-ide')),
  },
  {
    id: 'copilot',
    label: 'GitHub Copilot',
    setupCommand: 'node9 agents add copilot',
    hookFile: (h) => path.join(h, '.copilot', 'hooks', 'node9.json'),
    hookFormat: 'flat',
    hookEvents: [ck('PreToolUse'), lg('PostToolUse'), ck('UserPromptSubmit')],
    mcpFile: (h) => path.join(h, '.copilot', 'mcp-config.json'),
    present: (h) => exists(path.join(h, '.copilot')),
  },
  {
    id: 'cursor',
    label: 'Cursor',
    setupCommand: 'node9 agents add cursor',
    // MCP-only — no hook file (see note above).
    hookFormat: 'flat',
    hookEvents: [],
    mcpFile: (h) => path.join(h, '.cursor', 'mcp.json'),
    present: (h) => exists(path.join(h, '.cursor', 'mcp.json')),
  },
  {
    id: 'hermes',
    label: 'Hermes Agent',
    setupCommand: 'node9 agents add hermes',
    hookFile: (h) => hermesConfigPath(h),
    hookFormat: 'yaml',
    hookEvents: [ck('pre_tool_call'), lg('post_tool_call')],
    labelPad: 14, // 'post_tool_call' is wider than the default
    present: (h) => exists(hermesConfigPath(h)),
  },
  {
    // Plugin-shim agents — protected by a node9-authored plugin/extension file
    // (no hooks, no MCP). hookFormat is unused for these (shimFile drives it).
    id: 'opencode',
    label: 'OpenCode',
    setupCommand: 'node9 agents add opencode',
    hookFormat: 'flat',
    hookEvents: [],
    shimFile: (h) => path.join(opencodeConfigDir(h), 'plugins', 'node9.js'),
    present: (h) =>
      exists(opencodeConfigDir(h)) ||
      exists(path.join(opencodeConfigDir(h), 'plugins', 'node9.js')),
  },
  {
    id: 'pi',
    label: 'Pi',
    setupCommand: 'node9 agents add pi',
    hookFormat: 'flat',
    hookEvents: [],
    shimFile: (h) => path.join(h, '.pi', 'agent', 'extensions', 'node9.js'),
    present: (h) =>
      exists(path.join(h, '.pi', 'agent')) ||
      exists(path.join(h, '.pi', 'agent', 'extensions', 'node9.js')),
  },
];

export type WireState = 'wired' | 'unwired' | 'invalid' | 'absent';

export interface AgentWiringRow {
  id: string;
  label: string;
  setupCommand: string;
  installed: boolean;
  /** Deterministic footprint (config file / install dir). Drives status display. */
  present: boolean;
  // ── Hooks ──
  /** Per-event wiring. Empty when the hook file is absent/invalid. */
  hooks: Array<{ label: string; wired: boolean }>;
  /** Legacy single-state (primary hook), kept for the current doctor + tests. */
  wireState: WireState;
  hookLabel: string; // e.g. 'PreToolUse hook'
  settingsPath: string; // the hook file
  /** Format of the hook config — for "not valid JSON/YAML" messages. */
  configFormat: 'JSON' | 'YAML';
  // ── MCP ──
  /** node9-wrapped servers ("name → args"); null when the agent has no MCP surface. */
  mcpServers: string[] | null;
  /** A node9 MCP entry is present (wrapped server or the standalone mcp-server). */
  mcpProtected: boolean;
  // ── Rollup ──
  /** node9 is protecting this agent: any hook wired OR an MCP entry present. */
  isProtected: boolean;
}

/**
 * Resolve, for every agent in the registry, its install + hook + MCP wiring.
 * One `detectAgents()` call; pure (fs reads only). Deterministic given `home`.
 */
export function getAgentWiring(home: string = os.homedir()): AgentWiringRow[] {
  const detected = detectAgents(home);
  return AGENT_SPECS.map((spec) => {
    const present = spec.present(home);
    const pad = spec.labelPad ?? DEFAULT_LABEL_PAD;

    let hooks: Array<{ label: string; wired: boolean }>;
    let wireState: WireState;
    let hookLabel: string;
    let settingsPath: string;

    if (spec.shimFile) {
      // Plugin-shim agent — presence of the node9-authored file is the wiring.
      const shimWired = exists(spec.shimFile(home));
      hooks = [{ label: 'node9 plugin (node9 check)', wired: shimWired }];
      wireState = shimWired ? 'wired' : present ? 'unwired' : 'absent';
      hookLabel = 'node9 plugin';
      settingsPath = spec.shimFile(home);
    } else {
      const root: HookRoot = spec.hookFile
        ? readHookRoot(spec.hookFile(home), spec.hookFormat)
        : 'absent';
      const primary = spec.hookEvents[0];
      const rootPresent = root !== 'absent' && root !== 'invalid';
      // Always list every event (wired:false when absent/invalid) so a
      // present-but-unwired agent still renders ✗ rows in status.
      hooks = spec.hookEvents.map((ev) => ({
        label: hookLabelOf(ev, pad),
        wired: rootPresent && eventWired(root as Record<string, unknown>, ev, spec.hookFormat),
      }));
      if (root === 'absent') wireState = 'absent';
      else if (root === 'invalid') wireState = 'invalid';
      else wireState = primary && eventWired(root, primary, spec.hookFormat) ? 'wired' : 'unwired';
      hookLabel = primary ? `${primary.key} hook` : 'MCP proxy';
      settingsPath = spec.hookFile ? spec.hookFile(home) : spec.mcpFile ? spec.mcpFile(home) : '';
    }

    const mcp = spec.mcpFile ? readMcp(spec.mcpFile(home), spec.mcpFormat ?? 'json') : null;
    const anyHookWired = hooks.some((h) => h.wired);

    return {
      id: spec.id,
      label: spec.label,
      setupCommand: spec.setupCommand,
      installed: detected[spec.id],
      present,
      hooks,
      wireState,
      hookLabel,
      settingsPath,
      configFormat: spec.hookFormat === 'yaml' ? 'YAML' : 'JSON',
      mcpServers: mcp ? mcp.wrapped : null,
      mcpProtected: mcp ? mcp.present : false,
      isProtected: anyHookWired || (mcp?.present ?? false),
    };
  });
}
