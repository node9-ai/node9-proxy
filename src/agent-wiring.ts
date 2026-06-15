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
import { isNode9Hook, hermesConfigPath, detectAgents } from './setup';

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
  label: string; // status-style display, e.g. 'PreToolUse (node9 check)'
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

interface McpServer {
  command?: string;
  args?: string[];
}

// node9 wraps an upstream server as { command: 'node9', args: [...] } and also
// installs a standalone { command: 'node9', args: ['mcp-server'] } entry — both
// have command 'node9'. `present` = any node9-owned entry; `wrapped` = the
// human-readable list ("name → args") shown by status.
function readMcp(filePath: string): { wrapped: string[]; present: boolean } {
  const parsed = readJson<{ mcpServers?: Record<string, McpServer> }>(filePath);
  if (parsed === null || parsed === 'invalid') return { wrapped: [], present: false };
  const servers = parsed.mcpServers ?? {};
  const entries = Object.entries(servers);
  const present = entries.some(([, s]) => s?.command === 'node9');
  const wrapped = entries
    .filter(([, s]) => s?.command === 'node9' && Array.isArray(s.args) && s.args.length > 0)
    .map(([name, s]) => `${name} → ${(s.args as string[]).join(' ')}`);
  return { wrapped, present };
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
}

const pre = (label = 'PreToolUse'): HookEvent => ({ key: label, label: `${label} (node9 check)` });
const post = (label = 'PostToolUse'): HookEvent => ({ key: label, label: `${label} (node9 log)` });

// Only agents with verifiable wiring are listed. Plugin-shim agents (OpenCode,
// Pi) are intentionally omitted until their shim detection is encoded — better
// silent than wrong.
//
// Cursor is MCP-ONLY: node9 does NOT wire it via hooks (setup.ts:1334 —
// "Cursor does not yet support a pre-execution hooks file"); its protection is
// the MCP surface. It has no hookFile, so `isProtected` comes from MCP alone.
export const AGENT_SPECS: AgentSpec[] = [
  {
    id: 'claude',
    label: 'Claude Code',
    setupCommand: 'node9 setup claude',
    hookFile: (h) => path.join(h, '.claude', 'settings.json'),
    hookFormat: 'matcher',
    hookEvents: [pre(), post()],
    mcpFile: (h) => path.join(h, '.claude.json'),
  },
  {
    id: 'gemini',
    label: 'Gemini CLI',
    setupCommand: 'node9 setup gemini',
    hookFile: (h) => path.join(h, '.gemini', 'settings.json'),
    hookFormat: 'matcher',
    hookEvents: [pre('BeforeTool'), post('AfterTool')],
    mcpFile: (h) => path.join(h, '.gemini', 'settings.json'),
  },
  {
    id: 'codex',
    label: 'Codex',
    setupCommand: 'node9 setup codex',
    hookFile: (h) => path.join(h, '.codex', 'hooks.json'),
    hookFormat: 'matcher',
    hookEvents: [pre(), pre('UserPromptSubmit')],
  },
  {
    id: 'antigravity',
    label: 'Antigravity',
    setupCommand: 'node9 setup antigravity',
    hookFile: (h) => path.join(h, '.gemini', 'config', 'hooks.json'),
    hookFormat: 'matcher',
    hookEvents: [pre(), post()],
    mcpFile: (h) => path.join(h, '.gemini', 'config', 'mcp_config.json'),
  },
  {
    id: 'copilot',
    label: 'GitHub Copilot',
    setupCommand: 'node9 setup copilot',
    hookFile: (h) => path.join(h, '.copilot', 'hooks', 'node9.json'),
    hookFormat: 'flat',
    hookEvents: [pre(), post(), pre('UserPromptSubmit')],
    mcpFile: (h) => path.join(h, '.copilot', 'mcp-config.json'),
  },
  {
    id: 'cursor',
    label: 'Cursor',
    setupCommand: 'node9 setup cursor',
    // MCP-only — no hook file (see note above).
    hookFormat: 'flat',
    hookEvents: [],
    mcpFile: (h) => path.join(h, '.cursor', 'mcp.json'),
  },
  {
    id: 'hermes',
    label: 'Hermes Agent',
    setupCommand: 'node9 setup hermes',
    hookFile: (h) => hermesConfigPath(h),
    hookFormat: 'yaml',
    hookEvents: [pre('pre_tool_call'), post('post_tool_call')],
  },
];

export type WireState = 'wired' | 'unwired' | 'invalid' | 'absent';

export interface AgentWiringRow {
  id: string;
  label: string;
  setupCommand: string;
  installed: boolean;
  // ── Hooks ──
  /** Per-event wiring. Empty when the hook file is absent/invalid. */
  hooks: Array<{ label: string; wired: boolean }>;
  /** Legacy single-state (primary hook), kept for the current doctor + tests. */
  wireState: WireState;
  hookLabel: string; // e.g. 'PreToolUse hook'
  settingsPath: string; // the hook file
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
    const root: HookRoot = spec.hookFile
      ? readHookRoot(spec.hookFile(home), spec.hookFormat)
      : 'absent';
    const primary = spec.hookEvents[0];

    let wireState: WireState;
    let hooks: Array<{ label: string; wired: boolean }> = [];
    if (root === 'absent') {
      wireState = 'absent';
    } else if (root === 'invalid') {
      wireState = 'invalid';
    } else {
      hooks = spec.hookEvents.map((ev) => ({
        label: ev.label,
        wired: eventWired(root, ev, spec.hookFormat),
      }));
      wireState = primary && eventWired(root, primary, spec.hookFormat) ? 'wired' : 'unwired';
    }

    const mcp = spec.mcpFile ? readMcp(spec.mcpFile(home)) : null;
    const anyHookWired = hooks.some((h) => h.wired);

    return {
      id: spec.id,
      label: spec.label,
      setupCommand: spec.setupCommand,
      installed: detected[spec.id],
      hooks,
      wireState,
      hookLabel: primary ? `${primary.key} hook` : 'MCP proxy',
      settingsPath: spec.hookFile ? spec.hookFile(home) : spec.mcpFile ? spec.mcpFile(home) : '',
      mcpServers: mcp ? mcp.wrapped : null,
      mcpProtected: mcp ? mcp.present : false,
      isProtected: anyHookWired || (mcp?.present ?? false),
    };
  });
}
