// src/agent-wiring.ts
// Single source of truth for "is node9 wired into agent X?" — used by
// `node9 doctor` (and intended for `node9 status` to adopt, replacing its
// hand-rolled per-agent checks). Previously doctor checked only 3 agents and
// status checked a different 6; this registry stops them drifting.
//
// Each agent has a genuinely different wiring contract (matcher vs flat hook
// arrays, JSON vs YAML, different settings paths), so the registry encodes the
// contract per agent and exposes one uniform result shape.
import fs from 'fs';
import path from 'path';
import os from 'os';
import * as yaml from 'yaml';
import { isNode9Hook, hermesConfigPath, detectAgents } from './setup';

// ── Shared low-level hook detectors (mirrors status.ts; this is now the home) ──

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

// Flat-array variant for agents (Copilot, Cursor) whose hooks have no matcher
// level. Array.isArray guards a config where the event key is a non-array.
function flatHaveNode9Hook(entries: HookEntry[] | undefined): boolean {
  return (Array.isArray(entries) ? entries : []).some((h) => isNode9Hook(h.command));
}

export type WireState = 'wired' | 'unwired' | 'invalid' | 'absent';

interface AgentSpec {
  id: keyof ReturnType<typeof detectAgents>;
  label: string; // "Claude Code"
  hookLabel: string; // "PreToolUse hook"
  setupCommand: string; // "node9 setup claude"
  settingsPath: (home: string) => string;
  /** Detect whether node9's hook is present in this agent's settings. */
  wireState: (home: string) => WireState;
}

// Generic JSON-settings wire check shared by most agents.
function jsonWire(filePath: string, read: (parsed: Record<string, unknown>) => boolean): WireState {
  const parsed = readJson<Record<string, unknown>>(filePath);
  if (parsed === null) return 'absent';
  if (parsed === 'invalid') return 'invalid';
  return read(parsed) ? 'wired' : 'unwired';
}

// Hermes config.yaml (HERMES_HOME-aware) — pre_tool_call hook.
function hermesWire(home: string): WireState {
  const configPath = hermesConfigPath(home);
  if (!fs.existsSync(configPath)) return 'absent';
  let raw: string;
  try {
    raw = fs.readFileSync(configPath, 'utf-8');
  } catch {
    return 'absent'; // unreadable (perms) — treat as not present
  }
  try {
    const cfg = yaml.parse(raw) as {
      hooks?: Record<string, Array<{ command?: string }>>;
    } | null;
    const pre = (cfg?.hooks?.pre_tool_call ?? []).some(
      (e) => typeof e?.command === 'string' && isNode9Hook(e.command)
    );
    return pre ? 'wired' : 'unwired';
  } catch {
    return 'invalid';
  }
}

// The registry. Only agents with verifiable hook wiring are listed; plugin-
// shim agents (OpenCode, Pi) are intentionally omitted until their shim
// detection is encoded — better silent than wrong.
export const AGENT_SPECS: AgentSpec[] = [
  {
    id: 'claude',
    label: 'Claude Code',
    hookLabel: 'PreToolUse hook',
    setupCommand: 'node9 setup claude',
    settingsPath: (h) => path.join(h, '.claude', 'settings.json'),
    wireState: (h) =>
      jsonWire(path.join(h, '.claude', 'settings.json'), (p) =>
        matchersHaveNode9Hook((p.hooks as { PreToolUse?: HookMatcher[] } | undefined)?.PreToolUse)
      ),
  },
  {
    id: 'gemini',
    label: 'Gemini CLI',
    hookLabel: 'BeforeTool hook',
    setupCommand: 'node9 setup gemini',
    settingsPath: (h) => path.join(h, '.gemini', 'settings.json'),
    wireState: (h) =>
      jsonWire(path.join(h, '.gemini', 'settings.json'), (p) =>
        matchersHaveNode9Hook((p.hooks as { BeforeTool?: HookMatcher[] } | undefined)?.BeforeTool)
      ),
  },
  {
    id: 'codex',
    label: 'Codex',
    hookLabel: 'PreToolUse hook',
    setupCommand: 'node9 setup codex',
    settingsPath: (h) => path.join(h, '.codex', 'hooks.json'),
    wireState: (h) =>
      jsonWire(path.join(h, '.codex', 'hooks.json'), (p) =>
        matchersHaveNode9Hook((p.hooks as { PreToolUse?: HookMatcher[] } | undefined)?.PreToolUse)
      ),
  },
  {
    id: 'antigravity',
    label: 'Antigravity',
    hookLabel: 'PreToolUse hook',
    setupCommand: 'node9 setup antigravity',
    settingsPath: (h) => path.join(h, '.gemini', 'config', 'hooks.json'),
    wireState: (h) =>
      jsonWire(path.join(h, '.gemini', 'config', 'hooks.json'), (p) =>
        matchersHaveNode9Hook((p.hooks as { PreToolUse?: HookMatcher[] } | undefined)?.PreToolUse)
      ),
  },
  {
    id: 'copilot',
    label: 'GitHub Copilot',
    hookLabel: 'PreToolUse hook',
    setupCommand: 'node9 setup copilot',
    settingsPath: (h) => path.join(h, '.copilot', 'hooks', 'node9.json'),
    wireState: (h) =>
      jsonWire(path.join(h, '.copilot', 'hooks', 'node9.json'), (p) =>
        flatHaveNode9Hook((p.hooks as { PreToolUse?: HookEntry[] } | undefined)?.PreToolUse)
      ),
  },
  {
    id: 'cursor',
    label: 'Cursor',
    hookLabel: 'preToolUse hook',
    setupCommand: 'node9 setup cursor',
    settingsPath: (h) => path.join(h, '.cursor', 'hooks.json'),
    wireState: (h) =>
      jsonWire(path.join(h, '.cursor', 'hooks.json'), (p) =>
        flatHaveNode9Hook((p.hooks as { preToolUse?: HookEntry[] } | undefined)?.preToolUse)
      ),
  },
  {
    id: 'hermes',
    label: 'Hermes Agent',
    hookLabel: 'pre_tool_call hook',
    setupCommand: 'node9 setup hermes',
    settingsPath: (h) => hermesConfigPath(h),
    wireState: (h) => hermesWire(h),
  },
];

export interface AgentWiringRow {
  id: string;
  label: string;
  hookLabel: string;
  setupCommand: string;
  settingsPath: string;
  installed: boolean;
  wireState: WireState;
}

/**
 * Resolve, for every agent in the registry, whether it's installed and whether
 * node9 is wired in. One `detectAgents()` call; pure (no I/O beyond fs reads).
 */
export function getAgentWiring(home: string = os.homedir()): AgentWiringRow[] {
  const detected = detectAgents(home);
  return AGENT_SPECS.map((spec) => ({
    id: spec.id,
    label: spec.label,
    hookLabel: spec.hookLabel,
    setupCommand: spec.setupCommand,
    settingsPath: spec.settingsPath(home),
    installed: detected[spec.id],
    wireState: spec.wireState(home),
  }));
}
