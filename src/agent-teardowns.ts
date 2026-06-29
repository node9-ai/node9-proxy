// src/agent-teardowns.ts
// Single source of truth: agent id → its teardown function. Both `node9
// uninstall` (runs every entry) and `node9 removefrom <agent>` (resolves one)
// drive off this list, so a newly-supported agent is wired into BOTH the moment
// its teardown is added here — no more drifting hardcoded lists in cli.ts.
//
// agent-teardowns.unit.test.ts asserts every `teardown*` export from ./setup
// appears here, so a new teardown can never be silently forgotten by uninstall.

import {
  teardownClaude,
  teardownGemini,
  teardownCodex,
  teardownCursor,
  teardownWindsurf,
  teardownVSCode,
  teardownHermes,
  teardownAntigravity,
  teardownCopilot,
  teardownHud,
  teardownClaudeDesktop,
  teardownOpencode,
  teardownPi,
} from './setup';

export interface AgentTeardown {
  /** Lowercase id accepted by `removefrom <target>`. */
  id: string;
  /** Display label shown by `uninstall`. */
  label: string;
  /** Zero-arg, no-op-safe teardown (each checks fs.existsSync before removing). */
  fn: () => void;
  /** Alternate ids accepted by `removefrom` (e.g. agy → antigravity). */
  aliases?: string[];
}

export const AGENT_TEARDOWNS: AgentTeardown[] = [
  { id: 'claude', label: 'Claude', fn: teardownClaude },
  { id: 'gemini', label: 'Gemini', fn: teardownGemini },
  { id: 'codex', label: 'Codex', fn: teardownCodex },
  { id: 'cursor', label: 'Cursor', fn: teardownCursor },
  { id: 'windsurf', label: 'Windsurf', fn: teardownWindsurf },
  { id: 'vscode', label: 'VSCode', fn: teardownVSCode },
  { id: 'hermes', label: 'Hermes', fn: teardownHermes },
  { id: 'antigravity', label: 'Antigravity', fn: teardownAntigravity, aliases: ['agy'] },
  { id: 'copilot', label: 'Copilot', fn: teardownCopilot },
  { id: 'hud', label: 'HUD', fn: teardownHud },
  {
    id: 'claudedesktop',
    label: 'Claude Desktop',
    fn: teardownClaudeDesktop,
    aliases: ['claude-desktop'],
  },
  { id: 'opencode', label: 'OpenCode', fn: teardownOpencode },
  { id: 'pi', label: 'Pi', fn: teardownPi },
];

/** Resolve a `removefrom <target>` argument (id or alias, case-insensitive). */
export function resolveAgentTeardown(target: string): AgentTeardown | undefined {
  const t = target.trim().toLowerCase();
  return AGENT_TEARDOWNS.find((a) => a.id === t || a.aliases?.includes(t));
}

/** All accepted `removefrom` targets (ids + aliases) — for help text + errors. */
export function agentTeardownTargets(): string[] {
  return AGENT_TEARDOWNS.flatMap((a) => [a.id, ...(a.aliases ?? [])]);
}
