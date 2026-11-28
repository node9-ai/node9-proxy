// src/addons/agent-ids.ts
// The agent ids the add-ons inventory files things under (`claude`,
// `codex`...), by the name the hook gives the calling agent and writes in the
// audit row. One table: the hook (resolve.ts) and the reader of the audit log
// (mcp-seen.ts) must agree on it, or an agent the hook judges would have its
// calls skipped by the reader.

export const AGENT_ID: Record<string, string> = {
  'Claude Code': 'claude',
  Codex: 'codex',
  'Gemini CLI': 'gemini',
  Antigravity: 'antigravity',
  'GitHub Copilot': 'copilot',
  Cursor: 'cursor',
  Windsurf: 'windsurf',
  VSCode: 'vscode',
  'Claude Desktop': 'claudeDesktop',
  Hermes: 'hermes',
  'Hermes Agent': 'hermes',
  OpenCode: 'opencode',
  Pi: 'pi',
};

/** The agent id for a hook's agent name, or undefined. An own-property
 *  lookup: the name comes from a hook payload or an audit row, and a plain
 *  index would answer `constructor` with a function. */
export function agentIdOf(label: string | undefined): string | undefined {
  return label !== undefined && Object.hasOwn(AGENT_ID, label) ? AGENT_ID[label] : undefined;
}
