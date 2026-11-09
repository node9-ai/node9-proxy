// The tools that hand a brief to another agent (node9Firewall#428, ASI07).
// Exact names: an MCP tool whose name says "agent" is not a spawn, and a
// rename upstream is a one-line change here, not a regex that silently
// matches more.

const SPAWN_TOOLS: ReadonlySet<string> = new Set([
  // Claude Code: `Task` before 2.1, `Agent` from 2.1.
  'Task',
  'Agent',
  // Codex multi-agent: the spawn, and a message to a running subagent.
  'collaborationspawn_agent',
  'collaborationsend_input',
]);

/** True for a tool call whose input is a brief another agent will act on. */
export function isSpawnTool(toolName: string): boolean {
  return SPAWN_TOOLS.has(toolName);
}

/** The subset that starts a new subagent (a message to a running one is not
 *  a spawn): what the fan-out limit counts. */
const SUBAGENT_SPAWNS: ReadonlySet<string> = new Set(['Task', 'Agent', 'collaborationspawn_agent']);

export function isSubagentSpawn(toolName: string): boolean {
  return SUBAGENT_SPAWNS.has(toolName);
}
