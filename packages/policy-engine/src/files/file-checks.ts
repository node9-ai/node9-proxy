// packages/policy-engine/src/files/file-checks.ts
// The file checks of the gate as one verdict: protected files
// (files/protected-access.ts), a git hook disarmed through a file operation
// (files/git-hooks.ts, node9Firewall#413 part 2) and the agent's own
// instruction and memory files (files/agent-files.ts, part 4). evaluatePolicy
// and the history scan (scan/canonical.ts) both call this, so the two name
// the same rule for the same call.

import type { CatalogSettings } from '../catalog';
import type { PolicyVerdict } from '../policy';
import { evaluateProtectedFileAccess } from './protected-access';
import { evaluateGitHooksFileAccess } from './git-hooks';
import { evaluateAgentFileWrite, type AgentFileHooks } from './agent-files';
import type { FileAccess, FileAccessContext } from './paths';

/** A file verdict names the path it is about. */
export type FileCheckVerdict = PolicyVerdict & {
  ruleName: string;
  path: string;
  operation: FileAccess['operation'];
};

/** `a` outranks `b`: block over review over a logged allow over allow. */
function stricterFileVerdict(a: PolicyVerdict, b: PolicyVerdict): boolean {
  const rank = (v: PolicyVerdict): number =>
    v.decision === 'block' ? 3 : v.decision === 'review' ? 2 : v.logged ? 1 : 0;
  return rank(a) > rank(b);
}

/**
 * The strictest file verdict for the accesses, or null. `fromShell` says
 * whether the accesses came from a shell command (content unseen) or from a
 * file tool (content in `args`). May throw; the gate treats a throw as an
 * incomplete inspection.
 */
export function evaluateFileChecks(
  args: unknown,
  accesses: FileAccess[],
  context: FileAccessContext,
  settings: CatalogSettings,
  fromShell: boolean,
  hooks: AgentFileHooks = {}
): FileCheckVerdict | null {
  let verdict: FileCheckVerdict | null = evaluateProtectedFileAccess(accesses, context, settings);
  // A git hook disarmed through a file operation: the stricter of the two
  // file verdicts stands.
  const gitHooks = evaluateGitHooksFileAccess(args, accesses, context, settings, fromShell);
  if (gitHooks && (!verdict || stricterFileVerdict(gitHooks, verdict))) verdict = gitHooks;
  // The agent's own instruction and memory files: a write there is at least
  // recorded; one that carries an instruction or changes the hooks is asked
  // about.
  const agentFile = evaluateAgentFileWrite(args, accesses, context, settings, fromShell, hooks);
  if (agentFile && (!verdict || stricterFileVerdict(agentFile, verdict))) verdict = agentFile;
  return verdict;
}
