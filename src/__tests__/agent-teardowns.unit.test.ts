// Drift guard: every teardown* function exported from setup.ts must be wired
// into AGENT_TEARDOWNS, so a newly-supported agent can never be silently left
// behind by `node9 uninstall` / `removefrom` (the #186 bug). Mirrors the
// mcp-capability exhaustiveness test pattern.

import { describe, it, expect } from 'vitest';
import * as setup from '../setup';
import { AGENT_TEARDOWNS, resolveAgentTeardown, agentTeardownTargets } from '../agent-teardowns';

describe('AGENT_TEARDOWNS', () => {
  it('wires EVERY teardown* export from setup.ts (no agent can be forgotten)', () => {
    const exportedTeardowns = Object.entries(setup).filter(
      ([name, val]) => name.startsWith('teardown') && typeof val === 'function'
    );
    expect(exportedTeardowns.length).toBeGreaterThan(0);

    const wired = new Set(AGENT_TEARDOWNS.map((a) => a.fn));
    const missing = exportedTeardowns
      .filter(([, fn]) => !wired.has(fn as () => void))
      .map(([name]) => name);
    expect(missing).toEqual([]);
  });

  it('includes the agents that uninstall used to miss', () => {
    for (const id of ['opencode', 'pi', 'antigravity', 'copilot', 'hud', 'claudedesktop']) {
      expect(
        AGENT_TEARDOWNS.find((a) => a.id === id),
        id
      ).toBeDefined();
    }
  });

  it('has unique ids', () => {
    const ids = AGENT_TEARDOWNS.map((a) => a.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('resolves ids and aliases case-insensitively', () => {
    expect(resolveAgentTeardown('opencode')?.id).toBe('opencode');
    expect(resolveAgentTeardown('PI')?.id).toBe('pi');
    expect(resolveAgentTeardown('agy')?.id).toBe('antigravity');
    expect(resolveAgentTeardown('claude-desktop')?.id).toBe('claudedesktop');
    expect(resolveAgentTeardown('nope')).toBeUndefined();
    expect(agentTeardownTargets()).toContain('opencode');
  });
});
