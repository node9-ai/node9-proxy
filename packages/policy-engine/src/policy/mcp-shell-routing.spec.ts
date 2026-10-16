import { describe, expect, it } from 'vitest';
import { evaluatePolicy } from './index';
import { DEFAULT_CONFIG } from '../../../../src/config';

describe('MCP executor shell parity', () => {
  const context = { agent: 'Claude Code', cwd: '/workspace/project' };
  const config = structuredClone(DEFAULT_CONFIG);
  config.policy.sandboxPaths = [];

  it.each(['exec', 'mcp__tools__exec', 'run_command', 'mcp__ops__terminal'])(
    '%s applies the same command check as Bash',
    async (tool) => {
      const args = { command: 'sudo whoami' };
      const bash = await evaluatePolicy(config, 'Bash', args, context);
      expect(bash.decision).toBe('review');
      expect(await evaluatePolicy(config, tool, args, context)).toMatchObject({
        decision: bash.decision,
        checkId: bash.checkId,
      });
    }
  );

  it.each(['cmd', 'script'])('projects %s for Bash-scoped rules', async (field) => {
    const args = { [field]: 'sudo whoami' };
    expect(await evaluatePolicy(config, 'mcp__ops__exec', args, context)).toMatchObject({
      decision: 'review',
      checkId: 'commands.sudo',
    });
    expect(args).toEqual({ [field]: 'sudo whoami' });
  });

  it.each(['exec', 'mcp__tools__exec'])('allows benign commands through %s', async (tool) => {
    for (const command of ['ls -la /workspace/project', 'tar -czf backup.tgz ./src']) {
      expect((await evaluatePolicy(config, tool, { command }, context)).decision).toBe('allow');
    }
  });

  it('does not interpret workflow or SQL tools as shell executors', async () => {
    for (const tool of ['run', 'execute', 'mcp__db__execute']) {
      const result = await evaluatePolicy(config, tool, { script: 'sudo whoami' }, context);
      expect(result.checkId).not.toBe('commands.sudo');
    }
  });
});
