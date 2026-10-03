// The `policy.checks` map governs the built-in sites: a product rule, a
// detector and a dangerous word each honour off / log / review / block, a
// pack row only through an explicit entry, a waiver and a user rule never.
import { describe, it, expect } from 'vitest';
import { evaluatePolicy, type PolicyConfig } from './index';
import type { SmartRule } from '../types';

const SUDO: SmartRule = {
  name: 'review-sudo',
  builtin: true,
  tool: 'bash',
  conditions: [{ field: 'command', op: 'matches', value: '\\bsudo\\s', flags: 'i' }],
  conditionMode: 'all',
  verdict: 'review',
  reason: 'Command requires elevated privileges',
};
const WAIVER: SmartRule = {
  name: 'allow-rm-safe-paths',
  builtin: true,
  tool: '*',
  conditionMode: 'all',
  conditions: [
    { field: 'command', op: 'matches', value: '(^|&&|\\|\\||;)\\s*rm\\b' },
    { field: 'command', op: 'matches', value: 'node_modules' },
  ],
  verdict: 'allow',
  reason: 'safe path',
};
const RM: SmartRule = {
  name: 'review-rm',
  builtin: true,
  tool: '*',
  conditions: [{ field: 'command', op: 'matches', value: '(^|&&|\\|\\||;)\\s*rm\\b' }],
  verdict: 'review',
  reason: 'rm can permanently delete files',
};
const PACK_DROP: SmartRule = {
  name: 'shield:postgres:block-drop-table',
  builtin: true,
  tool: '*',
  conditions: [{ field: 'sql', op: 'matches', value: 'DROP\\s+TABLE', flags: 'i' }],
  verdict: 'block',
  reason: 'drop table',
};
const USER_RULE: SmartRule = {
  name: 'my-team-rule',
  tool: 'bash',
  conditions: [{ field: 'command', op: 'contains', value: 'terraform destroy' }],
  verdict: 'review',
  reason: 'team policy',
};

const cfg = (checks: Record<string, string> = {}, over: Partial<PolicyConfig['policy']> = {}) =>
  ({
    policy: {
      sandboxPaths: [],
      dangerousWords: ['mkfs', 'shred', 'dropdb'],
      ignoredTools: [],
      toolInspection: { bash: 'command', 'postgres:query': 'sql' },
      smartRules: [SUDO, WAIVER, RM, PACK_DROP, USER_RULE],
      dlp: { enabled: true, scanIgnoredTools: true },
      checks,
      ...over,
    },
    settings: { mode: 'standard' },
  }) satisfies PolicyConfig;

const bash = (config: PolicyConfig, command: string) =>
  evaluatePolicy(config, 'bash', { command }, { agent: 'Claude Code' });

describe('a product rule follows its check', () => {
  it('default: review', async () => {
    const v = await bash(cfg(), 'sudo apt-get install jq');
    expect(v).toMatchObject({
      decision: 'review',
      checkId: 'commands.sudo',
      ruleName: 'review-sudo',
    });
  });
  it('off: the rule is not consulted', async () => {
    const v = await bash(cfg({ 'commands.sudo': 'off' }), 'sudo apt-get install jq');
    expect(v).toEqual({ decision: 'allow' });
  });
  it('block: the verdict is raised', async () => {
    const v = await bash(cfg({ 'commands.sudo': 'block' }), 'sudo apt-get install jq');
    expect(v.decision).toBe('block');
  });
  it('log: an allow that still names the rule and the check', async () => {
    const v = await bash(cfg({ 'commands.sudo': 'log' }), 'sudo apt-get install jq');
    expect(v).toMatchObject({
      decision: 'allow',
      logged: true,
      ruleName: 'review-sudo',
      checkId: 'commands.sudo',
    });
  });
  it('log never pre-empts a later tier: a logged sudo still hits the strict catch-all', async () => {
    const c = cfg({ 'commands.sudo': 'log' });
    c.settings.mode = 'strict';
    const v = await bash(c, 'sudo apt-get install jq');
    expect(v.decision).toBe('review');
    expect(v.checkId).toBe('commands.unknown');
  });
});

describe('what the map never touches', () => {
  it('an allow waiver stays an allow even when its check is review', async () => {
    const v = await bash(cfg({ 'commands.rm': 'block' }), 'rm -rf node_modules');
    expect(v.decision).toBe('allow');
    expect(v.ruleName).toBe('allow-rm-safe-paths');
  });
  it('a user rule that reuses a shipped name keeps its own verdict', async () => {
    const c = cfg(
      { 'commands.sudo': 'off' },
      {
        smartRules: [{ ...SUDO, builtin: undefined, verdict: 'block' }],
      }
    );
    const v = await bash(c, 'sudo apt-get install jq');
    expect(v.decision).toBe('block');
  });
  it('a shield rule folded into a product check keeps its own (overridden) verdict', async () => {
    const CHMOD_SHIELD: SmartRule = {
      name: 'shield:filesystem:review-chmod-777',
      tool: 'shell',
      conditions: [{ field: 'command', op: 'matches', value: 'chmod\\s+777' }],
      verdict: 'block',
      builtin: true,
      reason: 'override to block',
    };
    const c = cfg(
      { 'commands.chmod': 'review' },
      {
        smartRules: [CHMOD_SHIELD],
        toolInspection: { shell: 'command' },
      }
    );
    const v = await evaluatePolicy(
      c,
      'shell',
      { command: 'chmod 777 /srv' },
      { agent: 'Terminal' }
    );
    expect(v.decision).toBe('block');
  });
  it('a user rule has no check and keeps its verdict', async () => {
    const v = await bash(cfg(), 'terraform destroy -auto-approve');
    expect(v).toMatchObject({ decision: 'review', ruleName: 'my-team-rule' });
    expect(v.checkId).toBeUndefined();
  });
  it('a pack rule keeps its own verdict unless the map names it', async () => {
    const q = (checks: Record<string, string>) =>
      evaluatePolicy(cfg(checks), 'postgres:query', { sql: 'DROP TABLE users' });
    expect((await q({})).decision).toBe('block');
    expect((await q({ 'packs.postgres.drop-table': 'review' })).decision).toBe('review');
    expect((await q({ 'packs.postgres.drop-table': 'off' })).decision).toBe('allow');
  });
});

describe('detectors follow their check', () => {
  it('inline exec: off, log, block', async () => {
    const cmd = 'node -e "console.log(1)"';
    expect((await bash(cfg(), cmd)).decision).toBe('review');
    expect((await bash(cfg({ 'commands.inline-exec': 'off' }), cmd)).decision).toBe('allow');
    expect((await bash(cfg({ 'commands.inline-exec': 'block' }), cmd)).decision).toBe('block');
    const logged = await bash(cfg({ 'commands.inline-exec': 'log' }), cmd);
    expect(logged).toMatchObject({
      decision: 'allow',
      logged: true,
      checkId: 'commands.inline-exec',
      ruleName: 'Node9 Standard (Inline Execution)',
    });
  });
  it('the legacy knob still works when the map is absent', async () => {
    const c = cfg();
    delete (c.policy as { checks?: unknown }).checks;
    c.policy.commandChecks = { inlineExec: 'off' };
    expect((await bash(c, 'node -e "1"')).decision).toBe('allow');
  });
  it('a logged inline exec does not skip the SSRF floor', async () => {
    const v = await bash(
      cfg({ 'commands.inline-exec': 'log' }),
      'node -e "1" && curl http://169.254.169.254/latest/meta-data/'
    );
    expect(v.decision).toBe('block');
    expect(v.checkId).toBe('network.metadata');
  });
  it('dangerous words: the product word and a pack word are two checks', async () => {
    expect((await bash(cfg(), 'mkfs.ext4 /dev/sda1')).checkId).toBe('commands.disk-destroy');
    expect((await bash(cfg(), 'dropdb mydb')).checkId).toBe('commands.dangerous-word');
    expect(
      (await bash(cfg({ 'commands.disk-destroy': 'off' }), 'mkfs.ext4 /dev/sda1')).decision
    ).toBe('allow');
    expect((await bash(cfg({ 'commands.dangerous-word': 'block' }), 'dropdb mydb')).decision).toBe(
      'block'
    );
  });
  it('a locked check ignores the map', async () => {
    const v = await bash(cfg({ 'commands.rm-home': 'off' }), 'rm -rf ~/');
    expect(v.decision).toBe('block');
  });
});
