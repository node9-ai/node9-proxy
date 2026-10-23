// Dangerous actions as category shields (node9Firewall#385): finance,
// identity and publishing. Each rule is one glob that covers the BARE tool
// name the gateway sends (`create_refund`) and the namespaced name the agent
// hook sends (`mcp__stripe__create_refund`); the test derives the tool names
// from the glob so a rule cannot drift from what this file asserts.
import { describe, it, expect } from 'vitest';
import { BUILTIN_SHIELDS } from './index';
import { evaluatePolicy } from '../policy';
import { evaluateSmartConditions } from '../rules';
import { toolMatchesRule } from '../shell';
import { DEFAULT_CONFIG } from '../../../../src/config';

const ACTION_SHIELDS = ['finance', 'identity', 'publishing'] as const;

/** The tool names a `{,mcp__*__}{a,b}` or `{,mcp__*__}a` glob names. */
function toolsOf(glob: string): string[] {
  const m = /^\{,mcp__\*__\}(?:\{([^}]*)\}|([A-Za-z0-9_]+))$/.exec(glob);
  if (!m) throw new Error(`not a dual-spelling tool glob: ${glob}`);
  return (m[1] ?? m[2]).split(',');
}

const READS = [
  'list_customers',
  'retrieve_balance',
  'list_payment_intents',
  'search_documentation',
  'get_user',
  'list_users',
  'list_releases',
  'get_deployment',
  'read_email',
  'create_customer',
  'create_product',
  'recreate_refund',
  'refund_policy_lookup',
];

describe('action shields: every tool rule meets both spellings and no read', () => {
  for (const name of ACTION_SHIELDS) {
    const shield = BUILTIN_SHIELDS[name];
    it(`${name} exists with the shield shape`, () => {
      expect(shield).toBeDefined();
      expect(shield.description.length).toBeGreaterThan(20);
      expect(shield.smartRules.length).toBeGreaterThan(4);
      for (const r of shield.smartRules) {
        expect(r.name, name).toMatch(new RegExp(`^shield:${name}:review-`));
        expect(r.verdict, r.name).toBe('review');
        expect(r.reason, r.name).toContain('node9 asks before');
      }
    });
    const toolRules = shield.smartRules.filter(
      (r) => typeof r.tool === 'string' && r.tool !== 'bash'
    );
    for (const r of toolRules) {
      it(`${r.name} matches its tools bare and namespaced`, () => {
        expect(r.conditions).toEqual([]);
        for (const tool of toolsOf(r.tool as string)) {
          expect(toolMatchesRule(tool, r.tool), tool).toBe(true);
          expect(toolMatchesRule(`mcp__stripe__${tool}`, r.tool), tool).toBe(true);
          expect(toolMatchesRule(`mcp__my_server__${tool}`, r.tool), tool).toBe(true);
          // A longer name that merely ends in the tool is another tool.
          expect(toolMatchesRule(`x${tool}`, r.tool), tool).toBe(false);
        }
      });
    }
    it(`${name} leaves reads and look-alikes alone`, () => {
      for (const read of READS) {
        for (const r of toolRules) {
          expect(toolMatchesRule(read, r.tool), `${read} vs ${r.name}`).toBe(false);
          expect(toolMatchesRule(`mcp__srv__${read}`, r.tool), `${read} vs ${r.name}`).toBe(false);
        }
      }
    });
  }
});

describe('publishing: the shell commands that publish are the same switch', () => {
  const shell = BUILTIN_SHIELDS.publishing.smartRules.filter((r) => r.tool === 'bash');
  const fires = (command: string) => shell.some((r) => evaluateSmartConditions({ command }, r));
  it.each([
    'npm publish',
    'npm publish --access public',
    'pnpm publish -r',
    'yarn npm publish',
    'cd dist && npm publish',
    'twine upload dist/*',
    'cargo publish --dry-run',
    'gem push my-gem-1.0.0.gem',
    'docker push ghcr.io/o/img:1',
    'gh release create v1.2.0 --notes "x"',
    'gh release upload v1.2.0 out.tgz',
  ])('%s asks', (command) => {
    expect(fires(command)).toBe(true);
  });
  it.each([
    'npm run publish-docs',
    'npm install',
    'docker build -t x .',
    'docker pull nginx',
    'gh release list',
    'gh release view v1.0.0',
    'cargo build --release',
    'echo "npm publish" > notes.md',
    'git commit -m "npm publish later"',
  ])('%s does not', (command) => {
    expect(fires(command)).toBe(false);
  });
});

describe('the gate, with a shield on', () => {
  const withShield = (name: (typeof ACTION_SHIELDS)[number]) =>
    ({
      ...DEFAULT_CONFIG,
      settings: { ...DEFAULT_CONFIG.settings, mode: 'standard' },
      policy: {
        ...DEFAULT_CONFIG.policy,
        smartRules: [...DEFAULT_CONFIG.policy.smartRules, ...BUILTIN_SHIELDS[name].smartRules],
      },
    }) as typeof DEFAULT_CONFIG;
  const gate = (cfg: typeof DEFAULT_CONFIG, tool: string, args: unknown) =>
    evaluatePolicy(cfg, tool, args, { agent: 'Claude Code' });

  it('finance: a refund through the hook or the gateway is reviewed, a read is not', async () => {
    const cfg = withShield('finance');
    const hook = await gate(cfg, 'mcp__stripe__create_refund', {
      payment_intent: 'pi_1',
      amount: 1200,
    });
    expect(hook.decision).toBe('review');
    expect(hook.ruleName).toBe('shield:finance:review-refund');
    const gateway = await gate(cfg, 'create_refund', { payment_intent: 'pi_1', amount: 1200 });
    expect(gateway.decision).toBe('review');
    expect((await gate(cfg, 'mcp__stripe__list_customers', { limit: 10 })).decision).toBe('allow');
    expect(
      (await gate(cfg, 'mcp__stripe__create_customer', { email: 'a@example.com' })).decision
    ).toBe('allow');
  });

  it('identity and publishing: the AgentDojo tools are met by exact name', async () => {
    expect(
      (await gate(withShield('identity'), 'mcp__workspace__update_password', { password: 'x' }))
        .ruleName
    ).toBe('shield:identity:review-password');
    expect(
      (await gate(withShield('identity'), 'invite_user_to_slack', { user: 'eve' })).ruleName
    ).toBe('shield:identity:review-membership');
    expect(
      (await gate(withShield('finance'), 'send_money', { recipient: 'US12', amount: 100 })).ruleName
    ).toBe('shield:finance:review-transfer');
    expect(
      (
        await gate(withShield('publishing'), 'post_webpage', {
          url: 'https://x.example',
          content: 'hi',
        })
      ).ruleName
    ).toBe('shield:publishing:review-post');
  });

  it('without the shield the same calls pass (the shields ship off)', async () => {
    const cfg = {
      ...DEFAULT_CONFIG,
      settings: { ...DEFAULT_CONFIG.settings, mode: 'standard' },
    } as typeof DEFAULT_CONFIG;
    expect((await gate(cfg, 'mcp__stripe__create_refund', { amount: 1 })).decision).toBe('allow');
    expect((await gate(cfg, 'send_money', { amount: 1 })).decision).toBe('allow');
  });
});
