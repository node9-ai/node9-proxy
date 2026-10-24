// Actions that move money, change access or publish (node9Firewall#385,
// node9Firewall#390). finance.json, identity.json and publishing.json are
// templates; apps.ts builds two things from them:
//   - app shields (stripe, paypal): the template scoped to the app's MCP
//     server, plus its CLI, API and library doors, off by default;
//   - the general checks actions.money / actions.access / actions.publish:
//     the template on every server no app shield claims, on by default.
// Each template rule is one glob that covers the BARE tool name the gateway
// sends (`create_refund`) and the namespaced name the hook sends
// (`mcp__stripe__create_refund`); the tests derive the tool names from the
// glob so a rule cannot drift from what this file asserts.
import { describe, it, expect } from 'vitest';
import { BUILTIN_SHIELDS } from './index';
import {
  ACTION_TEMPLATES,
  APP_SERVER_GLOB,
  GENERAL_ACTION_RULES,
  REPLACED_SHIELDS,
  type ActionTemplateName,
} from './apps';
import { evaluatePolicy } from '../policy';
import { evaluateSmartConditions, mcpServerFromToolName, ruleServerMatches } from '../rules';
import { toolMatchesRule } from '../shell';
import { CHECK_GROUPS, getCheck } from '../catalog';
import type { SmartRule } from '../types';
import { DEFAULT_CONFIG } from '../../../../src/config';

const TEMPLATES = Object.keys(ACTION_TEMPLATES) as ActionTemplateName[];

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

describe('action templates: every tool rule meets both spellings and no read', () => {
  for (const name of TEMPLATES) {
    const rules = ACTION_TEMPLATES[name];
    it(`${name} has the template shape`, () => {
      expect(rules.length).toBeGreaterThan(4);
      for (const r of rules) {
        expect(r.name, name).toMatch(new RegExp(`^shield:${name}:review-`));
        expect(r.verdict, r.name).toBe('review');
        expect(r.reason, r.name).toContain('node9 asks before');
      }
    });
    const toolRules = rules.filter((r) => typeof r.tool === 'string' && r.tool !== 'bash');
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

  it('the templates are no longer shields; their names say what replaced them', () => {
    for (const name of TEMPLATES) {
      expect(BUILTIN_SHIELDS[name], name).toBeUndefined();
      expect(REPLACED_SHIELDS[name], name).toMatch(/check/);
    }
  });
});

describe('publishing: the shell commands that publish', () => {
  const shell = ACTION_TEMPLATES.publishing.filter((r) => r.tool === 'bash');
  const fires = (command: string) => shell.some((r) => evaluateSmartConditions({ command }, r));
  it.each([
    'npm publish',
    'npm publish --access public',
    'pnpm publish -r',
    'yarn npm publish',
    'cd dist && npm publish',
    'twine upload dist/*',
    'cargo publish',
    'gem push my-gem-1.0.0.gem',
    'docker push ghcr.io/o/img:1',
    'gh release create v1.2.0 --notes "x"',
    'gh release upload v1.2.0 out.tgz',
    // The same publish, spelled the ways people and agents really type it.
    'NPM_TOKEN=x npm publish',
    'sudo npm publish',
    'cd pkg\nnpm publish',
    '/usr/local/bin/npm publish',
    'npm --tag beta publish',
    'pnpm -r publish',
    'npx npm publish',
    'python -m twine upload dist/*',
    'poetry publish --build',
    'uv publish',
    'docker image push ghcr.io/o/img:1',
    'docker buildx build --push -t ghcr.io/o/img:1 .',
    'gh -R o/r release create v1',
    'npx lerna publish from-package',
    'npx changeset publish',
    'npx @vscode/vsce publish',
    'cd x && podman push img',
    // A dry run is still asked about: matching `--dry-run` anywhere in the
    // command let `npm publish --dry-run=false`, a `# --dry-run` comment or a
    // log file named `--dry-run` through. A review on a dry run costs little.
    'npm publish --dry-run=false',
    'npm publish # --dry-run',
    'npm publish > /tmp/no--dry-run.log',
    'cargo publish --dry-run',
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
    'git commit -m "npm publish later"',
    // A quoted mention outside a message flag (`echo "npm publish"`) does ask:
    // the command text keeps its quotes, and telling a mention from
    // `NPM_TOKEN="$T" npm publish` is beyond a regex. A review, not a block.
    'npm i publish-kit',
    'npm view x publishConfig',
    'npm test | grep publish',
    'gh release delete v1',
    'poetry install',
    'npm-run-all build publish',
    'pnpm-lock-check publish',
  ])('%s does not', (command) => {
    expect(fires(command)).toBe(false);
  });
});

describe('server scope: server and notServer', () => {
  it('reads the server from the hook spelling', () => {
    expect(mcpServerFromToolName('mcp__stripe__create_refund')).toBe('stripe');
    expect(mcpServerFromToolName('mcp__stripe_prod__create_refund')).toBe('stripe_prod');
    expect(mcpServerFromToolName('create_refund')).toBeUndefined();
  });

  it('server needs a matching label; notServer refuses one and admits none', () => {
    expect(ruleServerMatches({ server: '*stripe*' }, 'stripe')).toBe(true);
    expect(ruleServerMatches({ server: '*stripe*' }, 'Stripe-Prod')).toBe(true);
    expect(ruleServerMatches({ server: '*stripe*' }, 'paypal')).toBe(false);
    expect(ruleServerMatches({ server: '*stripe*' }, undefined)).toBe(false);
    expect(ruleServerMatches({ notServer: APP_SERVER_GLOB }, 'stripe')).toBe(false);
    expect(ruleServerMatches({ notServer: APP_SERVER_GLOB }, 'my-paypal')).toBe(false);
    expect(ruleServerMatches({ notServer: APP_SERVER_GLOB }, 'acme-billing')).toBe(true);
    expect(ruleServerMatches({ notServer: APP_SERVER_GLOB }, undefined)).toBe(true);
    expect(ruleServerMatches({}, undefined)).toBe(true);
  });
});

describe('the general action checks', () => {
  it('are catalog checks in their own group, on by default at review', () => {
    expect(CHECK_GROUPS.map((g) => g.id)).toContain('actions');
    for (const id of ['actions.money', 'actions.access', 'actions.publish']) {
      const def = getCheck(id);
      expect(def, id).toBeDefined();
      expect(def!.group).toBe('actions');
      expect(def!.defaultValue).toBe('review');
      expect(def!.plain, id).toBeTruthy();
      expect(def!.legacy?.length, id).toBeGreaterThan(0);
    }
    expect(getCheck('actions.money')!.legacy).toContain('review-action-money-refund');
    expect(getCheck('actions.access')!.legacy).toContain('review-action-access-membership');
    expect(getCheck('actions.publish')!.legacy).toContain('review-action-publish-release');
  });

  it('every rule is an MCP tool rule kept off a server an app shield claims', () => {
    for (const r of GENERAL_ACTION_RULES) {
      expect(r.tool, r.name).not.toBe('bash');
      expect(r.notServer, r.name).toBe(APP_SERVER_GLOB);
      expect(r.reason, r.name).toMatch(/check\)\.$/);
    }
  });

  // A shell publish names a registry, which is an app: it becomes a door of
  // that app's shield, and the exposure gate keeps logging a publish to the
  // project's own registry (node9Firewall#318).
  it('a shell publish is not a general check', () => {
    const names = GENERAL_ACTION_RULES.map((r) => r.name);
    expect(names).not.toContain('review-action-publish-npm-publish');
  });

  it('ship in the default config', () => {
    const names = new Set(DEFAULT_CONFIG.policy.smartRules.map((r) => r.name));
    for (const r of GENERAL_ACTION_RULES) expect(names.has(r.name), r.name).toBe(true);
  });
});

describe('app shields: one app, every door', () => {
  for (const name of ['stripe', 'paypal']) {
    it(`${name} is a shield whose tool rules are scoped to its own server`, () => {
      const shield = BUILTIN_SHIELDS[name];
      expect(shield).toBeDefined();
      const toolRules = shield.smartRules.filter((r) => r.tool !== 'bash');
      expect(toolRules.length).toBe(ACTION_TEMPLATES.finance.length);
      for (const r of toolRules) {
        expect(r.name).toMatch(new RegExp(`^shield:${name}:review-`));
        expect(r.server).toBe(`*${name}*`);
      }
      const doors = shield.smartRules.filter((r) => r.tool === 'bash');
      expect(doors.length).toBeGreaterThan(1);
    });
  }

  const door = (shield: string, command: string): string | undefined =>
    BUILTIN_SHIELDS[shield].smartRules
      .filter((r) => r.tool === 'bash')
      .find((r) => evaluateSmartConditions({ command }, r))?.name;

  it.each([
    ['stripe refunds create --charge ch_1', 'shield:stripe:review-cli'],
    ['NPM_TOKEN=x stripe refunds create --charge ch_1', 'shield:stripe:review-cli'],
    ['stripe payouts create --amount 1000 --currency usd', 'shield:stripe:review-cli'],
    ['stripe payment_intents confirm pi_1', 'shield:stripe:review-cli'],
    ['stripe post /v1/refunds -d charge=ch_1', 'shield:stripe:review-cli-request'],
    [
      'curl https://api.stripe.com/v1/refunds -u "$STRIPE_KEY:" -d charge=ch_1',
      'shield:stripe:review-api',
    ],
    ['curl -X POST https://api.stripe.com/v1/payouts -u "$K:"', 'shield:stripe:review-api'],
    ['http POST api.stripe.com/v1/transfers amount=100', 'shield:stripe:review-api'],
    [
      'python -c "import stripe; stripe.Refund.create(charge=\'ch_1\')"',
      'shield:stripe:review-code',
    ],
    [
      "const r = await stripe.refunds.create({ payment_intent: 'pi_1' });",
      'shield:stripe:review-code-node',
    ],
    [
      'requests.post("https://api.stripe.com/v1/refunds", data={"charge": "ch_1"})',
      'shield:stripe:review-code-http',
    ],
  ])('stripe: %s', (command, rule) => {
    expect(door('stripe', command)).toBe(rule);
  });

  it.each([
    'stripe refunds list',
    'stripe customers create --email a@example.com',
    'stripe login',
    'stripe listen --forward-to localhost:3000',
    'curl https://api.stripe.com/v1/refunds -u "$K:"',
    'curl https://api.stripe.com/v1/balance -u "$K:"',
    'stripe.Refund.list(limit=3)',
    'npm install stripe',
    'grep -r stripe src',
  ])('stripe leaves alone: %s', (command) => {
    expect(door('stripe', command)).toBeUndefined();
  });

  it.each([
    [
      'curl -X POST https://api-m.paypal.com/v2/payments/captures/7XY/refund -H "Authorization: Bearer $T"',
      'shield:paypal:review-api',
    ],
    [
      'curl https://api-m.paypal.com/v1/payments/payouts -d @batch.json -H "Authorization: Bearer $T"',
      'shield:paypal:review-api',
    ],
    [
      'curl -X POST https://api-m.paypal.com/v2/checkout/orders/5O1/capture -H "Authorization: Bearer $T"',
      'shield:paypal:review-api',
    ],
    ['const request = new paypal.payments.CapturesRefundRequest(id);', 'shield:paypal:review-code'],
    ['await ordersController.captureOrder({ id })', 'shield:paypal:review-code'],
  ])('paypal: %s', (command, rule) => {
    expect(door('paypal', command)).toBe(rule);
  });

  it.each([
    'curl -X POST https://api-m.sandbox.paypal.com/v2/payments/captures/7XY/refund',
    'curl https://api-m.paypal.com/v2/checkout/orders/5O1',
    'npm install @paypal/paypal-server-sdk',
  ])('paypal leaves alone: %s', (command) => {
    expect(door('paypal', command)).toBeUndefined();
  });
});

describe('the gate', () => {
  const cfgWith = (...shields: string[]) =>
    ({
      ...DEFAULT_CONFIG,
      settings: { ...DEFAULT_CONFIG.settings, mode: 'standard' },
      policy: {
        ...DEFAULT_CONFIG.policy,
        smartRules: [
          ...DEFAULT_CONFIG.policy.smartRules,
          ...shields.flatMap((s) => BUILTIN_SHIELDS[s].smartRules),
        ],
      },
    }) as typeof DEFAULT_CONFIG;
  const gate = (cfg: typeof DEFAULT_CONFIG, tool: string, args: unknown, mcpServer?: string) =>
    evaluatePolicy(cfg, tool, args, { agent: 'Claude Code', mcpServer });

  it('by default: an action on an unknown or unnamed server is reviewed by the general check', async () => {
    const cfg = cfgWith();
    const cases: Array<[string, string]> = [
      ['send_money', 'review-action-money-transfer'],
      ['create_refund', 'review-action-money-refund'],
      ['mcp__acme_billing__refund_order', 'review-action-money-refund'],
      ['mcp__workspace__update_password', 'review-action-access-password'],
      ['invite_user_to_slack', 'review-action-access-membership'],
      ['post_webpage', 'review-action-publish-post'],
    ];
    for (const [tool, rule] of cases) {
      const r = await gate(cfg, tool, { amount: 1 });
      expect(r.decision, tool).toBe('review');
      expect(r.ruleName, tool).toBe(rule);
    }
  });

  it('by default: user and access management is reviewed, ordinary work in the same apps passes', async () => {
    const cfg = cfgWith();
    const cases: Array<[string, unknown, string]> = [
      ['mcp__chat__add_user_to_channel', { user: 'eve', channel: 'general' }, 'membership'],
      ['add_user_to_channel', { user: 'eve', channel: 'general' }, 'membership'],
      ['mcp__chat__remove_user_from_slack', { user: 'eve' }, 'membership'],
      ['remove_user_from_slack', { user: 'eve' }, 'membership'],
      ['mcp__drive__share_file', { file_id: '7', email: 'eve@example.test' }, 'access'],
      ['share_file', { file_id: '7', email: 'eve@example.test' }, 'access'],
    ];
    for (const [tool, args, rule] of cases) {
      const r = await gate(cfg, tool, args);
      expect(r.decision, tool).toBe('review');
      expect(r.ruleName, tool).toBe(`review-action-access-${rule}`);
    }
    for (const tool of [
      'mcp__chat__send_channel_message',
      'mcp__calendar__add_calendar_event_participants',
      'mcp__bank__update_user_info',
      'mcp__drive__create_file',
    ]) {
      expect((await gate(cfg, tool, { text: 'hi' })).decision, tool).toBe('allow');
    }
  });

  it('a server an app shield claims is quiet while that shield is off', async () => {
    const cfg = cfgWith();
    expect((await gate(cfg, 'mcp__stripe__create_refund', { amount: 1 })).decision).toBe('allow');
    expect((await gate(cfg, 'create_refund', { amount: 1 }, 'stripe-prod')).decision).toBe('allow');
    expect((await gate(cfg, 'mcp__paypal__create_refund', { amount: 1 })).decision).toBe('allow');
  });

  it('with Stripe on: its server is reviewed by its own rule, through the hook and the gateway; PayPal is untouched', async () => {
    const cfg = cfgWith('stripe');
    const hook = await gate(cfg, 'mcp__stripe__create_refund', { amount: 1 });
    expect(hook.decision).toBe('review');
    expect(hook.ruleName).toBe('shield:stripe:review-refund');
    const gateway = await gate(cfg, 'create_refund', { amount: 1 }, 'stripe');
    expect(gateway.ruleName).toBe('shield:stripe:review-refund');
    // The same tool from PayPal (shield off) stays quiet, not Stripe's to judge.
    expect((await gate(cfg, 'mcp__paypal__create_refund', { amount: 1 })).decision).toBe('allow');
    // An unnamed server is still the general check's.
    expect((await gate(cfg, 'create_refund', { amount: 1 })).ruleName).toBe(
      'review-action-money-refund'
    );
    // Reads pass.
    expect((await gate(cfg, 'mcp__stripe__list_customers', { limit: 10 })).decision).toBe('allow');
  });

  it('with Stripe on: the stripe CLI in the shell is reviewed by the Stripe shield', async () => {
    const r = await gate(cfgWith('stripe'), 'Bash', {
      command: 'stripe refunds create --charge ch_1',
    });
    expect(r.decision).toBe('review');
    expect(r.ruleName).toBe('shield:stripe:review-cli');
    expect(
      (await gate(cfgWith(), 'Bash', { command: 'stripe refunds create --charge ch_1' })).decision
    ).toBe('allow');
  });

  it('the check value governs the general rules: off lets the call through', async () => {
    const base = cfgWith();
    const cfg = {
      ...base,
      policy: {
        ...base.policy,
        checks: { 'actions.money': 'off' },
        smartRules: base.policy.smartRules.map((r: SmartRule) => ({ ...r, builtin: true })),
      },
    } as typeof DEFAULT_CONFIG;
    expect((await gate(cfg, 'send_money', { amount: 1 })).decision).toBe('allow');
    expect((await gate(cfg, 'invite_user_to_slack', { user: 'eve' })).decision).toBe('review');
  });
});
