// Actions that move money, change access or publish, at the REAL gate
// (node9Firewall#385, node9Firewall#390): the PreToolUse hook in a fresh HOME,
// on the tool names the agent sends. The general checks (actions.money,
// actions.access, actions.publish) are on by default for every server no app
// shield claims; an app shield (stripe) covers its own server and its shell
// doors, and a claimed server stays quiet while its shield is off. One
// end-to-end exercise per path, as the repo rules require for anything that
// gates.
import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import fs from 'fs';
import { CLI, makeHome, runCli, probe, cleanup, writeConfig } from './helpers/gauntlet';

const homes: string[] = [];
function home(opts: { shield?: string; checks?: Record<string, string> } = {}): string {
  const h = makeHome('node9-action-shield-');
  homes.push(h);
  // A check value lives in the v2 file (`node9 checks` prints that shape).
  writeConfig(
    h,
    opts.checks
      ? {
          version: '2',
          mode: 'standard',
          checks: opts.checks,
          approvals: { channels: [], timeoutSeconds: 0 },
        }
      : {
          settings: {
            mode: 'standard',
            approvalTimeoutMs: 0,
            approvers: { native: false, browser: false, cloud: false, terminal: false },
          },
          policy: {},
        }
  );
  if (opts.shield) {
    const r = runCli(h, ['shield', 'enable', opts.shield]);
    expect(r.error).toBeUndefined();
    expect(r.status, r.stderr).toBe(0);
  }
  return h;
}

beforeAll(() => {
  expect(fs.existsSync(CLI), `built CLI missing at ${CLI}`).toBe(true);
});
afterEach(() => {
  for (const h of homes.splice(0)) cleanup(h);
});

describe.skipIf(process.platform === 'win32')('actions at the real gate', () => {
  it('by default: money on an unknown server is held by the Money check; a read passes', () => {
    const h = home();
    const refund = probe(h, 'mcp__acme_billing__refund_order', { order: 'o1', amount: 1200 });
    expect(refund.error).toBeUndefined();
    expect(refund.verdict, refund.stdout).toBe('review');
    expect(refund.stdout).toContain('Money check');
    expect(probe(h, 'mcp__acme_billing__list_orders', { limit: 5 }).verdict).toBe('allow');
  });

  it('by default: a server an app shield claims is quiet while that shield is off', () => {
    const h = home();
    expect(probe(h, 'mcp__stripe__create_refund', { payment_intent: 'pi_3Q' }).verdict).toBe(
      'allow'
    );
  });

  it('stripe on: its MCP refund and its CLI refund are held; PayPal is not its business', () => {
    const h = home({ shield: 'stripe' });
    const mcp = probe(h, 'mcp__stripe__create_refund', { payment_intent: 'pi_3Q', amount: 1200 });
    expect(mcp.verdict, mcp.stdout).toBe('review');
    expect(mcp.stdout).toContain('Stripe');
    const cli = probe(h, 'Bash', { command: 'stripe refunds create --charge ch_1' });
    expect(cli.verdict, cli.stdout).toBe('review');
    expect(probe(h, 'mcp__stripe__list_customers', { limit: 5 }).verdict).toBe('allow');
    expect(probe(h, 'mcp__paypal__create_refund', { id: 'c1' }).verdict).toBe('allow');
  });

  it('okta on: a password reset on its server and a user created through the API are held', () => {
    const h = home({ shield: 'okta' });
    const mcp = probe(h, 'mcp__okta__reset_password', { user: 'u1' });
    expect(mcp.verdict, mcp.stdout).toBe('review');
    expect(mcp.stdout).toContain('Okta');
    const api = probe(h, 'Bash', {
      command:
        'curl -X POST "https://acme.okta.com/api/v1/users?activate=true" -H "Authorization: SSWS $T" -d @u.json',
    });
    expect(api.verdict, api.stdout).toBe('review');
    expect(probe(h, 'mcp__okta__list_users', {}).verdict).toBe('allow');
  });

  it('square on: a refund on its server is held; a Squarespace server stays with the general checks', () => {
    const h = home({ shield: 'square' });
    const mcp = probe(h, 'mcp__square__create_refund', { payment_id: 'p1' });
    expect(mcp.verdict, mcp.stdout).toBe('review');
    expect(mcp.stdout).toContain('Square');
    const site = probe(h, 'mcp__squarespace__create_refund', { order: 'o1' });
    expect(site.verdict, site.stdout).toBe('review');
    expect(site.stdout).toContain('Money check');
  });

  it('the old finance shield name says what replaced it', () => {
    const h = home();
    const r = runCli(h, ['shield', 'enable', 'finance']);
    expect(r.error).toBeUndefined();
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('Money check');
  });

  it('by default: a password change, adding a user to a channel and sharing a file are held', () => {
    const h = home();
    expect(probe(h, 'mcp__acme_idp__reset_password', { user: 'u1' }).verdict).toBe('review');
    expect(probe(h, 'mcp__chat__add_user_to_channel', { user: 'eve' }).verdict).toBe('review');
    expect(probe(h, 'mcp__drive__share_file', { file_id: '7' }).verdict).toBe('review');
    expect(probe(h, 'mcp__acme_idp__list_users', {}).verdict).toBe('allow');
    expect(probe(h, 'mcp__chat__send_channel_message', { text: 'hi' }).verdict).toBe('allow');
  });

  it('by default: an MCP release is held; a shell publish waits for its registry shield', () => {
    const h = home();
    expect(probe(h, 'mcp__github__create_release', { tag: 'v1' }).verdict).toBe('review');
    // A shell publish names a registry (an app); it is in no shield for now,
    // as in 2.37.0's default (node9Firewall#390, design section 16).
    expect(probe(h, 'Bash', { command: 'npm publish --access public' }).verdict).toBe('allow');
  });

  it('a check set to off lets its actions through, and only its own', () => {
    const h = home({ checks: { 'actions.money': 'off' } });
    expect(probe(h, 'mcp__acme_billing__refund_order', { order: 'o1' }).verdict).toBe('allow');
    expect(probe(h, 'mcp__acme_idp__reset_password', { user: 'u1' }).verdict).toBe('review');
  });
});
