// Dangerous actions as category shields, at the REAL gate: `node9 shield
// enable finance` in a fresh HOME, then the PreToolUse hook on the namespaced
// tool names the agent sends. One end-to-end exercise per shield, as the
// repo rules require for anything that gates (node9Firewall#385).
import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import fs from 'fs';
import { CLI, makeHome, runCli, probe, cleanup, writeConfig } from './helpers/gauntlet';

const homes: string[] = [];
function home(shield?: string): string {
  const h = makeHome('node9-action-shield-');
  homes.push(h);
  writeConfig(h, {
    settings: {
      mode: 'standard',
      approvalTimeoutMs: 0,
      approvers: { native: false, browser: false, cloud: false, terminal: false },
    },
    policy: {},
  });
  if (shield) {
    const r = runCli(h, ['shield', 'enable', shield]);
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

describe.skipIf(process.platform === 'win32')('action shields at the real gate', () => {
  it('finance on: a refund is held for approval, a read passes', () => {
    const h = home('finance');
    const refund = probe(h, 'mcp__stripe__create_refund', {
      payment_intent: 'pi_3Q',
      amount: 1200,
    });
    expect(refund.error).toBeUndefined();
    expect(refund.verdict, refund.stdout).toBe('review');
    expect(refund.stdout).toContain('Finance shield');
    const read = probe(h, 'mcp__stripe__list_customers', { limit: 5 });
    expect(read.verdict, read.stdout).toBe('allow');
  });

  it('finance off (the default): the same refund passes', () => {
    const h = home();
    const refund = probe(h, 'mcp__stripe__create_refund', {
      payment_intent: 'pi_3Q',
      amount: 1200,
    });
    expect(refund.verdict, refund.stdout).toBe('allow');
  });

  it('identity on: a password change is held', () => {
    const h = home('identity');
    expect(probe(h, 'mcp__okta__reset_password', { user: 'u1' }).verdict).toBe('review');
    expect(probe(h, 'mcp__okta__list_users', {}).verdict).toBe('allow');
  });

  it('publishing on: both doors, the MCP release and the shell publish', () => {
    const h = home('publishing');
    expect(probe(h, 'mcp__github__create_release', { tag: 'v1' }).verdict).toBe('review');
    expect(probe(h, 'Bash', { command: 'npm publish --access public' }).verdict).toBe('review');
    expect(probe(h, 'Bash', { command: 'npm run build' }).verdict).toBe('allow');
  });
});
