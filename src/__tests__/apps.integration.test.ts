// `node9 apps` at the real CLI and the real gate (node9Firewall#390, phase 2):
// a fresh HOME whose audit log shows an agent working in a project that
// depends on Stripe. Found = protected; turned off stays off; a server a
// person linked to Stripe meets Stripe's rules at the hook.
import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import fs from 'fs';
import path from 'path';
import { CLI, makeHome, runCli, probe, cleanup, writeConfig } from './helpers/gauntlet';

const SECRET = 'sk_live_' + 'Z9y8X7w6V5u4T3s2R1q0P9o8';
const homes: string[] = [];

function seededHome(): { home: string; project: string } {
  const home = makeHome('node9-apps-');
  homes.push(home);
  writeConfig(home, {
    settings: {
      mode: 'standard',
      approvalTimeoutMs: 0,
      approvers: { native: false, browser: false, cloud: false, terminal: false },
    },
    policy: {},
  });
  const project = path.join(home, 'shop');
  fs.mkdirSync(project, { recursive: true });
  fs.writeFileSync(
    path.join(project, 'package.json'),
    JSON.stringify({ dependencies: { stripe: '^14' } })
  );
  fs.writeFileSync(path.join(project, '.env'), `STRIPE_SECRET_KEY=${SECRET}\n`);
  const audit = [
    { ts: '2026-10-24T10:00:00Z', tool: 'Bash', argsPreview: 'npm test', workingDir: project },
  ];
  fs.writeFileSync(
    path.join(home, '.node9', 'audit.log'),
    audit.map((r) => JSON.stringify(r)).join('\n') + '\n'
  );
  return { home, project };
}

const read = (home: string, f: string) =>
  JSON.parse(fs.readFileSync(path.join(home, '.node9', f), 'utf8'));

beforeAll(() => {
  expect(fs.existsSync(CLI), `built CLI missing at ${CLI}`).toBe(true);
});
afterEach(() => {
  for (const h of homes.splice(0)) cleanup(h);
});

describe.skipIf(process.platform === 'win32')('node9 apps', () => {
  it('scan finds Stripe from the project, protects it, and keeps no value', () => {
    const { home } = seededHome();
    const r = runCli(home, ['apps', 'scan']);
    expect(r.error).toBeUndefined();
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toContain('Found Stripe: protected');
    const apps = read(home, 'apps.json');
    expect(apps.apps.stripe.state).toBe('on');
    expect(apps.apps.stripe.by).toBe('detected');
    expect(read(home, 'shields.json').active).toContain('stripe');
    expect(fs.readFileSync(path.join(home, '.node9', 'apps.json'), 'utf8')).not.toContain(SECRET);
    // The gate now reviews a Stripe refund.
    expect(probe(home, 'mcp__stripe__create_refund', { payment_intent: 'pi_1' }).verdict).toBe(
      'review'
    );
  });

  it('turned off stays off: a later scan does not turn it back on', () => {
    const { home } = seededHome();
    expect(runCli(home, ['apps', 'scan']).status).toBe(0);
    const off = runCli(home, ['apps', 'stripe', 'off']);
    expect(off.status, off.stderr).toBe(0);
    expect(read(home, 'shields.json').active).not.toContain('stripe');
    expect(runCli(home, ['apps', 'scan']).status).toBe(0);
    expect(read(home, 'apps.json').apps.stripe.state).toBe('off');
    expect(read(home, 'shields.json').active).not.toContain('stripe');
    expect(probe(home, 'mcp__stripe__create_refund', { payment_intent: 'pi_1' }).verdict).toBe(
      'allow'
    );
  });

  it('disabling an app shield before node9 found it still keeps it off', () => {
    const { home } = seededHome();
    expect(runCli(home, ['shield', 'disable', 'stripe']).status).toBe(0);
    expect(runCli(home, ['apps', 'scan']).status).toBe(0);
    const shieldsFile = path.join(home, '.node9', 'shields.json');
    const active = fs.existsSync(shieldsFile) ? read(home, 'shields.json').active : [];
    expect(active).not.toContain('stripe');
    expect(read(home, 'apps.json').apps.stripe.state).toBe('off');
  });

  it('node9 shield disable stripe is a decision detection keeps too', () => {
    const { home } = seededHome();
    expect(runCli(home, ['apps', 'scan']).status).toBe(0);
    expect(runCli(home, ['shield', 'disable', 'stripe']).status).toBe(0);
    expect(runCli(home, ['apps', 'scan']).status).toBe(0);
    expect(read(home, 'apps.json').apps.stripe).toMatchObject({ state: 'off', by: 'user' });
  });

  it('a server linked to Stripe meets Stripe rules, not the general check', () => {
    const { home } = seededHome();
    expect(runCli(home, ['apps', 'stripe', 'on']).status).toBe(0);
    const before = probe(home, 'mcp__acme_billing__create_refund', { id: 'o1' });
    expect(before.verdict).toBe('review');
    expect(before.stdout).toContain('Money check');
    const link = runCli(home, ['apps', 'link', 'acme_billing', 'stripe']);
    expect(link.status, link.stderr).toBe(0);
    const after = probe(home, 'mcp__acme_billing__create_refund', { id: 'o1' });
    expect(after.verdict).toBe('review');
    expect(after.stdout).toContain('(Stripe)');
  });

  it('an action verdict per app: refunds allowed with --force, payouts still asked', () => {
    const { home } = seededHome();
    expect(runCli(home, ['apps', 'stripe', 'on']).status).toBe(0);
    const noForce = runCli(home, ['apps', 'stripe', 'refunds', 'allow']);
    expect(noForce.status).toBe(1);
    expect(runCli(home, ['apps', 'stripe', 'refunds', 'allow', '--force']).status).toBe(0);
    expect(probe(home, 'mcp__stripe__create_refund', { id: 'r' }).verdict).toBe('allow');
    expect(probe(home, 'mcp__stripe__create_payout', { amount: 1 }).verdict).toBe('review');
  });

  it('the list names the app and how it was found', () => {
    const { home } = seededHome();
    expect(runCli(home, ['apps', 'scan']).status).toBe(0);
    const r = runCli(home, ['apps']);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/Stripe\s+protected/);
    expect(r.stdout).toContain('package stripe');
    expect(r.stdout).not.toContain(SECRET);
  });
});
