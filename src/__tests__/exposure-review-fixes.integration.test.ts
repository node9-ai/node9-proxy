// fw#318 review fixes, the real path: a keyed machine whose workspace list
// holds masked entries ('<masked>#sha256:<hex>', as the dashboard stores
// them), a real daemon, the built hook. Covers F7 (the managed list changes
// the verdict end to end), F4 (a masked entry matches by hash, a different
// IBAN with the same last four does not), F1 (a send let through draws no
// edge), F5 (another gate's row carries no exposure fields) and P1 (the
// audit log holds no full address or IBAN). IBANs and the token are built
// from parts: none is written whole here.
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'fs';
import path from 'path';
import { trustedEntryOf } from '@node9/policy-engine';
import { startDaemonHook, cliExists, type DaemonHook } from './helpers/daemon-hook';
import { writeKeyedHome } from './helpers/env';

const itUnix = it.skipIf(process.platform === 'win32' || !cliExists);
let h: DaemonHook;

function ibanOf(country: string, bban: string): string {
  const digits = [...`${bban}${country}00`].map((c) => parseInt(c, 36).toString()).join('');
  let rem = 0;
  for (const d of digits) rem = (rem * 10 + Number(d)) % 97;
  return `${country}${String(98 - rem).padStart(2, '0')}${bban}`;
}
const IBAN = ibanOf('GB', 'NODE' + '000000' + '12345678');
// IBAN-shaped with a failing checksum: a sandbox account. A valid IBAN in a
// transfer's arguments is stopped by the PII gate before exposure is judged.
const ACCOUNT = 'GB00' + 'NODE' + '000000' + '12345678';
const OTHER_ACCOUNT = 'GB00' + 'NODE' + '000001' + '12345678';
const PARTNER = 'billing' + '@partner.example';
// An AWS key id shape, concatenated so no scanner reads this file as a leak.
const TOKEN = 'AKIA' + 'J2XZKZMV' + 'P3NQRSTU';

function auditRows(): Array<Record<string, unknown>> {
  const file = path.join(h.home, '.node9', 'audit.log');
  if (!fs.existsSync(file)) return [];
  return fs
    .readFileSync(file, 'utf-8')
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l) as Record<string, unknown>);
}

beforeAll(async () => {
  if (!cliExists || process.platform === 'win32') return;
  h = await startDaemonHook({ sessionId: 'exposure-review-fixes' });
  writeKeyedHome(h.home);
  fs.writeFileSync(
    path.join(h.home, '.node9', 'rules-cache.json'),
    JSON.stringify({
      fetchedAt: '2026-10-18T00:00:00Z',
      rules: [],
      shields: [],
      managedConfig: {
        locked: [],
        untrustedContent: {
          enabled: true,
          afterExposure: 'ask-once',
          orgDomains: [],
          trustedRecipients: [
            trustedEntryOf(`email:${PARTNER}`),
            trustedEntryOf(`account:${ACCOUNT}`),
          ],
        },
      },
    })
  );
  // The session reads an email that names both, and an address it does not trust.
  expect(
    h.log(
      'mcp__gmail__get_message',
      { id: '1' },
      {
        output: `Our IBAN is ${IBAN}. Invoices go to ${PARTNER}, copies to attacker@example.com.`,
      }
    ).status
  ).toBe(0);
}, 20_000);

afterAll(() => h?.dispose());

describe('review fixes on a keyed machine', () => {
  itUnix('F7/F4: a masked workspace entry trusts the address it hashes', () => {
    expect(h.check('mcp__gmail__send_email', { to: PARTNER, body: 'invoice' }).ask).toBeUndefined();
    const other = h.check('mcp__gmail__send_email', { to: 'attacker@example.com', body: 'x' });
    expect(other.ask).toBe('ask');
  });

  itUnix('F4: the trusted account goes through; another with the same last four is held', () => {
    expect(h.check('mcp__bank__transfer', { recipient: ACCOUNT, amount: 10 }).ask).toBeUndefined();
    const held = h.check('mcp__bank__transfer', { recipient: OTHER_ACCOUNT, amount: 10 });
    expect(held.ask).toBe('ask');
  });

  itUnix('F1: the send let through carries the count and no edge to the read', () => {
    const row = auditRows().find(
      (r) => r.tool === 'mcp__gmail__send_email' && r.decision === 'allow'
    );
    expect(row?.exposure).toEqual({ kind: 'logged', destinations: 1 });
    expect(row?.exposureFromEid).toBeUndefined();
  });

  itUnix('F5: a DLP block after exposure carries no exposure fields', () => {
    h.check('mcp__gmail__send_email', { to: PARTNER, body: `token ${TOKEN}` });
    const block = auditRows().find((x) => String(x.checkedBy).includes('dlp'));
    expect(block).toBeDefined();
    expect(block?.exposure).toBeUndefined();
    expect(block?.exposureFromEid).toBeUndefined();
  });

  itUnix('P1: the audit log holds no full address or IBAN, and the read row is local', () => {
    const text = fs.readFileSync(path.join(h.home, '.node9', 'audit.log'), 'utf-8');
    expect(text).not.toContain(PARTNER);
    expect(text).not.toContain(IBAN);
    expect(text).not.toContain(ACCOUNT);
    expect(text).toContain('b***@partner.example');
    const source = auditRows().find((r) => r.checkedBy === 'exposure-source');
    expect(typeof source?.eid).toBe('string');
  });
});
