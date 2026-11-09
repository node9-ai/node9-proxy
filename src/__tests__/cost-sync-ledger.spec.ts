import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { writeLedgerOnce } from '../costSync';
import { readCostLedger, utcDay } from '../cost-ledger';

// The daemon writes today's spend ledger from the session files it parses
// (behavior.cost-budget, node9Firewall#427); on a HOME with no session file
// the ledger still exists, dated today, with no sessions.

let home: string;
let saved: { home?: string; profile?: string };
beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-ledger-sync-'));
  saved = { home: process.env.HOME, profile: process.env.USERPROFILE };
  // os.homedir() reads USERPROFILE on Windows, HOME elsewhere.
  process.env.HOME = home;
  process.env.USERPROFILE = home;
});
afterEach(() => {
  process.env.HOME = saved.home;
  process.env.USERPROFILE = saved.profile;
  fs.rmSync(home, { recursive: true, force: true });
});

describe('writeLedgerOnce', () => {
  it('writes a ledger for today under HOME, empty when there are no session files', () => {
    const now = new Date();
    writeLedgerOnce(now);
    const l = readCostLedger(home);
    expect(l).not.toBeNull();
    expect(l!.day).toBe(utcDay(now));
    expect(l!.asOf).toBe(now.toISOString());
    expect(l!.sessions).toEqual({});
    expect(l!.dayUSD).toBe(0);
    if (process.platform !== 'win32')
      expect(fs.statSync(path.join(home, '.node9', 'cost', 'sessions.json')).mode & 0o077).toBe(0);
  });
});
