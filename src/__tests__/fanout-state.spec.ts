import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { recordSpawnAndCheck } from '../loop-detector';

// The fan-out ledger beside the loop state (behavior.fanout, node9Firewall#427).

let home: string;
let saved: string | undefined;
beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-fanout-'));
  saved = process.env.HOME;
  process.env.HOME = home;
});
afterEach(() => {
  process.env.HOME = saved;
  fs.rmSync(home, { recursive: true, force: true });
});

describe('recordSpawnAndCheck', () => {
  it("counts a session's spawns in the window and is over past the threshold", () => {
    for (let i = 1; i <= 3; i++)
      expect(recordSpawnAndCheck('s1', 3, 60_000)).toEqual({ count: i, over: false });
    expect(recordSpawnAndCheck('s1', 3, 60_000)).toEqual({ count: 4, over: true });
    // Another session counts on its own.
    expect(recordSpawnAndCheck('s2', 3, 60_000)).toEqual({ count: 1, over: false });
  });

  it('forgets spawns older than the window', () => {
    const file = path.join(home, '.node9', 'fanout-state.json');
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const old = Date.now() - 120_000;
    fs.writeFileSync(file, JSON.stringify({ s1: [old, old, old], s3: [old] }));
    expect(recordSpawnAndCheck('s1', 3, 60_000)).toEqual({ count: 1, over: false });
    const state = JSON.parse(fs.readFileSync(file, 'utf-8')) as Record<string, number[]>;
    expect(state.s3).toBeUndefined();
    expect(state.s1).toHaveLength(1);
  });

  it('a broken state file starts fresh', () => {
    const file = path.join(home, '.node9', 'fanout-state.json');
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, '[not an object');
    expect(recordSpawnAndCheck('s1', 3, 60_000)).toEqual({ count: 1, over: false });
  });
});
