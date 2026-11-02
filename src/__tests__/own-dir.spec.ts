import { describe, it, expect, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { ensureOwnDir, isSameOwnDir, removeOldFlag } from '../utils/own-dir';

const itUnix = it.skipIf(process.platform === 'win32');
const rooms: string[] = [];
const room = () => {
  const r = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-own-dir-'));
  rooms.push(r);
  return r;
};
afterEach(() => {
  for (const r of rooms.splice(0)) fs.rmSync(r, { recursive: true, force: true });
});

const TEN_DAYS_AGO = (Date.now() - 10 * 24 * 60 * 60 * 1000) / 1000;

describe('ensureOwnDir', () => {
  it('creates the directory and returns its identity', () => {
    const dir = path.join(room(), 'a', 'flags');
    const seen = ensureOwnDir(dir);
    expect(seen).not.toBeNull();
    expect(isSameOwnDir(dir, seen!)).toBe(true);
  });

  itUnix('refuses a link', () => {
    const r = room();
    fs.mkdirSync(path.join(r, 'target'));
    fs.symlinkSync(path.join(r, 'target'), path.join(r, 'flags'));
    expect(ensureOwnDir(path.join(r, 'flags'))).toBeNull();
  });
});

// Review: the directory is checked once, and the clean-up runs later. A swap
// in between (rename the real directory away, put a link in its place) must
// stop every delete.
describe('removeOldFlag after a swap', () => {
  itUnix('deletes nothing once the checked directory was replaced by a link', () => {
    const r = room();
    const dir = path.join(r, 'flags');
    const seen = ensureOwnDir(dir)!;
    const target = path.join(r, 'project');
    fs.mkdirSync(target);
    const victim = path.join(target, 's1.node9-flag');
    fs.writeFileSync(victim, 'x');
    fs.utimesSync(victim, TEN_DAYS_AGO, TEN_DAYS_AGO);
    fs.renameSync(dir, path.join(r, 'moved'));
    fs.symlinkSync(target, dir);
    expect(isSameOwnDir(dir, seen)).toBe(false);
    removeOldFlag(dir, seen, 's1.node9-flag', Date.now());
    expect(fs.existsSync(victim)).toBe(true);
  });

  it('deletes an old flag in the directory it checked, and nothing else', () => {
    const dir = path.join(room(), 'flags');
    const seen = ensureOwnDir(dir)!;
    for (const name of ['s1.node9-flag', 'package.json', 'Makefile']) {
      fs.writeFileSync(path.join(dir, name), 'x');
      fs.utimesSync(path.join(dir, name), TEN_DAYS_AGO, TEN_DAYS_AGO);
      removeOldFlag(dir, seen, name, Date.now());
    }
    expect(fs.readdirSync(dir).sort()).toEqual(['Makefile', 'package.json']);
  });
});
