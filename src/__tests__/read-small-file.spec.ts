// The posture readers checked a file with stat and then read it by name
// (CodeQL js/file-system-race on the release PR, 2026-11-03): a file swapped
// in between could be a FIFO (the read blocks) or a much larger file. The
// shared reader opens once, checks the open descriptor, and reads at most the
// limit.
import { describe, it, expect, afterEach } from 'vitest';
import { execFileSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { readSmallFile } from '../utils/read-small-file';

const posix = it.skipIf(process.platform === 'win32');
const rooms: string[] = [];
const room = () => {
  const r = fs.mkdtempSync(path.join(os.tmpdir(), 'n9rs-'));
  rooms.push(r);
  return r;
};
afterEach(() => {
  for (const r of rooms.splice(0)) fs.rmSync(r, { recursive: true, force: true });
});

describe('readSmallFile', () => {
  it('reads a small regular file', () => {
    const f = path.join(room(), 'a.md');
    fs.writeFileSync(f, 'hello');
    expect(readSmallFile(f, 1024)).toBe('hello');
  });

  it('refuses a file over the limit', () => {
    const f = path.join(room(), 'big.md');
    fs.writeFileSync(f, 'x'.repeat(2048));
    expect(readSmallFile(f, 1024)).toBeNull();
  });

  it('refuses a directory and a missing file', () => {
    const r = room();
    expect(readSmallFile(r, 1024)).toBeNull();
    expect(readSmallFile(path.join(r, 'none'), 1024)).toBeNull();
  });

  posix('does not block on a FIFO', () => {
    const f = path.join(room(), 'pipe.md');
    execFileSync('mkfifo', [f]);
    const started = Date.now();
    expect(readSmallFile(f, 1024)).toBeNull();
    expect(Date.now() - started).toBeLessThan(2000);
  });

  posix('follows a link to a regular file (dotfile managers link CLAUDE.md)', () => {
    const r = room();
    const real = path.join(r, 'real.md');
    fs.writeFileSync(real, 'linked');
    const link = path.join(r, 'CLAUDE.md');
    fs.symlinkSync(real, link);
    expect(readSmallFile(link, 1024)).toBe('linked');
  });
});
