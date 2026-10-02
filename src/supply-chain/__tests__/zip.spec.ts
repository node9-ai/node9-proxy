import { describe, it, expect, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { readZipEntries, readZipEntry } from '../zip';
import { buildZip } from './zip-fixture';

const tmp: string[] = [];
function open(buf: Buffer): { fd: number; size: number } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-zip-'));
  tmp.push(dir);
  const p = path.join(dir, 'a.zip');
  fs.writeFileSync(p, buf);
  const fd = fs.openSync(p, 'r');
  return { fd, size: buf.length };
}
afterEach(() => {
  for (const d of tmp.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});

describe('readZipEntries / readZipEntry', () => {
  it('reads stored and deflated entries', () => {
    const { fd, size } = open(
      buildZip([
        { name: 'MAL-1.json', data: '{"id":"MAL-1"}' },
        { name: 'GHSA-1.json', data: 'stored text', store: true },
      ])
    );
    const entries = readZipEntries(fd, size);
    expect(entries.map((e) => e.name)).toEqual(['MAL-1.json', 'GHSA-1.json']);
    expect(readZipEntry(fd, entries[0]).toString()).toBe('{"id":"MAL-1"}');
    expect(readZipEntry(fd, entries[1]).toString()).toBe('stored text');
    fs.closeSync(fd);
  });

  it('follows the ZIP64 end record when the 32-bit fields are saturated', () => {
    const { fd, size } = open(
      buildZip(
        [
          { name: 'a.json', data: 'A' },
          { name: 'b.json', data: 'B' },
        ],
        { zip64: true }
      )
    );
    const entries = readZipEntries(fd, size);
    expect(entries.map((e) => readZipEntry(fd, e).toString())).toEqual(['A', 'B']);
    fs.closeSync(fd);
  });

  it('rejects a file with no end record', () => {
    const { fd, size } = open(Buffer.from('not a zip at all, just text'));
    expect(() => readZipEntries(fd, size)).toThrow(/end of central directory/);
    fs.closeSync(fd);
  });

  it('refuses an entry above the size cap (zip-bomb guard)', () => {
    const big = Buffer.alloc(5 * 1024 * 1024, 0x61); // deflates to a few KB
    const { fd, size } = open(buildZip([{ name: 'bomb.json', data: big }]));
    const [entry] = readZipEntries(fd, size);
    expect(() => readZipEntry(fd, entry)).toThrow(/size cap/);
    // A lying header (small declared size) is still stopped by inflate's own limit.
    const lying = { ...entry, uncompressedSize: 10 };
    expect(() => readZipEntry(fd, lying)).toThrow();
    fs.closeSync(fd);
  });

  it('rejects an unsupported compression method', () => {
    const buf = buildZip([{ name: 'x', data: 'x', store: true }]);
    const { fd, size } = open(buf);
    const [entry] = readZipEntries(fd, size);
    expect(() => readZipEntry(fd, { ...entry, method: 12 })).toThrow(/unsupported/);
    fs.closeSync(fd);
  });
});
