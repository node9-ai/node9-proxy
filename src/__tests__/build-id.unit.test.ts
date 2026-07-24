// Unit tests for the daemon build identity (task #18, commit a).
//
// compareBuild is the safety core of the takeover rule: strict total order,
// version dominates, mtime only breaks version ties. describeBuildDrift is
// the doctor/status inference: "no /health on a serving daemon" itself proves
// an older build, because the installed build (this code) implements it.

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  computeBuildId,
  buildIdString,
  parseBuildId,
  compareBuild,
  describeBuildDrift,
  CURRENT_BUILD,
} from '../daemon/build-id';

const b = (version: string, mtimeMs: number) => ({ version, mtimeMs });

describe('compareBuild — strict total order', () => {
  it('version dominates mtime (older version with newer mtime still loses)', () => {
    expect(compareBuild(b('1.64.0', 1000), b('1.63.0', 9999))).toBeGreaterThan(0);
    expect(compareBuild(b('1.63.0', 9999), b('1.64.0', 1000))).toBeLessThan(0);
  });

  it('numeric compare, not lexicographic (1.10.0 > 1.9.0)', () => {
    expect(compareBuild(b('1.10.0', 0), b('1.9.0', 0))).toBeGreaterThan(0);
  });

  it('version tie → mtime breaks it', () => {
    expect(compareBuild(b('1.63.0', 2000), b('1.63.0', 1000))).toBeGreaterThan(0);
    expect(compareBuild(b('1.63.0', 1000), b('1.63.0', 2000))).toBeLessThan(0);
  });

  it('full tie → 0 (equal ⇒ yield, no ping-pong)', () => {
    expect(compareBuild(b('1.63.0', 1000), b('1.63.0', 1000))).toBe(0);
  });

  it('a malformed peer version can never win (parses as 0.0.0-ish)', () => {
    expect(compareBuild(b('garbage', 9999), b('0.0.1', 0))).toBeLessThan(0);
  });
});

describe('buildIdString / parseBuildId round-trip', () => {
  it('round-trips', () => {
    const id = b('1.63.0', 1753357612975);
    expect(parseBuildId(buildIdString(id))).toEqual(id);
  });

  it('rejects malformed inputs (callers must yield, not guess)', () => {
    for (const bad of [null, undefined, '', '1.63.0', '+123', 'x+y', '1.63.0+-5', 42]) {
      expect(parseBuildId(bad as never)).toBeNull();
    }
  });
});

describe('computeBuildId', () => {
  it('reads the real package.json version and stats the entry file', () => {
    const pkg = JSON.parse(
      fs.readFileSync(path.resolve(__dirname, '../../package.json'), 'utf-8')
    ) as { version: string };
    const tmp = path.join(os.tmpdir(), `build-id-entry-${process.pid}.js`);
    fs.writeFileSync(tmp, '// entry');
    try {
      const id = computeBuildId(tmp);
      expect(id.version).toBe(pkg.version);
      expect(id.mtimeMs).toBeGreaterThan(0);
    } finally {
      fs.rmSync(tmp, { force: true });
    }
  });

  it('missing entry → mtime 0, version still set (never throws)', () => {
    const id = computeBuildId('/definitely/not/a/file.js');
    expect(id.mtimeMs).toBe(0);
    expect(id.version).not.toBe('');
  });

  it('CURRENT_BUILD is captured and shaped (module-load constant)', () => {
    expect(typeof CURRENT_BUILD.version).toBe('string');
    expect(typeof CURRENT_BUILD.mtimeMs).toBe('number');
  });
});

describe('describeBuildDrift — the doctor inference', () => {
  const installed = b('1.63.0', 2000);

  it('no daemon reachable → null (nothing to say)', () => {
    expect(describeBuildDrift(null, installed)).toBeNull();
  });

  it('same buildId → null (no drift)', () => {
    expect(describeBuildDrift({ version: '1.63.0', buildId: '1.63.0+2000' }, installed)).toBeNull();
  });

  it('different buildId → names BOTH builds', () => {
    const msg = describeBuildDrift({ version: '1.62.0', buildId: '1.62.0+1000' }, installed);
    expect(msg).toContain('1.62.0+1000');
    expect(msg).toContain('1.63.0+2000');
  });

  it('serving daemon without /health → provably older → drift', () => {
    const msg = describeBuildDrift('no-health', installed);
    expect(msg).toContain('OLD code');
    expect(msg).toContain('1.63.0');
  });

  it('malformed health payload (no usable buildId) → null, never a false accusation', () => {
    expect(describeBuildDrift({ version: 123, buildId: 42 }, installed)).toBeNull();
  });
});
