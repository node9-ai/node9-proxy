/**
 * Unit tests for skill pinning (supply chain & update drift defense).
 * Mirrors src/__tests__/mcp-pin.unit.test.ts, with directory hashing and the
 * per-root `exists` flag added for AST 02 / AST 07 coverage.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

import {
  hashSkillRoot,
  getRootKey,
  readSkillPins,
  readSkillPinsSafe,
  checkPin,
  updatePin,
  removePin,
  clearAllPins,
  defaultSkillRootEntries,
  verifyAndPinRoots,
} from '../skill-pin';

// ---------------------------------------------------------------------------
// hashSkillRoot
// ---------------------------------------------------------------------------

describe('hashSkillRoot', () => {
  let tmpDir: string;
  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-skill-hash-'));
  });
  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('returns exists=false when the path does not exist', () => {
    const result = hashSkillRoot(path.join(tmpDir, 'nope'));
    expect(result).toEqual({ exists: false, contentHash: '', fileCount: 0 });
  });

  it('hashes a single file root', () => {
    const p = path.join(tmpDir, 'CLAUDE.md');
    fs.writeFileSync(p, 'hello');
    const r = hashSkillRoot(p);
    expect(r.exists).toBe(true);
    expect(r.contentHash).toMatch(/^[a-f0-9]{64}$/);
    expect(r.fileCount).toBe(1);
  });

  it("produces different hashes when a file's content changes", () => {
    const p = path.join(tmpDir, 'CLAUDE.md');
    fs.writeFileSync(p, 'a');
    const before = hashSkillRoot(p).contentHash;
    fs.writeFileSync(p, 'b');
    expect(hashSkillRoot(p).contentHash).not.toBe(before);
  });

  it('hashes a directory root recursively', () => {
    const root = path.join(tmpDir, 'skills');
    fs.mkdirSync(path.join(root, 'nested'), { recursive: true });
    fs.writeFileSync(path.join(root, 'a.md'), 'a');
    fs.writeFileSync(path.join(root, 'nested', 'c.md'), 'c');
    const r = hashSkillRoot(root);
    expect(r.fileCount).toBe(2);
    expect(r.contentHash).toMatch(/^[a-f0-9]{64}$/);
  });

  it('is order-invariant for directory roots', () => {
    const a = path.join(tmpDir, 'a');
    const b = path.join(tmpDir, 'b');
    fs.mkdirSync(a);
    fs.mkdirSync(b);
    fs.writeFileSync(path.join(a, 'z.md'), 'z');
    fs.writeFileSync(path.join(a, 'a.md'), 'a');
    fs.writeFileSync(path.join(b, 'a.md'), 'a');
    fs.writeFileSync(path.join(b, 'z.md'), 'z');
    expect(hashSkillRoot(a).contentHash).toBe(hashSkillRoot(b).contentHash);
  });

  it('detects added / removed / modified files', () => {
    const root = path.join(tmpDir, 'skills');
    fs.mkdirSync(root);
    fs.writeFileSync(path.join(root, 'a.md'), 'a');
    const h1 = hashSkillRoot(root).contentHash;
    fs.writeFileSync(path.join(root, 'b.md'), 'b');
    const h2 = hashSkillRoot(root).contentHash;
    expect(h2).not.toBe(h1);
    fs.writeFileSync(path.join(root, 'a.md'), 'tampered');
    expect(hashSkillRoot(root).contentHash).not.toBe(h2);
    fs.unlinkSync(path.join(root, 'b.md'));
    expect(hashSkillRoot(root).contentHash).not.toBe(h2);
  });

  it('skips symlinks (never follows them out of the tree)', () => {
    const root = path.join(tmpDir, 'skills');
    fs.mkdirSync(root);
    fs.writeFileSync(path.join(root, 'real.md'), 'real');
    try {
      fs.symlinkSync(path.join(tmpDir, 'outside.md'), path.join(root, 'link.md'));
    } catch {
      return; // Windows without developer mode — skip
    }
    expect(hashSkillRoot(root).fileCount).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// getRootKey
// ---------------------------------------------------------------------------

describe('getRootKey', () => {
  it('returns a stable 16-char hex string per path', () => {
    expect(getRootKey('/p/skills')).toMatch(/^[a-f0-9]{16}$/);
    expect(getRootKey('/p/skills')).toBe(getRootKey('/p/skills'));
    expect(getRootKey('/p/a')).not.toBe(getRootKey('/p/b'));
  });
});

// ---------------------------------------------------------------------------
// Pin file operations
// ---------------------------------------------------------------------------

describe('pin file operations', () => {
  let tmpHome: string;
  let origHome: string;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-skillpin-test-'));
    origHome = process.env.HOME!;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome; // Windows: os.homedir() reads USERPROFILE
  });

  afterEach(() => {
    process.env.HOME = origHome;
    process.env.USERPROFILE = origHome;
    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  it('returns empty roots when no file exists', () => {
    expect(readSkillPins().roots).toEqual({});
    expect(checkPin('abc1234567890123', 'h', true)).toBe('new');
  });

  it('updatePin + checkPin round-trip', () => {
    const key = getRootKey('/p');
    updatePin(key, '/p', 'a'.repeat(64), true, 3);
    expect(checkPin(key, 'a'.repeat(64), true)).toBe('match');
    expect(checkPin(key, 'b'.repeat(64), true)).toBe('mismatch');
  });

  it('classifies exists-flip as mismatch (both directions)', () => {
    const key = getRootKey('/p');
    // existed → vanished
    updatePin(key, '/p', 'a'.repeat(64), true, 1);
    expect(checkPin(key, '', false)).toBe('mismatch');
    // did not exist → appeared
    updatePin(key, '/p', '', false, 0);
    expect(checkPin(key, 'a'.repeat(64), true)).toBe('mismatch');
  });

  it('removePin + clearAllPins both work', () => {
    const key = getRootKey('/p');
    updatePin(key, '/p', 'a'.repeat(64), true, 1);
    removePin(key);
    expect(checkPin(key, 'a'.repeat(64), true)).toBe('new');
    updatePin(key, '/p', 'a'.repeat(64), true, 1);
    clearAllPins();
    expect(readSkillPins().roots).toEqual({});
  });

  it('persists the full pin entry correctly', () => {
    const key = getRootKey('/p');
    updatePin(key, '/p', 'c'.repeat(64), true, 7);
    const entry = readSkillPins().roots[key];
    expect(entry.rootPath).toBe('/p');
    expect(entry.contentHash).toBe('c'.repeat(64));
    expect(entry.exists).toBe(true);
    expect(entry.fileCount).toBe(7);
    expect(entry.pinnedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('pin file is created with mode 0o600', { skip: process.platform === 'win32' }, () => {
    updatePin(getRootKey('/p'), '/p', 'a'.repeat(64), true, 1);
    const stat = fs.statSync(path.join(tmpHome, '.node9', 'skill-pins.json'));
    expect(stat.mode & 0o777).toBe(0o600);
  });

  it('fails closed on corrupt pin file', () => {
    const dir = path.join(tmpHome, '.node9');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'skill-pins.json'), 'not json');
    expect(() => readSkillPins()).toThrow(/corrupt/i);
    expect(checkPin('anykey1234567890', 'h', true)).toBe('corrupt');
    const result = readSkillPinsSafe();
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('corrupt');
  });

  it('distinguishes missing vs corrupt in readSkillPinsSafe', () => {
    const missing = readSkillPinsSafe();
    expect(missing.ok).toBe(false);
    if (!missing.ok) expect(missing.reason).toBe('missing');
    updatePin(getRootKey('/p'), '/p', 'a'.repeat(64), true, 1);
    const ok = readSkillPinsSafe();
    expect(ok.ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Installed plugins as roots (review of the marketplace-catalog fix)
// ---------------------------------------------------------------------------

describe('installed plugins as pin roots', () => {
  let tmpHome: string;
  let origHome: string;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-skillpin-roots-'));
    origHome = process.env.HOME!;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
  });

  afterEach(() => {
    process.env.HOME = origHome;
    process.env.USERPROFILE = origHome;
    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  function install(count: number): void {
    const plugins: Record<string, unknown> = {};
    for (let i = 0; i < count; i++) {
      const dir = path.join(tmpHome, '.claude', 'plugins', 'cache', 'm', `p${i}`, '1.0.0');
      fs.mkdirSync(dir, { recursive: true });
      plugins[`p${i}@m`] = [{ version: '1.0.0', installPath: dir }];
    }
    fs.writeFileSync(
      path.join(tmpHome, '.claude', 'plugins', 'installed_plugins.json'),
      JSON.stringify({ plugins })
    );
  }

  it('pins every installed plugin, past the add-ons report cap of 100', () => {
    install(120);
    expect(defaultSkillRootEntries(tmpHome)).toHaveLength(120);
  });

  it('drops the pins of marketplace catalog folders that earlier versions wrote', () => {
    install(1);
    const catalog = path.join(tmpHome, '.claude', 'plugins', 'marketplaces', 'm', 'plugins', 'x');
    updatePin(getRootKey(catalog), catalog, 'a'.repeat(64), true, 1);
    updatePin(getRootKey('/my/AGENTS.md'), '/my/AGENTS.md', 'b'.repeat(64), true, 1);
    expect(verifyAndPinRoots(defaultSkillRootEntries(tmpHome))).toEqual({ kind: 'verified' });
    const roots = Object.values(readSkillPins().roots).map((r) => r.rootPath);
    expect(roots).not.toContain(catalog);
    // A pin the user asked for stays; the installed plugin is pinned.
    expect(roots).toContain('/my/AGENTS.md');
    expect(roots).toHaveLength(2);
  });

  it('a plugin version the workspace approved is re-pinned, not drift; any other change is', () => {
    install(1);
    const [root] = defaultSkillRootEntries(tmpHome);
    expect(root.plugin).toBe('p0@m');
    expect(verifyAndPinRoots([root])).toEqual({ kind: 'verified' });
    fs.writeFileSync(path.join(root.path, 'SKILL.md'), 'v2');
    const v2 = hashSkillRoot(root.path).contentHash;
    const approvedV2 = (_r: unknown, hash: string) => hash === v2;
    expect(verifyAndPinRoots([root], approvedV2)).toEqual({ kind: 'verified' });
    // v2 is now the pin: unchanged, it verifies without the approval.
    expect(verifyAndPinRoots([root])).toEqual({ kind: 'verified' });
    // A further change nobody approved is drift.
    fs.writeFileSync(path.join(root.path, 'SKILL.md'), 'v3');
    expect(verifyAndPinRoots([root], approvedV2).kind).toBe('drift');
  });
});
