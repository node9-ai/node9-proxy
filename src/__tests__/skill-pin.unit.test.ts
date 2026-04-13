/**
 * Unit tests for skill pinning (supply chain & update drift defense).
 *
 * TDD: These tests are written BEFORE the implementation exists.
 * Each test describes a contract that src/skill-pin.ts must satisfy.
 *
 * Mirrors the structure of src/__tests__/mcp-pin.unit.test.ts with two
 * extensions specific to skills: (a) hashing filesystem roots (files or
 * directories) instead of in-memory JSON tool definitions, and
 * (b) per-root `exists` bookkeeping so "skill root appeared" and
 * "skill root vanished" are both classified as drift.
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
  computePinDiff,
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

  it('returns exists=false with empty hash when the path does not exist', () => {
    const result = hashSkillRoot(path.join(tmpDir, 'does-not-exist'));
    expect(result.exists).toBe(false);
    expect(result.contentHash).toBe('');
    expect(result.fileCount).toBe(0);
  });

  it('hashes a single file root (exists=true, fileCount=1)', () => {
    const filePath = path.join(tmpDir, 'CLAUDE.md');
    fs.writeFileSync(filePath, 'hello skill');
    const result = hashSkillRoot(filePath);
    expect(result.exists).toBe(true);
    expect(result.contentHash).toMatch(/^[a-f0-9]{64}$/);
    expect(result.fileCount).toBe(1);
  });

  it("produces different hashes when a file's content changes", () => {
    const filePath = path.join(tmpDir, 'CLAUDE.md');
    fs.writeFileSync(filePath, 'original');
    const before = hashSkillRoot(filePath).contentHash;
    fs.writeFileSync(filePath, 'tampered');
    const after = hashSkillRoot(filePath).contentHash;
    expect(before).not.toBe(after);
  });

  it('hashes a directory root recursively (fileCount reflects all files)', () => {
    const root = path.join(tmpDir, 'skills');
    fs.mkdirSync(path.join(root, 'nested'), { recursive: true });
    fs.writeFileSync(path.join(root, 'a.md'), 'a');
    fs.writeFileSync(path.join(root, 'b.md'), 'b');
    fs.writeFileSync(path.join(root, 'nested', 'c.md'), 'c');
    const result = hashSkillRoot(root);
    expect(result.exists).toBe(true);
    expect(result.fileCount).toBe(3);
    expect(result.contentHash).toMatch(/^[a-f0-9]{64}$/);
  });

  it('is order-invariant for directory roots (filesystem traversal order must not affect hash)', () => {
    const rootA = path.join(tmpDir, 'skills-a');
    const rootB = path.join(tmpDir, 'skills-b');
    fs.mkdirSync(rootA, { recursive: true });
    fs.mkdirSync(rootB, { recursive: true });
    // Create in different order — contents are identical
    fs.writeFileSync(path.join(rootA, 'z.md'), 'z');
    fs.writeFileSync(path.join(rootA, 'a.md'), 'a');
    fs.writeFileSync(path.join(rootB, 'a.md'), 'a');
    fs.writeFileSync(path.join(rootB, 'z.md'), 'z');
    expect(hashSkillRoot(rootA).contentHash).toBe(hashSkillRoot(rootB).contentHash);
  });

  it('produces a different hash when a file is added to a directory', () => {
    const root = path.join(tmpDir, 'skills');
    fs.mkdirSync(root);
    fs.writeFileSync(path.join(root, 'a.md'), 'a');
    const before = hashSkillRoot(root).contentHash;
    fs.writeFileSync(path.join(root, 'b.md'), 'b');
    const after = hashSkillRoot(root).contentHash;
    expect(before).not.toBe(after);
  });

  it('produces a different hash when a file is removed from a directory', () => {
    const root = path.join(tmpDir, 'skills');
    fs.mkdirSync(root);
    fs.writeFileSync(path.join(root, 'a.md'), 'a');
    fs.writeFileSync(path.join(root, 'b.md'), 'b');
    const before = hashSkillRoot(root).contentHash;
    fs.unlinkSync(path.join(root, 'b.md'));
    const after = hashSkillRoot(root).contentHash;
    expect(before).not.toBe(after);
  });

  it("produces a different hash when a nested file's content changes", () => {
    const root = path.join(tmpDir, 'skills');
    fs.mkdirSync(path.join(root, 'nested'), { recursive: true });
    fs.writeFileSync(path.join(root, 'nested', 'c.md'), 'original');
    const before = hashSkillRoot(root).contentHash;
    fs.writeFileSync(path.join(root, 'nested', 'c.md'), 'tampered');
    const after = hashSkillRoot(root).contentHash;
    expect(before).not.toBe(after);
  });

  it('handles an empty directory', () => {
    const root = path.join(tmpDir, 'empty-skills');
    fs.mkdirSync(root);
    const result = hashSkillRoot(root);
    expect(result.exists).toBe(true);
    expect(result.fileCount).toBe(0);
    expect(result.contentHash).toMatch(/^[a-f0-9]{64}$/);
  });

  it('skips symlinks (never follows them into arbitrary filesystem locations)', () => {
    const root = path.join(tmpDir, 'skills');
    fs.mkdirSync(root);
    fs.writeFileSync(path.join(root, 'real.md'), 'real');
    const target = path.join(tmpDir, 'outside.md');
    fs.writeFileSync(target, 'outside');
    try {
      fs.symlinkSync(target, path.join(root, 'link.md'));
    } catch {
      // Windows without developer mode can't create symlinks — skip the assertion.
      return;
    }
    const result = hashSkillRoot(root);
    // Only the real file should be counted; link is ignored.
    expect(result.fileCount).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// getRootKey
// ---------------------------------------------------------------------------

describe('getRootKey', () => {
  it('returns a 16-char hex string', () => {
    const key = getRootKey('/home/user/.claude/skills');
    expect(key).toMatch(/^[a-f0-9]{16}$/);
  });

  it('returns the same key for the same path', () => {
    const p = '/home/user/.claude/skills';
    expect(getRootKey(p)).toBe(getRootKey(p));
  });

  it('returns different keys for different paths', () => {
    expect(getRootKey('/project-a/.cursor/rules')).not.toBe(getRootKey('/project-b/.cursor/rules'));
  });
});

// ---------------------------------------------------------------------------
// Pin file operations (read/write/check/update/remove)
// ---------------------------------------------------------------------------

describe('pin file operations', () => {
  let tmpHome: string;
  let origHome: string;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-skillpin-test-'));
    origHome = process.env.HOME!;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome; // Windows: os.homedir() reads USERPROFILE, not HOME
  });

  afterEach(() => {
    process.env.HOME = origHome;
    process.env.USERPROFILE = origHome;
    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  it('readSkillPins returns empty roots when no file exists', () => {
    const pins = readSkillPins();
    expect(pins.roots).toEqual({});
  });

  it('checkPin returns "new" for an unknown root', () => {
    expect(checkPin('abc1234567890123', 'somehash', true)).toBe('new');
  });

  it('updatePin saves a pin and checkPin returns "match"', () => {
    const key = getRootKey('/p/skills');
    const hash = 'a'.repeat(64);
    updatePin(key, '/p/skills', hash, true, 5);
    expect(checkPin(key, hash, true)).toBe('match');
  });

  it('checkPin returns "mismatch" when content hash differs', () => {
    const key = getRootKey('/p/skills');
    updatePin(key, '/p/skills', 'a'.repeat(64), true, 2);
    expect(checkPin(key, 'b'.repeat(64), true)).toBe('mismatch');
  });

  it('checkPin returns "mismatch" when exists flag flips (root now missing)', () => {
    const key = getRootKey('/p/skills');
    updatePin(key, '/p/skills', 'a'.repeat(64), true, 2);
    // Same "hash" (empty) but exists flipped from true to false = drift.
    expect(checkPin(key, '', false)).toBe('mismatch');
  });

  it('checkPin returns "mismatch" when exists flag flips (root newly appeared)', () => {
    const key = getRootKey('/p/skills');
    updatePin(key, '/p/skills', '', false, 0);
    expect(checkPin(key, 'a'.repeat(64), true)).toBe('mismatch');
  });

  it('removePin deletes a pin so checkPin returns "new"', () => {
    const key = getRootKey('/p/skills');
    updatePin(key, '/p/skills', 'a'.repeat(64), true, 1);
    removePin(key);
    expect(checkPin(key, 'a'.repeat(64), true)).toBe('new');
  });

  it('clearAllPins removes all pins', () => {
    updatePin('k1'.padEnd(16, '0'), '/a', 'a'.repeat(64), true, 1);
    updatePin('k2'.padEnd(16, '0'), '/b', 'b'.repeat(64), true, 1);
    clearAllPins();
    expect(readSkillPins().roots).toEqual({});
  });

  it('readSkillPins returns saved data with correct fields', () => {
    const key = getRootKey('/p/skills');
    updatePin(key, '/p/skills', 'c'.repeat(64), true, 7);
    const pins = readSkillPins();
    const entry = pins.roots[key];
    expect(entry).toBeDefined();
    expect(entry.rootPath).toBe('/p/skills');
    expect(entry.contentHash).toBe('c'.repeat(64));
    expect(entry.exists).toBe(true);
    expect(entry.fileCount).toBe(7);
    expect(entry.pinnedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('pin file is created with mode 0o600', { skip: process.platform === 'win32' }, () => {
    updatePin(getRootKey('/p/skills'), '/p/skills', 'a'.repeat(64), true, 1);
    const pinPath = path.join(tmpHome, '.node9', 'skill-pins.json');
    const stat = fs.statSync(pinPath);
    expect(stat.mode & 0o777).toBe(0o600);
  });

  it('readSkillPins throws on corrupted pin file (fail closed)', () => {
    const node9Dir = path.join(tmpHome, '.node9');
    fs.mkdirSync(node9Dir, { recursive: true });
    fs.writeFileSync(path.join(node9Dir, 'skill-pins.json'), 'not valid json');
    expect(() => readSkillPins()).toThrow(/corrupt/i);
  });

  it('readSkillPinsSafe returns corrupt for invalid JSON', () => {
    const node9Dir = path.join(tmpHome, '.node9');
    fs.mkdirSync(node9Dir, { recursive: true });
    fs.writeFileSync(path.join(node9Dir, 'skill-pins.json'), 'not valid json');
    const result = readSkillPinsSafe();
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('corrupt');
  });

  it('readSkillPinsSafe returns corrupt for empty file', () => {
    const node9Dir = path.join(tmpHome, '.node9');
    fs.mkdirSync(node9Dir, { recursive: true });
    fs.writeFileSync(path.join(node9Dir, 'skill-pins.json'), '');
    const result = readSkillPinsSafe();
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('corrupt');
  });

  it('readSkillPinsSafe returns corrupt for JSON missing roots object', () => {
    const node9Dir = path.join(tmpHome, '.node9');
    fs.mkdirSync(node9Dir, { recursive: true });
    fs.writeFileSync(path.join(node9Dir, 'skill-pins.json'), '{"version": 1}');
    const result = readSkillPinsSafe();
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('corrupt');
  });

  it('readSkillPinsSafe returns missing when no file exists', () => {
    const result = readSkillPinsSafe();
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('missing');
  });

  it('readSkillPinsSafe returns ok with valid pins', () => {
    updatePin(getRootKey('/p'), '/p', 'a'.repeat(64), true, 1);
    const result = readSkillPinsSafe();
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.pins.roots[getRootKey('/p')]).toBeDefined();
  });

  it('checkPin returns "corrupt" for corrupted pin file', () => {
    const node9Dir = path.join(tmpHome, '.node9');
    fs.mkdirSync(node9Dir, { recursive: true });
    fs.writeFileSync(path.join(node9Dir, 'skill-pins.json'), 'not valid json');
    expect(checkPin('anykey1234567890', 'anyhash', true)).toBe('corrupt');
  });

  it('checkPin returns "new" when file is missing (not corrupt)', () => {
    expect(checkPin('anykey1234567890', 'anyhash', true)).toBe('new');
  });
});

// ---------------------------------------------------------------------------
// computePinDiff — used by `node9 skill pin update` to show what changed
// ---------------------------------------------------------------------------

describe('computePinDiff', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-skill-diff-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('returns kind="unchanged" when the root has not changed', () => {
    const root = path.join(tmpDir, 'skills');
    fs.mkdirSync(root);
    fs.writeFileSync(path.join(root, 'a.md'), 'a');
    const hashed = hashSkillRoot(root);
    const diff = computePinDiff(
      {
        rootPath: root,
        exists: hashed.exists,
        contentHash: hashed.contentHash,
        fileCount: hashed.fileCount,
        pinnedAt: new Date().toISOString(),
      },
      root
    );
    expect(diff.kind).toBe('unchanged');
  });

  it('returns kind="appeared" when pin recorded !exists but the root now exists', () => {
    const root = path.join(tmpDir, 'skills');
    fs.mkdirSync(root);
    fs.writeFileSync(path.join(root, 'a.md'), 'a');
    const diff = computePinDiff(
      {
        rootPath: root,
        exists: false,
        contentHash: '',
        fileCount: 0,
        pinnedAt: new Date().toISOString(),
      },
      root
    );
    expect(diff.kind).toBe('appeared');
  });

  it('returns kind="vanished" when pin recorded exists but the root is now missing', () => {
    const root = path.join(tmpDir, 'skills-missing');
    const diff = computePinDiff(
      {
        rootPath: root,
        exists: true,
        contentHash: 'a'.repeat(64),
        fileCount: 1,
        pinnedAt: new Date().toISOString(),
      },
      root
    );
    expect(diff.kind).toBe('vanished');
  });

  it('reports added / removed / modified files for a directory root', () => {
    const root = path.join(tmpDir, 'skills');
    fs.mkdirSync(root);
    fs.writeFileSync(path.join(root, 'keep.md'), 'keep');
    fs.writeFileSync(path.join(root, 'modify.md'), 'original');
    fs.writeFileSync(path.join(root, 'remove.md'), 'gone-soon');
    const before = hashSkillRoot(root);
    const pin = {
      rootPath: root,
      exists: before.exists,
      contentHash: before.contentHash,
      fileCount: before.fileCount,
      pinnedAt: new Date().toISOString(),
      // Implementation detail: computePinDiff may need the per-file manifest.
      // We stash it on the pin here so the diff helper can show per-file changes.
      fileManifest: before.fileManifest,
    };

    // Mutate: modify one, remove one, add one
    fs.writeFileSync(path.join(root, 'modify.md'), 'tampered');
    fs.unlinkSync(path.join(root, 'remove.md'));
    fs.writeFileSync(path.join(root, 'add.md'), 'new');

    const diff = computePinDiff(pin, root);
    expect(diff.kind).toBe('changed');
    if (diff.kind !== 'changed') return;
    expect(diff.added).toEqual(['add.md']);
    expect(diff.removed).toEqual(['remove.md']);
    expect(diff.modified).toEqual(['modify.md']);
  });

  it('reports kind="changed" even without a fileManifest (single-file root)', () => {
    const file = path.join(tmpDir, 'CLAUDE.md');
    fs.writeFileSync(file, 'original');
    const before = hashSkillRoot(file);
    const pin = {
      rootPath: file,
      exists: before.exists,
      contentHash: before.contentHash,
      fileCount: before.fileCount,
      pinnedAt: new Date().toISOString(),
    };
    fs.writeFileSync(file, 'tampered');
    const diff = computePinDiff(pin, file);
    expect(diff.kind).toBe('changed');
  });
});
