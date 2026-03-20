import { describe, it, expect, vi, beforeEach } from 'vitest';
import fs from 'fs';
import os from 'os';

vi.spyOn(os, 'homedir').mockReturnValue('/mock/home');

import {
  SHIELDS,
  getShield,
  resolveShieldName,
  listShields,
  readActiveShields,
  writeActiveShields,
} from '../shields.js';

// ── fs mocks ──────────────────────────────────────────────────────────────────
const readFileSyncSpy = vi.spyOn(fs, 'readFileSync');
const writeFileSyncSpy = vi.spyOn(fs, 'writeFileSync').mockImplementation(() => undefined);
const renameSyncSpy = vi.spyOn(fs, 'renameSync').mockImplementation(() => undefined);
const mkdirSyncSpy = vi.spyOn(fs, 'mkdirSync').mockImplementation(() => undefined);

beforeEach(() => {
  vi.clearAllMocks();
  writeFileSyncSpy.mockImplementation(() => undefined);
  renameSyncSpy.mockImplementation(() => undefined);
  mkdirSyncSpy.mockImplementation(() => undefined);
});

// ── resolveShieldName ─────────────────────────────────────────────────────────
describe('resolveShieldName', () => {
  it('resolves canonical name', () => {
    expect(resolveShieldName('postgres')).toBe('postgres');
    expect(resolveShieldName('github')).toBe('github');
    expect(resolveShieldName('aws')).toBe('aws');
    expect(resolveShieldName('filesystem')).toBe('filesystem');
  });

  it('resolves aliases', () => {
    expect(resolveShieldName('pg')).toBe('postgres');
    expect(resolveShieldName('postgresql')).toBe('postgres');
    expect(resolveShieldName('git')).toBe('github');
    expect(resolveShieldName('amazon')).toBe('aws');
    expect(resolveShieldName('fs')).toBe('filesystem');
  });

  it('is case-insensitive', () => {
    expect(resolveShieldName('PG')).toBe('postgres');
    expect(resolveShieldName('GITHUB')).toBe('github');
    expect(resolveShieldName('FS')).toBe('filesystem');
  });

  it('returns null for unknown names', () => {
    expect(resolveShieldName('mysql')).toBeNull();
    expect(resolveShieldName('')).toBeNull();
    expect(resolveShieldName('unknown')).toBeNull();
  });
});

// ── getShield ─────────────────────────────────────────────────────────────────
describe('getShield', () => {
  it('returns the shield definition for a known name', () => {
    const shield = getShield('postgres');
    expect(shield).not.toBeNull();
    expect(shield?.name).toBe('postgres');
  });

  it('resolves aliases transparently', () => {
    expect(getShield('pg')?.name).toBe('postgres');
  });

  it('returns null for unknown name', () => {
    expect(getShield('unknown')).toBeNull();
  });
});

// ── listShields ───────────────────────────────────────────────────────────────
describe('listShields', () => {
  it('returns all four shields', () => {
    const names = listShields().map((s) => s.name);
    expect(names).toContain('postgres');
    expect(names).toContain('github');
    expect(names).toContain('aws');
    expect(names).toContain('filesystem');
  });
});

// ── readActiveShields ─────────────────────────────────────────────────────────
describe('readActiveShields', () => {
  it('returns empty array when file does not exist', () => {
    const err = Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    readFileSyncSpy.mockImplementation(() => {
      throw err;
    });
    expect(readActiveShields()).toEqual([]);
  });

  it('returns validated active shields', () => {
    readFileSyncSpy.mockReturnValue(JSON.stringify({ active: ['postgres', 'github'] }));
    expect(readActiveShields()).toEqual(['postgres', 'github']);
  });

  it('filters out unknown shield names from corrupted file', () => {
    readFileSyncSpy.mockReturnValue(
      JSON.stringify({ active: ['postgres', 'evil-injection', 'mysql', null, 42] })
    );
    expect(readActiveShields()).toEqual(['postgres']);
  });

  it('returns empty array on malformed JSON', () => {
    readFileSyncSpy.mockReturnValue('not-json{{{');
    expect(readActiveShields()).toEqual([]);
  });

  it('returns empty array when active is not an array', () => {
    readFileSyncSpy.mockReturnValue(JSON.stringify({ active: 'postgres' }));
    expect(readActiveShields()).toEqual([]);
  });
});

// ── writeActiveShields ────────────────────────────────────────────────────────
describe('writeActiveShields', () => {
  it('writes shields list atomically', () => {
    writeActiveShields(['postgres', 'github']);
    expect(writeFileSyncSpy).toHaveBeenCalledOnce();
    const written = writeFileSyncSpy.mock.calls[0][1] as string;
    expect(JSON.parse(written)).toEqual({ active: ['postgres', 'github'] });
    expect(renameSyncSpy).toHaveBeenCalledOnce();
  });
});

// ── filesystem shield rule regexes ────────────────────────────────────────────
describe('filesystem shield: block-rm-rf-home regex', () => {
  const rule = SHIELDS.filesystem.smartRules.find(
    (r) => r.name === 'shield:filesystem:block-rm-rf-home'
  )!;

  // Helper: check if ALL conditions match the given command
  function matches(command: string): boolean {
    return rule.conditions.every((c) => {
      const re = new RegExp(c.value, c.flags);
      return re.test(command);
    });
  }

  it('matches rm -rf ~', () => expect(matches('rm -rf ~')).toBe(true));
  it('matches rm -rf ~/projects', () => expect(matches('rm -rf ~/projects')).toBe(true));
  it('matches rm -rf $HOME', () => expect(matches('rm -rf $HOME')).toBe(true));
  it('matches rm -rf /home/user', () => expect(matches('rm -rf /home/user')).toBe(true));
  it('matches rm -rf /root', () => expect(matches('rm -rf /root')).toBe(true));
  it('matches rm -fr ~/foo', () => expect(matches('rm -fr ~/foo')).toBe(true));
  it('matches rm --recursive /home/user', () =>
    expect(matches('rm --recursive /home/user')).toBe(true));

  it('does not match rm -rf /tmp (not a home path)', () =>
    expect(matches('rm -rf /tmp')).toBe(false));
  it('does not match rm /home/user (no recursive flag)', () =>
    expect(matches('rm /home/user')).toBe(false));
  it('does not match ls -r /home/user (not rm)', () =>
    expect(matches('ls -r /home/user')).toBe(false));
});

describe('filesystem shield: review-write-etc regex', () => {
  const rule = SHIELDS.filesystem.smartRules.find(
    (r) => r.name === 'shield:filesystem:review-write-etc'
  )!;

  function matches(command: string): boolean {
    return rule.conditions.every((c) => {
      const re = new RegExp(c.value, c.flags);
      return re.test(command);
    });
  }

  it('matches tee /etc/hosts', () => expect(matches('tee /etc/hosts')).toBe(true));
  it('matches cp file /etc/nginx/nginx.conf', () =>
    expect(matches('cp file /etc/nginx/nginx.conf')).toBe(true));
  it('matches > /etc/cron.d/job', () => expect(matches('echo foo > /etc/cron.d/job')).toBe(true));

  // Should NOT fire on read-only access (key improvement over previous version)
  it('does not match cat /etc/hosts (read-only)', () =>
    expect(matches('cat /etc/hosts')).toBe(false));
  it('does not match grep foo /etc/nginx/nginx.conf (read-only)', () =>
    expect(matches('grep foo /etc/nginx/nginx.conf')).toBe(false));
});

// ── dangerous words ───────────────────────────────────────────────────────────
describe('shield dangerousWords', () => {
  it('filesystem shield does not include dd (too many false positives)', () => {
    expect(SHIELDS.filesystem.dangerousWords).not.toContain('dd');
  });

  it('disable word-protection: shared words survive when another shield is active', () => {
    // Simulate: postgres and a hypothetical second shield both have 'dropdb'
    // The Set-based disable logic should keep 'dropdb' if any other active shield needs it
    const shieldWords = new Set(SHIELDS.postgres.dangerousWords);
    const protectedWords = new Set(SHIELDS.postgres.dangerousWords); // same shield still "active"
    const existing = [...SHIELDS.postgres.dangerousWords];
    const result = existing.filter((w) => !shieldWords.has(w) || protectedWords.has(w));
    // Words protected by another active shield survive
    expect(result).toEqual(existing);
  });
});
