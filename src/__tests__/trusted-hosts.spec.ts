// src/__tests__/trusted-hosts.spec.ts
// Unit tests for trusted-host allowlist: normalisation, exact match, wildcard, add/remove.
import { describe, it, expect, vi, beforeEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import {
  normalizeHost,
  isTrustedHost,
  addTrustedHost,
  removeTrustedHost,
  _resetTrustedHostsCache,
} from '../auth/trusted-hosts.js';

// ── normalizeHost ──────────────────────────────────────────────────────────────

describe('normalizeHost', () => {
  it('strips https:// protocol', () => {
    expect(normalizeHost('https://api.mycompany.com')).toBe('api.mycompany.com');
  });

  it('strips http:// protocol', () => {
    expect(normalizeHost('http://api.mycompany.com')).toBe('api.mycompany.com');
  });

  it('strips path', () => {
    expect(normalizeHost('https://api.mycompany.com/collect')).toBe('api.mycompany.com');
  });

  it('strips numeric port', () => {
    expect(normalizeHost('api.mycompany.com:443')).toBe('api.mycompany.com');
  });

  it('strips user@ prefix', () => {
    expect(normalizeHost('user@host.com')).toBe('host.com');
  });

  it('lowercases', () => {
    expect(normalizeHost('API.MyCompany.COM')).toBe('api.mycompany.com');
  });

  it('leaves plain FQDN unchanged', () => {
    expect(normalizeHost('api.mycompany.com')).toBe('api.mycompany.com');
  });
});

// ── isTrustedHost (with mocked fs) ────────────────────────────────────────────

vi.spyOn(os, 'homedir').mockReturnValue('/mock/home');

describe('isTrustedHost', () => {
  beforeEach(() => {
    _resetTrustedHostsCache();
    vi.spyOn(fs, 'readFileSync').mockImplementation((p) => {
      if (String(p).includes('trusted-hosts')) {
        return JSON.stringify({
          hosts: [
            { host: 'api.mycompany.com', addedAt: 1000, addedBy: 'user' },
            { host: '*.logs.io', addedAt: 1001, addedBy: 'user' },
          ],
        });
      }
      return '';
    });
  });

  it('matches exact host', () => {
    expect(isTrustedHost('api.mycompany.com')).toBe(true);
  });

  it('matches after stripping protocol and path', () => {
    expect(isTrustedHost('https://api.mycompany.com/collect')).toBe(true);
  });

  it('does NOT match subdomain of exact entry', () => {
    expect(isTrustedHost('evil.api.mycompany.com')).toBe(false);
  });

  it('does NOT match unrelated host', () => {
    expect(isTrustedHost('evil.com')).toBe(false);
  });

  it('wildcard *.logs.io matches direct subdomain', () => {
    expect(isTrustedHost('app.logs.io')).toBe(true);
  });

  it('wildcard *.logs.io matches deeper subdomain', () => {
    expect(isTrustedHost('us.app.logs.io')).toBe(true);
  });

  it('wildcard *.logs.io does NOT match bare domain logs.io', () => {
    // *.logs.io requires at least one subdomain label — the bare domain is not covered.
    expect(isTrustedHost('logs.io')).toBe(false);
  });

  it('wildcard does NOT match attacker suffix (evil.logs.io.attacker.com)', () => {
    // Ensures the suffix check uses a leading dot so "logs.io.attacker.com"
    // does not match "*.logs.io" via naive endsWith("logs.io").
    expect(isTrustedHost('evil.logs.io.attacker.com')).toBe(false);
  });

  it('wildcard match is case-insensitive', () => {
    expect(isTrustedHost('APP.LOGS.IO')).toBe(true);
  });

  it('exact match is case-insensitive', () => {
    expect(isTrustedHost('API.MyCompany.COM')).toBe(true);
  });

  it('wildcard does NOT match bare domain even with trailing dot', () => {
    expect(isTrustedHost('logs.io.')).toBe(false);
  });

  it('returns false when trusted-hosts.json is missing', () => {
    _resetTrustedHostsCache();
    vi.spyOn(fs, 'readFileSync').mockImplementation(() => {
      throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    });
    expect(isTrustedHost('api.mycompany.com')).toBe(false);
  });

  it('re-reads file when mtime changes (cross-process cache invalidation)', () => {
    // First call — cache is warm with api.mycompany.com
    expect(isTrustedHost('api.mycompany.com')).toBe(true);

    // Simulate another process writing a new file (different mtime, no new hosts)
    _resetTrustedHostsCache();
    vi.spyOn(fs, 'readFileSync').mockImplementation((p) => {
      if (String(p).includes('trusted-hosts')) {
        return JSON.stringify({ hosts: [] }); // host removed by CLI in another process
      }
      return '';
    });

    // Should re-read and return false — cache was invalidated
    expect(isTrustedHost('api.mycompany.com')).toBe(false);
  });
});

// ── addTrustedHost / removeTrustedHost ────────────────────────────────────────

describe('addTrustedHost / removeTrustedHost', () => {
  beforeEach(() => {
    _resetTrustedHostsCache();
    vi.spyOn(os, 'homedir').mockReturnValue('/mock/home');
    vi.spyOn(fs, 'mkdirSync').mockReturnValue(undefined);
    vi.spyOn(fs, 'renameSync').mockReturnValue(undefined);
  });

  it('addTrustedHost writes new entry', () => {
    vi.spyOn(fs, 'readFileSync').mockReturnValue(JSON.stringify({ hosts: [] }));
    const writeSpy = vi.spyOn(fs, 'writeFileSync').mockReturnValue(undefined);

    addTrustedHost('api.newhost.com');

    expect(writeSpy).toHaveBeenCalledOnce();
    const written = JSON.parse(writeSpy.mock.calls[0][1] as string);
    expect(written.hosts).toHaveLength(1);
    expect(written.hosts[0].host).toBe('api.newhost.com');
    expect(written.hosts[0].addedBy).toBe('user');
  });

  it('addTrustedHost normalizes URL before storing', () => {
    vi.spyOn(fs, 'readFileSync').mockReturnValue(JSON.stringify({ hosts: [] }));
    const writeSpy = vi.spyOn(fs, 'writeFileSync').mockReturnValue(undefined);

    addTrustedHost('https://api.newhost.com/v1/ingest');

    expect(writeSpy).toHaveBeenCalledOnce();
    const written = JSON.parse(writeSpy.mock.calls[0][1] as string);
    expect(written.hosts[0].host).toBe('api.newhost.com');
  });

  it('addTrustedHost is idempotent', () => {
    vi.spyOn(fs, 'readFileSync').mockReturnValue(
      JSON.stringify({ hosts: [{ host: 'api.newhost.com', addedAt: 1000, addedBy: 'user' }] })
    );
    const writeSpy = vi.spyOn(fs, 'writeFileSync').mockReturnValue(undefined);

    addTrustedHost('api.newhost.com');

    expect(writeSpy).not.toHaveBeenCalled();
  });

  it('removeTrustedHost removes existing entry and returns true', () => {
    vi.spyOn(fs, 'readFileSync').mockReturnValue(
      JSON.stringify({ hosts: [{ host: 'api.newhost.com', addedAt: 1000, addedBy: 'user' }] })
    );
    const writeSpy = vi.spyOn(fs, 'writeFileSync').mockReturnValue(undefined);

    const result = removeTrustedHost('api.newhost.com');

    expect(result).toBe(true);
    const written = JSON.parse(writeSpy.mock.calls[0][1] as string);
    expect(written.hosts).toHaveLength(0);
  });

  it('removeTrustedHost returns false when host not found', () => {
    vi.spyOn(fs, 'readFileSync').mockReturnValue(JSON.stringify({ hosts: [] }));
    const writeSpy = vi.spyOn(fs, 'writeFileSync').mockReturnValue(undefined);

    const result = removeTrustedHost('nothere.com');

    expect(result).toBe(false);
    expect(writeSpy).not.toHaveBeenCalled();
  });
});
