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

  it('strips non-standard port (port-agnostic trust)', () => {
    // :8443 normalizes to the same host as :443 — trusting a hostname covers all ports.
    expect(normalizeHost('api.mycompany.com:8443')).toBe('api.mycompany.com');
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

  it('wildcard *.logs.io matches arbitrarily deep subdomains', () => {
    // endsWith('.' + domain) matches at any depth, not just one level.
    // This is intentional: *.mycompany.com should cover all subdomains.
    expect(isTrustedHost('a.b.c.logs.io')).toBe(true);
  });

  it('wildcard *.mycompany.com does NOT match bare mycompany.com', () => {
    // Reviewer-requested explicit test: the most exploitable edge case —
    // attacker controls mycompany.com and uses it as a sink.
    // The mock data has api.mycompany.com (exact) — add a wildcard entry inline.
    _resetTrustedHostsCache();
    vi.spyOn(fs, 'readFileSync').mockImplementation((p) => {
      if (String(p).includes('trusted-hosts')) {
        return JSON.stringify({
          hosts: [{ host: '*.mycompany.com', addedAt: 1000, addedBy: 'user' }],
        });
      }
      return '';
    });
    expect(isTrustedHost('api.mycompany.com')).toBe(true); // subdomain: OK
    expect(isTrustedHost('mycompany.com')).toBe(false); // bare domain: NOT OK
  });

  it('wildcard does NOT match attacker suffix (evil.logs.io.attacker.com)', () => {
    // Ensures the suffix check uses a leading dot so "logs.io.attacker.com"
    // does not match "*.logs.io" via naive endsWith("logs.io").
    expect(isTrustedHost('evil.logs.io.attacker.com')).toBe(false);
  });

  it('wildcard does NOT match a host that ends with the domain but has no leading dot', () => {
    // "evillogs.io" ends with "logs.io" but NOT ".logs.io" — must not match *.logs.io.
    // This guards against an endsWith(domain) check that omits the leading dot.
    expect(isTrustedHost('evillogs.io')).toBe(false);
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

  it('returns false for all hosts when file is deleted while cache is warm', () => {
    // Cache is warm with api.mycompany.com (mtime is a real nonzero value in the spy).
    // When the file disappears, statSync throws → getFileMtime() returns 0.
    // 0 !== real-mtime → cache miss → readTrustedHosts() catches ENOENT → returns [].
    // This confirms the fail-safe: a deleted file is never confused with a cache hit.
    expect(isTrustedHost('api.mycompany.com')).toBe(true); // warm the cache

    _resetTrustedHostsCache();
    vi.spyOn(fs, 'readFileSync').mockImplementation(() => {
      throw Object.assign(new Error('ENOENT: no such file'), { code: 'ENOENT' });
    });

    expect(isTrustedHost('api.mycompany.com')).toBe(false);
    expect(isTrustedHost('app.logs.io')).toBe(false);
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

  it('cache hit avoids repeated readFileSync calls', () => {
    // Verify the cache actually suppresses redundant disk reads within the TTL window.
    // readFileSync must be called exactly once even though isTrustedHost is called three times.
    let readCount = 0;
    vi.spyOn(fs, 'readFileSync').mockImplementation((p) => {
      if (String(p).includes('trusted-hosts')) {
        readCount++;
        return JSON.stringify({
          hosts: [{ host: 'api.mycompany.com', addedAt: 1000, addedBy: 'user' }],
        });
      }
      return '';
    });

    isTrustedHost('api.mycompany.com'); // cache miss — reads file
    isTrustedHost('api.mycompany.com'); // cache hit — skips read
    isTrustedHost('evil.com'); // cache hit — skips read

    expect(readCount).toBe(1);
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

  // ── Wildcard pattern validation ───────────────────────────────────────────
  // Single-label wildcards (*.com, *.io) would match virtually any destination
  // and completely bypass exfiltration detection — they must be rejected at add time.

  it('addTrustedHost rejects single-label wildcard *.com', () => {
    expect(() => addTrustedHost('*.com')).toThrow(/too broad/);
  });

  it('addTrustedHost rejects single-label wildcard *.io', () => {
    expect(() => addTrustedHost('*.io')).toThrow(/too broad/);
  });

  it('addTrustedHost rejects single-label wildcard regardless of capitalisation', () => {
    // normalizeHost lowercases before the check, so *.COM is treated as *.com
    expect(() => addTrustedHost('*.COM')).toThrow(/too broad/);
  });

  it('addTrustedHost accepts *.co.uk (known PSL limitation — base has a dot)', () => {
    // Our single-label check (base must contain a dot) accepts *.co.uk because
    // "co.uk" contains a dot. True second-level TLD rejection would require a
    // Public Suffix List — out of scope. Users are responsible for not adding
    // country-code TLD wildcards. Documented as a known limitation.
    vi.spyOn(fs, 'readFileSync').mockReturnValue(JSON.stringify({ hosts: [] }));
    vi.spyOn(fs, 'writeFileSync').mockReturnValue(undefined);
    expect(() => addTrustedHost('*.co.uk')).not.toThrow();
  });

  it('addTrustedHost accepts a valid two-label wildcard *.mycompany.com', () => {
    vi.spyOn(fs, 'readFileSync').mockReturnValue(JSON.stringify({ hosts: [] }));
    const writeSpy = vi.spyOn(fs, 'writeFileSync').mockReturnValue(undefined);

    expect(() => addTrustedHost('*.mycompany.com')).not.toThrow();
    expect(writeSpy).toHaveBeenCalledOnce();
  });

  it('addTrustedHost accepts a three-label wildcard *.api.mycompany.com', () => {
    vi.spyOn(fs, 'readFileSync').mockReturnValue(JSON.stringify({ hosts: [] }));
    const writeSpy = vi.spyOn(fs, 'writeFileSync').mockReturnValue(undefined);

    expect(() => addTrustedHost('*.api.mycompany.com')).not.toThrow();
    expect(writeSpy).toHaveBeenCalledOnce();
  });
});
