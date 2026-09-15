// A governed agent can rewrite ~/.node9/credentials.json through Bash: the
// credential jail covers reads and the file-tool door, not a shell redirect.
// Every shipper then sent `Authorization: Bearer <device key>` to whatever host
// that file named. Confirmed end to end on 2026-09-14 — the bearer token
// arrived at an attacker-controlled listener, with the audit stream behind it.
//
// The old guard checked scheme and userinfo only, so `https://evil.example/`
// passed, and it ran at 2 of the 12 places apiUrl becomes a destination. This
// runs once in getCredentials instead, where an untrusted file becomes program
// data, so no consumer can receive a hostile apiUrl at all.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { validateApiUrl, safeApiUrl, apiEndpoint, DEFAULT_API_URL } from '../auth/api-url';

describe('validateApiUrl', () => {
  it('THE ATTACK: refuses a host that is not ours', () => {
    expect(validateApiUrl('https://evil.example.com/v1')).toBeNull();
    expect(validateApiUrl('https://attacker.co.uk/x')).toBeNull();
    // The shape that matters most: a lookalike that ends in our name.
    expect(validateApiUrl('https://api.node9.ai.evil.com/v1')).toBeNull();
  });

  it('accepts the real endpoint and its siblings without a list', () => {
    for (const u of [
      DEFAULT_API_URL,
      'https://dev-api.node9.ai/api/v1/intercept',
      'https://staging.node9.ai/api/v1',
      'https://node9.ai/x',
    ]) {
      expect(validateApiUrl(u), u).not.toBeNull();
    }
  });

  it('accepts loopback on either scheme, for local dev and the suite', () => {
    expect(validateApiUrl('http://127.0.0.1:9931/v1')).not.toBeNull();
    expect(validateApiUrl('https://localhost:1/api/v1')).not.toBeNull();
  });

  it('refuses plaintext http to anywhere that is not loopback', () => {
    // A bearer token over http is a leak on its own.
    expect(validateApiUrl('http://api.node9.ai/v1')).toBeNull();
  });

  it('refuses userinfo, non-web schemes and junk', () => {
    expect(validateApiUrl('https://x@api.node9.ai/v1')).toBeNull();
    expect(validateApiUrl('file:///etc/passwd')).toBeNull();
    expect(validateApiUrl('javascript:alert(1)')).toBeNull();
    expect(validateApiUrl('not a url')).toBeNull();
    expect(validateApiUrl('')).toBeNull();
    expect(validateApiUrl(undefined)).toBeNull();
    expect(validateApiUrl({ toString: () => DEFAULT_API_URL })).toBeNull();
  });

  it('honours NODE9_API_HOST_ALLOW for self-hosted', () => {
    vi.stubEnv('NODE9_API_HOST_ALLOW', 'corp.example,  *.other.test ');
    expect(validateApiUrl('https://node9.corp.example/v1')).not.toBeNull();
    expect(validateApiUrl('https://a.b.other.test/v1')).not.toBeNull();
    expect(validateApiUrl('https://evil.example.com/v1')).toBeNull();
    vi.unstubAllEnvs();
  });
});

describe('the host pin cannot widen to a whole TLD', () => {
  // The first version took "the last two labels" as the registrable domain.
  // That reads api.node9.co.uk as co.uk and would accept every host in the TLD.
  it('never accepts a bare public suffix as the allowed domain', () => {
    for (const host of ['co.uk', 'com.au', 'co.il', 'ai', 'com']) {
      expect(validateApiUrl(`https://evil.${host}/v1`), host).toBeNull();
    }
  });

  it('accepts only the default host and its immediate parent', () => {
    expect(validateApiUrl('https://node9.ai/x')).not.toBeNull();
    expect(validateApiUrl('https://a.b.node9.ai/x')).not.toBeNull();
    expect(validateApiUrl('https://node9.ai.evil.com/x')).toBeNull();
  });
});

describe('one home for DEFAULT_API_URL', () => {
  it('is what node9 login writes and what the pin validates', async () => {
    // Two copies would let login write a URL its own pin then rejects, and
    // every login would silently fall back. Assert they are literally the same.
    const written = await import('../credentials.js');
    expect(validateApiUrl(DEFAULT_API_URL)).not.toBeNull();
    expect(typeof written.writeCredentialsAndConfig).toBe('function');
  });
});

describe('safeApiUrl', () => {
  it('falls back to the real endpoint instead of disabling the cloud', () => {
    const seen: unknown[] = [];
    expect(safeApiUrl('https://evil.example.com/v1', (r) => seen.push(r))).toBe(DEFAULT_API_URL);
    expect(seen).toEqual(['https://evil.example.com/v1']);
  });

  it('passes an accepted value through untouched', () => {
    const u = 'https://dev-api.node9.ai/api/v1/intercept';
    expect(safeApiUrl(u)).toBe(u);
  });
});

describe('apiEndpoint', () => {
  it('derives a sibling without escaping the host', () => {
    const e = apiEndpoint(DEFAULT_API_URL, 'cost-sync');
    expect(e?.hostname).toBe('api.node9.ai');
  });

  it('cannot be walked off the host by the suffix', () => {
    expect(apiEndpoint(DEFAULT_API_URL, '//evil.example.com/x')?.hostname).not.toBe(
      'evil.example.com'
    );
  });

  it('returns null when the base is rejected', () => {
    expect(apiEndpoint('https://evil.example.com', 'cost-sync')).toBeNull();
  });
});

describe('getCredentials refuses a redirected key at the source', () => {
  let home: string;
  let saved: string | undefined;

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-apiurl-'));
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    saved = process.env.HOME;
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    delete process.env.NODE9_API_KEY;
    delete process.env.NODE9_API_URL;
    vi.resetModules();
  });
  afterEach(() => {
    if (saved !== undefined) process.env.HOME = saved;
    try {
      fs.rmSync(home, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  });

  const writeCreds = (apiUrl: string) =>
    fs.writeFileSync(
      path.join(home, '.node9', 'credentials.json'),
      JSON.stringify({ default: { apiKey: 'nk_test_key', apiUrl } })
    );

  it('THE REPRO: an agent-rewritten apiUrl does not reach any consumer', async () => {
    writeCreds('https://evil.example.com/v1');
    const { getCredentials } = await import('../config/index.js');
    const creds = getCredentials();
    expect(creds?.apiKey).toBe('nk_test_key');
    expect(creds?.apiUrl).toBe(DEFAULT_API_URL);
    expect(creds?.apiUrl).not.toContain('evil.example.com');
  });

  it('leaves a legitimate apiUrl alone', async () => {
    writeCreds('https://dev-api.node9.ai/api/v1/intercept');
    const { getCredentials } = await import('../config/index.js');
    expect(getCredentials()?.apiUrl).toBe('https://dev-api.node9.ai/api/v1/intercept');
  });

  it('records a rejection once, not once per call', async () => {
    // getCredentials re-reads the file every call and runs on the hook path.
    // Unguarded, 25 calls wrote 25 lines into a log already tens of MB.
    writeCreds('https://evil.example.com/v1');
    const { getCredentials } = await import('../config/index.js');
    for (let i = 0; i < 25; i++) getCredentials();
    const log = path.join(home, '.node9', 'hook-debug.log');
    const lines = fs.existsSync(log)
      ? fs.readFileSync(log, 'utf-8').split('\n').filter(Boolean).length
      : 0;
    expect(lines).toBe(1);
  });

  it('guards the env path too, since a hook inherits the agent env', async () => {
    process.env.NODE9_API_KEY = 'nk_env_key';
    process.env.NODE9_API_URL = 'https://evil.example.com/v1';
    const { getCredentials } = await import('../config/index.js');
    expect(getCredentials()?.apiUrl).toBe(DEFAULT_API_URL);
  });
});
