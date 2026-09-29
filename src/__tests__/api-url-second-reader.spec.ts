// #335 pinned apiUrl in getCredentials and its header said "a consumer can no
// longer receive a hostile apiUrl at all". Found on 2026-09-19 while verifying
// the CodeQL triage reasons against code: daemon/sync.ts had a SECOND reader,
// readCredentials(), "same pattern as getCredentials()", with no pin. The
// daemon's policy sync, the policy push, the audit shipper and posture all read
// through it, each sending `Authorization: Bearer <device key>` to whatever
// host the file names. Policy sync also WRITES what that host returns into
// rules-cache.json, so an agent that can rewrite credentials.json through the
// Bash door can serve itself a policy.
//
// Measured on origin/main 82f031d, temp HOME, hostile file:
//   getCredentials().apiUrl   https://api.node9.ai/api/v1/intercept
//   readCredentials().apiUrl  https://evil.example.com/api/v1/intercept/policies/sync
//
// Rows marked THE ATTACK / refuses / pins were red on the parent; the rest are
// the known-true instrument and the behaviour that must not change. The
// review of the fix (2026-09-20) added the rows in the last three blocks.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { DEFAULT_API_URL } from '../auth/api-url';

const SYNC_DEFAULT = `${DEFAULT_API_URL}/policies/sync`;
const HOSTILE = 'https://evil.example.com/api/v1/intercept';

function useTempHome() {
  let home = '';
  let saved: string | undefined;
  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-reader2-'));
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    saved = process.env.HOME;
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    delete process.env.NODE9_API_KEY;
    delete process.env.NODE9_API_URL;
    delete process.env.NODE9_PROFILE;
    vi.resetModules();
  });
  afterEach(() => {
    if (saved !== undefined) process.env.HOME = saved;
    delete process.env.NODE9_API_KEY;
    delete process.env.NODE9_API_URL;
    delete process.env.NODE9_PROFILE;
    try {
      fs.rmSync(home, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  });
  const writeCreds = (profiles: Record<string, unknown>) =>
    fs.writeFileSync(path.join(home, '.node9', 'credentials.json'), JSON.stringify(profiles));
  return { writeCreds };
}

describe('the second credentials reader (daemon/sync.ts readCredentials) is pinned', () => {
  const { writeCreds } = useTempHome();

  it('KNOWN-TRUE: getCredentials refuses the same file (the instrument works)', async () => {
    writeCreds({ default: { apiKey: 'nk_test_key', apiUrl: HOSTILE } });
    const { getCredentials } = await import('../config/index.js');
    expect(getCredentials()?.apiUrl).toBe(DEFAULT_API_URL);
  });

  it('THE ATTACK: a hostile profile apiUrl does not reach the policy sync', async () => {
    writeCreds({ default: { apiKey: 'nk_test_key', apiUrl: HOSTILE } });
    const { readCredentials } = await import('../daemon/sync.js');
    const creds = readCredentials();
    expect(creds?.apiKey).toBe('nk_test_key');
    expect(creds?.apiUrl).toBe(SYNC_DEFAULT);
  });

  it('pins the env path too, since the daemon inherits its environment', async () => {
    process.env.NODE9_API_KEY = 'nk_env_key';
    process.env.NODE9_API_URL = HOSTILE;
    const { readCredentials } = await import('../daemon/sync.js');
    expect(readCredentials()?.apiUrl).toBe(SYNC_DEFAULT);
  });

  it('keeps a legitimate staging host, with the sync suffix', async () => {
    writeCreds({
      default: { apiKey: 'nk_test_key', apiUrl: 'https://dev-api.node9.ai/api/v1/intercept' },
    });
    const { readCredentials } = await import('../daemon/sync.js');
    expect(readCredentials()?.apiUrl).toBe(
      'https://dev-api.node9.ai/api/v1/intercept/policies/sync'
    );
  });

  it('pins a named profile as well', async () => {
    process.env.NODE9_PROFILE = 'work';
    writeCreds({ work: { apiKey: 'nk_work_key', apiUrl: HOSTILE } });
    const { readCredentials } = await import('../daemon/sync.js');
    const creds = readCredentials();
    expect(creds?.apiKey).toBe('nk_work_key');
    expect(creds?.apiUrl).toBe(SYNC_DEFAULT);
  });

  it('still returns null when there is no key (unchanged)', async () => {
    const { readCredentials } = await import('../daemon/sync.js');
    expect(readCredentials()).toBeNull();
  });
});

describe('review findings: the shapes the rewrite had to keep or fix', () => {
  const { writeCreds } = useTempHome();

  it('a trailing slash on the stored base still reaches the sync route', async () => {
    // safeApiUrl hands an accepted value back unchanged, so `…/intercept/`
    // used to skip the rewrite: sync GET the bare base and every push keyed on
    // `/policies/sync` returned null silently.
    writeCreds({ default: { apiKey: 'nk_test_key', apiUrl: `${DEFAULT_API_URL}/` } });
    const { readCredentials } = await import('../daemon/sync.js');
    expect(readCredentials()?.apiUrl).toBe(SYNC_DEFAULT);
  });

  it('the legacy flat shape with a trailing slash gets the same treatment', async () => {
    writeCreds({ apiKey: 'nk_flat', apiUrl: `${DEFAULT_API_URL}/` });
    const { readCredentials } = await import('../daemon/sync.js');
    expect(readCredentials()?.apiUrl).toBe(SYNC_DEFAULT);
  });

  it('a non-string apiKey is "no key", not "Bearer 123"', async () => {
    // The deleted reader required a non-empty string; getCredentials did not,
    // so the daemon started shipping under a number. Both readers now agree.
    writeCreds({ default: { apiKey: 123, apiUrl: DEFAULT_API_URL } });
    const { getCredentials } = await import('../config/index.js');
    const { readCredentials } = await import('../daemon/sync.js');
    expect(getCredentials()).toBeNull();
    expect(readCredentials()).toBeNull();
  });

  it('an empty-string apiKey is "no key" too', async () => {
    writeCreds({ default: { apiKey: '' } });
    const { readCredentials } = await import('../daemon/sync.js');
    expect(readCredentials()).toBeNull();
  });
});

describe('the audit shipper endpoint uses the strong pin, not the scheme-only twin', () => {
  // auth/cloud.ts exported a validateApiUrl that predates #335: scheme and
  // userinfo only, any https host accepted. The shipper imported that one.
  it('refuses a non-node9 https host', async () => {
    const { buildBatchEndpoint } = await import('../daemon/audit-shipper.js');
    expect(buildBatchEndpoint(HOSTILE)).toBeNull();
  });

  it('still builds the endpoint for the real host and for loopback', async () => {
    const { buildBatchEndpoint } = await import('../daemon/audit-shipper.js');
    expect(buildBatchEndpoint(DEFAULT_API_URL)).toBe(`${DEFAULT_API_URL}/audit/batch`);
    expect(buildBatchEndpoint('http://127.0.0.1:1/intercept')).toBe(
      'http://127.0.0.1:1/intercept/audit/batch'
    );
  });
});

describe('revokeSelf sends the key only to a pinned host, and says so', () => {
  // `node9 logout` and `node9 uninstall` both read apiUrl straight off disk
  // and hand it to revokeSelf. The pin belongs inside revokeSelf, once.
  type Post = (url: string, body: unknown, bearer?: string) => Promise<unknown>;
  async function withPost(impl: Post) {
    vi.resetModules();
    const seen: string[] = [];
    vi.doMock('../utils/post-json', () => ({
      postJson: async (url: string, body: unknown, bearer?: string) => {
        seen.push(url);
        return impl(url, body, bearer);
      },
    }));
    const { revokeSelf } = await import('../cli/commands/logout.js');
    return { revokeSelf, seen, done: () => vi.doUnmock('../utils/post-json') };
  }

  it('posts the disconnect to the default host when the file names a hostile one', async () => {
    const { revokeSelf, seen, done } = await withPost(async () => ({ ok: true }));
    const r = await revokeSelf({ apiKey: 'nk_test_key', apiUrl: HOSTILE });
    done();
    expect(seen).toEqual([`${DEFAULT_API_URL}/machines/self/disconnect`]);
    expect(r.outcome).toBe('revoked');
  });

  it('an absent apiUrl means the default host (the callers no longer need a fallback)', async () => {
    const { revokeSelf, seen, done } = await withPost(async () => ({ ok: true }));
    await revokeSelf({ apiKey: 'nk_test_key' });
    done();
    expect(seen).toEqual([`${DEFAULT_API_URL}/machines/self/disconnect`]);
  });

  it('a 401 from the default host after the pin swapped the stored host is NOT "already"', async () => {
    // Self-hosted machine, shell without NODE9_API_HOST_ALLOW: the stored host
    // is rejected, the revoke goes to api.node9.ai, and that 401 used to print
    // "already disconnected" while the key stayed live on the operator's server.
    const { revokeSelf, done } = await withPost(async () => {
      throw new Error('HTTP 401');
    });
    const r = await revokeSelf({ apiKey: 'nk_test_key', apiUrl: HOSTILE });
    done();
    expect(r.outcome).toBe('unreachable');
    expect(r.outcome === 'unreachable' && r.detail).toContain('evil.example.com');
    expect(r.outcome === 'unreachable' && r.detail).toContain('NODE9_API_HOST_ALLOW');
  });

  it('a 401 from the host the file actually named still means "already"', async () => {
    const { revokeSelf, done } = await withPost(async () => {
      throw new Error('HTTP 401');
    });
    const r = await revokeSelf({ apiKey: 'nk_test_key', apiUrl: DEFAULT_API_URL });
    done();
    expect(r.outcome).toBe('already');
  });
});

describe('every module that turns the credentials file into an apiUrl is on the list', () => {
  // A static tripwire, and an approximation: the behavioural tests above are
  // the proof, this one makes the next reader fail with its own path in the
  // message. It is an explicit allowlist rather than a heuristic ("imports the
  // pin, or calls getCredentials, or calls revokeSelf"): the heuristic let a
  // file pass wholesale for one call anywhere in it. Adding a file here is a
  // conscious act, and the comment beside it has to say how that file pins.
  const READERS: Record<string, string> = {
    'auth/browser-login.ts':
      'compares only the saved attempt key; endpoints remain pinned by device-login and onboarding',
    'config/index.ts': 'getCredentials: the one parser, pins via safeApiUrl',
    'credentials.ts': 'the WRITER (node9 login); writes DEFAULT_API_URL, reads only to migrate',
    'cli.ts': 'uninstall: parses the profile map, hands apiUrl to revokeSelf, which pins',
    'cli/commands/logout.ts': 'logout: same as uninstall; revokeSelf pins inside',
  };

  it('finds exactly the known readers under src/', () => {
    const root = path.resolve(__dirname, '..');
    const found: string[] = [];
    const walk = (dir: string) => {
      for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
        const p = path.join(dir, ent.name);
        if (ent.isDirectory()) {
          if (ent.name === '__tests__' || ent.name === 'node_modules') continue;
          walk(p);
          continue;
        }
        if (!p.endsWith('.ts') || /\.(spec|test)\.ts$/.test(p)) continue;
        const rel = path.relative(root, p).split(path.sep).join('/');
        if (rel === 'auth/api-url.ts') continue; // the pin itself
        const raw = fs.readFileSync(p, 'utf-8');
        // Cheap prefilter on the raw text, then decide on the comment-stripped
        // text: daemon/sync.ts said "same pattern as getCredentials()" in a
        // comment and would have matched a naive scan. The line-comment strip
        // also truncates `//` inside string literals, which is harmless for
        // the two names checked here and would not be for a URL.
        if (!/credentials\.json|CREDENTIALS_FILE/.test(raw)) continue;
        const src = raw.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
        if (!/credentials\.json|CREDENTIALS_FILE/.test(src) || !src.includes('apiUrl')) continue;
        found.push(rel);
      }
    };
    walk(root);
    expect(
      found.sort(),
      'a file that names the credentials file and touches apiUrl is not in READERS; ' +
        'either it pins (add it with a reason) or it is the next unpinned reader'
    ).toEqual(Object.keys(READERS).sort());
  });
});
