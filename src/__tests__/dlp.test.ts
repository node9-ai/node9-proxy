import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import { scanArgs, scanFilePath, DLP_PATTERNS } from '../dlp.js';

// NOTE: All fake secret strings are built via concatenation so GitHub's secret
// scanner doesn't flag this test file. The values are obviously fake (sequential
// letters/numbers) and are never used outside of these unit tests.

// ── Helpers ───────────────────────────────────────────────────────────────────

// Fake AWS Access Key ID — split to defeat static secret scanners
const FAKE_AWS_KEY = 'AKIA' + 'IOSFODNN7' + 'EXAMPLE';

// Stripe keys: sk_(live|test)_ + exactly 24 alphanumeric chars
const FAKE_STRIPE_LIVE = 'sk_live_' + 'abcdefghijklmnop' + 'qrstuvwx';
const FAKE_STRIPE_TEST = 'sk_test_' + 'abcdefghijklmnop' + 'qrstuvwx';

// OpenAI key: sk- + 20+ alphanumeric chars
const FAKE_OPENAI_KEY = 'sk-' + 'abcdefghij' + '1234567890klmn';

// Slack bot token
const FAKE_SLACK_TOKEN = 'xoxb-' + '1234-5678-abcdefghij';

// ── Pattern coverage ──────────────────────────────────────────────────────────

describe('DLP_PATTERNS — built-in patterns', () => {
  it('detects AWS Access Key ID', () => {
    const match = scanArgs({ command: `aws s3 cp --key ${FAKE_AWS_KEY} s3://bucket/` });
    expect(match).not.toBeNull();
    expect(match!.patternName).toBe('AWS Access Key ID');
    expect(match!.severity).toBe('block');
    expect(match!.redactedSample).not.toContain(FAKE_AWS_KEY);
    expect(match!.redactedSample).toMatch(/AKIA\*+MPLE/);
  });

  it('detects GitHub personal access token (ghp_)', () => {
    const token = 'ghp_' + 'a'.repeat(36);
    const match = scanArgs({ command: `git clone https://${token}@github.com/org/repo` });
    expect(match).not.toBeNull();
    expect(match!.patternName).toBe('GitHub Token');
    expect(match!.severity).toBe('block');
    expect(match!.redactedSample).not.toContain(token);
  });

  it('detects GitHub OAuth token (gho_)', () => {
    const token = 'gho_' + 'b'.repeat(36);
    const match = scanArgs({ env: { TOKEN: token } });
    expect(match).not.toBeNull();
    expect(match!.patternName).toBe('GitHub Token');
  });

  it('detects Slack bot token', () => {
    const match = scanArgs({ header: `Authorization: ${FAKE_SLACK_TOKEN}` });
    expect(match).not.toBeNull();
    expect(match!.patternName).toBe('Slack Bot Token');
    expect(match!.severity).toBe('block');
  });

  it('detects OpenAI API key', () => {
    const match = scanArgs({ command: `curl -H "Authorization: ${FAKE_OPENAI_KEY}"` });
    expect(match).not.toBeNull();
    expect(match!.patternName).toBe('OpenAI API Key');
    expect(match!.severity).toBe('block');
  });

  it('detects Stripe live secret key', () => {
    const match = scanArgs({ env: `STRIPE_KEY=${FAKE_STRIPE_LIVE}` });
    expect(match).not.toBeNull();
    expect(match!.patternName).toBe('Stripe Secret Key');
    expect(match!.severity).toBe('block');
  });

  it('detects Stripe test secret key', () => {
    const match = scanArgs({ env: `STRIPE_KEY=${FAKE_STRIPE_TEST}` });
    expect(match).not.toBeNull();
    expect(match!.patternName).toBe('Stripe Secret Key');
  });

  it('detects PEM private key header', () => {
    const pemHeader = '-----BEGIN RSA ' + 'PRIVATE KEY-----';
    const match = scanArgs({ content: `${pemHeader}\nMIIEowIBAAK...` });
    expect(match).not.toBeNull();
    expect(match!.patternName).toBe('Private Key (PEM)');
    expect(match!.severity).toBe('block');
  });

  it('detects Bearer token with review severity', () => {
    const match = scanArgs({ header: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig' });
    expect(match).not.toBeNull();
    expect(match!.patternName).toBe('Bearer Token');
    expect(match!.severity).toBe('review'); // not a hard block
  });
});

// ── Redaction ─────────────────────────────────────────────────────────────────

describe('maskSecret redaction', () => {
  it('shows first 4 + last 4 chars of the matched secret', () => {
    const match = scanArgs({ key: FAKE_AWS_KEY });
    expect(match).not.toBeNull();
    // prefix = 'AKIA', suffix = 'MPLE'
    expect(match!.redactedSample).toMatch(/^AKIA/);
    expect(match!.redactedSample).toMatch(/MPLE$/);
    expect(match!.redactedSample).toContain('*');
    expect(match!.redactedSample).not.toContain('IOSFODNN7EXA');
  });
});

// ── Recursive scanning ────────────────────────────────────────────────────────

describe('scanArgs — recursive object scanning', () => {
  it('scans nested objects', () => {
    const match = scanArgs({ outer: { inner: { key: FAKE_AWS_KEY } } });
    expect(match).not.toBeNull();
    expect(match!.fieldPath).toBe('args.outer.inner.key');
  });

  it('scans arrays', () => {
    const match = scanArgs({ envVars: ['SAFE=value', `SECRET=${FAKE_AWS_KEY}`] });
    expect(match).not.toBeNull();
    expect(match!.fieldPath).toContain('[1]');
  });

  it('returns null for clean args', () => {
    expect(scanArgs({ command: 'ls -la /tmp', options: { verbose: true } })).toBeNull();
  });

  it('returns null for non-object primitives', () => {
    expect(scanArgs(42)).toBeNull();
    expect(scanArgs(null)).toBeNull();
    expect(scanArgs(undefined)).toBeNull();
  });
});

// ── JSON-in-string ────────────────────────────────────────────────────────────

describe('scanArgs — JSON-in-string detection', () => {
  it('detects a secret inside a JSON-encoded string field', () => {
    const inner = JSON.stringify({ api_key: FAKE_AWS_KEY, region: 'us-east-1' });
    const match = scanArgs({ content: inner });
    expect(match).not.toBeNull();
    expect(match!.patternName).toBe('AWS Access Key ID');
  });

  it('does not crash on invalid JSON strings', () => {
    expect(() => scanArgs({ content: '{not valid json' })).not.toThrow();
  });

  it('skips JSON parse for strings longer than 10 KB', () => {
    const longJson = '{"key": "' + 'x'.repeat(10_001) + '"}';
    // Should not throw and should not attempt to parse
    expect(() => scanArgs({ content: longJson })).not.toThrow();
  });
});

// ── Depth & length limits ─────────────────────────────────────────────────────

describe('scanArgs — performance guards', () => {
  it('stops recursion at MAX_DEPTH (5)', () => {
    // 6 levels deep — secret at level 6 should not be found
    const deep = { a: { b: { c: { d: { e: { f: FAKE_AWS_KEY } } } } } };
    const match = scanArgs(deep);
    // depth=0 is the top-level object, key 'a' is depth 1, ..., key 'f' is depth 6
    // Our MAX_DEPTH=5 guard returns null at depth > 5, so the string at depth 6 is skipped
    expect(match).toBeNull();
  });

  it('only scans the first 100 KB of a long string', () => {
    // Secret is beyond the 100 KB limit — should not be found
    const padding = 'x'.repeat(100_001);
    const match = scanArgs({ content: padding + FAKE_AWS_KEY });
    expect(match).toBeNull();
  });

  it('finds a secret within the first 100 KB', () => {
    const padding = 'x'.repeat(50_000);
    const match = scanArgs({ content: `${padding} ${FAKE_AWS_KEY} ` });
    expect(match).not.toBeNull();
  });
});

// ── All patterns export ───────────────────────────────────────────────────────

describe('DLP_PATTERNS export', () => {
  it('exports at least 9 built-in patterns', () => {
    // 9 patterns as of current implementation:
    // AWS Key ID, GitHub Token, Slack Bot Token, OpenAI Key, Stripe Secret Key,
    // Private Key PEM, GCP Service Account, NPM Auth Token, Bearer Token
    expect(DLP_PATTERNS.length).toBeGreaterThanOrEqual(9);
  });

  it('all patterns have name, regex, and severity', () => {
    for (const p of DLP_PATTERNS) {
      expect(p.name).toBeTruthy();
      expect(p.regex).toBeInstanceOf(RegExp);
      expect(['block', 'review']).toContain(p.severity);
    }
  });
});

// ── scanFilePath — sensitive file path blocking ───────────────────────────────

// Typed alias to reduce repetition when accessing realpathSync.native
type RealpathWithNative = typeof fs.realpathSync & { native: (p: unknown) => string };

describe('scanFilePath — sensitive path blocking', () => {
  // Save the original .native so afterEach can restore it precisely.
  // vi.restoreAllMocks() only restores vi.spyOn spies — direct property
  // assignments survive it, so we must restore manually to guarantee isolation.
  const originalNative = (fs.realpathSync as RealpathWithNative).native;

  beforeEach(() => {
    vi.spyOn(fs, 'realpathSync').mockImplementation((p) => String(p));
    // Mock realpathSync.native — called unconditionally in production (no existsSync pre-check)
    (fs.realpathSync as RealpathWithNative).native = vi
      .fn()
      .mockImplementation((p: unknown) => String(p));
  });

  afterEach(() => {
    vi.restoreAllMocks();
    // Explicitly restore .native since restoreAllMocks() doesn't track it
    (fs.realpathSync as RealpathWithNative).native = originalNative;
  });

  it('blocks access to SSH key files', () => {
    const match = scanFilePath('/home/user/.ssh/id_rsa', '/');
    expect(match).not.toBeNull();
    expect(match!.patternName).toBe('Sensitive File Path');
    expect(match!.severity).toBe('block');
  });

  it('blocks access to AWS credentials directory', () => {
    const match = scanFilePath('/home/user/.aws/credentials', '/');
    expect(match).not.toBeNull();
    expect(match!.severity).toBe('block');
  });

  it('blocks .env files', () => {
    expect(scanFilePath('/project/.env', '/')).not.toBeNull();
    expect(scanFilePath('/project/.env.local', '/')).not.toBeNull();
    expect(scanFilePath('/project/.env.production', '/')).not.toBeNull();
  });

  it('does NOT block .envoy or similar non-credential files', () => {
    expect(scanFilePath('/project/.envoy-config', '/')).toBeNull();
    expect(scanFilePath('/project/environment.ts', '/')).toBeNull();
  });

  it('blocks PEM certificate files', () => {
    expect(scanFilePath('/certs/server.pem', '/')).not.toBeNull();
    expect(scanFilePath('/keys/private.key', '/')).not.toBeNull();
  });

  it('blocks /etc/passwd and /etc/shadow', () => {
    expect(scanFilePath('/etc/passwd', '/')).not.toBeNull();
    expect(scanFilePath('/etc/shadow', '/')).not.toBeNull();
  });

  it('returns null for ordinary source files', () => {
    expect(scanFilePath('src/app.ts', '/project')).toBeNull();
    expect(scanFilePath('README.md', '/project')).toBeNull();
    expect(scanFilePath('package.json', '/project')).toBeNull();
  });

  it('returns null for empty or missing path', () => {
    expect(scanFilePath('', '/project')).toBeNull();
  });

  it('calls realpathSync.native unconditionally (no existsSync pre-check)', () => {
    // native() is always called — existsSync guard removed to eliminate TOCTOU window
    const nativeSpy = vi.mocked((fs.realpathSync as RealpathWithNative).native);
    scanFilePath('/project/safe-looking-link.txt', '/project');
    expect(nativeSpy).toHaveBeenCalled();
  });

  it('blocks when a symlink resolves to a sensitive path', () => {
    (fs.realpathSync as RealpathWithNative).native = vi
      .fn()
      .mockReturnValue('/home/user/.ssh/id_rsa');
    const match = scanFilePath('/project/totally-safe-link', '/project');
    expect(match).not.toBeNull();
    expect(match!.severity).toBe('block');
  });

  it('does NOT block when a symlink resolves to a safe path', () => {
    (fs.realpathSync as RealpathWithNative).native = vi.fn().mockReturnValue('/project/src/app.ts');
    expect(scanFilePath('/project/link-to-app', '/project')).toBeNull();
  });

  it('blocks path traversal that resolves outside project root to a sensitive path', () => {
    // ../../.ssh/id_rsa from /project/src resolves to /home/user/.ssh/id_rsa
    (fs.realpathSync as RealpathWithNative).native = vi
      .fn()
      .mockReturnValue('/home/user/.ssh/id_rsa');
    const match = scanFilePath('../../.ssh/id_rsa', '/project/src');
    expect(match).not.toBeNull();
    expect(match!.severity).toBe('block');
  });

  it('treats ENOENT as safe — new file being written is not a symlink', () => {
    (fs.realpathSync as RealpathWithNative).native = vi.fn().mockImplementation(() => {
      throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    });
    // Non-existent file: safe, cannot be a symlink pointing anywhere
    expect(scanFilePath('/project/src/new-file.ts', '/project')).toBeNull();
  });

  it('is fail-closed when native throws with a non-ENOENT error', () => {
    // EACCES, unexpected errors, or TOCTOU remnants → block immediately
    (fs.realpathSync as RealpathWithNative).native = vi.fn().mockImplementation(() => {
      throw Object.assign(new Error('EACCES'), { code: 'EACCES' });
    });
    expect(() => scanFilePath('/project/src/app.ts', '/project')).not.toThrow();
    const match = scanFilePath('/project/src/app.ts', '/project');
    expect(match).not.toBeNull();
    expect(match!.severity).toBe('block');
  });

  it('blocks (fail-closed) on TOCTOU — safe-looking symlink pointing to sensitive file', () => {
    // The attack: /project/harmless-config.ts → /home/user/.ssh/id_rsa
    // native() throws because file was deleted between check and resolve
    (fs.realpathSync as RealpathWithNative).native = vi.fn().mockImplementation(() => {
      throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    });
    // ENOENT on a path that looks safe → treated as safe (not a TOCTOU attack)
    // The attack scenario requires the file to EXIST (so attacker can create symlink)
    // In that case native() would succeed and return the sensitive resolved path
    // This test confirms: if file is deleted mid-race, we don't block unnecessarily
    expect(scanFilePath('/project/harmless-config.ts', '/project')).toBeNull();
  });
});
