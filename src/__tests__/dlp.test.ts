import { describe, it, expect } from 'vitest';
import { scanArgs, DLP_PATTERNS } from '../dlp.js';

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
  it('exports at least 7 built-in patterns', () => {
    expect(DLP_PATTERNS.length).toBeGreaterThanOrEqual(7);
  });

  it('all patterns have name, regex, and severity', () => {
    for (const p of DLP_PATTERNS) {
      expect(p.name).toBeTruthy();
      expect(p.regex).toBeInstanceOf(RegExp);
      expect(['block', 'review']).toContain(p.severity);
    }
  });
});
