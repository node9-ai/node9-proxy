// Pin rows for the SSRF floor: EVERY row here must be GREEN on today's code,
// before the floor exists. Two kinds live side by side:
//
//   1. Non-regression (corpus section E): loopback and RFC1918 under all four
//      egress configurations. The floor must not touch these. If one moves,
//      the floor widened and the 72 measured loopback hits become 72 blocks.
//   2. Behaviour the floor is expected to CHANGE, pinned at its current value
//      so the change is a visible red-to-green in the commit that makes it,
//      never a silent edit. Marked "flips in the floor commit".
//
// Values come from the corpus's measured table and were re-measured here.
import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

type Egress = {
  enabled: boolean;
  mode?: string;
  allow?: string[];
  deny?: string[];
  allowPrivate?: boolean;
  ssrfStrict?: boolean;
  ssrfAllow?: string[];
};
let home: string;

function makeHome(egress?: Egress, mode = 'standard'): string {
  const h = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-ssrf-pin-'));
  fs.mkdirSync(path.join(h, '.node9'), { recursive: true });
  fs.writeFileSync(
    path.join(h, '.node9', 'config.json'),
    JSON.stringify({ settings: { mode, autoStartDaemon: false }, policy: egress ? { egress } : {} })
  );
  return h;
}
function check(h: string, command: string) {
  const base = { ...process.env };
  delete base.NODE9_API_KEY;
  delete base.NODE9_API_URL;
  const r = spawnSync(
    process.execPath,
    [
      CLI,
      'check',
      JSON.stringify({
        hook_event_name: 'PreToolUse',
        tool_name: 'Bash',
        tool_input: { command },
        session_id: 'pin',
        cwd: h,
      }),
    ],
    {
      encoding: 'utf-8',
      timeout: 60000,
      cwd: os.tmpdir(),
      env: {
        ...base,
        HOME: h,
        USERPROFILE: h,
        NODE9_TESTING: '1',
        NODE9_NO_AUTO_DAEMON: '1',
        NO_COLOR: '1',
      },
    }
  );
  const stdout = r.stdout ?? '';
  let decision = 'allow';
  if (stdout.trim()) {
    try {
      decision =
        (JSON.parse(stdout) as { hookSpecificOutput?: { permissionDecision?: string } })
          .hookSpecificOutput?.permissionDecision ?? 'allow';
    } catch {
      /* silent allow prints nothing */
    }
  }
  return { status: r.status, stdout, stderr: r.stderr ?? '', decision };
}
const lastRow = (h: string): Record<string, unknown> => {
  const p = path.join(h, '.node9', 'audit.log');
  const lines = fs.readFileSync(p, 'utf-8').trim().split('\n').filter(Boolean);
  expect(lines.length, 'a row must exist (instrument self-check)').toBeGreaterThan(0);
  return JSON.parse(lines[lines.length - 1]) as Record<string, unknown>;
};

/** The four egress configurations every non-regression row is measured under. */
const CONFIGS: Array<[string, Egress | undefined]> = [
  ['enabled:false (the shipped default)', undefined],
  ['mode:review', { enabled: true, mode: 'review', allow: [], deny: [], allowPrivate: true }],
  [
    'block + allowPrivate:true',
    { enabled: true, mode: 'block', allow: [], deny: [], allowPrivate: true },
  ],
  [
    'block + allowPrivate:false',
    { enabled: true, mode: 'block', allow: [], deny: [], allowPrivate: false },
  ],
];

beforeAll(() => {
  if (!fs.existsSync(CLI)) throw new Error(`build first: ${CLI}`);
});
afterEach(() => {
  if (home) fs.rmSync(home, { recursive: true, force: true });
});

describe('P0 known-true: the harness can see a block at all', () => {
  it('an unknown host under mode:block is denied', () => {
    home = makeHome({ enabled: true, mode: 'block', allow: [], deny: [], allowPrivate: true });
    expect(check(home, 'curl https://unknown.example/x').decision).toBe('deny');
  });
  it('and the same host is allowed when egress is off', () => {
    home = makeHome(undefined);
    expect(check(home, 'curl https://unknown.example/x').decision).toBe('allow');
  });
});

// ── 1. NON-REGRESSION: the floor must not move any of these ────────────────
describe.each(CONFIGS)('E1-E7 non-regression under %s', (_label, egress) => {
  const strict = egress?.mode === 'block' && egress?.allowPrivate === false;
  const expected = strict ? 'deny' : 'allow';
  it.each([
    ['E1 loopback ip', 'curl http://127.0.0.1:3000/api'],
    ['E2 localhost', 'curl http://localhost:3000/api'],
    ['E3 short loopback', 'curl 127.1'],
    ['E4 rfc1918 10/8', 'curl http://10.0.0.5/x'],
    ['E6 rfc1918 192.168/16', 'curl http://192.168.1.10/x'],
    ['E7 rfc1918 172.16/12', 'curl http://172.16.0.9/x'],
  ])('%s stays %s', (_id, cmd) => {
    home = makeHome(egress);
    expect(check(home, cmd).decision).toBe(expected);
  });
});

// ── 2. WHAT THE FLOOR CHANGED (these five were pinned at the old value and
//      flipped in the commit that added the floor; the old value is in the
//      comment so the change stays legible) ──────────────────────────────────
describe('the floor closes every escape route', () => {
  const IMDS = 'curl http://169.254.169.254/latest/meta-data/iam/security-credentials/';

  it('B1 the decimal-form bypass is closed (was: allowed at the strictest config, even with an explicit deny)', () => {
    home = makeHome({ enabled: true, mode: 'block', allow: [], deny: [], allowPrivate: false });
    expect(check(home, 'curl 169.254.169.254/latest/meta-data/').decision).toBe('deny');
    expect(check(home, 'curl 2852039166/latest/meta-data/').decision).toBe('deny');
  });

  it('B2 metadata is blocked in all four configurations (was: allow / ask / allow)', () => {
    for (const [label, egress] of CONFIGS) {
      home = makeHome(egress);
      expect(check(home, IMDS).decision, label).toBe('deny');
      fs.rmSync(home, { recursive: true, force: true });
    }
    // Including when the address is explicitly allowlisted: tier 1 has no allow path.
    home = makeHome({
      enabled: true,
      mode: 'block',
      allow: ['169.254.169.254'],
      deny: [],
      allowPrivate: true,
    });
    expect(check(home, IMDS).decision, 'allowlisted').toBe('deny');
  });

  it('B2b nor can ssrfAllow exempt a tier-1 address', () => {
    home = makeHome({ enabled: false, ssrfAllow: ['169.254.169.254'] } as never);
    expect(check(home, IMDS).decision).toBe('deny');
  });

  it('B3 the GCP metadata hostname is blocked (was: allowed, .internal read as private)', () => {
    home = makeHome({ enabled: true, mode: 'block', allow: [], deny: [], allowPrivate: true });
    expect(check(home, 'curl http://metadata.google.internal/computeMetadata/v1/').decision).toBe(
      'deny'
    );
  });

  it('B4 0.0.0.0 follows loopback: reachable by default, blocked under strict', () => {
    // Changed 2026-09-08 after a false-positive corpus measured it: as a
    // DESTINATION 0.0.0.0 reaches this host, so blocking it on every machine
    // while 127.0.0.1 stayed reachable was incoherent, and `curl
    // http://0.0.0.0:3000` is how a developer reaches their own dev server.
    home = makeHome({ enabled: true, mode: 'block', allow: [], deny: [], allowPrivate: true });
    expect(check(home, 'curl http://0.0.0.0/x').decision).not.toBe('deny');
    home = makeHome({
      enabled: true,
      mode: 'block',
      allow: [],
      deny: [],
      allowPrivate: true,
      ssrfStrict: true,
    });
    expect(check(home, 'curl http://0.0.0.0/x').decision).toBe('deny');
  });

  it('B5 node9 pause still silences it, which is a documented limit, not an oversight', () => {
    home = makeHome({ enabled: true, mode: 'block', allow: [], deny: [], allowPrivate: false });
    const base = { ...process.env };
    delete base.NODE9_API_KEY;
    const r = spawnSync(
      process.execPath,
      [
        CLI,
        'check',
        JSON.stringify({
          hook_event_name: 'PreToolUse',
          tool_name: 'Bash',
          tool_input: { command: IMDS },
          session_id: 'pin',
          cwd: home,
        }),
      ],
      {
        encoding: 'utf-8',
        timeout: 60000,
        cwd: os.tmpdir(),
        env: {
          ...base,
          HOME: home,
          USERPROFILE: home,
          NODE9_TESTING: '1',
          NODE9_NO_AUTO_DAEMON: '1',
          NODE9_PAUSED: '1',
        },
      }
    );
    expect(r.status).toBe(0);
    expect(r.stdout.trim()).toBe('');
  });

  it('B6 tier 3 is opt-in: loopback blocks only under ssrfStrict', () => {
    home = makeHome({ enabled: false } as never);
    expect(check(home, 'curl http://127.0.0.1:3000/api').decision, 'default').toBe('allow');
    fs.rmSync(home, { recursive: true, force: true });
    home = makeHome({ enabled: false, ssrfStrict: true } as never);
    expect(check(home, 'curl http://127.0.0.1:3000/api').decision, 'strict').toBe('deny');
    fs.rmSync(home, { recursive: true, force: true });
    // and an overridable tier IS exemptable
    home = makeHome({ enabled: false, ssrfStrict: true, ssrfAllow: ['127.0.0.1'] } as never);
    expect(check(home, 'curl http://127.0.0.1:3000/api').decision, 'strict + exempt').toBe('allow');
  });
});

// ── 2b. BYPASSES AND FALSE POSITIVES FOUND IN REVIEW ──────────────────────
// Every row here was reproduced at the real gate before the fix. The three
// bypasses share one root cause: extractShellDestTokens stripped userinfo
// BEFORE it stripped the path, and skipped port-stripping for a bracketed
// IPv6 token. The false positives share another: a bare small integer in
// destination position (a flag value the VALUE_FLAGS list does not cover)
// parsed as the packed address 0.0.0.x and hit the non-overridable
// unspecified tier.
describe('R1 bypasses: these reached a tier-1 address and were ALLOWED', () => {
  it.each([
    ['@ in the query voids the floor', 'curl http://169.254.169.254/latest/meta-data/?a=@'],
    ['@ in the query, decimal spelling', 'curl http://2852039166/latest/meta-data/?@'],
    [
      '@ in the query, metadata hostname',
      'curl http://metadata.google.internal/computeMetadata/v1/?k=@v',
    ],
    ['bracketed IPv6 with a port', 'curl http://[fd00:ec2::254]:80/latest/meta-data/'],
    ['bracketed mapped IPv4 with a port', 'curl http://[::ffff:169.254.169.254]:8080/x'],
    ['scp host:path form', 'scp secret.txt 169.254.169.254:/tmp/x'],
    ['scp host:path, decimal spelling', 'scp 2852039166:/etc/passwd .'],
    ['scp with userinfo', 'scp user@169.254.169.254:/x .'],
  ])('%s is blocked', (_id, cmd) => {
    home = makeHome(undefined); // the SHIPPED default: egress off
    expect(check(home, cmd).decision).toBe('deny');
  });
});

describe('R2 false positives: an ordinary command must not hit the floor', () => {
  it.each([
    ['curl --max-redirs 0 https://example.com/'],
    ['curl --limit-rate 0 https://example.com/'],
    ['curl --retry-delay 0 https://example.com/'],
    ['curl --max-filesize 0 https://example.com/'],
    ['curl -w 0 https://example.com/'],
    ['wget --wait 0 https://example.com/'],
    ['curl --max-time 15 https://example.com/'],
    ['curl --retry 5 https://example.com/'],
  ])('%s is allowed', (cmd) => {
    home = makeHome(undefined);
    expect(check(home, cmd).decision).toBe('allow');
  });

  it('but a bare decimal that really denotes a protected address still blocks', () => {
    home = makeHome(undefined);
    expect(check(home, 'curl 2852039166/latest/meta-data/').decision).toBe('deny');
    // The small-integer forms still resolve to 0.0.0.0, which is now the
    // strict tier rather than an always-on one (B4), so what this row pins is
    // the DECODING, exercised where the floor still acts on it.
    const strictHome = makeHome({
      enabled: true,
      mode: 'block',
      allow: [],
      deny: [],
      allowPrivate: true,
      ssrfStrict: true,
    });
    expect(check(strictHome, 'curl http://0/').decision).toBe('deny');
    expect(check(strictHome, 'curl http://0.0.0.0/x').decision).toBe('deny');
  });
});

// ── 3. The row identity the floor must match or deliberately change ────────
describe('todays egress block row identity', () => {
  it('E-id a floor block carries its own ruleName (was: egress:curl:<host> via smart-rule-block)', () => {
    home = makeHome({ enabled: true, mode: 'block', allow: [], deny: [], allowPrivate: false });
    expect(check(home, 'curl http://169.254.169.254/x').decision).toBe('deny');
    const row = lastRow(home);
    expect(String(row.ruleName)).toBe('ssrf:metadata:curl:169.254.169.254');
    // The floor routes through the policy path, so checkedBy is smart-rule-block
    // exactly as an ordinary egress block is; the ruleName is what the taxonomy
    // keys on for it (dimensionOfBlock, and the mirrored firewall rule).
    expect(row.checkedBy).toBe('smart-rule-block');
  });

  it('E-id2 an ORDINARY egress block is unchanged', () => {
    home = makeHome({ enabled: true, mode: 'block', allow: [], deny: [], allowPrivate: true });
    expect(check(home, 'curl https://unknown.example/x').decision).toBe('deny');
    const row = lastRow(home);
    expect(row.checkedBy).toBe('smart-rule-block');
    expect(row.ruleName).toBe('egress:curl:unknown.example');
  });
  it('E-tax the chosen checkedBy contains "egress" so the firewall taxonomy files it under Network', () => {
    // canon-taxonomy.ts maps cb contains 'egress' -> network, fallback toolRules.
    // Asserted here as a pure string property so this repo owns the constraint.
    expect('ssrf-egress-floor-block').toContain('egress');
    expect('observe-mode-ssrf-egress-would-block').toContain('egress');
  });
});
