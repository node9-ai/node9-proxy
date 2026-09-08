// Unit + integration tests for `node9 egress` — the posture remediation on-ramp.
// Unit: applyEgress read-merge-write semantics. Integration: the real CLI
// subprocess writes ~/.node9/config.json (requires `npm run build`).

import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { applyEgress } from '../cli/commands/egress';
import { isValidEgressHost, normalizeEgressHost } from '../auth/egress-config';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

describe('egress host validation (shared by CLI + MCP)', () => {
  it('accepts FQDNs and wildcard globs', () => {
    for (const h of ['app.node9.ai', 'node9.ai', '*.node9.ai', 'api.mycorp.co.uk']) {
      expect(isValidEgressHost(h), h).toBe(true);
    }
  });

  it('rejects non-hosts (spaces, schemes, bare words, empty)', () => {
    for (const h of ['not a host', 'http://node9.ai', 'localhost', 'node9', '']) {
      expect(isValidEgressHost(h), h).toBe(false);
    }
  });

  it('normalizes case and surrounding whitespace', () => {
    expect(normalizeEgressHost('  APP.Node9.AI  ')).toBe('app.node9.ai');
  });
});

describe('applyEgress (read-merge-write)', () => {
  it('sets the egress block without clobbering other config', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const config: any = {
      policy: { smartRules: ['keepme'], dlp: { enabled: true } },
      settings: { mode: 'standard' },
    };
    applyEgress(config, { enabled: true, mode: 'block' });
    expect(config.policy.egress).toEqual({
      enabled: true,
      mode: 'block',
      allow: [],
      deny: [],
      allowPrivate: true,
      // The floor knobs are part of the block now; a written config states
      // them explicitly rather than leaving them to be inferred.
      ssrfStrict: false,
      ssrfAllow: [],
    });
    expect(config.policy.smartRules).toEqual(['keepme']); // untouched
    expect(config.settings.mode).toBe('standard'); // untouched
  });

  it('merges onto an existing egress block, preserving the allowlist', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const config: any = { policy: { egress: { enabled: true, mode: 'review', allow: ['x.com'] } } };
    applyEgress(config, { mode: 'block' });
    expect(config.policy.egress).toMatchObject({ enabled: true, mode: 'block', allow: ['x.com'] });
  });
});

describe('node9 egress (integration)', () => {
  let home: string;

  beforeAll(() => {
    expect(fs.existsSync(CLI), `built CLI not found at ${CLI} — run npm run build`).toBe(true);
  });

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'egress-int-'));
  });
  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  function run(args: string[]) {
    const baseEnv = { ...process.env };
    delete baseEnv.NODE9_API_KEY;
    return spawnSync(process.execPath, [CLI, 'egress', ...args], {
      encoding: 'utf-8',
      timeout: 60000,
      cwd: os.tmpdir(),
      env: {
        ...baseEnv,
        NODE9_NO_AUTO_DAEMON: '1',
        NODE9_TESTING: '1',
        HOME: home,
        USERPROFILE: home,
      },
    });
  }
  const readEgress = () =>
    JSON.parse(fs.readFileSync(path.join(home, '.node9', 'config.json'), 'utf8')).policy.egress;

  it('watch → enabled review config on disk', () => {
    const r = run(['watch']);
    expect(r.status).toBe(0);
    expect(readEgress()).toMatchObject({ enabled: true, mode: 'review' });
  });

  it('lock → enabled block config', () => {
    run(['watch']);
    run(['lock']);
    expect(readEgress()).toMatchObject({ enabled: true, mode: 'block' });
  });

  it('allow → adds a host to the allowlist', () => {
    run(['watch']);
    run(['allow', '*.mycorp.com']);
    expect(readEgress().allow).toContain('*.mycorp.com');
  });

  it('off → disables', () => {
    run(['lock']);
    run(['off']);
    expect(readEgress().enabled).toBe(false);
  });

  it('status (no subcommand) prints and exits 0', () => {
    const r = run([]);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/Egress control/i);
  });

  // ── The SSRF floor: status surface + the two knobs ────────────────────────
  // The floor blocks before any egress policy is consulted, and until now no
  // screen said so. A user who runs `node9 egress` and reads four lines about
  // allow/deny has no way to learn that some addresses are hard-blocked, which
  // tier is on, or who decided.

  it('S0 `egress status` is a synonym for the bare command, not an error', () => {
    // The bare command shows status, but "status" is the word a user reaches
    // for; without this it exited 1 with "too many arguments for 'egress'".
    const bare = run([]);
    const named = run(['status']);
    expect(named.status, named.stderr).toBe(0);
    expect(named.stdout).toBe(bare.stdout);
  });

  // ── Truthfulness of the floor block (code review, 2026-09-08) ────────────
  // Three claims were wrong: the floor is SHELL-ONLY (WebFetch and MCP fetch
  // tools reach the address unchecked), CGNAT is blocked by default and was
  // named nowhere, and `node9 pause` lifts the whole thing.

  it('T1 the block says it covers shell commands, not the whole machine', () => {
    const out = run([]).stdout;
    expect(out, 'the surface it actually covers').toMatch(/shell command/i);
    expect(out, 'the surface it does NOT cover').toMatch(/WebFetch|fetch tool/i);
  });

  it('T2 CGNAT is named in the always-blocked set', () => {
    expect(run([]).stdout).toMatch(/100\.64|carrier-grade|CGNAT/i);
  });

  it('T3 the "no setting releases these" claim carries the pause caveat', () => {
    expect(run([]).stdout).toMatch(/pause/i);
  });

  it('S1 status names the always-blocked tier, unconditionally', () => {
    const r = run([]);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/Protected addresses/i);
    expect(r.stdout, 'the always-on part is stated even with egress off').toMatch(
      /cloud metadata|metadata endpoint/i
    );
  });

  it('S2 status reports the strict tier as OFF by default', () => {
    const r = run([]);
    expect(r.stdout).toMatch(/Internal addresses:\s+off/i);
  });

  it('S3 status reports the strict tier as ON once it is set', () => {
    run(['strict', 'on']);
    const r = run([]);
    expect(r.stdout).toMatch(/Internal addresses:\s+on/i);
  });

  it('S4 strict on/off round-trips through the config file', () => {
    run(['strict', 'on']);
    expect(readEgress().ssrfStrict).toBe(true);
    run(['strict', 'off']);
    expect(readEgress().ssrfStrict).toBe(false);
  });

  it('S5 strict rejects a value that is neither on nor off (exit 1)', () => {
    const r = run(['strict', 'maybe']);
    expect(r.status).toBe(1);
    expect(readEgress, 'nothing written').toThrow();
  });

  it('S6 exempt adds an address to the exemption list and shows it', () => {
    run(['exempt', '100.64.0.1']);
    expect(readEgress().ssrfAllow).toContain('100.64.0.1');
    expect(run([]).stdout).toMatch(/100\.64\.0\.1/);
  });

  it('S7 exempt REFUSES a protected address, at the keystroke (exit 1)', () => {
    // The old behaviour dropped it silently at config-load time, so a user who
    // typed it believed the exemption existed.
    const r = run(['exempt', '169.254.169.254']);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/cannot be exempted|protected/i);
    expect(readEgress, 'nothing written').toThrow();
  });

  it('S8 exempt rejects a non-address (exit 1)', () => {
    const r = run(['exempt', 'not an address']);
    expect(r.status).toBe(1);
  });

  it('S9 status says WHO governs the strict tier', () => {
    run(['strict', 'on']);
    const r = run([]);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/set by:\s+this machine/i);
  });

  it('T5 a workspace-set value is attributed to the WORKSPACE', () => {
    // The keyed provenance branch had no row at all: deleting the assignment
    // left every other row green (mutation survived).
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    fs.writeFileSync(
      path.join(home, '.node9', 'credentials.json'),
      JSON.stringify({ default: { apiKey: 'k-not-real', apiUrl: 'https://example.invalid/api' } })
    );
    fs.writeFileSync(
      path.join(home, '.node9', 'rules-cache.json'),
      JSON.stringify({
        rules: [],
        shields: [],
        managedConfig: { egress: { ssrfStrict: true }, locked: [] },
        fetchedAt: '2026-09-08T00:00:00Z',
      })
    );
    const r = run([]);
    expect(r.error).toBeUndefined();
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toMatch(/Internal addresses:\s+on/i);
    expect(r.stdout).toMatch(/set by:\s+workspace/i);
  });

  it('T6 an UNKEYED org-managed machine also attributes it to the workspace', () => {
    // The two managed branches record provenance separately, and T5 only
    // covers the keyed one: deleting the unkeyed assignment stayed green.
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    fs.writeFileSync(
      path.join(home, '.node9', 'rules-cache.json'),
      JSON.stringify({
        rules: [],
        shields: [],
        managedConfig: { egress: { ssrfStrict: true }, locked: [] },
        fetchedAt: '2026-09-08T00:00:00Z',
      })
    );
    const r = run([]);
    expect(r.error).toBeUndefined();
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toMatch(/set by:\s+workspace/i);
  });

  it('T4 an untouched value is attributed to the DEFAULT, not to a layer', () => {
    // `set by` used to key on policySource, which is machine keyedness, not
    // provenance: a machine that had never set the field claimed a layer chose
    // it. Nobody set it here.
    const r = run([]);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/set by:\s+the shipped default/i);
  });

  // ── Bugs the review found in the two new subcommands ─────────────────────

  it('U1 exempt refuses a non-array ssrfAllow instead of shredding it', () => {
    // `[...current.ssrfAllow]` on a STRING spreads it per character, so a
    // hand-edited "10.0.0.1" became ["1","0",".","0",…] and the command still
    // exited 0. Same shape as the pre-existing addEgressHost.
    const cfgPath = path.join(home, '.node9', 'config.json');
    fs.mkdirSync(path.dirname(cfgPath), { recursive: true });
    const before = JSON.stringify({ policy: { egress: { ssrfAllow: '10.0.0.1' } } });
    fs.writeFileSync(cfgPath, before);
    const r = run(['exempt', '10.0.0.2']);
    expect(r.error).toBeUndefined();
    expect(r.status, r.stderr).toBe(1);
    expect(fs.readFileSync(cfgPath, 'utf8'), 'not rewritten').toBe(before);
  });

  it('U2 strict off does not claim success when the workspace overrides it', () => {
    // On an org-managed machine the write lands in config.json and the merge
    // then replaces it, so the old code printed "✓ Strict tier off" while the
    // very next status line said "on".
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    fs.writeFileSync(
      path.join(home, '.node9', 'rules-cache.json'),
      JSON.stringify({
        rules: [],
        shields: [],
        managedConfig: { egress: { ssrfStrict: true }, locked: [] },
        fetchedAt: '2026-09-08T00:00:00Z',
      })
    );
    const r = run(['strict', 'off']);
    expect(r.error).toBeUndefined();
    expect(r.stdout + r.stderr, 'says the workspace still governs').toMatch(
      /workspace|not in effect|still on/i
    );
    expect(run([]).stdout).toMatch(/Internal addresses:\s+on/i);
  });

  it('refuses to overwrite a malformed config (exit 1, file untouched)', () => {
    const cfgPath = path.join(home, '.node9', 'config.json');
    fs.mkdirSync(path.dirname(cfgPath), { recursive: true });
    const broken = '{ "policy": { not valid json';
    fs.writeFileSync(cfgPath, broken);
    const r = run(['lock']);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/not valid JSON/i);
    // The user's (broken) config must be left exactly as-is, not clobbered.
    expect(fs.readFileSync(cfgPath, 'utf8')).toBe(broken);
  });
});
