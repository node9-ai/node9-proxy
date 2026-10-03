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

  /** Every row goes through here, so the spawn-failure guard lives here once:
   *  a silent ENOENT or timeout must never read as a passing assertion. */
  function run(args: string[]) {
    const baseEnv = { ...process.env };
    delete baseEnv.NODE9_API_KEY;
    const r = spawnSync(process.execPath, [CLI, 'egress', ...args], {
      encoding: 'utf-8',
      timeout: 60000,
      cwd: os.tmpdir(),
      env: {
        ...baseEnv,
        NODE9_NO_AUTO_DAEMON: '1',
        NODE9_TESTING: '1',
        // These rows pin the legacy on-disk shape; migration has its own spec.
        NODE9_NO_CONFIG_MIGRATE: '1',
        HOME: home,
        USERPROFILE: home,
      },
    });
    expect(r.error, `spawn failed: ${r.error?.message}`).toBeUndefined();
    expect(r.status, 'the CLI did not exit').not.toBeNull();
    return r;
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

  // ── Truthfulness of the floor block ─────────────────────────────────────
  // 2026-09-08: three overclaims were removed (machine-wide, CGNAT unnamed,
  // pause). 2026-09-21: two of the replacements were themselves wrong, and
  // the reason they survived is that these rows asserted a WORD, not a claim:
  // /WebFetch|fetch tool/ matched both "does not pass this gate" and its
  // opposite, so the text could invert with the test still green. Each row
  // below now pins the sentence, and the measured verdict it describes is in
  // ssrf-pins.spec.ts (WebFetch to the metadata endpoint is denied) and
  // egress-carriers.integration.test.ts.

  it('T1 the block names the carriers it covers, and the one it does not', () => {
    const out = run([]).stdout;
    expect(out, 'shell is covered').toMatch(/shell command/i);
    expect(out, 'a declared URL is covered too, since 438cd16').toMatch(/declared URL|WebFetch/i);
    expect(out, 'it must NOT claim a declared URL bypasses the floor').not.toMatch(
      /(WebFetch|fetch tool)[^.]*\b(not pass|bypass|unchecked|never reach)/i
    );
    expect(out, 'the real gap is the interpreter one-liner').toMatch(
      /node -e|python3 -c|interpreter/i
    );
  });

  it('T2 CGNAT is named as reachable-by-default, NOT as always blocked', () => {
    const out = run([]).stdout;
    expect(out, 'CGNAT is named somewhere').toMatch(/100\.64|CGNAT/i);
    // Measured on a default install: `curl http://100.64.0.5/` is ALLOWED,
    // and an exemption releases it. It is in STRICT_TIERS and overridable.
    expect(out, 'the always-blocked list must not contain CGNAT').not.toMatch(
      /always blocked:[^\n]*(100\.64|CGNAT)/i
    );
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

  it('S2 status reports internal addresses as ALLOWED by default', () => {
    const r = run([]);
    // B1 renamed this label from the boolean on/off to the resolved state
    // (allowed | allowlist only | blocked), because on/off named one of the
    // two fields and left the other unreadable.
    expect(r.stdout).toMatch(/Internal addresses:\s+allowed/i);
  });

  it('S3 status reports internal addresses as BLOCKED once the tier is set', () => {
    run(['strict', 'on']);
    const r = run([]);
    expect(r.stdout).toMatch(/Internal addresses:\s+blocked/i);
  });

  it('S4 strict on/off round-trips through the config file', () => {
    run(['strict', 'on']);
    expect(readEgress().ssrfStrict).toBe(true);
    run(['strict', 'off']);
    expect(readEgress().ssrfStrict).toBe(false);
  });

  it('S5 strict rejects a value that is neither on nor off (exit 1)', () => {
    // A pre-existing file, so "no file" cannot masquerade as "refused": the
    // old form passed in a fresh HOME where the config never existed at all.
    run(['watch']);
    const before = fs.readFileSync(path.join(home, '.node9', 'config.json'), 'utf8');
    const r = run(['strict', 'maybe']);
    expect(r.status).toBe(1);
    expect(fs.readFileSync(path.join(home, '.node9', 'config.json'), 'utf8')).toBe(before);
  });

  it('S6 exempt adds an address to the exemption list and shows it', () => {
    run(['exempt', '100.64.0.1']);
    expect(readEgress().ssrfAllow).toContain('100.64.0.1');
    expect(run([]).stdout).toMatch(/100\.64\.0\.1/);
  });

  it('S7 exempt REFUSES a protected address, at the keystroke (exit 1)', () => {
    // The old behaviour dropped it silently at config-load time, so a user who
    // typed it believed the exemption existed.
    run(['watch']);
    const before = fs.readFileSync(path.join(home, '.node9', 'config.json'), 'utf8');
    const r = run(['exempt', '169.254.169.254']);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/cannot be exempted|protected/i);
    expect(fs.readFileSync(path.join(home, '.node9', 'config.json'), 'utf8')).toBe(before);
  });

  it('S7b a protected address already IN the file is dropped from the effective list', () => {
    // The local call site of sanitizeSsrfAllow had no test at all: deleting it
    // left every row green, and `node9 egress` then advertised a protected
    // address as an exemption in force. The status block claims to print the
    // EFFECTIVE list, so this is the row that makes the claim true.
    const cfgPath = path.join(home, '.node9', 'config.json');
    fs.mkdirSync(path.dirname(cfgPath), { recursive: true });
    fs.writeFileSync(
      cfgPath,
      JSON.stringify({ policy: { egress: { ssrfAllow: ['169.254.169.254', '100.64.0.1'] } } })
    );
    const out = run([]).stdout;
    expect(out).toMatch(/Exemptions:.*100\.64\.0\.1/);
    expect(out, 'the protected one is not advertised').not.toMatch(/169\.254\.169\.254/);
  });

  it('S8 exempt rejects a non-address (exit 1)', () => {
    const r = run(['exempt', 'not an address']);
    expect(r.status).toBe(1);
  });

  it('S8b exempt rejects a HOSTNAME: the engine matches addresses only', () => {
    // Found by the post-fix verification pass, not by the review: this command
    // accepted an FQDN and printed a note, while the dashboard refused it. The
    // engine compares an exemption against a normalized IP literal, so a
    // hostname entry can never match anything and is written dead.
    const r = run(['exempt', 'tailscale.example.com']);
    expect(r.status, r.stdout).toBe(1);
    expect(r.stderr).toMatch(/address/i);
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
    expect(r.stdout).toMatch(/Internal addresses:\s+blocked/i);
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
    expect(run([]).stdout).toMatch(/Internal addresses:\s+blocked/i);
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

  // ── B1: `egress internal`, the verb `allowPrivate` never had ─────────────
  // Measured 2026-09-21: of the five egress settings, allowPrivate was the
  // only one with no CLI at all. The cloud could set it (ManagedEgress has
  // the field, lockable as egressAllowPrivate) and the dashboard had a
  // control, so the ONLY user who could not reach it was the unconnected
  // one, who has nothing else. The panel's Internal addresses control has
  // three states and its middle one is exactly allowPrivate:false.
  //
  // The two booleans are one axis in sequence (the floor answers first, the
  // policy second), so one verb writes both and the state reads back as a
  // bijection.

  const readState = () => {
    const e = readEgress();
    return { ssrfStrict: e.ssrfStrict, allowPrivate: e.allowPrivate };
  };

  it('B1-1 `internal allowed` is the default state, written explicitly', () => {
    run(['watch']);
    const r = run(['internal', 'allowed']);
    expect(r.status, r.stderr).toBe(0);
    expect(readState()).toEqual({ ssrfStrict: false, allowPrivate: true });
  });

  it('B1-2 `internal listed` requires internal addresses to be allowlisted', () => {
    run(['watch']);
    const r = run(['internal', 'listed']);
    expect(r.status, r.stderr).toBe(0);
    expect(readState()).toEqual({ ssrfStrict: false, allowPrivate: false });
  });

  it('B1-3 `internal blocked` turns the strict tier on', () => {
    run(['watch']);
    const r = run(['internal', 'blocked']);
    expect(r.status, r.stderr).toBe(0);
    // Both fields are always written: a stored value that contradicts the
    // displayed state is how the next reader gets it wrong.
    expect(readState()).toEqual({ ssrfStrict: true, allowPrivate: false });
  });

  it('B1-4 the three states round-trip, in any order', () => {
    run(['watch']);
    for (const s of ['blocked', 'allowed', 'listed', 'allowed', 'blocked'] as const) {
      expect(run(['internal', s]).status, s).toBe(0);
      const st = readState();
      const back = st.ssrfStrict ? 'blocked' : st.allowPrivate ? 'allowed' : 'listed';
      expect(back, `wrote ${s}, read back ${back}`).toBe(s);
    }
  });

  it('B1-5 status names the resolved state, not two booleans', () => {
    run(['watch']);
    run(['internal', 'listed']);
    const out = run([]).stdout;
    expect(out, 'the state has a name a user can repeat back').toMatch(
      /Internal addresses:\s+(allowlist only|listed)/i
    );
  });

  it('B1-6 a bad verb exits 1 and names the three it accepts', () => {
    const r = run(['internal', 'sometimes']);
    expect(r.status).toBe(1);
    expect(`${r.stdout}${r.stderr}`).toMatch(/allowed/i);
    expect(`${r.stdout}${r.stderr}`).toMatch(/blocked/i);
  });

  it('B1-7 `strict on|off` still works and delegates to the same writer', () => {
    // It is documented, in use, and named in the posture row's remediation
    // line, so removing it breaks a published instruction. It stays as an
    // alias over one writer rather than a second way to set the field.
    run(['watch']);
    run(['strict', 'on']);
    expect(readState().ssrfStrict).toBe(true);
    run(['strict', 'off']);
    expect(readState().ssrfStrict).toBe(false);
  });

  it('B1-8 `strict off` does not silently widen past what the user had', () => {
    // From `listed` (allowPrivate false), `strict off` must land on `listed`,
    // not on `allowed`: turning a tier off is not consent to stop requiring
    // the allowlist.
    run(['watch']);
    run(['internal', 'listed']);
    run(['strict', 'on']);
    run(['strict', 'off']);
    expect(readState()).toEqual({ ssrfStrict: false, allowPrivate: false });
  });

  // ── B2: an exemption may name a RANGE ────────────────────────────────────
  // The engine rows are in packages/policy-engine/src/egress/exempt-range.spec.ts;
  // these two are the surfaces a user actually touches.

  it('B2-1 `exempt` accepts a CIDR range and lists it', () => {
    run(['watch']);
    const r = run(['exempt', '100.64.0.0/10']);
    expect(r.status, r.stderr).toBe(0);
    expect(readEgress().ssrfAllow).toContain('100.64.0.0/10');
    expect(run([]).stdout).toMatch(/100\.64\.0\.0\/10/);
  });

  it('B2-2 `exempt` still refuses a range that can never release anything', () => {
    // 169.254.0.0/16 is entirely link-local, which no setting releases, so the
    // entry would be listed as in force and do nothing. Same rule as the
    // single protected address at the keystroke (S7).
    const r = run(['exempt', '169.254.0.0/16']);
    expect(r.status).toBe(1);
    expect(`${r.stdout}${r.stderr}`).toMatch(/cannot be exempted|protected/i);
  });

  it('B2-3 a protected RANGE already in the file is dropped from the effective list', () => {
    // The sanitize path, for ranges: same guarantee S7b makes for a bare
    // address. A dead entry advertised as in force is the failure.
    const cfgPath = path.join(home, '.node9', 'config.json');
    fs.mkdirSync(path.dirname(cfgPath), { recursive: true });
    fs.writeFileSync(
      cfgPath,
      JSON.stringify({
        policy: { egress: { ssrfAllow: ['169.254.0.0/16', '224.0.0.0/4', '100.64.0.0/10'] } },
      })
    );
    const out = run([]).stdout;
    expect(out, 'the usable range survives').toMatch(/100\.64\.0\.0\/10/);
    expect(out, 'link-local is dropped').not.toMatch(/169\.254\.0\.0/);
    expect(out, 'multicast is dropped').not.toMatch(/224\.0\.0\.0/);
  });
});
