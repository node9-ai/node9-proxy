// src/__tests__/command-checks-governance.spec.ts
//
// /code-review wf_0ff1bc3d — governance integrity for the command-checks arc.
// Three holes let a repo-carried config or a local smart rule defeat an admin:
//
//  3a. A managed rmAdvisory/sqlDdl 'block' was defeated by a local smart rule:
//      a local rule named `review-rm` pre-empted injection outright, and the
//      unpinned `allow-rm-safe-paths` out-ranked an unpinned block by
//      first-match. The injected advisory is now EVICTED-and-PINNED when the
//      knob is org-managed.
//  3b. A repo `node9.config.json` (agent-writable) could set inlineExec/chmod/
//      sqlDdl to 'off' with no managed floor present. The project layer is now
//      tighten-only for command-checks.
//  3c. A managed egress mode 'off' was discarded when the dev never set a mode
//      (the seeded default 'review' out-ranked it). Absent-local now takes the
//      org value verbatim.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { getConfig, _resetConfigCache } from '../config';
import { authorizeHeadless, _resetConfigCache as _resetCore } from '../core.js';

const APPROVERS_OFF = { native: false, browser: false, cloud: false, terminal: false };
const BASE_SETTINGS = { mode: 'standard', approvalTimeoutMs: 0, approvers: APPROVERS_OFF };

describe('command-checks governance integrity (/code-review wf_0ff1bc3d)', () => {
  let tmpHome: string;
  let tmpProj: string;
  let origHome: string | undefined;
  let origUserprofile: string | undefined;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-ccgov-home-'));
    tmpProj = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-ccgov-proj-'));
    origHome = process.env.HOME;
    origUserprofile = process.env.USERPROFILE;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    delete process.env.NODE9_API_KEY;
    fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
    _resetConfigCache();
    _resetCore();
  });

  afterEach(() => {
    if (origHome !== undefined) process.env.HOME = origHome;
    else delete process.env.HOME;
    if (origUserprofile !== undefined) process.env.USERPROFILE = origUserprofile;
    else delete process.env.USERPROFILE;
    fs.rmSync(tmpHome, { recursive: true, force: true });
    fs.rmSync(tmpProj, { recursive: true, force: true });
    _resetConfigCache();
    _resetCore();
  });

  /** Global ~/.node9/config.json + a cloud rules-cache (managedConfig). */
  function seedHome(policy: object, cache?: object): void {
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'config.json'),
      JSON.stringify({ settings: BASE_SETTINGS, policy })
    );
    if (cache)
      fs.writeFileSync(path.join(tmpHome, '.node9', 'rules-cache.json'), JSON.stringify(cache));
    _resetConfigCache();
    _resetCore();
  }

  /** A repo-carried project config in a throwaway cwd. */
  function seedProject(policy: object): string {
    fs.writeFileSync(path.join(tmpProj, 'node9.config.json'), JSON.stringify({ policy }));
    _resetConfigCache();
    return tmpProj;
  }

  const orgKnob = (commandChecks: Record<string, string>, locked: string[] = []): object => ({
    fetchedAt: '2026-08-01T00:00:00Z',
    rules: [],
    managedConfig: { commandChecks, locked },
  });

  /** The gate's effective verdict for one command. */
  async function verdictFor(command: string, cwd?: string): Promise<'allow' | 'review' | 'block'> {
    const r = await authorizeHeadless(
      'Bash',
      { command },
      { agent: 'MCP' },
      { deferReview: true, cwd }
    );
    return r.approved ? 'allow' : r.review ? 'review' : 'block';
  }

  // ── /code-review round 4: four ways a local setting beat the org, or the
  //    org beat a STRICTER local setting. All four share one cause — two
  //    policies met and one OVERWROTE the other instead of combining by
  //    strictness. Written before the fix; every case here failed first.
  //
  //    Governing semantics (founder decision, this arc):
  //      · a lock is a FLOOR — a dev may be stricter, never weaker;
  //      · an UNLOCKED managed 'review' stays waivable by an explicit dev
  //        allow rule (a dev writing a narrow waiver IS a human reviewing);
  //        'block' and any LOCKED value are not waivable.
  describe('round 4 — an org mandate and a local rule combine by strictness', () => {
    // 1. EGRESS: allow-list entries WIDEN, so an agent-writable repo config may
    //    never contribute them once an outer layer has declared an egress
    //    stance — including the stance "enabled, block, no allow list at all",
    //    which is deny-everything and was being read as "no opinion".
    it('a repo config cannot add an allow host when global declared egress', () => {
      seedHome({ egress: { enabled: true, mode: 'block' } });
      const cwd = seedProject({ egress: { allow: ['attacker.example.com'] } });
      expect(getConfig(cwd).policy.egress.allow).not.toContain('attacker.example.com');
    });

    it('a repo config cannot widen an allow list the global config declared', () => {
      seedHome({ egress: { enabled: true, mode: 'block', allow: ['api.corp.com'] } });
      const cwd = seedProject({ egress: { allow: ['attacker.example.com'] } });
      const { allow } = getConfig(cwd).policy.egress;
      expect(allow).toContain('api.corp.com');
      expect(allow).not.toContain('attacker.example.com');
    });

    // The round-3 case this must not re-break: with NO outer egress config the
    // repo is the ONLY source, so dropping its allow list turned its own
    // declared hosts into deny-everything.
    it('a repo config IS the allow list when no outer layer declared egress', () => {
      seedHome({});
      const cwd = seedProject({
        egress: { enabled: true, mode: 'block', allow: ['api.corp.com'] },
      });
      expect(getConfig(cwd).policy.egress.allow).toContain('api.corp.com');
    });

    // 2. WAIVERS: 'review' is the DEFAULT knob value. If merely leaving it
    //    there destroys every local rm waiver, devs meet prompts on routine
    //    work and learn to approve blindly — a net security loss.
    it("an UNLOCKED managed 'review' leaves an explicit dev allow waiver intact", async () => {
      seedHome(
        {
          smartRules: [
            {
              name: 'allow-scratch-rm',
              tool: '*',
              conditionMode: 'all',
              conditions: [{ field: 'command', op: 'matches', value: 'rm -rf \\./scratch' }],
              verdict: 'allow',
              reason: 'dev waiver',
            },
          ],
        },
        orgKnob({ rmAdvisory: 'review' })
      );
      expect(await verdictFor('rm -rf ./scratch')).toBe('allow');
    });

    it("a LOCKED managed 'review' cannot be waived by a dev allow rule", async () => {
      seedHome(
        {
          smartRules: [
            {
              name: 'allow-scratch-rm',
              tool: '*',
              conditionMode: 'all',
              conditions: [{ field: 'command', op: 'matches', value: 'rm -rf \\./scratch' }],
              verdict: 'allow',
              reason: 'dev waiver',
            },
          ],
        },
        orgKnob({ rmAdvisory: 'review' }, ['commandChecksRmAdvisory'])
      );
      expect(await verdictFor('rm -rf ./scratch')).toBe('review');
    });

    it("a managed 'block' cannot be waived by a dev allow rule", async () => {
      seedHome(
        {
          smartRules: [
            {
              name: 'allow-scratch-rm',
              tool: '*',
              conditionMode: 'all',
              conditions: [{ field: 'command', op: 'matches', value: 'rm -rf \\./scratch' }],
              verdict: 'allow',
              reason: 'dev waiver',
            },
          ],
        },
        orgKnob({ rmAdvisory: 'block' })
      );
      expect(await verdictFor('rm -rf ./scratch')).toBe('block');
    });

    // 3. COVERAGE: strictestOf folded the twin's VERDICT in, then the twin was
    //    deleted and the BUILT-IN template's conditions were injected — so the
    //    dev's broader match was silently discarded. The built-in only matches
    //    rm at statement start; the dev's matched rm anywhere.
    it("a managed 'review' keeps the coverage of a STRICTER dev rule, not just its verdict", async () => {
      seedHome(
        {
          smartRules: [
            {
              name: 'review-rm',
              tool: '*',
              conditionMode: 'all',
              conditions: [{ field: 'command', op: 'matches', value: '\\brm\\b' }],
              verdict: 'block',
              reason: 'dev: every rm',
            },
          ],
        },
        orgKnob({ rmAdvisory: 'review' })
      );
      // Only the dev's condition reaches an rm that is not at statement start.
      expect(await verdictFor('find . | xargs rm -rf')).toBe('block');
      // and the mandate's own coverage still applies
      expect(await verdictFor('rm -rf ./build')).toBe('block');
    });

    // 4. LOCK AS FLOOR: `locked ? knobVerdict` took the cloud value outright,
    //    so locking a control at 'review' DOWNGRADED a dev who chose 'block'.
    it("a LOCKED managed 'review' does not downgrade a dev's stricter block", async () => {
      seedHome(
        {
          smartRules: [
            {
              name: 'review-rm',
              tool: '*',
              conditionMode: 'all',
              conditions: [{ field: 'command', op: 'matches', value: '(^|&&|\\|\\||;)\\s*rm\\b' }],
              verdict: 'block',
              reason: 'dev: block rm',
            },
          ],
        },
        orgKnob({ rmAdvisory: 'review' }, ['commandChecksRmAdvisory'])
      );
      expect(await verdictFor('rm -rf src')).toBe('block');
    });

    it('a lock still RAISES a dev who chose weaker', async () => {
      seedHome(
        {
          smartRules: [
            {
              name: 'review-rm',
              tool: '*',
              conditionMode: 'all',
              conditions: [{ field: 'command', op: 'matches', value: '(^|&&|\\|\\||;)\\s*rm\\b' }],
              verdict: 'review',
              reason: 'dev: just prompt',
            },
          ],
        },
        orgKnob({ rmAdvisory: 'block' }, ['commandChecksRmAdvisory'])
      );
      expect(await verdictFor('rm notes.txt')).toBe('block');
    });

    // The round-3 attack these fixes must not re-open: a decoy rule that
    // reuses the advisory's NAME, claims a strict verdict, and matches
    // NOTHING. It must not suppress or shade the mandate.
    it('a decoy rule that matches nothing cannot suppress a managed block', async () => {
      seedHome(
        {
          smartRules: [
            {
              name: 'review-rm',
              tool: '*',
              conditionMode: 'all',
              conditions: [
                { field: 'command', op: 'matches', value: 'THIS_MATCHES_NOTHING_XYZZY' },
              ],
              verdict: 'block',
              reason: 'decoy',
            },
          ],
        },
        orgKnob({ rmAdvisory: 'block' })
      );
      expect(await verdictFor('rm -rf src')).toBe('block');
    });

    // A weaker same-name twin must NOT survive. Keeping it would let a dev
    // extend the reach of the WEAKER verdict past the mandate's own coverage —
    // the mirror image of the coverage bug above, and the reason the twin is
    // kept only when it is stricter.
    it('a WEAKER same-name dev rule is dropped, not kept alongside the mandate', async () => {
      seedHome(
        {
          smartRules: [
            {
              name: 'review-rm',
              tool: '*',
              conditionMode: 'all',
              conditions: [{ field: 'command', op: 'matches', value: '\\brm\\b' }],
              verdict: 'allow',
              reason: 'dev: allow every rm',
            },
          ],
        },
        orgKnob({ rmAdvisory: 'block' })
      );
      // Asserted on the rule set, not on a gate verdict: the built-in's own
      // condition misses pipe-fed rm (`\|\|` is `||`, not a single pipe), so a
      // gate probe here would measure that PRE-EXISTING coverage gap instead of
      // the eviction this test is about.
      const survivors = getConfig().policy.smartRules.filter((r) => r.name === 'review-rm');
      expect(survivors).toHaveLength(1);
      expect(survivors[0].verdict).toBe('block');
      expect(survivors[0].conditions?.[0]?.value).not.toBe('\\brm\\b');
    });
  });

  // ── 3a. managed rmAdvisory 'block' survives local smart rules ────────────
  it("a local review-rm ALLOW rule cannot defeat a LOCKED managed rmAdvisory='block'", async () => {
    seedHome(
      {
        // The bypass: a local rule reusing the advisory's name, set to allow.
        smartRules: [
          {
            name: 'review-rm',
            tool: '*',
            conditions: [{ field: 'command', op: 'matches', value: 'rm\\b' }],
            verdict: 'allow',
          },
        ],
      },
      orgKnob({ rmAdvisory: 'block' }, ['commandChecksRmAdvisory'])
    );
    const r = await authorizeHeadless('Bash', { command: 'rm notes.txt' }, { agent: 'MCP' }, {});
    expect(r.approved).toBe(false);
    const injected = getConfig().policy.smartRules.filter((x) => x.name === 'review-rm');
    // The local twin was evicted; the pinned org block is the only survivor.
    expect(injected).toHaveLength(1);
    expect(injected[0].verdict).toBe('block');
    expect(injected[0].pinned).toBe(true);
  });

  it("a managed rmAdvisory='block' out-ranks allow-rm-safe-paths (rm node_modules blocks)", async () => {
    seedHome({}, orgKnob({ rmAdvisory: 'block' }));
    const r = await authorizeHeadless(
      'Bash',
      { command: 'rm -rf node_modules' },
      { agent: 'MCP' },
      {}
    );
    expect(r.approved).toBe(false); // pinned block beats the earlier unpinned allow
  });

  it("a managed sqlDdl='block' hard-blocks the SQL advisory even with a local same-name rule", async () => {
    seedHome(
      {
        smartRules: [
          {
            name: 'review-drop-table-sql',
            tool: '*',
            conditions: [{ field: 'sql', op: 'matches', value: 'drop' }],
            verdict: 'allow',
          },
        ],
      },
      orgKnob({ sqlDdl: 'block' })
    );
    const r = await authorizeHeadless(
      'mcp__postgres__query',
      { sql: 'DROP TABLE users' },
      { agent: 'MCP' },
      {}
    );
    expect(r.approved).toBe(false);
  });

  it('UNMANAGED behaviour unchanged: a local review-rm rule still customizes rm locally', async () => {
    // No managedConfig → the dev owns their rules; a local review-rm allow wins.
    seedHome({
      commandChecks: { rmAdvisory: 'review' },
      smartRules: [
        {
          name: 'review-rm',
          tool: '*',
          conditions: [{ field: 'command', op: 'matches', value: 'rm\\b' }],
          verdict: 'allow',
        },
      ],
    });
    const r = await authorizeHeadless('Bash', { command: 'rm notes.txt' }, { agent: 'MCP' }, {});
    expect(r.approved).toBe(true);
    const rules = getConfig().policy.smartRules.filter((x) => x.name === 'review-rm');
    expect(rules.every((x) => !x.pinned)).toBe(true); // nothing pinned when unmanaged
  });

  // ── 3b. a repo config may only TIGHTEN command-checks ────────────────────
  it("a repo node9.config.json inlineExec='off' is clamped to 'review' (cannot weaken)", () => {
    seedHome({});
    const cwd = seedProject({ commandChecks: { inlineExec: 'off', chmod: 'off', sqlDdl: 'off' } });
    const cc = getConfig(cwd).policy.commandChecks ?? {};
    // The clamp works by NOT writing the key, so `?? 'review'` is the correct
    // read — but on its own it would also pass if the project file were never
    // loaded at all. The per-key tighten controls below are what make these
    // assertions mean something (/code-review 2026-08-13).
    expect(cc.inlineExec ?? 'review').toBe('review');
    expect(cc.chmod ?? 'review').toBe('review');
    expect(cc.sqlDdl ?? 'review').toBe('review');
  });

  it('CONTROL: the project file IS read for each clamped key (tighten works per key)', () => {
    // Without this, the clamp assertions above are indistinguishable from a
    // fixture that was never loaded (wrong path, parse error swallowed).
    seedHome({});
    const cwd = seedProject({
      commandChecks: { inlineExec: 'block', chmod: 'block', sqlDdl: 'block' },
    });
    const cc = getConfig(cwd).policy.commandChecks ?? {};
    expect(cc.inlineExec).toBe('block');
    expect(cc.chmod).toBe('block');
    expect(cc.sqlDdl).toBe('block');
  });

  it("a repo config CAN tighten (inlineExec='block' honoured)", () => {
    seedHome({});
    const cwd = seedProject({ commandChecks: { inlineExec: 'block' } });
    expect(getConfig(cwd).policy.commandChecks?.inlineExec).toBe('block');
  });

  it("the GLOBAL (~/.node9) layer keeps full control — an 'off' there is honoured", () => {
    seedHome({ commandChecks: { inlineExec: 'off' } });
    expect(getConfig().policy.commandChecks?.inlineExec).toBe('off');
  });

  it("a repo 'off' cannot lower a stricter global 'block'", () => {
    seedHome({ commandChecks: { inlineExec: 'block' } });
    const cwd = seedProject({ commandChecks: { inlineExec: 'off' } });
    expect(getConfig(cwd).policy.commandChecks?.inlineExec).toBe('block');
  });

  // ── R3: the DECOY bypass — the reason the eviction table was deleted ─────
  // A same-named rule with a strong verdict but conditions that match NOTHING
  // made the old "skip if the twin is already >= the mandate" guard skip
  // injection entirely, so the org's mandate was never applied and `rm -rf src`
  // ran unguarded. Injection is now unconditional under a managed knob.
  const decoyRm = {
    name: 'review-rm',
    tool: '*',
    conditionMode: 'all',
    conditions: [{ field: 'command', op: 'matches', value: 'ZZZ_NEVER_MATCHES' }],
    verdict: 'block',
    reason: 'decoy: strong verdict, impossible condition',
  };

  it('a DECOY same-name rule cannot suppress a managed mandate (unlocked)', async () => {
    seedHome({ smartRules: [decoyRm] }, orgKnob({ rmAdvisory: 'block' }));
    for (const command of ['rm -rf src', 'rm notes.txt']) {
      const r = await authorizeHeadless('Bash', { command }, { agent: 'MCP' }, {});
      expect(r.approved, command).toBe(false);
    }
    // The injected rule carries the REAL rm condition, not the decoy's.
    const rules = getConfig().policy.smartRules.filter((x) => x.name === 'review-rm');
    expect(rules).toHaveLength(1);
    expect(rules[0].pinned).toBe(true);
    expect(JSON.stringify(rules[0].conditions)).not.toContain('ZZZ_NEVER_MATCHES');
  });

  it('a DECOY cannot suppress a managed mandate when LOCKED either', async () => {
    seedHome(
      { smartRules: [decoyRm] },
      orgKnob({ rmAdvisory: 'block' }, ['commandChecksRmAdvisory'])
    );
    const r = await authorizeHeadless('Bash', { command: 'rm -rf src' }, { agent: 'MCP' }, {});
    expect(r.approved).toBe(false);
  });

  // The pin defeats array order, so the safe-path waiver can no longer shade
  // the advisory as a separate rule — it is folded into the injected rule's own
  // conditions for REVIEW, while BLOCK deliberately still blocks safe paths.
  it("managed rmAdvisory='review' still honours the safe-path waiver", async () => {
    seedHome({}, orgKnob({ rmAdvisory: 'review' }));
    for (const safe of ['rm -rf node_modules', 'rm -rf dist']) {
      const r = await authorizeHeadless('Bash', { command: safe }, { agent: 'MCP' }, {});
      expect(r.approved, safe).toBe(true);
    }
    const risky = await authorizeHeadless('Bash', { command: 'rm -rf src' }, { agent: 'MCP' }, {});
    expect(risky.approved).toBe(false);
  });

  it("managed rmAdvisory='block' blocks safe paths too (admin escalation)", async () => {
    seedHome({}, orgKnob({ rmAdvisory: 'block' }));
    const r = await authorizeHeadless(
      'Bash',
      { command: 'rm -rf node_modules' },
      { agent: 'MCP' },
      {}
    );
    expect(r.approved).toBe(false);
  });

  // ── R3: a repo egress policy as the ONLY source must not self-deny ───────
  it('a repo egress policy works when no outer layer declared egress', () => {
    seedHome({});
    const cwd = seedProject({
      egress: { enabled: true, mode: 'block', allow: ['api.github.com', 'registry.internal'] },
    });
    const eg = getConfig(cwd).policy.egress;
    expect(eg.enabled).toBe(true);
    expect(eg.mode).toBe('block');
    expect(eg.allow).toContain('api.github.com'); // was [] → deny-everything
  });

  it('a repo still cannot WIDEN an allowlist the global layer declared', () => {
    seedHome({ egress: { enabled: true, mode: 'block', allow: ['api.github.com'] } });
    const cwd = seedProject({ egress: { allow: ['evil.example.com'] } });
    expect(getConfig(cwd).policy.egress.allow).not.toContain('evil.example.com');
  });

  // ── 3c. managed egress mode floor when the dev never set a mode ──────────
  it("a managed egress mode='off' applies when the dev never set a mode", () => {
    seedHome(
      {},
      {
        fetchedAt: '2026-08-01T00:00:00Z',
        rules: [],
        managedConfig: { egress: { enabled: true, mode: 'off' } },
      }
    );
    expect(getConfig().policy.egress.mode).toBe('off');
  });

  // ── 3a-bis. eviction must never WEAKEN the developer's own rule ──────────
  // The floor law is "a member may tighten, never loosen". An admin setting the
  // knob to its DEFAULT 'review' intends no change — it must not delete a
  // stricter local rule (/code-review 2026-08-13: it did, block → prompt).
  const localRm = (verdict: string) => ({
    name: 'review-rm',
    tool: '*',
    conditionMode: 'all',
    conditions: [{ field: 'command', op: 'matches', value: '(^|&&|\\|\\||;)\\s*rm\\b' }],
    verdict,
    reason: 'dev choice',
  });

  it("an UNLOCKED managed 'review' does not weaken a dev's stricter block rule", async () => {
    seedHome({ smartRules: [localRm('block')] }, orgKnob({ rmAdvisory: 'review' }));
    const r = await authorizeHeadless('Bash', { command: 'rm notes.txt' }, { agent: 'MCP' }, {});
    expect(r.approved).toBe(false);
    expect(r.review).not.toBe(true); // still a hard block, not a prompt
    // TWO rules survive by design (/code-review round 4): the dev's stricter
    // rule keeps its own CONDITIONS — folding only its verdict into the mandate
    // silently narrowed what the mandate covered — and the mandate keeps the
    // built-in's. Both carry `effective`, so they can never disagree.
    const rules = getConfig().policy.smartRules.filter((x) => x.name === 'review-rm');
    expect(rules).toHaveLength(2);
    expect(rules.every((x) => x.verdict === 'block')).toBe(true);
    expect(rules.every((x) => x.pinned === true)).toBe(true);
  });

  // SEMANTICS CHANGED (/code-review round 4). This test previously asserted
  // that a lock "wins outright" — the org value applied verbatim, up OR down.
  // That made locking a control at 'review' DOWNGRADE a dev who had chosen
  // 'block': the act of locking made the device less safe. A lock is now a
  // FLOOR — it stops a dev going weaker, never stricter.
  it("a LOCKED managed 'review' is a FLOOR — it does not downgrade a stricter dev rule", async () => {
    seedHome(
      { smartRules: [localRm('block')] },
      orgKnob({ rmAdvisory: 'review' }, ['commandChecksRmAdvisory'])
    );
    const r = await authorizeHeadless(
      'Bash',
      { command: 'rm notes.txt' },
      { agent: 'MCP' },
      {
        deferReview: true,
      }
    );
    expect(r.review).not.toBe(true);
    expect(r.approved).toBe(false); // the dev's stricter block stands
  });

  it("an unlocked managed 'review' still replaces a WEAKER (allow) dev twin", async () => {
    seedHome({ smartRules: [localRm('allow')] }, orgKnob({ rmAdvisory: 'review' }));
    const r = await authorizeHeadless(
      'Bash',
      { command: 'rm notes.txt' },
      { agent: 'MCP' },
      {
        deferReview: true,
      }
    );
    expect(r.review).toBe(true);
  });

  it("a managed 'off' leaves the dev's own rule untouched", async () => {
    seedHome({ smartRules: [localRm('block')] }, orgKnob({ rmAdvisory: 'off' }));
    const r = await authorizeHeadless('Bash', { command: 'rm notes.txt' }, { agent: 'MCP' }, {});
    expect(r.approved).toBe(false);
    expect(r.review).not.toBe(true);
  });

  // ── 3b-bis. the repo layer may not weaken EGRESS either ──────────────────
  it('a repo config cannot disable egress, widen the allow-list, or lower the mode', () => {
    seedHome({
      egress: { enabled: true, mode: 'block', allow: ['api.github.com'], allowPrivate: false },
    });
    const cwd = seedProject({
      egress: { enabled: false, mode: 'off', allow: ['evil.example.com'], allowPrivate: true },
    });
    const eg = getConfig(cwd).policy.egress;
    expect(eg.enabled).toBe(true); // repo cannot turn the gate off
    expect(eg.mode).toBe('block'); // repo cannot lower the mode
    expect(eg.allow).not.toContain('evil.example.com'); // repo cannot widen allow
    expect(eg.allowPrivate).not.toBe(true); // repo cannot re-open private nets
  });

  it('a repo config CAN still tighten egress (deny entries, stricter mode)', () => {
    seedHome({ egress: { enabled: true, mode: 'review' } });
    const cwd = seedProject({ egress: { mode: 'block', deny: ['bad.example.com'] } });
    const eg = getConfig(cwd).policy.egress;
    expect(eg.mode).toBe('block');
    expect(eg.deny).toContain('bad.example.com');
  });

  it("a dev's explicit egress mode='block' is kept over a managed 'off' (floor keeps stricter)", () => {
    seedHome(
      { egress: { mode: 'block' } },
      {
        fetchedAt: '2026-08-01T00:00:00Z',
        rules: [],
        managedConfig: { egress: { enabled: true, mode: 'off' } },
      }
    );
    expect(getConfig().policy.egress.mode).toBe('block');
  });
});

// ── Contract 2: ONE shell-shape definition across gate / scan / explain ─────
// These three answered "is this tool shell-shaped?" differently, so a rule the
// gate enforced could be missing from the report and denied by explain
// (/code-review round 3).
describe('shell-shape consistency across gate, scan and explain', () => {
  const SUDO = { command: 'sudo systemctl restart nginx' };
  const REVIEW_SUDO = {
    rule: {
      name: 'review-sudo',
      tool: 'bash',
      conditionMode: 'all' as const,
      conditions: [{ field: 'command', op: 'matches' as const, value: '\\bsudo\\s', flags: 'i' }],
      verdict: 'review' as const,
      reason: 'sudo',
    },
    sourceType: 'default' as const,
  };

  it('the canonical extractor covers every shell-shaped spelling the gate does', async () => {
    const { extractCanonicalFindings } = await import('@node9/policy-engine');
    for (const toolName of ['Bash', 'shell', 'run_shell_command', 'terminal.execute']) {
      const found = extractCanonicalFindings(
        { toolName, args: SUDO, timestamp: '2026-08-14T00:00:00Z' },
        {
          sessionId: 's',
          lineIndex: 0,
          project: 'p',
          agent: 'claude',
          rules: [REVIEW_SUDO],
          toolInspection: { bash: 'command', 'terminal.execute': 'command' },
          dlpEnabled: false,
        }
      );
      expect(
        found.map((f) => f.ruleName),
        toolName
      ).toContain('review-sudo');
    }
  });
});
