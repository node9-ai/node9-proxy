// src/__tests__/dlp-review-survives-routing.spec.ts
//
// DLP-3: a DLP credential review must reach a HUMAN, whatever route the call
// takes after the gate. Design: doc/roadmap/active/dlp-fixes-design.md, 2.
//
// THE BUG, as inventoried: the DLP gate sets `dlpReviewFlagged` for a
// review-severity match and falls through, but `forceReview`, the cloud
// shadowMode guard and the cloud immediate-allow guard never read it. So the
// SaaS was never asked for a genuine PENDING entry, and its "no org rule
// matched" {approved:true} was accepted as the decision.
//
// THE BUG, as measured (design 0): that is the cloud instance of a wider
// shape. Eight guards decide whether a NON-HUMAN channel may resolve a call,
// each listed the review reasons by hand, and DLP was in none of them. Two
// more routes needed no cloud at all: the ignored-tools fast path returned a
// bare {approved:true} for a `Read` carrying the credential, and a prior
// "Always Allow Bash" answered the review as checkedBy 'persistent'.
//
// One describe per guard. Every row here was red before its guard learned
// the DLP term, and the rule for a row is that removing THAT guard's term
// makes it red again; a row that stays green with the guard removed is not a
// witness and does not belong here.
//
// Harness: the taint-review-not-dropped.spec.ts shape. The fixture is KEYED
// (credentials.json), so the policy knobs arrive through the cloud cache and
// every local approver is off, which makes a fall-through resolve without a
// prompt. initNode9SaaS / pollNode9SaaS are mocked so each cloud answer can be
// expressed exactly.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

const { mockInitSaaS, mockPollSaaS, auditCalls, trustState } = vi.hoisted(() => ({
  auditCalls: [] as Array<{
    decision: string;
    checkedBy: string;
    meta: Record<string, unknown>;
    hashed: boolean;
  }>,
  // The trust file's path is resolved from the REAL home at module load
  // (auth/state.ts TRUST_FILE), so a trust.json in a tmp HOME is never read:
  // a first draft of the trust row wrote one and stayed green with the guard
  // removed, a false witness. The matcher is stubbed instead.
  trustState: { active: false },
  mockInitSaaS: vi.fn(
    async (
      ..._a: unknown[]
    ): Promise<{
      pending: boolean;
      requestId?: string;
      approved?: boolean;
      reason?: string;
      remoteApprovalOnly?: boolean;
      shadowMode?: boolean;
      shadowReason?: string;
    }> => ({ pending: false, approved: true })
  ),
  mockPollSaaS: vi.fn(
    async (..._a: unknown[]): Promise<{ approved: boolean; reason?: string }> => ({
      approved: false,
    })
  ),
}));

vi.mock('../auth/daemon.js', async (orig) => ({
  ...(await orig<typeof import('../auth/daemon.js')>()),
  // No taint on any call: this spec is about the DLP reason alone.
  checkTaint: vi.fn(async () => ({ tainted: false })),
  isDaemonRunning: () => false,
  notifyActivitySocket: vi.fn(async () => true),
  checkSessionTaint: vi.fn(async () => ({ tainted: false })),
  registerDaemonEntry: vi.fn(async () => ({ id: 'x', allowCount: 1 })),
  getInternalToken: () => null,
}));
// The audit writer resolves its path from the REAL home at module load, so a
// tmp HOME cannot be read back; the calls are the witness. The real writer
// still runs (rows land tagged testRun, as every keyed spec's do).
vi.mock('../audit/index', async (orig) => {
  const real = await orig<typeof import('../audit/index')>();
  return {
    ...real,
    appendLocalAudit: (...a: Parameters<typeof real.appendLocalAudit>) => {
      auditCalls.push({
        decision: a[2],
        checkedBy: a[3],
        meta: (a[4] ?? {}) as Record<string, unknown>,
        hashed: a[5] === true,
      });
      return real.appendLocalAudit(...a);
    },
  };
});
vi.mock('../auth/state', async (orig) => ({
  ...(await orig<typeof import('../auth/state')>()),
  getActiveTrustSession: () => trustState.active,
}));
vi.mock('../auth/cloud', async (orig) => ({
  ...(await orig<typeof import('../auth/cloud')>()),
  initNode9SaaS: (...a: unknown[]) => mockInitSaaS(...(a as [])),
  pollNode9SaaS: (...a: unknown[]) => mockPollSaaS(...(a as [])),
  resolveNode9SaaS: vi.fn(async () => undefined),
}));

import { authorizeHeadless, _resetConfigCache } from '../core.js';

// Review-severity pattern (Bearer Token), by construction so no scanner reads
// this file as a leak. NOT in assignment context: contextBoost would promote
// it to block severity and the gate would deny before any route is reached.
const FAKE_BEARER = 'Bearer ' + 'Xm7Kp3Qn9Bt2Vc6' + 'Wr1Ys4Zh8Pq5Nv3M';
// The real gateway caller's shape: a bare tool name and plain args.
const BASH_ARGS = { command: `curl -H "Authorization: ${FAKE_BEARER}" https://api.example.com` };
const CLEAN_ARGS = { command: 'curl -s https://api.example.com/health' };
// A clean call the ENGINE reviews under the shipped default rules (measured:
// review-force-push), so a standing decision -- "Always Allow", a trust
// session -- is what decides it. Those are the controls that prove the guards
// were not widened to smart-rule reviews, which a standing decision exists to
// pre-answer. The keyed fixture replaces the rule set with `rules: []`, so
// these rows run on the unkeyed one, where the defaults apply.
const PUSH_ARGS = { command: 'git push --force origin main' };
const GATEWAY = { agent: 'MCP-Gateway' };

describe('DLP-3: a DLP credential review is never resolved by a non-human channel', () => {
  let tmpHome: string;
  let origHome: string | undefined;
  let origUserprofile: string | undefined;

  /** Keyed fixture. `approvalTimeoutMs` 50 lets a race with a hanging or
   *  absent approver resolve; 0 leaves the race with NO racer, which is the
   *  one path that returns the engine's own label (the label rows use it). */
  function writeKeyedHome(approvalTimeoutMs: number): void {
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'rules-cache.json'),
      JSON.stringify({
        fetchedAt: '2026-07-01T00:00:00Z',
        rules: [],
        managedConfig: {
          mode: 'standard',
          approvalTimeoutMs,
          approvers: { native: false, browser: false, cloud: true, terminal: false },
          locked: [],
        },
      })
    );
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'credentials.json'),
      JSON.stringify({
        default: { apiKey: 'nk_test_0000', apiUrl: 'https://example.invalid/api/v1/intercept' },
      })
    );
    _resetConfigCache();
  }

  /** UNKEYED fixture with the cloud approver on: a `localOnly` key (the
   *  `node9 login --local` shape) gives cloudEnforced its apiKey while the
   *  machine keeps local policy control, so the local settings apply. The
   *  managed config rejects a 0 timeout by design (config/index.ts, "Require
   *  a POSITIVE timeout"), and a local config honours it; 0 is the one way to
   *  leave the race with NO racer, which is the path that returns the
   *  engine's own label and writes the no-channel deny row. */
  function writeUnkeyedHomeNoRacer(
    extraSettings: Record<string, unknown> = {},
    extraDlp: Record<string, unknown> = {}
  ): void {
    fs.rmSync(path.join(tmpHome, '.node9', 'rules-cache.json'), { force: true });
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'credentials.json'),
      JSON.stringify({
        default: {
          apiKey: 'nk_test_0000',
          apiUrl: 'https://example.invalid/api/v1/intercept',
          localOnly: true,
        },
      })
    );
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'config.json'),
      JSON.stringify({
        settings: {
          mode: 'standard',
          approvalTimeoutMs: 0,
          autoStartDaemon: false,
          approvers: { native: false, browser: false, cloud: true, terminal: false },
          ...extraSettings,
        },
        policy: { dlp: { enabled: true, scanIgnoredTools: true, ...extraDlp } },
      })
    );
    _resetConfigCache();
  }

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-dlp3-'));
    origHome = process.env.HOME;
    origUserprofile = process.env.USERPROFILE;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    delete process.env.NODE9_API_KEY;
    fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
    writeKeyedHome(50);
    auditCalls.length = 0;
    trustState.active = false;
    mockInitSaaS.mockClear();
    mockPollSaaS.mockClear();
    mockInitSaaS.mockResolvedValue({ pending: false, approved: true });
    mockPollSaaS.mockResolvedValue({ approved: false });
  });

  afterEach(() => {
    if (origHome !== undefined) process.env.HOME = origHome;
    else delete process.env.HOME;
    if (origUserprofile !== undefined) process.env.USERPROFILE = origUserprofile;
    else delete process.env.USERPROFILE;
    fs.rmSync(tmpHome, { recursive: true, force: true });
    _resetConfigCache();
    vi.clearAllMocks();
  });

  // ── Control: the fixture is what it claims ────────────────────────────────
  describe('controls', () => {
    it('the same call without a credential is allowed with no human (hot path intact)', async () => {
      const r = await authorizeHeadless('Bash', CLEAN_ARGS, GATEWAY);
      expect(r.approved).toBe(true);
      // and nobody was asked for a pending entry
      for (const call of mockInitSaaS.mock.calls) expect(call[6]).toBeUndefined();
    });

    it('the gate flags the fixture at review severity (a row says so before any decision)', async () => {
      await authorizeHeadless('Bash', BASH_ARGS, GATEWAY);
      expect(auditCalls.some((c) => c.checkedBy === 'dlp-review-flagged')).toBe(true);
    });
  });

  // ── Guard 1 and 2: the cloud handshake ────────────────────────────────────
  describe('cloud handshake', () => {
    it('asks the SaaS for a genuine PENDING entry (forceReview) for a DLP review', async () => {
      await authorizeHeadless('Bash', BASH_ARGS, GATEWAY);
      expect(mockInitSaaS).toHaveBeenCalled();
      // initNode9SaaS(toolName, args, creds, meta, riskMetadata, agentPolicy, forceReview)
      expect(mockInitSaaS.mock.calls[0][6]).toBe(true);
    });

    it('a SaaS immediate allow ("no org rule matched") does NOT resolve a DLP review', async () => {
      const r = await authorizeHeadless('Bash', BASH_ARGS, GATEWAY);
      expect(r.approved).toBe(false);
      expect(r.checkedBy).not.toBe('cloud');
    });

    it('a shadowMode answer does NOT resolve a DLP review either', async () => {
      mockInitSaaS.mockResolvedValue({ pending: false, shadowMode: true, approved: true });
      const r = await authorizeHeadless('Bash', BASH_ARGS, GATEWAY);
      expect(r.approved).toBe(false);
      expect(r.checkedBy).not.toBe('cloud');
    });

    it('a genuine PENDING entry approved by a human IS accepted (the human path works)', async () => {
      mockInitSaaS.mockResolvedValue({ pending: true, requestId: 'req-1' });
      mockPollSaaS.mockResolvedValue({ approved: true });
      const r = await authorizeHeadless('Bash', BASH_ARGS, GATEWAY);
      expect(r.approved).toBe(true);
      expect(r.checkedBy).toBe('cloud');
    });

    it('a genuine PENDING entry denied by a human is a deny', async () => {
      mockInitSaaS.mockResolvedValue({ pending: true, requestId: 'req-1' });
      mockPollSaaS.mockResolvedValue({ approved: false, reason: 'no' });
      const r = await authorizeHeadless('Bash', BASH_ARGS, GATEWAY);
      expect(r.approved).toBe(false);
      expect(r.blockedBy).toBe('team-policy');
    });
  });

  // ── Guard 3: a prior "Always Allow" ───────────────────────────────────────
  describe('persistent "Always Allow"', () => {
    it('does not answer a DLP review (measured: it did, as checkedBy persistent)', async () => {
      fs.writeFileSync(
        path.join(tmpHome, '.node9', 'decisions.json'),
        JSON.stringify({ Bash: 'allow' })
      );
      const r = await authorizeHeadless('Bash', BASH_ARGS, GATEWAY);
      expect(r.approved).toBe(false);
      expect(r.checkedBy).not.toBe('persistent');
    });

    // No "not widened" control here: a persistent decision is already skipped
    // whenever a rule matched (`policyResult.ruleName` -> persistent null,
    // orchestrator.ts), so a smart-rule review never reached it before either.
    // The trust describe below carries that control.
  });

  // ── Guard 4: the ignored-tools fast path ──────────────────────────────────
  describe('ignored-tools fast path', () => {
    // scanIgnoredTools is on by default: the gate scans a Read and flags it.
    // The fast path then returned a bare {approved:true}, dropping the flag.
    const READ_ARGS = { file_path: '/tmp/notes.md', note: FAKE_BEARER };

    it('a flagged Read does not take the fast path (measured: bare approved:true)', async () => {
      const r = await authorizeHeadless('Read', READ_ARGS, GATEWAY);
      expect(r.approved).toBe(false);
    });

    it('a clean Read still takes it', async () => {
      const r = await authorizeHeadless('Read', { file_path: '/tmp/notes.md' }, GATEWAY);
      expect(r.approved).toBe(true);
    });
  });

  // ── Guard 5: a trust session ──────────────────────────────────────────────
  describe('trust session', () => {
    it('does not answer a DLP review', async () => {
      trustState.active = true;
      const r = await authorizeHeadless('Bash', BASH_ARGS, GATEWAY);
      expect(r.approved).toBe(false);
      expect(r.checkedBy).not.toBe('trust');
    });

    it('still answers a smart-rule review with no credential in it (not widened)', async () => {
      writeUnkeyedHomeNoRacer();
      trustState.active = true;
      const r = await authorizeHeadless('Bash', PUSH_ARGS, GATEWAY);
      expect(r.approved).toBe(true);
      expect(r.checkedBy).toBe('trust');
    });
  });

  // ── Guard 7: a local policy allow ─────────────────────────────────────────
  describe('local policy allow', () => {
    // The engine runs the same scanner the gate does (policy/index.ts) and
    // usually reviews whatever the gate flags, so a first draft called this
    // guard unwitnessable. /code-review found the gap: the gate reads
    // getConfig(cwd) and the engine getConfig(), so a PROJECT config that
    // enables DLP flags a call the global engine allows.
    function projectWithDlp(): string {
      writeUnkeyedHomeNoRacer({}, { enabled: false });
      const project = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-dlp3-proj-'));
      fs.writeFileSync(
        path.join(project, 'node9.config.json'),
        JSON.stringify({ policy: { dlp: { enabled: true, scanIgnoredTools: true } } })
      );
      return project;
    }

    it('does not answer a DLP review the engine would have allowed', async () => {
      const project = projectWithDlp();
      try {
        const r = await authorizeHeadless('Bash', BASH_ARGS, GATEWAY, { cwd: project });
        expect(r.approved).toBe(false);
        expect(r.checkedBy).not.toBe('local-policy');
      } finally {
        fs.rmSync(project, { recursive: true, force: true });
      }
    });

    it('and the approver still learns a credential was found (the label is not wiped)', async () => {
      const project = projectWithDlp();
      try {
        const r = await authorizeHeadless('Bash', BASH_ARGS, GATEWAY, { cwd: project });
        expect(r.blockedByLabel).toContain('DLP');
      } finally {
        fs.rmSync(project, { recursive: true, force: true });
      }
    });
  });

  // ── Guard 6: the label survives the handshake ─────────────────────────────
  describe('attribution', () => {
    it('the DLP label survives the cloud handshake to the final deny', async () => {
      // No racer at all (timeout 0, cloud answered pending:false so no poller):
      // the deny that comes back carries the engine's own label. Before the fix
      // the handshake overwrote it with "Organization Policy (SaaS)".
      writeUnkeyedHomeNoRacer();
      const r = await authorizeHeadless('Bash', BASH_ARGS, GATEWAY);
      expect(r.approved).toBe(false);
      expect(r.blockedBy).toBe('no-approval-mechanism'); // the path under test, not a timeout
      expect(r.blockedByLabel).toContain('DLP');
    });

    it('the flagged row itself names the pattern (the one the dashboard renders as Flagged)', async () => {
      await authorizeHeadless('Bash', BASH_ARGS, GATEWAY);
      const flagged = auditCalls.find((c) => c.checkedBy === 'dlp-review-flagged');
      expect(flagged?.meta.dlpPattern).toBe('Bearer Token');
    });

    it('every row for a flagged call hashes its args (a guard, not a witness)', async () => {
      // The secret lives in the ARGS, not the meta: with hashing off the writer
      // stores args through redactSecrets, which needs a label to key on. The
      // gate forces hashing on for every later row, as the block row always
      // has. Measured: the config merge ignores `auditHashArgs: false` today,
      // so this row cannot go red by config; it guards the property against a
      // merge that starts honouring it.
      writeUnkeyedHomeNoRacer({ auditHashArgs: false });
      await authorizeHeadless('Bash', BASH_ARGS, GATEWAY);
      expect(auditCalls.length).toBeGreaterThan(1); // flagged + outcome
      for (const c of auditCalls)
        expect({ row: c.checkedBy, hashed: c.hashed }).toEqual({ row: c.checkedBy, hashed: true });
    });

    it("the daemon's background re-auth writes no deny row while the human's card is open", async () => {
      // With calledFromDaemon the native/terminal racers are skipped in THIS
      // process while the daemon holds the card; an empty race there is not a
      // decision, and a 'dlp-review-denied' row would be a deny nobody gave.
      writeUnkeyedHomeNoRacer();
      await authorizeHeadless('Bash', BASH_ARGS, GATEWAY, { calledFromDaemon: true });
      expect(auditCalls.some((c) => c.checkedBy === 'dlp-review-denied')).toBe(false);
    });

    it('the final deny row exists and names the pattern (the flagged row alone said "allow")', async () => {
      writeUnkeyedHomeNoRacer();
      await authorizeHeadless('Bash', BASH_ARGS, GATEWAY);
      const denies = auditCalls.filter((c) => c.decision === 'deny');
      expect(denies.length).toBeGreaterThan(0);
      expect(denies.some((c) => c.meta.dlpPattern === 'Bearer Token')).toBe(true);
      // and no row's attribution carries the secret itself
      for (const c of auditCalls)
        expect(JSON.stringify(c.meta)).not.toContain(FAKE_BEARER.slice(7));
    });
  });

  // ── Never allow on silence or failure ─────────────────────────────────────
  describe('no human answers', () => {
    it('a timeout is a deny, never an allow', async () => {
      mockInitSaaS.mockResolvedValue({ pending: true, requestId: 'req-1' });
      mockPollSaaS.mockImplementation(() => new Promise(() => {})); // nobody clicks
      const r = await authorizeHeadless('Bash', BASH_ARGS, GATEWAY);
      expect(r.approved).toBe(false);
      expect(r.blockedBy).toBe('timeout');
    });

    it('a cloud failure is a deny, never an allow', async () => {
      mockInitSaaS.mockRejectedValue(new Error('ECONNRESET'));
      const r = await authorizeHeadless('Bash', BASH_ARGS, GATEWAY);
      expect(r.approved).toBe(false);
    });
  });

  // ── Unchanged behaviour ───────────────────────────────────────────────────
  describe('what must not change', () => {
    it("reviewAction:'block' still hard-denies at the gate: no flagged row, no race", async () => {
      writeUnkeyedHomeNoRacer({}, { reviewAction: 'block' });
      const r = await authorizeHeadless('Bash', BASH_ARGS, GATEWAY);
      expect(r.approved).toBe(false);
      expect(r.blockedBy).toBe('local-config');
      expect(r.blockedByLabel).toContain('DLP');
      expect(auditCalls.some((c) => c.checkedBy === 'dlp-review-flagged')).toBe(false);
      expect(mockInitSaaS).not.toHaveBeenCalled();
    });

    it('inline-ask still defers a DLP review to the dev, before any SaaS call', async () => {
      const r = await authorizeHeadless(
        'Bash',
        BASH_ARGS,
        { agent: 'Claude Code' },
        { deferReview: true }
      );
      expect(r.review).toBe(true);
      expect(mockInitSaaS).not.toHaveBeenCalled();
    });
  });
});
