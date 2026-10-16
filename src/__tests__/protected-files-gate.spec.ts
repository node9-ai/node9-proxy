import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import os from 'os';
import { DEFAULT_CONFIG, type Config } from '../config';
import { authorizeHeadless } from '../auth/orchestrator';
import { explainPolicy } from '../policy';

const state = vi.hoisted(() => ({
  config: null as Config | null,
  daemon: false,
  taint: false,
  trust: false,
  cloud: false,
  audit: vi.fn(),
  init: vi.fn(),
  human: vi.fn(),
}));
vi.mock('../config', async (original) => {
  const real = await original<typeof import('../config')>();
  return {
    ...real,
    getConfig: (...args: Parameters<typeof real.getConfig>) =>
      state.config ?? real.getConfig(...args),
    getCredentials: () =>
      state.cloud ? { apiKey: 'fixture', apiUrl: 'https://example.invalid' } : null,
  };
});
vi.mock('../auth/state', async (original) => ({
  ...(await original<typeof import('../auth/state')>()),
  checkPause: () => ({ paused: false }),
  getPersistentDecision: () => (state.trust ? 'allow' : null),
  getActiveTrustSession: () => state.trust,
}));
vi.mock('../auth/daemon', async (original) => ({
  ...(await original<typeof import('../auth/daemon')>()),
  isDaemonRunning: () => state.daemon,
  checkSessionTaint: async () => ({ tainted: state.taint }),
  checkTaint: async () => ({ tainted: state.taint }),
  daemonHasInteractiveApprover: () => state.human(),
  notifyActivitySocket: async () => true,
  notifyTaint: async () => undefined,
  getInternalToken: () => null,
}));
vi.mock('../auth/cloud', async (original) => ({
  ...(await original<typeof import('../auth/cloud')>()),
  initNode9SaaS: (...args: unknown[]) => state.init(...args),
  pollNode9SaaS: async () => ({ approved: false }),
  resolveNode9SaaS: async () => undefined,
}));
vi.mock('../audit', async (original) => ({
  ...(await original<typeof import('../audit')>()),
  appendLocalAudit: (...args: unknown[]) => {
    state.audit(...args);
    return 'file-test-event';
  },
}));

const meta = { agent: 'claude', sessionId: 'protected-file-test' };
const options = { calledFromDaemon: true, deferReview: true };
// The protected-file policy is POSIX-only: on win32 the host prepares no
// accesses and legacy path DLP keeps its block (see src/policy/file-access.ts).
describe.skipIf(process.platform === 'win32')(
  'protected files at the real authorization gate',
  () => {
    beforeEach(() => {
      state.config = structuredClone(DEFAULT_CONFIG);
      state.config.policy.smartRules = [];
      state.config.policy.dangerousWords = [];
      state.config.policy.sandboxPaths = [];
      state.config.policy.loopDetection.enabled = false;
      state.config.settings.approvers = {
        native: false,
        browser: false,
        cloud: false,
        terminal: false,
      };
      state.config.settings.approvalTimeoutMs = 5;
      state.daemon = state.taint = state.trust = state.cloud = false;
      state.init.mockResolvedValue({ pending: false, approved: true });
      state.human.mockResolvedValue(true);
      state.audit.mockClear();
    });
    afterEach(() => vi.unstubAllEnvs());

    it.each(['Read', 'read_file'])(
      'asks on %s of hashes despite ignored-tool defaults',
      async (tool) => {
        expect(
          await authorizeHeadless(tool, { file_path: '/etc/shadow' }, meta, options)
        ).toMatchObject({ approved: false, review: true });
        expect(
          await authorizeHeadless(tool, { file_path: '/etc/passwd' }, meta, options)
        ).toMatchObject({ approved: true });
      }
    );
    it.each(['Write', 'Edit', 'write_file', 'edit_file', 'MultiEdit'])(
      'blocks %s of system authentication',
      async (tool) => {
        const result = await authorizeHeadless(
          tool,
          { file_path: '/etc/passwd', content: 'fixture' },
          meta,
          options
        );
        expect(result).toMatchObject({
          approved: false,
          ruleHit: 'block-system-auth-mutation',
          blockKind: 'protected-path',
        });
        expect(result.review).not.toBe(true);
      }
    );
    it('asks for startup writes through both doors', async () => {
      const target = `${os.homedir()}/.bashrc`;
      for (const [tool, args] of [
        ['Write', { path: target, content: 'export EDITOR=vim' }],
        ['Bash', { command: 'echo x >> ~/.bashrc' }],
      ] as const) {
        expect(await authorizeHeadless(tool, args, meta, options)).toMatchObject({
          approved: false,
          review: true,
        });
      }
    });
    it('holds with standing trust and persistent allow', async () => {
      state.trust = true;
      expect(
        await authorizeHeadless('Read', { path: '/etc/gshadow' }, meta, options)
      ).toMatchObject({
        approved: false,
        review: true,
      });
    });
    it('blocks before a tainted call can bypass ordinary policy', async () => {
      state.taint = true;
      expect(
        await authorizeHeadless('Bash', { command: 'rm /etc/passwd' }, meta, options)
      ).toMatchObject({ approved: false, ruleHit: 'block-system-auth-mutation' });
    });
    it('cannot soften a block when a real human could approve it', async () => {
      for (const name of ['VITEST', 'NODE_ENV', 'CI', 'NODE9_TESTING']) vi.stubEnv(name, '');
      state.daemon = true;
      state.config!.settings.approvers.native = true;
      vi.stubEnv('DISPLAY', ':0');
      const result = await authorizeHeadless('Bash', { command: 'rm /etc/passwd' }, meta, options);
      expect(result.approved).toBe(false);
      expect(result.review).not.toBe(true);
      expect(state.human).not.toHaveBeenCalled();
    });
    it('rejects an automatic cloud allow for a protected review', async () => {
      state.cloud = true;
      state.config!.settings.approvers.cloud = true;
      const result = await authorizeHeadless('Read', { path: '/etc/shadow' }, meta, {
        calledFromDaemon: true,
      });
      expect(result.approved).toBe(false);
      expect(state.init.mock.calls[0]?.at(-1)).toBe(true);
    });
    it('denies without any approval mechanism', async () => {
      state.config!.settings.approvalTimeoutMs = 0;
      const result = await authorizeHeadless('Read', { path: '/etc/shadow' }, meta, {
        calledFromDaemon: true,
      });
      expect(result).toMatchObject({ approved: false, noApprovalMechanism: true });
    });
    it('respects check settings without resurrecting legacy DLP', async () => {
      state.config!.policy.checks = { 'files.password-hashes': 'off' };
      expect(
        (await authorizeHeadless('Read', { path: '/etc/shadow' }, meta, options)).approved
      ).toBe(true);
      state.config!.policy.checks = { 'files.password-hashes': 'block' };
      const blocked = await authorizeHeadless('Read', { path: '/etc/shadow' }, meta, options);
      expect(blocked.approved).toBe(false);
      expect(blocked.review).not.toBe(true);
    });
    it('preserves the old system path block for unclassified tools', async () => {
      expect(
        (await authorizeHeadless('custom_file_tool', { path: '/etc/shadow' }, meta, options))
          .approved
      ).toBe(false);
    });
    it.each(['observe', 'audit'] as const)('records without enforcing in %s mode', async (mode) => {
      state.config!.settings.mode = mode;
      expect(
        (await authorizeHeadless('Write', { path: '/etc/passwd' }, meta, options)).approved
      ).toBe(true);
      expect(state.audit.mock.calls.some((c) => c[3] === 'observe-mode-file-protection')).toBe(
        true
      );
    });
    it('upgrades reviews under panic mode', async () => {
      state.config!.settings.panicMode = true;
      const result = await authorizeHeadless('Read', { path: '/etc/shadow' }, meta, options);
      expect(result.approved).toBe(false);
      expect(result.review).not.toBe(true);
    });
    it('works with secret DLP and shields disabled', async () => {
      state.config!.policy.dlp.enabled = false;
      expect(
        (await authorizeHeadless('Write', { path: '/etc/passwd' }, meta, options)).approved
      ).toBe(false);
      expect((await authorizeHeadless('Read', { path: '/etc/shadow' }, meta, options)).review).toBe(
        true
      );
    });
    it('preserves a content-DLP block on a startup write', async () => {
      const key = 'AKIA' + 'J2XZKZMV' + 'P3NQRSTU';
      const result = await authorizeHeadless(
        'Write',
        { path: `${os.homedir()}/.bashrc`, content: `AWS_ACCESS_KEY_ID=${key}` },
        meta,
        options
      );
      expect(result.approved).toBe(false);
      expect(result.review).not.toBe(true);
    });
    it('uses the request cwd and records the file rule', async () => {
      const result = await authorizeHeadless('Write', { path: 'passwd' }, meta, {
        ...options,
        cwd: '/etc',
      });
      expect(result).toMatchObject({ approved: false, ruleHit: 'block-system-auth-mutation' });
      expect(
        state.audit.mock.calls.some((c) => c[4]?.ruleName === 'block-system-auth-mutation')
      ).toBe(true);
    });
    it('agrees with explain for identified file reads and writes', async () => {
      expect((await explainPolicy('Read', { path: '/etc/shadow' })).decision).toBe('review');
      expect((await explainPolicy('Read', { path: '/etc/passwd' })).decision).toBe('allow');
      expect((await explainPolicy('Write', { path: '/etc/passwd' })).decision).toBe('block');
    });
  }
);
