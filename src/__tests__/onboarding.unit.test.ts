import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { onboardMachine, renderOnboardOutcome } from '../onboarding';
import { writeCredentialsAndConfig } from '../credentials';
import { setupDetectedAgents } from '../setup';
import { runCloudSync, runPolicyPush } from '../daemon/sync';
import { isTestingMode } from '../cli/daemon-starter';

vi.mock('../config/write', () => ({
  globalConfigPath: () => '/test/config.json',
  writeConfigFile: vi.fn(),
}));
vi.mock('../credentials', () => ({ writeCredentialsAndConfig: vi.fn() }));
vi.mock('../setup', () => ({ setupDetectedAgents: vi.fn() }));
vi.mock('../daemon/sync', () => ({ runCloudSync: vi.fn(), runPolicyPush: vi.fn() }));
vi.mock('../daemon/service', () => ({
  ensureAutostartHealthy: vi.fn(() => 'skipped'),
  autostartState: vi.fn(() => 'absent'),
  installDaemonService: vi.fn(() => ({ ok: true })),
}));
vi.mock('@inquirer/prompts', () => ({ confirm: vi.fn(() => Promise.resolve(true)) }));
import { confirm } from '@inquirer/prompts';
import { autostartState, installDaemonService } from '../daemon/service';
vi.mock('../auth/daemon', () => ({ isDaemonRunning: vi.fn(() => false) }));
vi.mock('../cli/daemon-starter', () => ({ isTestingMode: vi.fn(() => false) }));
vi.mock('../config', () => ({
  DEFAULT_CONFIG: { settings: { approvers: { native: true, terminal: true } } },
  getConfig: vi.fn(() => ({ settings: { autoStartDaemon: true } })),
}));

const step = (out: Awaited<ReturnType<typeof onboardMachine>>, name: string) =>
  out.steps.find((s) => s.name === name);

describe('onboardMachine', () => {
  beforeEach(() => {
    vi.mocked(writeCredentialsAndConfig).mockReturnValue({
      profileName: 'default',
      effectiveCloud: true,
    });
    vi.mocked(setupDetectedAgents).mockResolvedValue(['claude']);
    vi.mocked(runCloudSync).mockResolvedValue({
      ok: true,
      rules: 3,
      fetchedAt: '2026-08-28T00:00:00Z',
    });
    vi.mocked(runPolicyPush).mockResolvedValue({ ok: true });
    vi.mocked(isTestingMode).mockReturnValue(false);
  });

  it('is ok only when credentials + sync + register all succeed', async () => {
    const out = await onboardMachine('n9_live_x');
    expect(out.ok).toBe(true);
    expect(out.wired).toEqual(['claude']);
    expect(step(out, 'register')?.ok).toBe(true);
  });

  it('a failed cloud sync fails the onboarding with the reason', async () => {
    vi.mocked(runCloudSync).mockResolvedValue({ ok: false, reason: 'API returned 500' });
    const out = await onboardMachine('n9_live_x');
    expect(out.ok).toBe(false);
    expect(step(out, 'policy-sync')).toMatchObject({ ok: false, detail: 'API returned 500' });
  });

  it('a failed snapshot push (registration ack) fails the onboarding', async () => {
    vi.mocked(runPolicyPush).mockResolvedValue({ ok: false, reason: 'Push failed' });
    const out = await onboardMachine('n9_live_x');
    expect(out.ok).toBe(false);
    expect(step(out, 'register')).toMatchObject({ ok: false, detail: 'Push failed' });
  });

  it('an agent-wiring failure does NOT fail the onboarding (best-effort)', async () => {
    vi.mocked(setupDetectedAgents).mockRejectedValue(new Error('no settings file'));
    const out = await onboardMachine('n9_live_x');
    expect(out.ok).toBe(true);
    expect(step(out, 'agents')?.ok).toBe(false);
  });

  it('a credentials write failure short-circuits everything', async () => {
    vi.mocked(writeCredentialsAndConfig).mockImplementation(() => {
      throw new Error('EACCES');
    });
    const out = await onboardMachine('n9_live_x');
    expect(out.ok).toBe(false);
    expect(out.steps).toHaveLength(1);
    expect(runCloudSync).not.toHaveBeenCalled();
  });

  it('testing mode skips the cloud steps but still counts as ok', async () => {
    vi.mocked(isTestingMode).mockReturnValue(true);
    const out = await onboardMachine('n9_live_x');
    expect(out.ok).toBe(true);
    expect(runCloudSync).not.toHaveBeenCalled();
    expect(runPolicyPush).not.toHaveBeenCalled();
  });

  it('a named profile skips the cloud steps (they would verify the wrong key)', async () => {
    const out = await onboardMachine('n9_live_x', { profileName: 'work' });
    expect(out.ok).toBe(true);
    expect(runCloudSync).not.toHaveBeenCalled();
    expect(step(out, 'policy-sync')?.detail).toContain('named profile');
  });
});

describe('renderOnboardOutcome', () => {
  it('claims success only when ok, and carries failure reasons', async () => {
    vi.mocked(runPolicyPush).mockResolvedValue({ ok: false, reason: 'network down' });
    const out = await onboardMachine('n9_live_x');
    const text = renderOnboardOutcome(out, { workspaceName: 'Acme' });
    expect(text).not.toContain('✅');
    expect(text).toContain('Connection incomplete');
    expect(text).toContain('network down');
    expect(text).toContain('node9 sync');
  });
});

describe('dashboard login service prompt', () => {
  const input = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
  const output = Object.getOwnPropertyDescriptor(process.stdout, 'isTTY');
  beforeEach(() => {
    vi.clearAllMocks();
    for (const key of [
      'NODE9_NONINTERACTIVE',
      'CI',
      'GITHUB_ACTIONS',
      'GITLAB_CI',
      'TF_BUILD',
      'BUILDKITE',
    ])
      vi.stubEnv(key, '');
    Object.defineProperty(process.stdin, 'isTTY', { configurable: true, value: true });
    Object.defineProperty(process.stdout, 'isTTY', { configurable: true, value: true });
    vi.mocked(writeCredentialsAndConfig).mockReturnValue({
      profileName: 'default',
      effectiveCloud: true,
    });
    vi.mocked(setupDetectedAgents).mockResolvedValue([]);
    vi.mocked(runCloudSync).mockResolvedValue({ ok: true, rules: 0, fetchedAt: 'now' });
    vi.mocked(runPolicyPush).mockResolvedValue({ ok: true });
    vi.mocked(isTestingMode).mockReturnValue(false);
    vi.mocked(autostartState).mockReturnValue('absent');
    vi.mocked(confirm).mockResolvedValue(true);
    vi.mocked(installDaemonService).mockReturnValue({
      ok: true,
      platform: 'systemd',
      alreadyInstalled: false,
    });
  });
  afterEach(() => {
    if (input) Object.defineProperty(process.stdin, 'isTTY', input);
    else Reflect.deleteProperty(process.stdin, 'isTTY');
    if (output) Object.defineProperty(process.stdout, 'isTTY', output);
    else Reflect.deleteProperty(process.stdout, 'isTTY');
    vi.unstubAllEnvs();
  });
  it('restores interactive intent and offers service installation after successful registration', async () => {
    vi.mocked(setupDetectedAgents).mockImplementation(async () => {
      expect(process.env.NODE9_NONINTERACTIVE).toBe('1');
      return [];
    });
    const out = await onboardMachine('n9_live_x');
    expect(process.env.NODE9_NONINTERACTIVE).toBe('');
    expect(confirm).toHaveBeenCalledWith(expect.objectContaining({ default: true }));
    expect(installDaemonService).toHaveBeenCalledOnce();
    expect(step(out, 'daemon')?.ok).toBe(true);
  });
  it.each(['CI', 'NODE9_NONINTERACTIVE'])('skips prompts under %s', async (key) => {
    vi.stubEnv(key, '1');
    await onboardMachine('n9_live_x');
    expect(confirm).not.toHaveBeenCalled();
    expect(installDaemonService).not.toHaveBeenCalled();
  });
  it('skips prompts when stdin is piped or cloud registration fails', async () => {
    Object.defineProperty(process.stdin, 'isTTY', { configurable: true, value: false });
    await onboardMachine('n9_live_x');
    expect(confirm).not.toHaveBeenCalled();
    Object.defineProperty(process.stdin, 'isTTY', { configurable: true, value: true });
    vi.mocked(runPolicyPush).mockResolvedValue({ ok: false, reason: 'offline' });
    await onboardMachine('n9_live_x');
    expect(confirm).not.toHaveBeenCalled();
  });
  it('preserves successful login on decline, cancellation and installation failure', async () => {
    vi.mocked(confirm).mockResolvedValue(false);
    expect((await onboardMachine('n9_live_x')).ok).toBe(true);
    expect(installDaemonService).not.toHaveBeenCalled();
    const cancel = new Error('cancel');
    cancel.name = 'ExitPromptError';
    vi.mocked(confirm).mockRejectedValue(cancel);
    expect((await onboardMachine('n9_live_x')).ok).toBe(true);
    expect(installDaemonService).not.toHaveBeenCalled();
    vi.mocked(confirm).mockResolvedValue(true);
    vi.mocked(installDaemonService).mockReturnValue({
      ok: false,
      reason: 'service manager unavailable',
    });
    const out = await onboardMachine('n9_live_x');
    expect(out.ok).toBe(true);
    expect(step(out, 'daemon')?.ok).toBe(false);
  });
});
