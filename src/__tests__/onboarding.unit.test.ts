import { describe, it, expect, vi, beforeEach } from 'vitest';
import { onboardMachine, renderOnboardOutcome } from '../onboarding';
import { writeCredentialsAndConfig } from '../credentials';
import { setupDetectedAgents } from '../setup';
import { runCloudSync, runPolicyPush } from '../daemon/sync';
import { isTestingMode } from '../cli/daemon-starter';

vi.mock('../credentials', () => ({ writeCredentialsAndConfig: vi.fn() }));
vi.mock('../setup', () => ({ setupDetectedAgents: vi.fn() }));
vi.mock('../daemon/sync', () => ({ runCloudSync: vi.fn(), runPolicyPush: vi.fn() }));
vi.mock('../daemon/service', () => ({ ensureAutostartHealthy: vi.fn(() => 'skipped') }));
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
