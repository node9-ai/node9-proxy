import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
vi.mock('@inquirer/prompts', () => ({ select: vi.fn(), confirm: vi.fn() }));
vi.mock('../cli/interactive', () => ({
  isInteractive: () => true,
  isCI: () => false,
  isPromptCancellation: () => false,
}));
vi.mock('../config', () => ({ getCredentials: vi.fn(() => null) }));
vi.mock('../auth/browser-login', () => ({ loginViaBrowser: vi.fn() }));
vi.mock('../cli/local-setup', () => ({
  runLocalSetup: vi.fn(),
  renderSummary: () => 'Local summary',
}));
vi.mock('../onboarding', () => ({ renderOnboardOutcome: () => 'Cloud summary' }));
vi.mock('../cli/commands/logout', () => ({ disconnectMachine: vi.fn() }));
import { select, confirm } from '@inquirer/prompts';
import { loginViaBrowser } from '../auth/browser-login';
import { disconnectMachine } from '../cli/commands/logout';
import { runLocalSetup } from '../cli/local-setup';
import { getCredentials } from '../config';
import { runSetupWizard } from '../cli/first-run';
const outcome = { ok: false, wired: [], steps: [] };
beforeEach(() => {
  vi.clearAllMocks();
  vi.stubEnv('NODE9_API_KEY', '');
  vi.stubEnv('NODE9_PROFILE', '');
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.mocked(select).mockResolvedValue('dashboard');
  vi.mocked(getCredentials).mockReturnValue(null);
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});
describe('setup wizard routing', () => {
  it('successful cloud setup does not ask local or telemetry questions', async () => {
    vi.mocked(loginViaBrowser).mockResolvedValue({
      kind: 'connected',
      workspaceName: 'demo',
      outcome: { ...outcome, ok: true },
    });
    await runSetupWizard({ version: 'test' });
    expect(select).toHaveBeenCalledTimes(1);
    expect(confirm).not.toHaveBeenCalled();
    expect(runLocalSetup).not.toHaveBeenCalled();
  });
  it('can continue locally after cancellation with no saved connection', async () => {
    vi.mocked(loginViaBrowser).mockResolvedValue({ kind: 'cancelled', reason: 'Denied' });
    vi.mocked(confirm).mockResolvedValue(true);
    await runSetupWizard({ version: 'test' });
    expect(runLocalSetup).toHaveBeenCalledTimes(1);
    expect(disconnectMachine).not.toHaveBeenCalled();
  });
  it('keeps a pre-existing connection on cancellation', async () => {
    vi.mocked(loginViaBrowser).mockResolvedValue({ kind: 'cancelled', reason: 'Denied' });
    vi.mocked(getCredentials).mockReturnValue({
      apiKey: 'previous',
      apiUrl: 'https://example.invalid',
    });
    await runSetupWizard({ version: 'test' });
    expect(disconnectMachine).not.toHaveBeenCalled();
    expect(runLocalSetup).not.toHaveBeenCalled();
    expect(confirm).not.toHaveBeenCalled();
  });
  it('disconnects before local setup and reports unconfirmed remote revocation', async () => {
    vi.mocked(select).mockResolvedValueOnce('dashboard').mockResolvedValueOnce('local');
    vi.mocked(loginViaBrowser).mockResolvedValue({
      kind: 'partial',
      workspaceName: 'demo',
      outcome,
      retry: vi.fn(),
    });
    vi.mocked(disconnectMachine).mockResolvedValue({
      outcome: 'unreachable',
      localRemoved: true,
      detail: 'Offline',
    });
    await runSetupWizard({ version: 'test' });
    expect(disconnectMachine).toHaveBeenCalledWith({
      resetCloudApprover: true,
      profile: 'default',
    });
    expect(runLocalSetup).toHaveBeenCalledTimes(1);
    expect(console.log).toHaveBeenCalledWith(
      expect.stringContaining('revocation was not confirmed')
    );
  });
  it('keeps a partial connection without entering local setup', async () => {
    vi.mocked(select).mockResolvedValueOnce('dashboard').mockResolvedValueOnce('keep');
    vi.mocked(loginViaBrowser).mockResolvedValue({
      kind: 'partial',
      workspaceName: 'demo',
      outcome,
      retry: vi.fn(),
    });
    await runSetupWizard({ version: 'test' });
    expect(disconnectMachine).not.toHaveBeenCalled();
    expect(runLocalSetup).not.toHaveBeenCalled();
  });
});
