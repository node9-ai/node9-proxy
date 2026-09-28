import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
vi.mock('../auth/device-login', () => ({ runDeviceLogin: vi.fn() }));
vi.mock('../onboarding', () => ({ onboardMachine: vi.fn() }));
import { runDeviceLogin } from '../auth/device-login';
import { onboardMachine } from '../onboarding';
import { loginViaBrowser } from '../auth/browser-login';
let home: string;
beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-browser-'));
  vi.spyOn(os, 'homedir').mockReturnValue(home);
  fs.mkdirSync(path.join(home, '.node9'));
  vi.mocked(runDeviceLogin).mockReset();
  vi.mocked(onboardMachine).mockReset();
});
afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(home, { recursive: true, force: true });
});
describe('shared browser login', () => {
  it('does not classify previous credentials as a partial attempt after cancellation', async () => {
    const file = path.join(home, '.node9/credentials.json');
    fs.writeFileSync(file, JSON.stringify({ default: { apiKey: 'previous' } }));
    vi.mocked(runDeviceLogin).mockResolvedValue({ ok: false, reason: 'Denied', cancelled: true });
    expect(await loginViaBrowser({ cliVersion: 'test' })).toEqual({
      kind: 'cancelled',
      reason: 'Denied',
    });
    expect(onboardMachine).not.toHaveBeenCalled();
    expect(JSON.parse(fs.readFileSync(file, 'utf8')).default.apiKey).toBe('previous');
  });
  it('distinguishes connection errors from cancellation', async () => {
    vi.mocked(runDeviceLogin).mockResolvedValue({ ok: false, reason: 'Offline' });
    expect(await loginViaBrowser({ cliVersion: 'test' })).toEqual({
      kind: 'failed',
      reason: 'Offline',
    });
  });
  it('detects a key saved before a later exception and retries without device auth', async () => {
    vi.mocked(runDeviceLogin).mockResolvedValue({
      ok: true,
      apiKey: 'attempt',
      workspaceName: 'Demo',
      machineName: 'test',
    });
    vi.mocked(onboardMachine)
      .mockImplementationOnce(async (key) => {
        fs.writeFileSync(
          path.join(home, '.node9/credentials.json'),
          JSON.stringify({ default: { apiKey: key } })
        );
        process.env.NODE9_NONINTERACTIVE = '1';
        throw new Error('Sync failed');
      })
      .mockResolvedValueOnce({ ok: true, steps: [], wired: [] });
    const previous = process.env.NODE9_NONINTERACTIVE;
    const result = await loginViaBrowser({ cliVersion: 'test' });
    expect(result.kind).toBe('partial');
    expect(process.env.NODE9_NONINTERACTIVE).toBe(previous);
    if (result.kind !== 'partial') throw new Error('Expected partial');
    expect((await result.retry()).kind).toBe('connected');
    expect(runDeviceLogin).toHaveBeenCalledTimes(1);
  });
});
