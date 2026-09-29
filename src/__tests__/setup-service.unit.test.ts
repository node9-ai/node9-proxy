import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
vi.mock('../daemon/service', () => ({
  installDaemonService: vi.fn(),
  uninstallDaemonService: vi.fn(),
  isDaemonServiceInstalled: vi.fn(),
  isDaemonServiceEnabled: vi.fn(),
}));
vi.mock('../cli/daemon-starter', () => ({
  isTestingMode: () => false,
  autoStartDaemonAndWait: vi.fn(),
}));
import { installDaemonService, uninstallDaemonService } from '../daemon/service';
import { autoStartDaemonAndWait } from '../cli/daemon-starter';
import { applyChanges } from '../cli/local-setup';
let home: string;
let file: string;
beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-service-choice-'));
  vi.spyOn(os, 'homedir').mockReturnValue(home);
  fs.mkdirSync(path.join(home, '.node9'));
  file = path.join(home, '.node9/config.json');
  fs.writeFileSync(file, JSON.stringify({ settings: { autoStartDaemon: false }, custom: 42 }));
  vi.mocked(installDaemonService).mockReset();
  vi.mocked(uninstallDaemonService).mockReset();
  vi.mocked(autoStartDaemonAndWait).mockReset();
  vi.mocked(autoStartDaemonAndWait).mockResolvedValue(true);
});
afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(home, { recursive: true, force: true });
});
describe('setup service boundary', () => {
  it('enables autostart only after the service is installed and waits for the daemon', async () => {
    vi.mocked(installDaemonService).mockReturnValue({
      ok: true,
      platform: 'systemd',
      alreadyInstalled: false,
    });
    const result = await applyChanges([{ key: 'service', from: 'off', to: true }]);
    expect(result[0].ok).toBe(true);
    expect(installDaemonService).toHaveBeenCalledOnce();
    expect(uninstallDaemonService).not.toHaveBeenCalled();
    expect(autoStartDaemonAndWait).toHaveBeenCalledOnce();
    expect(JSON.parse(fs.readFileSync(file, 'utf8'))).toEqual({
      settings: { autoStartDaemon: true },
      custom: 42,
    });
  });
  it('does not claim or persist success when the service cannot be installed', async () => {
    vi.mocked(installDaemonService).mockReturnValue({
      ok: false,
      reason: 'Service manager unavailable',
    });
    const before = fs.readFileSync(file, 'utf8');
    expect(await applyChanges([{ key: 'service', from: 'off', to: true }])).toEqual([
      { key: 'service', ok: false, detail: 'Service manager unavailable' },
    ]);
    expect(autoStartDaemonAndWait).not.toHaveBeenCalled();
    expect(fs.readFileSync(file, 'utf8')).toBe(before);
  });
  it('removes autostart when the installed service is unchecked', async () => {
    fs.writeFileSync(file, JSON.stringify({ settings: { autoStartDaemon: true } }));
    vi.mocked(uninstallDaemonService).mockReturnValue({
      ok: true,
      platform: 'systemd',
      alreadyInstalled: false,
    });
    expect((await applyChanges([{ key: 'service', from: 'on', to: false }]))[0].ok).toBe(true);
    expect(uninstallDaemonService).toHaveBeenCalledOnce();
    expect(installDaemonService).not.toHaveBeenCalled();
    expect(JSON.parse(fs.readFileSync(file, 'utf8')).settings.autoStartDaemon).toBe(false);
  });
  it('reports an installed service whose daemon did not become ready', async () => {
    vi.mocked(installDaemonService).mockReturnValue({
      ok: true,
      platform: 'systemd',
      alreadyInstalled: false,
    });
    vi.mocked(autoStartDaemonAndWait).mockResolvedValue(false);
    const result = await applyChanges([{ key: 'service', from: 'off', to: true }]);
    expect(result[0].ok).toBe(false);
    expect(result[0].detail).toContain('not ready');
  });
});
