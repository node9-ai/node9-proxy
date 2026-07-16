/**
 * A1 (Commit 2 liveness — policy-sync-commit2-liveness-code-design.md):
 * isDaemonServiceEnabled() — the missing probe for the exact state that silently
 * staled policy for 6 days: the autostart unit is INSTALLED but DISABLED.
 *
 * Linux: `systemctl --user is-enabled node9-daemon` prints "enabled" / exit 0 only
 * when durably enabled. The check is deliberately STRICT — "enabled-runtime" (does
 * NOT survive reboot, the failure mode we target) and "static"/"indirect" must read
 * as NOT enabled. Darwin: `launchctl list <label>` exits 0 iff loaded.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('child_process', () => ({ spawnSync: vi.fn(), execFileSync: vi.fn() }));

import { spawnSync } from 'child_process';
import { isDaemonServiceEnabled } from '../daemon/service';

const mockSpawn = vi.mocked(spawnSync);
const origPlatform = Object.getOwnPropertyDescriptor(process, 'platform')!;
const setPlatform = (p: NodeJS.Platform) =>
  Object.defineProperty(process, 'platform', { value: p, configurable: true });
// Minimal SpawnSyncReturns shape the probe reads.
const ret = (status: number, stdout = '') => ({ status, stdout, stderr: '' }) as never;

beforeEach(() => mockSpawn.mockReset());
afterEach(() => Object.defineProperty(process, 'platform', origPlatform));

describe('isDaemonServiceEnabled — linux (systemctl)', () => {
  beforeEach(() => setPlatform('linux'));

  it('true when is-enabled prints "enabled" and exits 0', () => {
    mockSpawn.mockReturnValue(ret(0, 'enabled\n'));
    expect(isDaemonServiceEnabled()).toBe(true);
    // Probes the right unit, read-only.
    expect(mockSpawn).toHaveBeenCalledWith(
      'systemctl',
      ['--user', 'is-enabled', 'node9-daemon'],
      expect.anything()
    );
  });

  it('false when disabled (exit nonzero)', () => {
    mockSpawn.mockReturnValue(ret(1, 'disabled\n'));
    expect(isDaemonServiceEnabled()).toBe(false);
  });

  it('false for "enabled-runtime" — exits 0 but does NOT survive reboot (strict)', () => {
    mockSpawn.mockReturnValue(ret(0, 'enabled-runtime\n'));
    expect(isDaemonServiceEnabled()).toBe(false);
  });

  it('false when the unit is absent (nonzero, empty stdout)', () => {
    mockSpawn.mockReturnValue(ret(1, ''));
    expect(isDaemonServiceEnabled()).toBe(false);
  });
});

describe('isDaemonServiceEnabled — darwin (launchctl)', () => {
  beforeEach(() => setPlatform('darwin'));

  it('true when launchctl list <label> exits 0 (loaded)', () => {
    mockSpawn.mockReturnValue(ret(0));
    expect(isDaemonServiceEnabled()).toBe(true);
    expect(mockSpawn).toHaveBeenCalledWith(
      'launchctl',
      ['list', 'ai.node9.daemon'],
      expect.anything()
    );
  });

  it('false when not loaded (nonzero)', () => {
    mockSpawn.mockReturnValue(ret(1));
    expect(isDaemonServiceEnabled()).toBe(false);
  });
});

describe('isDaemonServiceEnabled — robustness', () => {
  it('false on an unsupported platform without probing', () => {
    setPlatform('win32');
    expect(isDaemonServiceEnabled()).toBe(false);
    expect(mockSpawn).not.toHaveBeenCalled();
  });

  it('false (never throws) when spawnSync returns a malformed result', () => {
    // A missing/undefined SpawnSyncReturns makes `r.status` throw inside the probe;
    // the try/catch must swallow it and return false. (Testing the catch via a
    // malformed RETURN rather than a mock-implementation-throw, which vitest v4
    // flags as a test error even when the code under test catches it.)
    setPlatform('linux');
    mockSpawn.mockReturnValue(undefined as never);
    expect(isDaemonServiceEnabled()).toBe(false);
  });
});
