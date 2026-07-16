/**
 * A3 (Commit 2 liveness): autostartRepairDecision() — the pure core of the
 * self-heal that runs on init/login. Decides whether to re-enable a disabled
 * autostart service. Pure (no systemctl) so the branching is testable; the thin
 * ensureAutostartHealthy() wrapper does the actual install.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { autostartRepairDecision } from '../daemon/service';

const origPlatform = Object.getOwnPropertyDescriptor(process, 'platform')!;
const setPlatform = (p: NodeJS.Platform) =>
  Object.defineProperty(process, 'platform', { value: p, configurable: true });
afterEach(() => Object.defineProperty(process, 'platform', origPlatform));

describe('autostartRepairDecision', () => {
  it("skips when autoStartDaemon is off (user opted out — don't force a service)", () => {
    setPlatform('linux');
    expect(
      autostartRepairDecision({ installed: false, enabled: false, autoStartDaemon: false })
    ).toBe('skip');
  });

  it('unsupported on a non linux/darwin platform', () => {
    setPlatform('win32');
    expect(
      autostartRepairDecision({ installed: false, enabled: false, autoStartDaemon: true })
    ).toBe('unsupported');
  });

  it('ok when already installed AND enabled (nothing to do)', () => {
    setPlatform('linux');
    expect(autostartRepairDecision({ installed: true, enabled: true, autoStartDaemon: true })).toBe(
      'ok'
    );
  });

  it('repairs when installed but DISABLED (the incident state)', () => {
    setPlatform('linux');
    expect(
      autostartRepairDecision({ installed: true, enabled: false, autoStartDaemon: true })
    ).toBe('repair');
  });

  it('does NOT auto-install a missing unit (only re-enables an existing one) — skip', () => {
    setPlatform('darwin');
    expect(
      autostartRepairDecision({ installed: false, enabled: false, autoStartDaemon: true })
    ).toBe('skip');
  });
});
