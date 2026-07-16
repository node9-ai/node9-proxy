/**
 * A2 (Commit 2 liveness): autostartAdvice() — the pure decision that doctor/status
 * render. Kept pure (no systemctl/fs) so it's testable without depending on the
 * host's real systemd state. The state that silently staled policy for 6 days:
 * installed && !enabled.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { autostartAdvice } from '../daemon/service';

const origPlatform = Object.getOwnPropertyDescriptor(process, 'platform')!;
const setPlatform = (p: NodeJS.Platform) =>
  Object.defineProperty(process, 'platform', { value: p, configurable: true });
afterEach(() => Object.defineProperty(process, 'platform', origPlatform));

describe('autostartAdvice', () => {
  it('warns on INSTALLED but DISABLED (the incident state) with the enable hint', () => {
    setPlatform('linux');
    const a = autostartAdvice({ installed: true, enabled: false, cloudEnabled: true });
    expect(a?.level).toBe('warn');
    expect(a?.message).toMatch(/INSTALLED but DISABLED/i);
    expect(a?.hint).toMatch(/systemctl --user enable --now node9-daemon/);
  });

  it('stays SILENT in privacy mode (advice is about cloud freshness, which privacy users skip)', () => {
    setPlatform('linux');
    expect(autostartAdvice({ installed: true, enabled: false, cloudEnabled: false })).toBeNull();
  });

  it('stays silent on an uninstallable platform (win32) even for a cloud user', () => {
    setPlatform('win32');
    expect(autostartAdvice({ installed: false, enabled: false, cloudEnabled: true })).toBeNull();
  });

  it('returns null when installed AND enabled (healthy)', () => {
    expect(autostartAdvice({ installed: true, enabled: true, cloudEnabled: true })).toBeNull();
  });

  it('info-warns on NOT installed only when cloud policy is enforced', () => {
    // Pinned to a real installable platform — on win32 this branch is silent by
    // design (see the sibling win32 test), so this assertion must not depend on
    // whatever platform the test runner happens to be (the bug that broke Windows CI).
    setPlatform('linux');
    const cloud = autostartAdvice({ installed: false, enabled: false, cloudEnabled: true });
    expect(cloud?.message).toMatch(/No daemon autostart installed/i);
    // privacy mode (no cloud) doesn't need autostart → silent
    expect(autostartAdvice({ installed: false, enabled: false, cloudEnabled: false })).toBeNull();
  });

  it('uses the node9-daemon-install hint on darwin (no systemctl)', () => {
    setPlatform('darwin');
    const a = autostartAdvice({ installed: true, enabled: false, cloudEnabled: true });
    expect(a?.hint).toMatch(/node9 daemon install/);
    expect(a?.hint).not.toMatch(/systemctl/);
  });
});
