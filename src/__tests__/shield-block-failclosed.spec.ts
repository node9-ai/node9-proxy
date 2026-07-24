// src/__tests__/shield-block-failclosed.spec.ts
//
// Fail-closed gate for the block→review downgrade (task #17).
//
// When the daemon is running, a smart-rule/shield hard-block is downgraded to a
// review ("a human is at the keyboard"). In a NON-INTERACTIVE context (headless
// server, a piped agent with no GUI and no `node9 tail` connected) that
// assumption is false — and the approver race could then resolve the review to
// ALLOW via a cloud immediate-allow of a client-side shield the SaaS has no rule
// for. That is a fail-open on a HARD BLOCK (confirmed live: a coin-flip between
// allow and block on identical inputs).
//
// The downgrade is now gated on `hasReachableHumanApprover`: a real human must
// be reachable (a GUI display for the native popup, or a connected input-capable
// tail) or the block STAYS hard. This unit-tests that gate directly — the full
// authorizeHeadless path can't, because vitest sets VITEST=1 → isTestEnv short-
// circuits every block to hard (the CI path is already fail-closed).
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const { mockHasInteractiveApprover } = vi.hoisted(() => ({
  mockHasInteractiveApprover: vi.fn<() => Promise<boolean>>(),
}));

vi.mock('../auth/daemon.js', () => ({
  DAEMON_PORT: 7391,
  DAEMON_HOST: '127.0.0.1',
  daemonHasInteractiveApprover: () => mockHasInteractiveApprover(),
  // The rest of the module is unused by hasReachableHumanApprover but must exist
  // so the import resolves.
  isDaemonRunning: vi.fn().mockReturnValue(false),
  notifyActivitySocket: vi.fn(),
  checkStatePredicates: vi.fn(),
  registerDaemonEntry: vi.fn(),
  waitForDaemonDecision: vi.fn(),
  notifyDaemonViewer: vi.fn(),
  resolveViaDaemon: vi.fn(),
  notifyTaint: vi.fn(),
  checkTaint: vi.fn(),
  checkSessionTaint: vi.fn(),
  getInternalToken: vi.fn(),
}));

import { hasReachableHumanApprover } from '../auth/orchestrator';

const ALL_ON = { native: true, terminal: true };

describe('hasReachableHumanApprover — fail-closed gate (task #17)', () => {
  let origDisplay: string | undefined;
  let origWayland: string | undefined;

  beforeEach(() => {
    origDisplay = process.env.DISPLAY;
    origWayland = process.env.WAYLAND_DISPLAY;
    delete process.env.DISPLAY;
    delete process.env.WAYLAND_DISPLAY;
    mockHasInteractiveApprover.mockResolvedValue(false);
  });
  afterEach(() => {
    if (origDisplay !== undefined) process.env.DISPLAY = origDisplay;
    else delete process.env.DISPLAY;
    if (origWayland !== undefined) process.env.WAYLAND_DISPLAY = origWayland;
    else delete process.env.WAYLAND_DISPLAY;
    vi.clearAllMocks();
  });

  it('NO display + NO tail → not reachable (the fail-open case → block stays hard)', async () => {
    expect(await hasReachableHumanApprover({ approvers: ALL_ON })).toBe(false);
  });

  it('a GUI display present → reachable (native popup can ask a human)', async () => {
    process.env.DISPLAY = ':0';
    expect(await hasReachableHumanApprover({ approvers: ALL_ON })).toBe(true);
    // Native was enough — never needed the daemon round-trip.
    expect(mockHasInteractiveApprover).not.toHaveBeenCalled();
  });

  it('a connected tail → reachable even with no display', async () => {
    mockHasInteractiveApprover.mockResolvedValue(true);
    expect(await hasReachableHumanApprover({ approvers: ALL_ON })).toBe(true);
  });

  it('display present but calledFromDaemon → NOT reachable via native (daemon shows no popup)', async () => {
    process.env.DISPLAY = ':0';
    // Only a tail can reach a human from the daemon's own pass; none here.
    expect(await hasReachableHumanApprover({ approvers: ALL_ON, calledFromDaemon: true })).toBe(
      false
    );
  });

  it('calledFromDaemon still reachable when a tail is connected', async () => {
    process.env.DISPLAY = ':0';
    mockHasInteractiveApprover.mockResolvedValue(true);
    expect(await hasReachableHumanApprover({ approvers: ALL_ON, calledFromDaemon: true })).toBe(
      true
    );
  });

  it('native approver disabled + no tail → not reachable even with a display', async () => {
    process.env.DISPLAY = ':0';
    expect(await hasReachableHumanApprover({ approvers: { native: false, terminal: true } })).toBe(
      false
    );
  });

  it('terminal approver disabled → a connected tail does not count', async () => {
    mockHasInteractiveApprover.mockResolvedValue(true);
    expect(await hasReachableHumanApprover({ approvers: { native: true, terminal: false } })).toBe(
      false
    );
  });

  it('fails closed when the daemon reachability check returns false', async () => {
    mockHasInteractiveApprover.mockResolvedValue(false);
    expect(await hasReachableHumanApprover({ approvers: ALL_ON })).toBe(false);
  });
});
