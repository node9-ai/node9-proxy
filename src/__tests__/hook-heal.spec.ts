// Agent-hook self-heal P1 — detect + nudge. Files resolve os.homedir() at call
// time, so spy homedir + a tmp HOME; mock the wiring source, the pause check, and
// the notification channel. runHookHeal must NEVER mutate an agent config (P1).
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

vi.mock('../ui/native', () => ({ sendDesktopNotification: vi.fn(), askNativePopup: vi.fn() }));
vi.mock('../agent-wiring', () => ({ getAgentWiring: vi.fn() }));
vi.mock('../auth/state', () => ({ checkPause: vi.fn(() => ({ paused: false })) }));

type Row = { id: string; label: string; installed: boolean; wireState: string };
const row = (over: Partial<Row> = {}): Row => ({
  id: 'claude',
  label: 'Claude Code',
  installed: true,
  wireState: 'wired',
  ...over,
});

describe('runHookHeal (P1 detect + nudge)', () => {
  let home: string;
  let runHookHeal: (home?: string) => void;
  let recordHookBaseline: (id: string, now: number) => void;
  let clearHookBaseline: () => void;
  let loadNotified: () => Set<string>;
  let getAgentWiring: ReturnType<typeof vi.fn>;
  let sendDesktopNotification: ReturnType<typeof vi.fn>;
  let checkPause: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-hookheal-'));
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    vi.spyOn(os, 'homedir').mockReturnValue(home);
    vi.resetModules();
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    runHookHeal = (await import('../daemon/hook-heal.js')).runHookHeal;
    const bl = await import('../daemon/hook-baseline.js');
    recordHookBaseline = bl.recordHookBaseline;
    clearHookBaseline = bl.clearHookBaseline;
    loadNotified = bl.loadNotified;
    getAgentWiring = (await import('../agent-wiring.js')).getAgentWiring as ReturnType<
      typeof vi.fn
    >;
    sendDesktopNotification = (await import('../ui/native.js'))
      .sendDesktopNotification as ReturnType<typeof vi.fn>;
    checkPause = (await import('../auth/state.js')).checkPause as ReturnType<typeof vi.fn>;
    sendDesktopNotification.mockClear();
    checkPause.mockReturnValue({ paused: false });
  });
  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  it('nudges once when a GOVERNED agent loses its hooks, then dedups', () => {
    recordHookBaseline('claude', 1);
    getAgentWiring.mockReturnValue([row({ wireState: 'unwired' })]);

    runHookHeal();
    expect(sendDesktopNotification).toHaveBeenCalledTimes(1);
    expect(sendDesktopNotification.mock.calls[0][1]).toContain('Claude Code');
    expect(loadNotified().has('claude')).toBe(true);

    runHookHeal(); // still unwired → no second nudge
    expect(sendDesktopNotification).toHaveBeenCalledTimes(1);
  });

  it('does NOT nudge for an agent node9 never governed (not in baseline)', () => {
    getAgentWiring.mockReturnValue([row({ id: 'gemini', label: 'Gemini', wireState: 'unwired' })]);
    runHookHeal();
    expect(sendDesktopNotification).not.toHaveBeenCalled();
  });

  it('does NOT nudge for a governed agent that is no longer installed', () => {
    recordHookBaseline('claude', 1);
    getAgentWiring.mockReturnValue([row({ installed: false, wireState: 'absent' })]);
    runHookHeal();
    expect(sendDesktopNotification).not.toHaveBeenCalled();
  });

  it('does nothing while node9 is paused', () => {
    recordHookBaseline('claude', 1);
    getAgentWiring.mockReturnValue([row({ wireState: 'unwired' })]);
    checkPause.mockReturnValue({ paused: true });
    runHookHeal();
    expect(sendDesktopNotification).not.toHaveBeenCalled();
    expect(loadNotified().has('claude')).toBe(false);
  });

  it('re-arms after the agent is re-wired (a future wipe nudges again)', () => {
    recordHookBaseline('claude', 1);

    getAgentWiring.mockReturnValue([row({ wireState: 'unwired' })]);
    runHookHeal(); // nudge #1
    expect(sendDesktopNotification).toHaveBeenCalledTimes(1);

    getAgentWiring.mockReturnValue([row({ wireState: 'wired' })]);
    runHookHeal(); // healed → clears notified
    expect(loadNotified().has('claude')).toBe(false);

    getAgentWiring.mockReturnValue([row({ wireState: 'unwired' })]);
    runHookHeal(); // wiped again → nudge #2
    expect(sendDesktopNotification).toHaveBeenCalledTimes(2);
  });

  it('an uninstall (clearHookBaseline) stops the nudge', () => {
    recordHookBaseline('claude', 1);
    clearHookBaseline();
    getAgentWiring.mockReturnValue([row({ wireState: 'unwired' })]);
    runHookHeal();
    expect(sendDesktopNotification).not.toHaveBeenCalled();
  });

  it('seeds intent from currently-wired agents on first run without nudging, then detects a later wipe', () => {
    getAgentWiring.mockReturnValue([
      row({ id: 'claude', wireState: 'wired' }),
      row({ id: 'gemini', label: 'Gemini', wireState: 'unwired' }),
    ]);
    runHookHeal(); // seeding pass — no prior intent to diff
    expect(sendDesktopNotification).not.toHaveBeenCalled();
    const b = JSON.parse(
      fs.readFileSync(path.join(home, '.node9', 'hooks-baseline.json'), 'utf-8')
    );
    expect(Object.keys(b)).toEqual(['claude']); // only the governed (wired) one seeded

    getAgentWiring.mockReturnValue([row({ id: 'claude', wireState: 'unwired' })]);
    runHookHeal(); // baseline no longer empty → a wipe of the seeded agent nudges
    expect(sendDesktopNotification).toHaveBeenCalledTimes(1);
  });

  it('recordHookBaseline is idempotent and clearHookBaseline forgets everything', () => {
    recordHookBaseline('claude', 111);
    recordHookBaseline('claude', 222); // no-op — keeps the first wiredAt
    const raw = JSON.parse(
      fs.readFileSync(path.join(home, '.node9', 'hooks-baseline.json'), 'utf-8')
    );
    expect(raw.claude.wiredAt).toBe(111);
    clearHookBaseline();
    expect(fs.existsSync(path.join(home, '.node9', 'hooks-baseline.json'))).toBe(false);
  });
});
