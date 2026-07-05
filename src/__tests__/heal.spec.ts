// `node9 heal` P2 — explicit, backup-first re-install of a wiped agent's hooks.
// setupAgent + getAgentWiring are mocked (no real config writes); hook-baseline is
// real over a tmp HOME.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

vi.mock('../setup', () => ({ setupAgent: vi.fn().mockResolvedValue(undefined) }));
vi.mock('../agent-wiring', () => ({ getAgentWiring: vi.fn() }));

type Row = {
  id: string;
  label: string;
  installed: boolean;
  wireState: string;
  settingsPath: string;
  hooks: Array<{ label: string; wired: boolean }>;
};
const row = (over: Partial<Row> = {}): Row => ({
  id: 'claude',
  label: 'Claude Code',
  installed: true,
  wireState: 'unwired',
  settingsPath: '',
  hooks: [{ label: 'PreToolUse', wired: false }], // has a hook surface
  ...over,
});

describe('runHeal (P2)', () => {
  let home: string;
  let runHeal: (name?: string) => Promise<{ healed: string[] }>;
  let recordHookBaseline: (id: string, now: number) => void;
  let loadNotified: () => Set<string>;
  let saveNotified: (s: Set<string>) => void;
  let getAgentWiring: ReturnType<typeof vi.fn>;
  let setupAgent: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-heal-'));
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    vi.spyOn(os, 'homedir').mockReturnValue(home);
    vi.resetModules();
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    runHeal = (await import('../cli/commands/heal.js')).runHeal;
    const bl = await import('../daemon/hook-baseline.js');
    recordHookBaseline = bl.recordHookBaseline;
    loadNotified = bl.loadNotified;
    saveNotified = bl.saveNotified;
    getAgentWiring = (await import('../agent-wiring.js')).getAgentWiring as ReturnType<
      typeof vi.fn
    >;
    setupAgent = (await import('../setup.js')).setupAgent as ReturnType<typeof vi.fn>;
    setupAgent.mockClear();
  });
  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  it('heals a governed+installed+unwired agent: backs up first, re-runs setup, re-arms', async () => {
    const settings = path.join(home, 'settings.json');
    fs.writeFileSync(settings, '{"hooks":{}}'); // the wiped config to back up
    recordHookBaseline('claude', 1);
    saveNotified(new Set(['claude'])); // daemon had nudged
    getAgentWiring.mockReturnValue([row({ settingsPath: settings })]);

    const res = await runHeal();

    expect(setupAgent).toHaveBeenCalledWith('claude'); // re-install ran
    expect(fs.existsSync(`${settings}.node9-heal-bak`)).toBe(true); // backup-first
    expect(loadNotified().has('claude')).toBe(false); // re-armed the nudge
    expect(res.healed).toEqual(['Claude Code']);
  });

  it('EXCLUDES an MCP-only agent (no hook surface) even if governed+unwired', async () => {
    recordHookBaseline('cursor', 1);
    getAgentWiring.mockReturnValue([
      row({ id: 'cursor', label: 'Cursor', wireState: 'absent', hooks: [] }),
    ]);
    const res = await runHeal();
    expect(setupAgent).not.toHaveBeenCalled();
    expect(res.healed).toEqual([]);
  });

  it('does nothing (no setup) when everything is healthy', async () => {
    recordHookBaseline('claude', 1);
    getAgentWiring.mockReturnValue([row({ wireState: 'wired' })]);
    const res = await runHeal();
    expect(setupAgent).not.toHaveBeenCalled();
    expect(res.healed).toEqual([]);
  });

  it('does NOT heal an agent node9 never governed (not in baseline)', async () => {
    getAgentWiring.mockReturnValue([row()]); // no baseline entry
    const res = await runHeal();
    expect(setupAgent).not.toHaveBeenCalled();
    expect(res.healed).toEqual([]);
  });

  it('heals only the named agent', async () => {
    recordHookBaseline('claude', 1);
    recordHookBaseline('gemini', 1);
    getAgentWiring.mockReturnValue([
      row({ id: 'claude', label: 'Claude Code' }),
      row({ id: 'gemini', label: 'Gemini' }),
    ]);
    const res = await runHeal('gemini');
    expect(setupAgent).toHaveBeenCalledTimes(1);
    expect(setupAgent).toHaveBeenCalledWith('gemini');
    expect(res.healed).toEqual(['Gemini']);
  });
});
