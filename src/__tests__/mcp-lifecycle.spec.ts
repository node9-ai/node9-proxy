// MCP lifecycle — orphan detection, lastSeen stamping, stale auto-removal.
// Tests the reconcileStale() function and the forget CLI guard logic.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

vi.mock('../ui/native', () => ({
  sendDesktopNotification: vi.fn(),
  askNativePopup: vi.fn(),
}));

describe('mcp lifecycle — stale detection & removal', () => {
  let home: string;
  let runMcpReconcile: () => void;
  let forgetAllStale: () => void;
  let getServerKey: typeof import('../mcp-pin').getServerKey;
  let quoteArg: typeof import('../mcp-cmd').quoteArg;

  const writeConfig = (settings: Record<string, unknown>) =>
    fs.writeFileSync(
      path.join(home, '.node9', 'config.json'),
      JSON.stringify({ settings, policy: {} })
    );
  const writeClaude = (servers: Record<string, unknown>) =>
    fs.writeFileSync(path.join(home, '.claude.json'), JSON.stringify({ mcpServers: servers }));
  const writePins = (servers: Record<string, unknown>) =>
    fs.writeFileSync(path.join(home, '.node9', 'mcp-pins.json'), JSON.stringify({ servers }));
  const readPins = () =>
    JSON.parse(fs.readFileSync(path.join(home, '.node9', 'mcp-pins.json'), 'utf-8'));

  beforeEach(async () => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-lifecycle-'));
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    vi.spyOn(os, 'homedir').mockReturnValue(home);
    vi.resetModules();
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    const reconciler = await import('../daemon/mcp-reconciler.js');
    runMcpReconcile = reconciler.runMcpReconcile;
    const pinMod = await import('../mcp-pin.js');
    getServerKey = pinMod.getServerKey;
    quoteArg = (await import('../mcp-cmd.js')).quoteArg;
    forgetAllStale = (await import('../cli/commands/mcp-pin.js')).forgetAllStale;
  });
  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  it('stamps lastSeen on pins that are still in inventory', () => {
    writeConfig({ mode: 'standard' });
    const upstreamCmd = 'npx -y mcp-redis';
    const sk = getServerKey(upstreamCmd);
    writePins({
      [sk]: {
        label: upstreamCmd,
        toolsHash: 'abc',
        toolNames: ['get', 'set'],
        toolCount: 2,
        pinnedAt: '2026-01-01T00:00:00.000Z',
      },
    });
    // Server is gatewayed in Claude config (still configured)
    writeClaude({
      redis: { command: 'node9', args: ['mcp-gateway', '--upstream', upstreamCmd] },
    });

    runMcpReconcile();
    const pins = readPins();
    expect(pins.servers[sk].lastSeen).toBeDefined();
    expect(new Date(pins.servers[sk].lastSeen).getTime()).toBeGreaterThan(Date.parse('2026-01-01'));
  });

  // A live server keeps the inventory non-empty, so removal genuinely runs and
  // this exercises the grace period — not the A1 empty-inventory guard (which
  // would keep the pin for a different reason).
  it('does NOT remove an orphan pin within the grace period', () => {
    writeConfig({ mode: 'standard', mcpStaleAfterDays: 7 });
    const sk = getServerKey('npx old-server');
    const twoDaysAgo = new Date(Date.now() - 2 * 86_400_000).toISOString();
    writePins({
      [sk]: {
        label: 'npx old-server',
        toolsHash: 'abc',
        toolNames: ['tool1'],
        toolCount: 1,
        pinnedAt: '2026-01-01T00:00:00.000Z',
        lastSeen: twoDaysAgo,
      },
    });
    writeClaude({ live: { command: 'npx', args: ['live-server'] } });

    runMcpReconcile();
    expect(readPins().servers[sk]).toBeDefined(); // within grace
  });

  it('auto-removes an orphan pin beyond the grace period (live server present)', () => {
    writeConfig({ mode: 'standard', mcpStaleAfterDays: 7 });
    const sk = getServerKey('npx old-server');
    const tenDaysAgo = new Date(Date.now() - 10 * 86_400_000).toISOString();
    writePins({
      [sk]: {
        label: 'npx old-server',
        toolsHash: 'abc',
        toolNames: ['tool1'],
        toolCount: 1,
        pinnedAt: '2026-01-01T00:00:00.000Z',
        lastSeen: tenDaysAgo,
      },
    });
    writeClaude({ live: { command: 'npx', args: ['live-server'] } });

    runMcpReconcile();
    expect(readPins().servers[sk]).toBeUndefined(); // removed
  });

  // A1: an EMPTY inventory (no live server detected — a missing/unreadable agent
  // config is indistinguishable from "no servers configured") must NOT trigger
  // removal, even beyond the grace period. A wrongly-removed pin re-pins to
  // whatever the server presents next, silently resetting the rug-pull baseline.
  it('does NOT auto-remove when the inventory is empty (A1 fail-closed)', () => {
    writeConfig({ mode: 'standard', mcpStaleAfterDays: 7 });
    const sk = getServerKey('npx gone-server');
    const tenDaysAgo = new Date(Date.now() - 10 * 86_400_000).toISOString();
    writePins({
      [sk]: {
        label: 'npx gone-server',
        toolsHash: 'abc',
        toolNames: ['tool1'],
        toolCount: 1,
        pinnedAt: '2026-01-01T00:00:00.000Z',
        lastSeen: tenDaysAgo,
      },
    });
    writeClaude({}); // EMPTY inventory — can't confirm the server is gone

    runMcpReconcile();
    expect(readPins().servers[sk]).toBeDefined(); // kept
  });

  it('respects mcpStaleAfterDays=0 (never auto-remove)', () => {
    writeConfig({ mode: 'standard', mcpStaleAfterDays: 0 });
    const upstreamCmd = 'npx ancient-server';
    const sk = getServerKey(upstreamCmd);
    const yearAgo = new Date(Date.now() - 365 * 86_400_000).toISOString();
    writePins({
      [sk]: {
        label: upstreamCmd,
        toolsHash: 'abc',
        toolNames: ['tool1'],
        toolCount: 1,
        pinnedAt: '2025-01-01T00:00:00.000Z',
        lastSeen: yearAgo,
      },
    });
    writeClaude({});

    runMcpReconcile();
    const pins = readPins();
    expect(pins.servers[sk]).toBeDefined(); // never removed
  });

  it('backfills lastSeen from pinnedAt when first detecting orphan', () => {
    // Use mcpStaleAfterDays=0 so backfill is visible without auto-removal
    writeConfig({ mode: 'standard', mcpStaleAfterDays: 0 });
    const upstreamCmd = 'npx disappeared';
    const sk = getServerKey(upstreamCmd);
    writePins({
      [sk]: {
        label: upstreamCmd,
        toolsHash: 'abc',
        toolNames: ['tool1'],
        toolCount: 1,
        pinnedAt: '2026-06-01T00:00:00.000Z',
        // no lastSeen field
      },
    });
    writeClaude({}); // not in config

    runMcpReconcile();
    const pins = readPins();
    // Should backfill lastSeen = pinnedAt (so the 7-day countdown starts from pinnedAt)
    expect(pins.servers[sk].lastSeen).toBe('2026-06-01T00:00:00.000Z');
  });

  // A still-configured but ungoverned server whose arg needs quoting must be
  // recognized as live — its pin was created by the gateway from the
  // quoteArg-joined upstream, so inventory must derive the SAME key. A naive
  // join would diverge (a space forces quoting), make the pin look orphaned,
  // and auto-remove a server the user is still running. Fails pre-fix.
  it('keeps a still-configured ungoverned server whose arg needs quoting', () => {
    writeConfig({ mode: 'standard', mcpStaleAfterDays: 7 });
    const command = 'npx';
    const args = ['fs-mcp', '--root', '/my path']; // spaced path → needs quoting
    const upstream = [command, ...args].map(quoteArg).join(' '); // as the gateway pins it
    const sk = getServerKey(upstream);
    const tenDaysAgo = new Date(Date.now() - 10 * 86_400_000).toISOString();
    writePins({
      [sk]: {
        label: upstream,
        toolsHash: 'abc',
        toolNames: ['read'],
        toolCount: 1,
        pinnedAt: '2026-01-01T00:00:00.000Z',
        lastSeen: tenDaysAgo, // old enough to be removed IF seen as orphaned
      },
    });
    writeClaude({ fs: { command, args } }); // still configured, ungoverned

    runMcpReconcile();
    const pins = readPins();
    // Recognized as live → kept and re-stamped, not auto-removed.
    expect(pins.servers[sk]).toBeDefined();
    expect(new Date(pins.servers[sk].lastSeen).getTime()).toBeGreaterThan(Date.parse(tenDaysAgo));
  });

  it('does not crash when pin file is missing', () => {
    writeConfig({ mode: 'standard' });
    writeClaude({ redis: { command: 'npx', args: ['redis-mcp'] } });
    // No pins file at all
    expect(() => runMcpReconcile()).not.toThrow();
  });

  it('handles mixed active and orphan pins correctly', () => {
    writeConfig({ mode: 'standard', mcpStaleAfterDays: 7 });
    const activeCmd = 'npx active-server';
    const staleCmd = 'npx stale-server';
    const activeSk = getServerKey(activeCmd);
    const staleSk = getServerKey(staleCmd);
    const tenDaysAgo = new Date(Date.now() - 10 * 86_400_000).toISOString();

    writePins({
      [activeSk]: {
        label: activeCmd,
        toolsHash: 'abc',
        toolNames: ['tool1'],
        toolCount: 1,
        pinnedAt: '2026-01-01T00:00:00.000Z',
      },
      [staleSk]: {
        label: staleCmd,
        toolsHash: 'def',
        toolNames: ['tool2'],
        toolCount: 1,
        pinnedAt: '2026-01-01T00:00:00.000Z',
        lastSeen: tenDaysAgo,
      },
    });
    // Only the active server is still configured
    writeClaude({
      active: { command: 'node9', args: ['mcp-gateway', '--upstream', activeCmd] },
    });

    runMcpReconcile();
    const pins = readPins();
    expect(pins.servers[activeSk]).toBeDefined();
    expect(pins.servers[activeSk].lastSeen).toBeDefined();
    expect(pins.servers[staleSk]).toBeUndefined(); // removed (stale > 7d)
  });

  // ── `node9 mcp forget --stale` (forgetAllStale) ─────────────────────────────
  const pinBody = (label: string) => ({
    label,
    toolsHash: 'abc',
    toolNames: ['tool1'],
    toolCount: 1,
    pinnedAt: '2026-01-01T00:00:00.000Z',
  });

  it('forget --stale removes an orphan when a live server is present', () => {
    writeConfig({ mode: 'standard' });
    const orphan = getServerKey('npx old-server');
    writePins({ [orphan]: pinBody('npx old-server') });
    writeClaude({ live: { command: 'npx', args: ['live-server'] } });

    forgetAllStale();
    expect(readPins().servers[orphan]).toBeUndefined();
  });

  // A1 at the manual path: an empty inventory must NOT wipe every pin — it exits
  // non-zero and keeps them (a wrongly-forgotten pin resets the rug-pull baseline
  // on the server's next connection).
  it('forget --stale refuses to wipe pins when the inventory is empty (A1)', () => {
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((() => {
      throw new Error('process.exit');
    }) as never);
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    writeConfig({ mode: 'standard' });
    const orphan = getServerKey('npx gone-server');
    writePins({ [orphan]: pinBody('npx gone-server') });
    writeClaude({}); // EMPTY inventory

    expect(() => forgetAllStale()).toThrow('process.exit');
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(readPins().servers[orphan]).toBeDefined(); // kept, not wiped
    errSpy.mockRestore();
    exitSpy.mockRestore();
  });

  // B1: removing N orphans is one read-modify-write, not N. Functionally, all
  // orphans go and the live server's pin stays — in a single pass.
  it('forget --stale removes all orphans and keeps the live one', () => {
    writeConfig({ mode: 'standard' });
    const orphanA = getServerKey('npx old-a');
    const orphanB = getServerKey('npx old-b');
    const live = getServerKey('npx live-server'); // matches the config below
    writePins({
      [orphanA]: pinBody('npx old-a'),
      [orphanB]: pinBody('npx old-b'),
      [live]: pinBody('npx live-server'),
    });
    writeClaude({ live: { command: 'npx', args: ['live-server'] } });

    forgetAllStale();
    const servers = readPins().servers;
    expect(servers[orphanA]).toBeUndefined();
    expect(servers[orphanB]).toBeUndefined();
    expect(servers[live]).toBeDefined();
  });
});
