// P3 Phase 2.6 — the reconcile pass: detect NEW ungoverned MCP servers, nudge
// (default) or auto-wrap, dedup via the baseline. BASELINE_FILE resolves
// os.homedir() at import, so spy homedir + resetModules + dynamic import.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

vi.mock('../ui/native', () => ({
  sendDesktopNotification: vi.fn(),
  askNativePopup: vi.fn(),
}));

describe('mcp reconcile pass', () => {
  let home: string;
  let runMcpReconcile: () => void;
  let sendSpy: ReturnType<typeof vi.fn>;

  const writeConfig = (settings: Record<string, unknown>) =>
    fs.writeFileSync(
      path.join(home, '.node9', 'config.json'),
      JSON.stringify({ settings, policy: {} })
    );
  const writeClaude = (servers: Record<string, unknown>) =>
    fs.writeFileSync(path.join(home, '.claude.json'), JSON.stringify({ mcpServers: servers }));
  const gmailEntry = () =>
    JSON.parse(fs.readFileSync(path.join(home, '.claude.json'), 'utf-8')).mcpServers.gmail;

  beforeEach(async () => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-reconpass-'));
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    vi.spyOn(os, 'homedir').mockReturnValue(home);
    vi.resetModules();
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    runMcpReconcile = (await import('../daemon/mcp-reconciler.js')).runMcpReconcile;
    sendSpy = (await import('../ui/native.js')).sendDesktopNotification as ReturnType<typeof vi.fn>;
    sendSpy.mockClear();
  });
  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  it('NUDGES a new ungoverned server once, then dedups on the next pass', () => {
    writeConfig({ mode: 'standard' }); // mcpAutoWrap unset → nudge
    writeClaude({
      gmail: { command: 'npx', args: ['gmail-mcp'] },
      node9: { command: 'node9', args: ['mcp-server'] }, // self — ignored
    });
    runMcpReconcile();
    expect(sendSpy).toHaveBeenCalledTimes(1);
    expect(String(sendSpy.mock.calls[0][0])).toMatch(/ungoverned/);
    expect(gmailEntry().command).toBe('npx'); // NOT wrapped in nudge mode

    sendSpy.mockClear();
    runMcpReconcile(); // nothing new → no notification
    expect(sendSpy).toHaveBeenCalledTimes(0);
  });

  it('AUTO-WRAPS when settings.mcpAutoWrap is true', () => {
    writeConfig({ mode: 'standard', mcpAutoWrap: true });
    writeClaude({ gmail: { command: 'npx', args: ['gmail-mcp'], env: { A: '1' } } });
    runMcpReconcile();
    expect(sendSpy).toHaveBeenCalledTimes(1);
    expect(String(sendSpy.mock.calls[0][0])).toMatch(/governed/);
    const wrapped = gmailEntry();
    expect(wrapped.command).toBe('node9');
    expect(wrapped.args[0]).toBe('mcp-gateway');
    expect(wrapped.env).toEqual({ A: '1' }); // preserved
  });

  it('a failed auto-wrap is NOT baselined (retried next tick) and NOT counted (fix #3)', () => {
    writeConfig({ mode: 'standard', mcpAutoWrap: true });
    writeClaude({ gmail: { command: 'npx', args: ['gmail-mcp'] } });
    // Make the write fail: chmod the config file read-only so writeMcpEntry's
    // rename into place throws.
    const f = path.join(home, '.claude.json');
    fs.chmodSync(f, 0o400);
    // Also make the dir read-only so the tmp+rename can't succeed.
    fs.chmodSync(home, 0o500);
    try {
      runMcpReconcile();
    } finally {
      fs.chmodSync(home, 0o700);
      fs.chmodSync(f, 0o600);
    }
    // baseline must be empty (so it retries) — the server wasn't governed.
    const baselineFile = path.join(home, '.node9', 'mcp-baseline.json');
    const baseline = fs.existsSync(baselineFile)
      ? JSON.parse(fs.readFileSync(baselineFile, 'utf-8'))
      : [];
    // A failed wrap IS baselined (nudge-once) so it doesn't storm the popup every
    // tick — but it's not counted as "Wrapped" and the user is still alerted once.
    expect(baseline).toHaveLength(1);
    const wrapped = sendSpy.mock.calls.some((c) => /Wrapped/.test(String(c[1])));
    expect(wrapped).toBe(false);
    const alerted = sendSpy.mock.calls.some((c) => /ungoverned/.test(String(c[1])));
    expect(alerted).toBe(true);

    // second tick with the same (still read-only) config → NO repeat popup (no storm)
    sendSpy.mockClear();
    runMcpReconcile();
    expect(sendSpy).toHaveBeenCalledTimes(0);
  });

  it('does nothing (no notification) when everything is already governed / self', () => {
    writeConfig({ mode: 'standard' });
    writeClaude({
      fs: { command: 'node9', args: ['mcp-gateway', '--upstream', 'npx x'] },
      node9: { command: 'node9', args: ['mcp-server'] },
    });
    runMcpReconcile();
    expect(sendSpy).toHaveBeenCalledTimes(0);
  });

  // R1 Layer 1 — the refresh pass: back-fill --config-name on governed servers.
  const claudeServer = (name: string) =>
    JSON.parse(fs.readFileSync(path.join(home, '.claude.json'), 'utf-8')).mcpServers[name];

  it('refresh: back-fills --config-name on a governed server that lacks it — SILENTLY, upstream preserved', () => {
    writeClaude({
      redis: {
        command: 'node9',
        args: ['mcp-gateway', '--upstream', 'npx redis-mcp redis://h:6379'],
      },
    });
    runMcpReconcile();
    const args = claudeServer('redis').args as string[];
    expect(args).toContain('--config-name');
    expect(args[args.indexOf('--config-name') + 1]).toBe('redis'); // stamped with the config key
    expect(args[args.indexOf('--upstream') + 1]).toBe('npx redis-mcp redis://h:6379'); // serverKey preserved
    expect(sendSpy).toHaveBeenCalledTimes(0); // NO popup (R2 fatigue)
  });

  it('refresh: leaves an already-stamped server untouched (idempotent, no double)', () => {
    writeClaude({
      redis: {
        command: 'node9',
        args: ['mcp-gateway', '--config-name', 'redis', '--upstream', 'npx x'],
      },
    });
    runMcpReconcile();
    const args = claudeServer('redis').args as string[];
    expect(args.filter((a) => a === '--config-name')).toHaveLength(1);
  });

  it("refresh: never overrides a user's custom --config-name (don't fight the user)", () => {
    writeClaude({
      redis: {
        command: 'node9',
        args: ['mcp-gateway', '--config-name', 'my-custom', '--upstream', 'npx x'],
      },
    });
    runMcpReconcile();
    const args = claudeServer('redis').args as string[];
    expect(args[args.indexOf('--config-name') + 1]).toBe('my-custom');
  });

  it('refresh: does NOT auto-rewrite a governed TOML (Codex) server (fix #8)', () => {
    const codexDir = path.join(home, '.codex');
    fs.mkdirSync(codexDir, { recursive: true });
    const toml =
      '[mcp_servers.git]\ncommand = "node9"\nargs = ["mcp-gateway", "--upstream", "uvx git"]\n';
    fs.writeFileSync(path.join(codexDir, 'config.toml'), toml);
    runMcpReconcile();
    // TOML untouched — no --config-name injected (smol-toml would reformat the file).
    expect(fs.readFileSync(path.join(codexDir, 'config.toml'), 'utf-8')).not.toContain(
      '--config-name'
    );
  });
});
