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

  it('does nothing (no notification) when everything is already governed / self', () => {
    writeConfig({ mode: 'standard' });
    writeClaude({
      fs: { command: 'node9', args: ['mcp-gateway', '--upstream', 'npx x'] },
      node9: { command: 'node9', args: ['mcp-server'] },
    });
    runMcpReconcile();
    expect(sendSpy).toHaveBeenCalledTimes(0);
  });
});
