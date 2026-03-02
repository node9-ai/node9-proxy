import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  authorizeHeadless,
  evaluatePolicy,
  getGlobalSettings,
  isDaemonRunning,
  _resetConfigCache,
} from '../core.js';

vi.mock('@inquirer/prompts', () => ({ confirm: vi.fn() }));

const existsSpy = vi.spyOn(fs, 'existsSync');
const readSpy = vi.spyOn(fs, 'readFileSync');
vi.spyOn(fs, 'writeFileSync').mockImplementation(() => undefined);
vi.spyOn(fs, 'mkdirSync').mockImplementation(() => undefined);
const homeSpy = vi.spyOn(os, 'homedir');

async function getConfirm() {
  return vi.mocked((await import('@inquirer/prompts')).confirm);
}

beforeEach(() => {
  _resetConfigCache();
  existsSpy.mockReturnValue(false);
  readSpy.mockReturnValue('');
  homeSpy.mockReturnValue('/mock/home');
  delete process.env.NODE9_API_KEY;
  Object.defineProperty(process.stdout, 'isTTY', { value: false, configurable: true });
});

afterEach(() => {
  vi.clearAllMocks();
  vi.unstubAllGlobals();
});

// ── getGlobalSettings ──────────────────────────────────────────────────────

describe('getGlobalSettings', () => {
  it('returns autoStartDaemon:true when no global config exists', () => {
    const s = getGlobalSettings();
    expect(s.autoStartDaemon).toBe(true);
  });

  it('returns autoStartDaemon:true when config has no setting', () => {
    const globalPath = path.join('/mock/home', '.node9', 'config.json');
    existsSpy.mockImplementation((p) => String(p) === globalPath);
    readSpy.mockImplementation((p) =>
      String(p) === globalPath ? JSON.stringify({ settings: { mode: 'standard' } }) : ''
    );
    expect(getGlobalSettings().autoStartDaemon).toBe(true);
  });

  it('returns autoStartDaemon:false when explicitly set to false', () => {
    const globalPath = path.join('/mock/home', '.node9', 'config.json');
    existsSpy.mockImplementation((p) => String(p) === globalPath);
    readSpy.mockImplementation((p) =>
      String(p) === globalPath
        ? JSON.stringify({ settings: { mode: 'standard', autoStartDaemon: false } })
        : ''
    );
    expect(getGlobalSettings().autoStartDaemon).toBe(false);
  });

  it('returns autoStartDaemon:true when explicitly set to true', () => {
    const globalPath = path.join('/mock/home', '.node9', 'config.json');
    existsSpy.mockImplementation((p) => String(p) === globalPath);
    readSpy.mockImplementation((p) =>
      String(p) === globalPath
        ? JSON.stringify({ settings: { mode: 'standard', autoStartDaemon: true } })
        : ''
    );
    expect(getGlobalSettings().autoStartDaemon).toBe(true);
  });

  it('returns defaults when config file is malformed JSON', () => {
    const globalPath = path.join('/mock/home', '.node9', 'config.json');
    existsSpy.mockImplementation((p) => String(p) === globalPath);
    readSpy.mockImplementation((p) => (String(p) === globalPath ? 'not json' : ''));
    const s = getGlobalSettings();
    expect(s.autoStartDaemon).toBe(true);
    expect(s.mode).toBe('standard');
  });
});

// ── Smart runner policy (shell tool) ──────────────────────────────────────

describe('smart runner — shell command policy', () => {
  it('blocks dangerous shell commands', async () => {
    const result = await evaluatePolicy('shell', { command: 'rm -rf /tmp/data' });
    expect(result).toBe('review');
  });

  it('allows safe shell commands', async () => {
    const result = await evaluatePolicy('shell', { command: 'ls -la' });
    expect(result).toBe('allow');
  });

  it('blocks when command contains dangerous word in path', async () => {
    const result = await evaluatePolicy('shell', { command: 'find . -delete' });
    expect(result).toBe('review');
  });

  it('allows npm install (no dangerous tokens)', async () => {
    const result = await evaluatePolicy('shell', { command: 'npm install express' });
    expect(result).toBe('allow');
  });
});

// ── autoStartDaemon: false → noApprovalMechanism (no daemon auto-start) ───

describe('autoStartDaemon: false — blocks without daemon when no TTY', () => {
  it('returns noApprovalMechanism when no API key, no daemon, no TTY', async () => {
    // Daemon not running (existsSpy returns false for PID file)
    const result = await authorizeHeadless('delete_user', {});
    expect(result.approved).toBe(false);
    expect(result.noApprovalMechanism).toBe(true);
  });

  it('shows terminal prompt when TTY is available (allowTerminalFallback)', async () => {
    Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true });
    const confirm = await getConfirm();
    vi.mocked(confirm).mockResolvedValue(true);

    const result = await authorizeHeadless('delete_user', {}, true);
    expect(result.approved).toBe(true);
    expect(confirm).toHaveBeenCalled();
  });

  it('terminal prompt returning false blocks the action', async () => {
    Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true });
    const confirm = await getConfirm();
    vi.mocked(confirm).mockResolvedValue(false);

    const result = await authorizeHeadless('delete_user', {}, true);
    expect(result.approved).toBe(false);
  });
});

// ── Daemon abandon → fallthrough ───────────────────────────────────────────

describe('daemon abandon fallthrough', () => {
  it('falls through to noApprovalMechanism when daemon returns abandoned', async () => {
    // Simulate a running daemon that returns 'abandoned'
    const pidPath = path.join('/mock/home', '.node9', 'daemon.pid');
    existsSpy.mockImplementation((p) => String(p) === pidPath);
    readSpy.mockImplementation((p) =>
      String(p) === pidPath ? JSON.stringify({ pid: process.pid, port: 7391 }) : ''
    );
    expect(isDaemonRunning()).toBe(true);

    // Mock fetch: /check succeeds, /wait returns 'abandoned'
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation((url: string) => {
        if (String(url).endsWith('/check')) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve({ id: 'test-id' }),
          });
        }
        // /wait/test-id
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ decision: 'abandoned' }),
        });
      })
    );

    const result = await authorizeHeadless('delete_user', {});
    // Daemon abandoned → falls through → no TTY → noApprovalMechanism
    expect(result.approved).toBe(false);
    expect(result.noApprovalMechanism).toBe(true);
  });

  it('falls through to terminal prompt when daemon abandons and TTY is available', async () => {
    const pidPath = path.join('/mock/home', '.node9', 'daemon.pid');
    existsSpy.mockImplementation((p) => String(p) === pidPath);
    readSpy.mockImplementation((p) =>
      String(p) === pidPath ? JSON.stringify({ pid: process.pid, port: 7391 }) : ''
    );

    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation((url: string) => {
        if (String(url).endsWith('/check')) {
          return Promise.resolve({ ok: true, json: () => Promise.resolve({ id: 'test-id' }) });
        }
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ decision: 'abandoned' }),
        });
      })
    );

    Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true });
    const confirm = await getConfirm();
    vi.mocked(confirm).mockResolvedValue(true);

    const result = await authorizeHeadless('delete_user', {}, true);
    // Daemon abandoned → falls through → TTY prompt → approved
    expect(result.approved).toBe(true);
    expect(confirm).toHaveBeenCalled();
  });
});

// ── isDaemonRunning: stale PID file ───────────────────────────────────────

describe('isDaemonRunning — stale PID file', () => {
  it('returns false when PID file exists but process is dead', () => {
    const pidPath = path.join('/mock/home', '.node9', 'daemon.pid');
    existsSpy.mockImplementation((p) => String(p) === pidPath);
    // Use PID 999999 which is virtually guaranteed to not exist
    readSpy.mockImplementation((p) =>
      String(p) === pidPath ? JSON.stringify({ pid: 999999, port: 7391 }) : ''
    );
    expect(isDaemonRunning()).toBe(false);
  });
});
