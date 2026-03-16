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

vi.mock('../ui/native', () => ({
  askNativePopup: vi.fn().mockReturnValue('deny'),
  sendDesktopNotification: vi.fn(),
}));

const existsSpy = vi.spyOn(fs, 'existsSync');
const readSpy = vi.spyOn(fs, 'readFileSync');
vi.spyOn(fs, 'writeFileSync').mockImplementation(() => undefined);
vi.spyOn(fs, 'mkdirSync').mockImplementation(() => undefined);
const homeSpy = vi.spyOn(os, 'homedir');

/** Mock global config with native approver disabled so the race engine
 *  relies only on daemon / terminal / cloud channels (matching test intent). */
function mockNoNativeConfig(extra?: Record<string, unknown>) {
  const globalPath = path.join('/mock/home', '.node9', 'config.json');
  existsSpy.mockImplementation((p) => String(p) === globalPath);
  readSpy.mockImplementation((p) =>
    String(p) === globalPath
      ? JSON.stringify({ settings: { approvers: { native: false }, ...extra } })
      : ''
  );
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
    // Use a non-sandbox path — /tmp/** is in sandboxPaths and would be auto-allowed
    const result = await evaluatePolicy('shell', { command: 'rm -rf /home/user/data' });
    expect(result.decision).toBe('review');
  });

  it('allows safe shell commands', async () => {
    const result = await evaluatePolicy('shell', { command: 'ls -la' });
    expect(result.decision).toBe('allow');
  });

  it('blocks when command contains dangerous word in path', async () => {
    // mkfs is in DANGEROUS_WORDS — triggers review even as a token in a find command
    const result = await evaluatePolicy('shell', {
      command: 'find /dev -name "sd*" -exec mkfs.ext4 {} +',
    });
    expect(result.decision).toBe('review');
  });

  it('allows npm install (no dangerous tokens)', async () => {
    const result = await evaluatePolicy('shell', { command: 'npm install express' });
    expect(result.decision).toBe('allow');
  });
});

// ── autoStartDaemon: false → noApprovalMechanism (no daemon auto-start) ───

describe('autoStartDaemon: false — blocks without daemon when no TTY', () => {
  it('returns noApprovalMechanism when no API key, no daemon, no TTY', async () => {
    mockNoNativeConfig();
    // Use mkfs_disk — contains mkfs (in DANGEROUS_WORDS) so triggers review
    const result = await authorizeHeadless('mkfs_disk', {});
    expect(result.approved).toBe(false);
    expect(result.noApprovalMechanism).toBe(true);
  });

  it('approves via persistent allow decision (deterministic, no HITL)', async () => {
    const decisionsPath = path.join('/mock/home', '.node9', 'decisions.json');
    existsSpy.mockImplementation((p) => String(p) === decisionsPath);
    readSpy.mockImplementation((p) =>
      // Use mkfs_disk — contains mkfs (in DANGEROUS_WORDS) so triggers review
      String(p) === decisionsPath ? JSON.stringify({ mkfs_disk: 'allow' }) : ''
    );

    const result = await authorizeHeadless('mkfs_disk', {});
    expect(result.approved).toBe(true);
  });

  it('blocks via persistent deny decision (deterministic, no HITL)', async () => {
    const decisionsPath = path.join('/mock/home', '.node9', 'decisions.json');
    existsSpy.mockImplementation((p) => String(p) === decisionsPath);
    readSpy.mockImplementation((p) =>
      // Use mkfs_disk — contains mkfs (in DANGEROUS_WORDS) so triggers review
      String(p) === decisionsPath ? JSON.stringify({ mkfs_disk: 'deny' }) : ''
    );

    const result = await authorizeHeadless('mkfs_disk', {});
    expect(result.approved).toBe(false);
  });
});

// ── Daemon abandon → fallthrough ───────────────────────────────────────────

describe('daemon abandon fallthrough', () => {
  it('returns noApprovalMechanism when daemon is not running and no other channels', async () => {
    mockNoNativeConfig();
    // Use mkfs_disk — contains mkfs (in DANGEROUS_WORDS) so triggers review
    const result = await authorizeHeadless('mkfs_disk', {});
    expect(result.approved).toBe(false);
    expect(result.noApprovalMechanism).toBe(true);
  });

  it('returns approved:false when daemon denies (deterministic daemon response)', async () => {
    const pidPath = path.join('/mock/home', '.node9', 'daemon.pid');
    const globalPath = path.join('/mock/home', '.node9', 'config.json');
    existsSpy.mockImplementation((p) => [pidPath, globalPath].includes(String(p)));
    readSpy.mockImplementation((p) => {
      if (String(p) === pidPath) return JSON.stringify({ pid: process.pid, port: 7391 });
      if (String(p) === globalPath)
        return JSON.stringify({ settings: { approvers: { native: false } } });
      return '';
    });

    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation((url: string) => {
        if (String(url).endsWith('/check')) {
          return Promise.resolve({ ok: true, json: () => Promise.resolve({ id: 'test-id' }) });
        }
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ decision: 'deny' }) });
      })
    );

    // Use mkfs_disk — contains mkfs (in DANGEROUS_WORDS) so triggers review
    const result = await authorizeHeadless('mkfs_disk', {});
    expect(result.approved).toBe(false);
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
