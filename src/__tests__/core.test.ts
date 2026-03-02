import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  authorizeAction,
  evaluatePolicy,
  authorizeHeadless,
  _resetConfigCache,
  getPersistentDecision,
  isDaemonRunning,
} from '../core.js';

vi.mock('@inquirer/prompts', () => ({ confirm: vi.fn() }));

// Global spies
const existsSpy = vi.spyOn(fs, 'existsSync');
const readSpy = vi.spyOn(fs, 'readFileSync');
vi.spyOn(fs, 'writeFileSync').mockImplementation(() => undefined);
vi.spyOn(fs, 'mkdirSync').mockImplementation(() => undefined);
const homeSpy = vi.spyOn(os, 'homedir');

async function getConfirm() {
  return vi.mocked((await import('@inquirer/prompts')).confirm);
}

// ── Config mock helpers ───────────────────────────────────────────────────────

function mockProjectConfig(config: object) {
  const projectPath = path.join(process.cwd(), 'node9.config.json');
  existsSpy.mockImplementation((p) => String(p) === projectPath);
  readSpy.mockImplementation((p) => (String(p) === projectPath ? JSON.stringify(config) : ''));
}

function mockGlobalConfig(config: object) {
  const globalPath = path.join('/mock/home', '.node9', 'config.json');
  existsSpy.mockImplementation((p) => String(p) === globalPath);
  readSpy.mockImplementation((p) => (String(p) === globalPath ? JSON.stringify(config) : ''));
}

function mockBothConfigs(projectConfig: object, globalConfig: object) {
  const projectPath = path.join(process.cwd(), 'node9.config.json');
  const globalPath = path.join('/mock/home', '.node9', 'config.json');
  existsSpy.mockImplementation((p) => [projectPath, globalPath].includes(String(p)));
  readSpy.mockImplementation((p) => {
    if (String(p) === projectPath) return JSON.stringify(projectConfig);
    if (String(p) === globalPath) return JSON.stringify(globalConfig);
    return '';
  });
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────

beforeEach(() => {
  _resetConfigCache();
  existsSpy.mockReturnValue(false);
  readSpy.mockReturnValue('');
  homeSpy.mockReturnValue('/mock/home');
  delete process.env.NODE9_API_KEY;
  delete process.env.NODE_ENV;
  Object.defineProperty(process.stdout, 'isTTY', { value: false, configurable: true });
});

afterEach(() => {
  vi.clearAllMocks();
  vi.unstubAllGlobals();
});

// ── Ignored tool patterns ─────────────────────────────────────────────────────

describe('ignored tool patterns', () => {
  it.each([
    'list_users',
    'list_s3_buckets',
    'get_config',
    'get_user_by_id',
    'read_file',
    'read_object',
    'describe_table',
    'describe_instance',
  ])('allows "%s" without prompting', async (tool) => {
    const confirm = await getConfirm();
    expect(await authorizeAction(tool, {})).toBe(true);
    expect(confirm).not.toHaveBeenCalled();
  });
});

// ── Standard mode — safe tools ────────────────────────────────────────────────

describe('standard mode — safe tools', () => {
  it.each(['create_user', 'send_notification', 'invoke_lambda', 'start_job'])(
    'allows "%s" without prompting',
    async (tool) => {
      const confirm = await getConfirm();
      expect(await authorizeAction(tool, {})).toBe(true);
      expect(confirm).not.toHaveBeenCalled();
    }
  );
});

// ── Standard mode — dangerous word detection ──────────────────────────────────

describe('standard mode — dangerous word detection', () => {
  beforeEach(async () => {
    (await getConfirm()).mockResolvedValue(true);
    Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true });
  });

  it.each([
    'delete_user',
    'drop_table',
    'remove_file',
    'terminate_instance',
    'refund_payment',
    'write_record',
    'update_schema',
    'destroy_cluster',
    'aws.rds.rm_database',
    'purge_queue',
    'format_disk',
  ])('intercepts "%s" and prompts for approval', async (tool) => {
    const confirm = await getConfirm();
    await authorizeAction(tool, { id: 42 });
    expect(confirm).toHaveBeenCalledTimes(1);
  });

  it('dangerous word match is case-insensitive', async () => {
    const confirm = await getConfirm();
    await authorizeAction('DELETE_USER', {});
    expect(confirm).toHaveBeenCalledTimes(1);
  });
});

// ── Terminal HITL — approve / deny ────────────────────────────────────────────

describe('terminal approval', () => {
  beforeEach(() => {
    Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true });
  });

  it('returns true when user approves', async () => {
    (await getConfirm()).mockResolvedValue(true);
    expect(await authorizeAction('delete_user', {})).toBe(true);
  });

  it('returns false when user denies', async () => {
    (await getConfirm()).mockResolvedValue(false);
    expect(await authorizeAction('delete_user', {})).toBe(false);
  });
});

// ── Bash tool — shell command interception ────────────────────────────────────

describe('Bash tool — shell command interception', () => {
  it.each([
    { cmd: 'rm /tmp/deleteme.txt', desc: 'rm command' },
    { cmd: 'rm -rf /', desc: 'rm -rf' },
    { cmd: 'sudo rm -rf /home/user', desc: 'sudo rm' },
    { cmd: 'rmdir /tmp/mydir', desc: 'rmdir command' },
    { cmd: '/usr/bin/rm file.txt', desc: 'absolute path to rm' },
    { cmd: 'find . -delete', desc: 'find -delete flag' },
    { cmd: 'npm update', desc: 'npm update' },
    { cmd: 'apt-get purge vim', desc: 'apt-get purge' },
  ])('blocks Bash when command is "$desc"', async ({ cmd }) => {
    expect(await evaluatePolicy('Bash', { command: cmd })).toBe('review');
  });

  it.each([
    { cmd: 'ls -la', desc: 'ls' },
    { cmd: 'cat /etc/hosts', desc: 'cat' },
    { cmd: 'git status', desc: 'git status' },
    { cmd: 'npm install', desc: 'npm install' },
    { cmd: 'node --version', desc: 'node --version' },
  ])('allows Bash when command is "$desc"', async ({ cmd }) => {
    expect(await evaluatePolicy('Bash', { command: cmd })).toBe('allow');
  });

  it('authorizeHeadless blocks Bash rm when no approval mechanism', async () => {
    const result = await authorizeHeadless('Bash', { command: 'rm /tmp/file' });
    expect(result.approved).toBe(false);
    expect(result.noApprovalMechanism).toBe(true);
    expect(result.changeHint).toMatch(/node9 login/i);
  });

  it('authorizeHeadless allows Bash ls', async () => {
    const result = await authorizeHeadless('Bash', { command: 'ls -la' });
    expect(result.approved).toBe(true);
  });
});

// ── False-positive regression ─────────────────────────────────────────────────

describe('false-positive regression — rm substring', () => {
  it.each(['confirm_action', 'check_permissions', 'perform_search'])(
    'does not block "%s"',
    async (tool) => {
      expect(await evaluatePolicy(tool)).toBe('allow');
    }
  );
});

// ── Strict mode ───────────────────────────────────────────────────────────────

describe('strict mode', () => {
  beforeEach(() => {
    mockProjectConfig({
      settings: { mode: 'strict' },
      policy: { dangerousWords: [], ignoredTools: ['list_*'] },
      environments: {},
    });
  });

  it('intercepts non-dangerous tools that would pass in standard mode', async () => {
    expect(await evaluatePolicy('create_user')).toBe('review');
  });

  it('still allows ignored tools', async () => {
    expect(await evaluatePolicy('list_users')).toBe('allow');
  });
});

// ── Environment config ────────────────────────────────────────────────────────

describe('environment config', () => {
  it('auto-allows dangerous actions when requireApproval is false', async () => {
    process.env.NODE_ENV = 'development';
    mockProjectConfig({
      settings: { mode: 'standard' },
      policy: { dangerousWords: ['delete'], ignoredTools: [] },
      environments: { development: { requireApproval: false } },
    });
    expect(await evaluatePolicy('delete_user')).toBe('allow');
  });

  it('requires approval when requireApproval is true for the active environment', async () => {
    process.env.NODE_ENV = 'production';
    mockProjectConfig({
      settings: { mode: 'standard' },
      policy: { dangerousWords: ['delete'], ignoredTools: [] },
      environments: { production: { requireApproval: true } },
    });
    expect(await evaluatePolicy('delete_user')).toBe('review');
  });
});

// ── Custom policy ─────────────────────────────────────────────────────────────

describe('custom policy', () => {
  it('respects user-defined dangerousWords', async () => {
    mockProjectConfig({
      settings: { mode: 'standard' },
      policy: { dangerousWords: ['deploy'], ignoredTools: [] },
      environments: {},
    });
    expect(await evaluatePolicy('deploy_to_prod')).toBe('review');
    expect(await evaluatePolicy('delete_user')).toBe('allow'); // not in custom list
  });

  it('respects user-defined ignoredTools', async () => {
    mockProjectConfig({
      settings: { mode: 'standard' },
      policy: { dangerousWords: ['delete'], ignoredTools: ['delete_*'] },
      environments: {},
    });
    expect(await evaluatePolicy('delete_temp_files')).toBe('allow');
  });
});

// ── Global config ─────────────────────────────────────────────────────────────

describe('global config (~/.node9/config.json)', () => {
  it('is used when no project config exists', async () => {
    mockGlobalConfig({
      settings: { mode: 'standard' },
      policy: { dangerousWords: ['nuke'], ignoredTools: [] },
      environments: {},
    });
    expect(await evaluatePolicy('nuke_everything')).toBe('review');
    expect(await evaluatePolicy('delete_user')).toBe('allow'); // not in custom list
  });

  it('project config takes precedence over global config', async () => {
    mockBothConfigs(
      // project: no dangerous words
      {
        settings: { mode: 'standard' },
        policy: { dangerousWords: [], ignoredTools: [] },
        environments: {},
      },
      // global: nuke is dangerous
      {
        settings: { mode: 'standard' },
        policy: { dangerousWords: ['nuke'], ignoredTools: [] },
        environments: {},
      }
    );
    expect(await evaluatePolicy('nuke_everything')).toBe('allow');
  });

  it('falls back to hardcoded defaults when neither config exists', async () => {
    // existsSpy returns false for all paths (set in beforeEach)
    expect(await evaluatePolicy('delete_user')).toBe('review');
    expect(await evaluatePolicy('list_users')).toBe('allow');
  });
});

// ── authorizeHeadless — full coverage ─────────────────────────────────────────

describe('authorizeHeadless', () => {
  it('returns approved:true for safe tools', async () => {
    expect(await authorizeHeadless('list_users', {})).toEqual({ approved: true });
  });

  it('returns approved:false with noApprovalMechanism when no API key', async () => {
    const result = await authorizeHeadless('delete_user', {});
    expect(result.approved).toBe(false);
    expect(result.noApprovalMechanism).toBe(true);
    expect(result.changeHint).toMatch(/node9 login/i);
  });

  it('calls cloud API and returns approved:true on approval', async () => {
    // agentMode must be true for cloud enforcement to activate
    mockGlobalConfig({ settings: { agentMode: true, slackEnabled: true } });
    process.env.NODE9_API_KEY = 'test-key';
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ approved: true, message: 'Approved via Slack' }),
      })
    );
    const result = await authorizeHeadless('delete_user', { id: 1 });
    expect(result.approved).toBe(true);
  });

  it('returns approved:false when cloud API denies', async () => {
    process.env.NODE9_API_KEY = 'test-key';
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ approved: false }),
      })
    );
    const result = await authorizeHeadless('delete_user', { id: 1 });
    expect(result.approved).toBe(false);
  });

  it('returns approved:false when cloud API call fails', async () => {
    process.env.NODE9_API_KEY = 'test-key';
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('Network error')));
    const result = await authorizeHeadless('delete_user', {});
    expect(result.approved).toBe(false);
  });

  it('does NOT prompt on TTY — headless means headless', async () => {
    Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true });
    const confirm = await getConfirm();
    const result = await authorizeHeadless('delete_user', {});
    expect(result.approved).toBe(false);
    expect(confirm).not.toHaveBeenCalled();
  });
});

// ── evaluatePolicy — project config ──────────────────────────────────────────

describe('evaluatePolicy — project config', () => {
  it('returns "review" for dangerous tool', async () => {
    expect(await evaluatePolicy('delete_user')).toBe('review');
  });

  it('returns "allow" for safe tool in standard mode', async () => {
    expect(await evaluatePolicy('create_user')).toBe('allow');
  });

  it('respects project-level dangerousWords override', async () => {
    mockProjectConfig({
      settings: { mode: 'standard' },
      policy: { dangerousWords: ['deploy'], ignoredTools: [] },
      environments: {},
    });
    expect(await evaluatePolicy('deploy_app')).toBe('review');
    expect(await evaluatePolicy('delete_user')).toBe('allow');
  });
});

// ── Persistent decisions ──────────────────────────────────────────────────────

describe('getPersistentDecision', () => {
  it('returns null when decisions file does not exist', () => {
    // existsSpy already returns false in beforeEach
    expect(getPersistentDecision('delete_user')).toBeNull();
  });

  it('returns "allow" when tool is set to always allow', () => {
    const decisionsPath = path.join('/mock/home', '.node9', 'decisions.json');
    existsSpy.mockImplementation((p) => String(p) === decisionsPath);
    readSpy.mockImplementation((p) =>
      String(p) === decisionsPath ? JSON.stringify({ delete_user: 'allow' }) : ''
    );
    expect(getPersistentDecision('delete_user')).toBe('allow');
  });

  it('returns "deny" when tool is set to always deny', () => {
    const decisionsPath = path.join('/mock/home', '.node9', 'decisions.json');
    existsSpy.mockImplementation((p) => String(p) === decisionsPath);
    readSpy.mockImplementation((p) =>
      String(p) === decisionsPath ? JSON.stringify({ delete_user: 'deny' }) : ''
    );
    expect(getPersistentDecision('delete_user')).toBe('deny');
  });

  it('returns null for an unrecognised value', () => {
    const decisionsPath = path.join('/mock/home', '.node9', 'decisions.json');
    existsSpy.mockImplementation((p) => String(p) === decisionsPath);
    readSpy.mockImplementation((p) =>
      String(p) === decisionsPath ? JSON.stringify({ delete_user: 'maybe' }) : ''
    );
    expect(getPersistentDecision('delete_user')).toBeNull();
  });
});

describe('authorizeHeadless — persistent decisions', () => {
  it('approves without API when persistent decision is "allow"', async () => {
    const decisionsPath = path.join('/mock/home', '.node9', 'decisions.json');
    existsSpy.mockImplementation((p) => String(p) === decisionsPath);
    readSpy.mockImplementation((p) =>
      String(p) === decisionsPath ? JSON.stringify({ delete_user: 'allow' }) : ''
    );
    const result = await authorizeHeadless('delete_user', {});
    expect(result.approved).toBe(true);
  });

  it('blocks without API when persistent decision is "deny"', async () => {
    const decisionsPath = path.join('/mock/home', '.node9', 'decisions.json');
    existsSpy.mockImplementation((p) => String(p) === decisionsPath);
    readSpy.mockImplementation((p) =>
      String(p) === decisionsPath ? JSON.stringify({ delete_user: 'deny' }) : ''
    );
    const result = await authorizeHeadless('delete_user', {});
    expect(result.approved).toBe(false);
    expect(result.reason).toMatch(/always deny/i);
  });
});

// ── isDaemonRunning ───────────────────────────────────────────────────────────

describe('isDaemonRunning', () => {
  it('returns false when PID file does not exist', () => {
    // existsSpy returns false (set in beforeEach)
    expect(isDaemonRunning()).toBe(false);
  });

  it('returns false when PID file has wrong port', () => {
    const pidPath = path.join('/mock/home', '.node9', 'daemon.pid');
    existsSpy.mockImplementation((p) => String(p) === pidPath);
    readSpy.mockImplementation((p) =>
      String(p) === pidPath ? JSON.stringify({ pid: process.pid, port: 9999 }) : ''
    );
    expect(isDaemonRunning()).toBe(false);
  });

  it('returns true when PID exists and process is alive', () => {
    const pidPath = path.join('/mock/home', '.node9', 'daemon.pid');
    existsSpy.mockImplementation((p) => String(p) === pidPath);
    readSpy.mockImplementation((p) =>
      // Use current process PID so kill(pid, 0) succeeds
      String(p) === pidPath ? JSON.stringify({ pid: process.pid, port: 7391 }) : ''
    );
    expect(isDaemonRunning()).toBe(true);
  });
});
