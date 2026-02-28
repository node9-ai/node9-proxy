import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { authorizeAction, evaluatePolicy, authorizeHeadless, _resetConfigCache } from '../core.js';

// Control interactive prompts
vi.mock('@inquirer/prompts', () => ({
  confirm: vi.fn(),
}));

// Prevent real config files on disk from affecting tests
vi.spyOn(fs, 'existsSync').mockReturnValue(false);
vi.spyOn(fs, 'readFileSync');

async function getConfirm() {
  const mod = await import('@inquirer/prompts');
  return vi.mocked(mod.confirm);
}

function mockConfig(config: object) {
  vi.mocked(fs.existsSync).mockReturnValue(true);
  vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(config));
}

// Simulate only ~/.node9/config.json existing (no project-level config)
function mockGlobalConfig(config: object) {
  const globalPath = path.join(os.homedir(), '.node9', 'config.json');
  vi.mocked(fs.existsSync).mockImplementation((p) => String(p) === globalPath);
  vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(config));
}

// Simulate both configs existing, with different JSON returned per path
function mockBothConfigs(projectConfig: object, globalConfig: object) {
  const projectPath = path.join(process.cwd(), 'node9.config.json');
  const globalPath = path.join(os.homedir(), '.node9', 'config.json');
  vi.mocked(fs.existsSync).mockImplementation((p) => {
    const s = String(p);
    return s === projectPath || s === globalPath;
  });
  vi.mocked(fs.readFileSync).mockImplementation((p) => {
    return String(p) === projectPath
      ? JSON.stringify(projectConfig)
      : JSON.stringify(globalConfig);
  });
}

beforeEach(() => {
  _resetConfigCache();
  delete process.env.NODE9_API_KEY;
  delete process.env.NODE_ENV;
  vi.mocked(fs.existsSync).mockReturnValue(false);
  Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true });
});

afterEach(() => {
  vi.clearAllMocks();
});

// ---------------------------------------------------------------------------
// Ignored tool patterns — should always pass without prompting
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Standard mode — safe tools
// ---------------------------------------------------------------------------
describe('standard mode — safe tools', () => {
  it.each([
    'create_user',
    'send_notification',
    'invoke_lambda',
    'start_job',
  ])('allows "%s" without prompting', async (tool) => {
    const confirm = await getConfirm();
    expect(await authorizeAction(tool, {})).toBe(true);
    expect(confirm).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Standard mode — dangerous word detection
// ---------------------------------------------------------------------------
describe('standard mode — dangerous word detection', () => {
  beforeEach(async () => {
    const confirm = await getConfirm();
    confirm.mockResolvedValue(true);
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

// ---------------------------------------------------------------------------
// Terminal HITL — approve / deny
// ---------------------------------------------------------------------------
describe('terminal approval', () => {
  it('returns true when user approves', async () => {
    const confirm = await getConfirm();
    confirm.mockResolvedValue(true);
    expect(await authorizeAction('delete_user', {})).toBe(true);
  });

  it('returns false when user denies', async () => {
    const confirm = await getConfirm();
    confirm.mockResolvedValue(false);
    expect(await authorizeAction('delete_user', {})).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Non-TTY (headless / CI) — no terminal, no API key
// ---------------------------------------------------------------------------
describe('headless environment', () => {
  beforeEach(() => {
    Object.defineProperty(process.stdout, 'isTTY', { value: false, configurable: true });
  });

  it('throws with a helpful message directing the user to node9 login', async () => {
    await expect(authorizeAction('delete_user', {})).rejects.toThrow(/node9 login/i);
  });
});

// ---------------------------------------------------------------------------
// Strict mode — everything requires approval except ignoredTools
// ---------------------------------------------------------------------------
describe('strict mode', () => {
  beforeEach(() => {
    mockConfig({
      settings: { mode: 'strict' },
      policy: { dangerousWords: [], ignoredTools: ['list_*'] },
      environments: {},
    });
  });

  it('intercepts non-dangerous tools that would pass in standard mode', async () => {
    const confirm = await getConfirm();
    confirm.mockResolvedValue(true);
    await authorizeAction('create_user', {});
    expect(confirm).toHaveBeenCalledTimes(1);
  });

  it('still allows ignored tools without prompting', async () => {
    const confirm = await getConfirm();
    expect(await authorizeAction('list_users', {})).toBe(true);
    expect(confirm).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Environment config — requireApproval / slackChannel
// ---------------------------------------------------------------------------
describe('environment config', () => {
  it('auto-allows dangerous actions when requireApproval is false', async () => {
    process.env.NODE_ENV = 'development';
    mockConfig({
      settings: { mode: 'standard' },
      policy: { dangerousWords: ['delete'], ignoredTools: [] },
      environments: { development: { requireApproval: false } },
    });

    const confirm = await getConfirm();
    expect(await authorizeAction('delete_user', {})).toBe(true);
    expect(confirm).not.toHaveBeenCalled();
  });

  it('still requires approval when requireApproval is true for the active environment', async () => {
    process.env.NODE_ENV = 'production';
    mockConfig({
      settings: { mode: 'standard' },
      policy: { dangerousWords: ['delete'], ignoredTools: [] },
      environments: { production: { requireApproval: true, slackChannel: '#prod-alerts' } },
    });

    const confirm = await getConfirm();
    confirm.mockResolvedValue(true);
    await authorizeAction('delete_user', {});
    expect(confirm).toHaveBeenCalledTimes(1);
  });

  it('falls back to default behaviour when NODE_ENV has no matching environment entry', async () => {
    process.env.NODE_ENV = 'staging';
    mockConfig({
      settings: { mode: 'standard' },
      policy: { dangerousWords: ['delete'], ignoredTools: [] },
      environments: { production: { requireApproval: true } },
    });

    const confirm = await getConfirm();
    confirm.mockResolvedValue(false);
    expect(await authorizeAction('delete_user', {})).toBe(false);
    expect(confirm).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------------------
// Custom policy — user-defined dangerousWords and ignoredTools
// ---------------------------------------------------------------------------
describe('custom policy', () => {
  it('respects user-defined dangerousWords', async () => {
    mockConfig({
      settings: { mode: 'standard' },
      policy: { dangerousWords: ['deploy'], ignoredTools: [] },
      environments: {},
    });

    const confirm = await getConfirm();
    confirm.mockResolvedValue(true);
    await authorizeAction('deploy_to_prod', {});
    expect(confirm).toHaveBeenCalledTimes(1);
  });

  it('respects user-defined ignoredTools', async () => {
    mockConfig({
      settings: { mode: 'standard' },
      policy: { dangerousWords: ['delete'], ignoredTools: ['delete_*'] },
      environments: {},
    });

    const confirm = await getConfirm();
    // delete_* is in ignoredTools — should pass through
    expect(await authorizeAction('delete_temp_files', {})).toBe(true);
    expect(confirm).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// evaluatePolicy — pure synchronous policy check, no side effects
// ---------------------------------------------------------------------------
describe('evaluatePolicy', () => {
  it.each(['list_users', 'get_config', 'read_file', 'describe_table'])(
    'returns "allow" for ignored tool "%s"',
    (tool) => {
      expect(evaluatePolicy(tool)).toBe('allow');
    }
  );

  it.each(['create_user', 'send_email', 'invoke_lambda'])(
    'returns "allow" for safe tool "%s" in standard mode',
    (tool) => {
      expect(evaluatePolicy(tool)).toBe('allow');
    }
  );

  it.each(['delete_user', 'drop_table', 'rm_data', 'destroy_cluster'])(
    'returns "review" for dangerous tool "%s"',
    (tool) => {
      expect(evaluatePolicy(tool)).toBe('review');
    }
  );

  it('returns "allow" when requireApproval is false for the active environment', () => {
    process.env.NODE_ENV = 'development';
    mockConfig({
      settings: { mode: 'standard' },
      policy: { dangerousWords: ['delete'], ignoredTools: [] },
      environments: { development: { requireApproval: false } },
    });
    expect(evaluatePolicy('delete_user')).toBe('allow');
  });

  it('returns "review" for non-dangerous tool in strict mode', () => {
    mockConfig({
      settings: { mode: 'strict' },
      policy: { dangerousWords: [], ignoredTools: ['list_*'] },
      environments: {},
    });
    expect(evaluatePolicy('create_user')).toBe('review');
  });

  it('returns "allow" for ignored tool even in strict mode', () => {
    mockConfig({
      settings: { mode: 'strict' },
      policy: { dangerousWords: [], ignoredTools: ['list_*'] },
      environments: {},
    });
    expect(evaluatePolicy('list_users')).toBe('allow');
  });
});

// ---------------------------------------------------------------------------
// authorizeHeadless — used by the PreToolUse / BeforeTool hook
// ---------------------------------------------------------------------------
describe('authorizeHeadless', () => {
  beforeEach(() => {
    delete process.env.NODE9_API_KEY;
  });

  it('returns approved:true for safe tools without any API call', async () => {
    const result = await authorizeHeadless('list_users', {});
    expect(result).toEqual({ approved: true });
  });

  it('returns approved:false with a helpful reason when no API key is configured', async () => {
    Object.defineProperty(process.stdout, 'isTTY', { value: false, configurable: true });
    const result = await authorizeHeadless('delete_user', {});
    expect(result.approved).toBe(false);
    expect(result.reason).toMatch(/node9 login/i);
  });

  it('calls the cloud API and returns approved:true when the API approves', async () => {
    process.env.NODE9_API_KEY = 'test-key';
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ approved: true, message: 'Approved via Slack' }),
    }));

    const result = await authorizeHeadless('delete_user', { id: 1 });
    expect(result.approved).toBe(true);

    vi.unstubAllGlobals();
  });

  it('calls the cloud API and returns approved:false when the API denies', async () => {
    process.env.NODE9_API_KEY = 'test-key';
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ approved: false, message: 'Denied' }),
    }));

    const result = await authorizeHeadless('delete_user', { id: 1 });
    expect(result.approved).toBe(false);

    vi.unstubAllGlobals();
  });

  it('returns approved:false when the cloud API call fails', async () => {
    process.env.NODE9_API_KEY = 'test-key';
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('Network error')));

    const result = await authorizeHeadless('delete_user', {});
    expect(result.approved).toBe(false);

    vi.unstubAllGlobals();
  });
});

// ---------------------------------------------------------------------------
// Claude Code Bash tool — inspect command content, not just the tool name
// ---------------------------------------------------------------------------
describe('Bash tool — shell command interception', () => {
  beforeEach(async () => {
    const confirm = await getConfirm();
    confirm.mockResolvedValue(true);
  });

  it.each([
    { cmd: 'rm /tmp/deleteme.txt',     desc: 'rm command' },
    { cmd: 'rm -rf /',                 desc: 'rm -rf' },
    { cmd: 'sudo rm -rf /home/user',   desc: 'sudo rm' },
    { cmd: 'rmdir /tmp/mydir',         desc: 'rmdir command' },
    { cmd: '/usr/bin/rm file.txt',     desc: 'absolute path to rm' },
    { cmd: 'find . -delete',           desc: 'find --delete flag' },
    { cmd: 'npm update',               desc: 'npm update' },
    { cmd: 'apt-get purge vim',        desc: 'apt-get purge' },
    { cmd: 'echo "rm -rf /" | bash',   desc: 'pipe with rm' },
    { cmd: 'r\\m -rf /',               desc: 'escaped command' },
    { cmd: '$(echo rm) -rf /',         desc: 'subshell command' },
    { cmd: 'git commit && rm test.sh', desc: 'chained commands' },
  ])('blocks Bash tool when command is "$desc"', async ({ cmd }) => {
    const confirm = await getConfirm();
    await authorizeAction('Bash', { command: cmd });
    expect(confirm).toHaveBeenCalledTimes(1);
  });

  it.each([
    { cmd: 'ls -la',             desc: 'ls' },
    { cmd: 'cat /etc/hosts',     desc: 'cat' },
    { cmd: 'git status',         desc: 'git status' },
    { cmd: 'npm install',        desc: 'npm install' },
    { cmd: 'echo hello',         desc: 'echo' },
    { cmd: 'pwd',                desc: 'pwd' },
    { cmd: 'node --version',     desc: 'node --version' },
  ])('allows Bash tool when command is "$desc"', async ({ cmd }) => {
    const confirm = await getConfirm();
    expect(await authorizeAction('Bash', { command: cmd })).toBe(true);
    expect(confirm).not.toHaveBeenCalled();
  });

  it('does not false-positive on "confirm_action" (rm substring in old impl)', async () => {
    const confirm = await getConfirm();
    expect(await authorizeAction('confirm_action', {})).toBe(true);
    expect(confirm).not.toHaveBeenCalled();
  });

  it('does not false-positive on check_permissions (rm substring in old impl)', async () => {
    const confirm = await getConfirm();
    expect(await authorizeAction('check_permissions', {})).toBe(true);
    expect(confirm).not.toHaveBeenCalled();
  });

  it('evaluatePolicy returns "review" for Bash with dangerous command', () => {
    expect(evaluatePolicy('Bash', { command: 'rm -rf /tmp' })).toBe('review');
  });

  it('evaluatePolicy returns "allow" for Bash with safe command', () => {
    expect(evaluatePolicy('Bash', { command: 'git status' })).toBe('allow');
  });

  it('evaluatePolicy allows "rm -rf node_modules" via path-based rule', () => {
    expect(evaluatePolicy('Bash', { command: 'rm -rf node_modules' })).toBe('allow');
  });

  it('evaluatePolicy allows "rm -rf dist" via path-based rule', () => {
    expect(evaluatePolicy('Bash', { command: 'rm -rf dist' })).toBe('allow');
  });

  it('evaluatePolicy still returns "review" for "rm -rf src" (not in allowPaths)', () => {
    expect(evaluatePolicy('Bash', { command: 'rm -rf src' })).toBe('review');
  });

  it('evaluatePolicy returns "review" for "rm -rf /etc" (dangerous path)', () => {
    expect(evaluatePolicy('Bash', { command: 'rm -rf /etc' })).toBe('review');
  });

  it('evaluatePolicy returns "review" for Gemini CLI run_shell_command with dangerous command', () => {
    expect(evaluatePolicy('run_shell_command', { command: 'rm -rf /tmp' })).toBe('review');
  });

  it('evaluatePolicy returns "allow" for Gemini CLI run_shell_command with safe command', () => {
    expect(evaluatePolicy('run_shell_command', { command: 'git status' })).toBe('allow');
  });

  it('evaluatePolicy is case-insensitive for tool name lookups (e.g., "Shell")', () => {
    expect(evaluatePolicy('Shell', { command: 'rm -rf /tmp' })).toBe('review');
    expect(evaluatePolicy('SHELL', { command: 'rm -rf /tmp' })).toBe('review');
    expect(evaluatePolicy('shell', { command: 'ls' })).toBe('allow');
  });

  it('evaluatePolicy correctly identifies "Shell" as a shell tool for Gemini CLI', () => {
    // Should extract command from 'command' field even if tool name is capitalized
    expect(evaluatePolicy('Shell', { command: 'rm -rf /tmp' })).toBe('review');
  });

  it('authorizeHeadless blocks Gemini CLI run_shell_command rm when no API key', async () => {
    Object.defineProperty(process.stdout, 'isTTY', { value: false, configurable: true });
    const result = await authorizeHeadless('run_shell_command', { command: 'rm /tmp/file' });
    expect(result.approved).toBe(false);
    expect(result.reason).toMatch(/node9 login/i);
  });
});

// ---------------------------------------------------------------------------
// Global config — ~/.node9/config.json fallback
// ---------------------------------------------------------------------------
describe('global config (~/.node9/config.json)', () => {
  it('uses global config when no project config exists', async () => {
    mockGlobalConfig({
      settings: { mode: 'standard' },
      policy: { dangerousWords: ['nuke'], ignoredTools: [] },
      environments: {},
    });

    const confirm = await getConfirm();
    confirm.mockResolvedValue(true);
    await authorizeAction('nuke_everything', {});
    expect(confirm).toHaveBeenCalledTimes(1);
  });

  it('global config allows safe tools', async () => {
    mockGlobalConfig({
      settings: { mode: 'standard' },
      policy: { dangerousWords: ['nuke'], ignoredTools: [] },
      environments: {},
    });

    const confirm = await getConfirm();
    expect(await authorizeAction('create_user', {})).toBe(true);
    expect(confirm).not.toHaveBeenCalled();
  });

  it('project config takes precedence over global config', async () => {
    // Global has 'nuke' as dangerous; project overrides with empty list → should allow
    mockBothConfigs(
      { settings: { mode: 'standard' }, policy: { dangerousWords: [], ignoredTools: [] }, environments: {} },
      { settings: { mode: 'standard' }, policy: { dangerousWords: ['nuke'], ignoredTools: [] }, environments: {} }
    );

    const confirm = await getConfirm();
    expect(await authorizeAction('nuke_everything', {})).toBe(true);
    expect(confirm).not.toHaveBeenCalled();
  });

  it('falls back to hardcoded defaults when neither config exists', () => {
    // existsSync returns false for all paths (set in beforeEach)
    expect(evaluatePolicy('delete_user')).toBe('review');
    expect(evaluatePolicy('list_users')).toBe('allow');
  });
});
