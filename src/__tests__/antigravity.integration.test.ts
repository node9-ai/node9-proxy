/**
 * Integration tests for the Antigravity (agy) hook dialect.
 *
 * Spawns the real built CLI (`dist/cli.js`) with an isolated HOME, feeding
 * it PreToolUse/PostToolUse payloads captured from agy 1.0.6 via spy hook
 * (doc/roadmap/antigravity-target.md §0.3). Verifies the two behaviors that
 * differ from every other agent:
 *
 *   1. Blocks MUST be `{"decision":"deny"}` — agy silently ignores the
 *      Claude shape (`decision:"block"` + exit 2) and RUNS the tool
 *      (fail-open, verified live §0.4).
 *   2. PostToolUse fires with `toolCall: null` on non-tool steps — `log`
 *      must skip them instead of writing junk audit rows.
 *
 * Same harness rules as check.integration.test.ts: requires `npm run build`,
 * NODE9_NO_AUTO_DAEMON=1, NODE9_TESTING=1, per-test temp HOME.
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

interface RunResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

/** Real PreToolUse payload captured from agy 1.0.6 (command rewritten per test). */
function agyPrePayload(commandLine: string): object {
  return {
    artifactDirectoryPath:
      '/home/nadav/.gemini/antigravity-cli/brain/6c322973-64a8-41da-b2e9-06c217bb69a1',
    conversationId: '6c322973-64a8-41da-b2e9-06c217bb69a1',
    stepIdx: 3,
    toolCall: {
      args: { CommandLine: commandLine, Cwd: '/tmp/agy-hooktest', WaitMsBeforeAsync: 2000 },
      name: 'run_command',
    },
    transcriptPath:
      '/home/nadav/.gemini/antigravity-cli/brain/6c322973-64a8-41da-b2e9-06c217bb69a1/.system_generated/logs/transcript_full.jsonl',
    workspacePaths: ['/tmp/agy-hooktest'],
  };
}

/** Real non-tool PostToolUse payload (planner step) captured from agy 1.0.6. */
const AGY_POST_NULL_TOOLCALL = {
  artifactDirectoryPath:
    '/home/nadav/.gemini/antigravity-cli/brain/6c322973-64a8-41da-b2e9-06c217bb69a1',
  conversationId: '6c322973-64a8-41da-b2e9-06c217bb69a1',
  error: '',
  stepIdx: 1,
  toolCall: null,
  transcriptPath:
    '/home/nadav/.gemini/antigravity-cli/brain/6c322973-64a8-41da-b2e9-06c217bb69a1/.system_generated/logs/transcript_full.jsonl',
  workspacePaths: ['/tmp/agy-hooktest'],
};

function run(
  subcommand: 'check' | 'log',
  extraArgs: string[],
  payload: object,
  home: string
): RunResult {
  const baseEnv = { ...process.env };
  delete baseEnv.NODE9_API_KEY;
  delete baseEnv.NODE9_API_URL;
  // A real ANTIGRAVITY_CONVERSATION_ID from the test runner's own shell
  // would short-circuit fingerprint assertions — strip it.
  delete baseEnv.ANTIGRAVITY_CONVERSATION_ID;
  const result = spawnSync(
    process.execPath,
    [CLI, subcommand, ...extraArgs, JSON.stringify(payload)],
    {
      encoding: 'utf-8',
      timeout: 60000,
      cwd: home,
      env: {
        ...baseEnv,
        NODE9_NO_AUTO_DAEMON: '1',
        NODE9_TESTING: '1',
        HOME: home,
        USERPROFILE: home,
      },
    }
  );
  expect(result.error).toBeUndefined();
  return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

function makeTempHome(config: object): string {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-agy-test-'));
  const node9Dir = path.join(tmpHome, '.node9');
  fs.mkdirSync(node9Dir, { recursive: true });
  fs.writeFileSync(path.join(node9Dir, 'config.json'), JSON.stringify(config));
  return tmpHome;
}

function cleanupHome(tmpHome: string) {
  try {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  } catch (e: unknown) {
    if ((e as NodeJS.ErrnoException).code !== 'EBUSY') throw e;
    console.warn(`[cleanupHome] EBUSY — temp dir leaked: ${tmpHome}`);
  }
}

const BLOCK_FORCE_PUSH_CONFIG = {
  settings: {
    mode: 'standard',
    autoStartDaemon: false,
    approvers: { native: false, browser: false, cloud: false, terminal: false },
  },
  policy: {
    smartRules: [
      {
        name: 'block-force-push',
        tool: 'bash',
        conditions: [
          { field: 'command', op: 'matches', value: 'git push.*(--force|-f\\b)', flags: 'i' },
        ],
        conditionMode: 'all',
        verdict: 'block',
        reason: 'Force push blocked by policy',
      },
      {
        name: 'allow-readonly-bash',
        tool: 'bash',
        conditions: [
          { field: 'command', op: 'matches', value: '^\\s*(ls|cat|grep|find|echo)', flags: 'i' },
        ],
        conditionMode: 'all',
        verdict: 'allow',
        reason: 'Read-only command',
      },
    ],
  },
};

beforeAll(() => {
  if (!fs.existsSync(CLI)) {
    throw new Error(`dist/cli.js not found. Run "npm run build" first.\nExpected: ${CLI}`);
  }
});

// ── 1. check: deny shape (the fail-open regression guard) ────────────────────

describe('antigravity check — deny response shape', () => {
  let tmpHome: string;
  beforeEach(() => {
    tmpHome = makeTempHome(BLOCK_FORCE_PUSH_CONFIG);
  });
  afterEach(() => cleanupHome(tmpHome));

  it('blocked run_command → {"decision":"deny"} on stdout (NOT Claude\'s "block" shape)', () => {
    // agy 1.0.6 verified live: decision:"block" + exit 2 is ignored and
    // the tool RUNS. Only decision:"deny" blocks. This test pins the
    // fingerprint-detection path (no --agent flag).
    const r = run('check', [], agyPrePayload('git push origin main --force'), tmpHome);
    const parsed = JSON.parse(r.stdout.trim());
    expect(parsed.decision).toBe('deny');
    // The reason carries the negotiation message — agy surfaces it to the
    // model verbatim as "Tool call denied with reason: …" (verified live),
    // so the AI-facing instructions ride along.
    expect(parsed.reason).toContain('Smart Rule: block-force-push');
    expect(parsed.reason).toContain('Do NOT retry');
    // agy ignores exit codes; 0 matches the verified capture.
    expect(r.status).toBe(0);
    expect(r.stderr).toBe('');
  });

  it('blocked run_command with --agent antigravity → same deny shape', () => {
    // The flag is what setupAntigravity actually registers — deterministic
    // shape selection even if Google changes payload fields.
    const r = run(
      'check',
      ['--agent', 'antigravity'],
      agyPrePayload('git push origin main --force'),
      tmpHome
    );
    const parsed = JSON.parse(r.stdout.trim());
    expect(parsed.decision).toBe('deny');
    expect(r.status).toBe(0);
  });

  it('allowed run_command → exit 0 with no stdout (verified agy allow contract)', () => {
    // Verified live: empty stdout + exit 0 = allow on agy.
    const r = run('check', [], agyPrePayload('echo hello-node9'), tmpHome);
    expect(r.status).toBe(0);
    expect(r.stdout.trim()).toBe('');
    expect(r.stderr).toBe('');
  });

  it('smart rules match the CommandLine arg via canonicalToolInput mapping', () => {
    // The rule's condition field is `command` (Claude vocabulary); the agy
    // payload carries `CommandLine`. Without boundary normalisation the
    // rule would silently never match — a protection gap, not a crash.
    const r = run('check', [], agyPrePayload('git push --force origin dev'), tmpHome);
    expect(JSON.parse(r.stdout.trim()).decision).toBe('deny');
  });
});

// ── 2. log: audit rows ────────────────────────────────────────────────────────

describe('antigravity log — audit rows', () => {
  let tmpHome: string;
  beforeEach(() => {
    tmpHome = makeTempHome({ settings: { mode: 'standard', autoStartDaemon: false } });
  });
  afterEach(() => cleanupHome(tmpHome));

  const auditPath = () => path.join(tmpHome, '.node9', 'audit.log');

  it('run_command post payload → audit row with canonical Bash + agentToolName + agent', () => {
    const post = {
      ...(agyPrePayload('echo hello-node9') as Record<string, unknown>),
      error: '',
    };
    const r = run('log', [], post, tmpHome);
    expect(r.status).toBe(0);

    const lines = fs.readFileSync(auditPath(), 'utf-8').trim().split('\n');
    expect(lines).toHaveLength(1);
    const entry = JSON.parse(lines[0]);
    expect(entry.tool).toBe('Bash');
    expect(entry.agentToolName).toBe('run_command');
    expect(entry.agent).toBe('Antigravity');
    // canonicalToolInput mapped CommandLine → command for downstream readers.
    expect(entry.args.command).toBe('echo hello-node9');
    expect(entry.args.CommandLine).toBeUndefined();
    // conversationId is agy's session id.
    expect(entry.sessionId).toBe('6c322973-64a8-41da-b2e9-06c217bb69a1');
  });

  it('toolCall: null (planner step) → NO audit row written', () => {
    // Without the guard, every model turn writes a junk `unknown` row.
    const r = run('log', [], AGY_POST_NULL_TOOLCALL, tmpHome);
    expect(r.status).toBe(0);
    expect(fs.existsSync(auditPath())).toBe(false);
  });

  it('--agent antigravity sets the agent label even without fingerprint fields', () => {
    // Minimal payload: flag-based attribution must not depend on agy
    // dialect fields surviving future agy versions.
    const r = run(
      'log',
      ['--agent', 'antigravity'],
      { tool_name: 'Bash', tool_input: { command: 'ls' } },
      tmpHome
    );
    expect(r.status).toBe(0);
    const entry = JSON.parse(fs.readFileSync(auditPath(), 'utf-8').trim());
    expect(entry.agent).toBe('Antigravity');
  });
});
