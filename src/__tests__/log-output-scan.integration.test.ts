/**
 * Integration tests for gap1 response-channel DLP in the `log` PostToolUse hook.
 * Spawns the built CLI (dist/cli.js) — requires `npm run build` first — with a
 * payload whose tool_response.output contains a secret, and asserts node9 emits
 * a PostToolUse `additionalContext` warning on stdout for Claude/Codex.
 *
 * No daemon is needed: the session-taint notify is best-effort (no-ops when the
 * daemon is down), but the additionalContext emit is pure stdout.
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

// Assembled at runtime so no secret-shaped literal sits in this source file
// (node9's own DLP would otherwise flag it). Matches the GitHubToken pattern.
const FAKE_TOKEN = ['ghp', '_', 'A1b2C3d4E5f6', 'G7h8I9j0K1l2', 'M3n4O5p6Q7r8'].join('');

function runLog(payload: object, home: string): { stdout: string; status: number | null } {
  const baseEnv = { ...process.env };
  delete baseEnv.NODE9_API_KEY;
  delete baseEnv.NODE9_API_URL;
  const r = spawnSync(process.execPath, [CLI, 'log', JSON.stringify(payload)], {
    encoding: 'utf-8',
    timeout: 15000,
    env: {
      ...baseEnv,
      NODE9_NO_AUTO_DAEMON: '1',
      NODE9_TESTING: '1',
      HOME: home,
      USERPROFILE: home,
    },
  });
  return { stdout: r.stdout ?? '', status: r.status };
}

describe('log — response-channel DLP (gap1)', () => {
  let home: string;

  beforeAll(() => {
    expect(fs.existsSync(CLI), `built CLI not found at ${CLI} — run npm run build`).toBe(true);
  });

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'log-gap1-'));
  });

  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('emits a PostToolUse additionalContext warning when tool output contains a secret (Claude)', () => {
    const { stdout, status } = runLog(
      {
        hook_event_name: 'PostToolUse',
        tool_name: 'Read',
        tool_use_id: 'tu1', // → detected as Claude Code
        session_id: 's1',
        tool_response: { output: `cfg:\n  github_token: ${FAKE_TOKEN}\n` },
      },
      home
    );
    expect(status).toBe(0);
    const parsed = JSON.parse(stdout.trim()) as {
      hookSpecificOutput?: { hookEventName?: string; additionalContext?: string };
    };
    expect(parsed.hookSpecificOutput?.hookEventName).toBe('PostToolUse');
    expect(parsed.hookSpecificOutput?.additionalContext).toMatch(/credential/i);
    // The warning names the pattern, never the secret value.
    expect(stdout).not.toContain(FAKE_TOKEN);
  });

  it('stays silent (no stdout) when tool output is clean', () => {
    const { stdout, status } = runLog(
      {
        hook_event_name: 'PostToolUse',
        tool_name: 'Read',
        tool_use_id: 'tu2',
        session_id: 's2',
        tool_response: { output: 'nothing sensitive here, just some logs\n' },
      },
      home
    );
    expect(status).toBe(0);
    expect(stdout.trim()).toBe('');
  });
});
