/**
 * Integration tests for `node9 status` — Agent Wiring section.
 *
 * Regression scope:
 *   1. Copilot / Antigravity / Hermes were missing from status entirely —
 *      `setup` wired them (1.28.0/1.29.0) but the Agent Wiring section was
 *      hardcoded to Claude/Gemini/Cursor. A wired agent showed nothing.
 *   2. status.ts carried a stale local copy of isNode9Hook that did not
 *      match the post-#185 quoted hook form
 *      (`"/path/node" "/path/cli.js" check`) — a correctly wired Claude
 *      install rendered ✗ (not wired).
 *
 * Same harness rules as check.integration.test.ts: requires `npm run
 * build`, NODE9_NO_AUTO_DAEMON=1, NODE9_TESTING=1, per-test temp HOME.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

function runStatus(home: string): { status: number | null; stdout: string; stderr: string } {
  const baseEnv = { ...process.env };
  delete baseEnv.NODE9_API_KEY;
  delete baseEnv.NODE9_API_URL;
  // A real HERMES_HOME on the dev machine would leak the dev Hermes config
  // into the isolated temp HOME.
  delete baseEnv.HERMES_HOME;
  const result = spawnSync(process.execPath, [CLI, 'status'], {
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
  });
  expect(result.error).toBeUndefined();
  return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

function writeJson(filePath: string, data: unknown): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

let home: string;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-status-test-'));
});

afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

describe('status — Copilot CLI wiring', () => {
  it('shows the GitHub Copilot section with ✓ for wired hooks', () => {
    writeJson(path.join(home, '.copilot', 'hooks', 'node9.json'), {
      version: 1,
      hooks: {
        PreToolUse: [{ type: 'command', command: 'node9 check --agent copilot', timeoutSec: 600 }],
        PostToolUse: [{ type: 'command', command: 'node9 log --agent copilot', timeoutSec: 600 }],
        UserPromptSubmit: [
          { type: 'command', command: 'node9 check --agent copilot', timeoutSec: 600 },
        ],
      },
    });
    const { status, stdout } = runStatus(home);
    expect(status).toBe(0);
    expect(stdout).toContain('GitHub Copilot');
    expect(stdout).toContain('✓ PreToolUse  (node9 check)');
    expect(stdout).toContain('✓ PostToolUse (node9 log)');
    expect(stdout).toContain('✓ UserPromptSubmit (node9 check)');
  });

  it('shows ✗ when ~/.copilot exists but node9 hooks are absent', () => {
    fs.mkdirSync(path.join(home, '.copilot'), { recursive: true });
    const { status, stdout } = runStatus(home);
    expect(status).toBe(0);
    expect(stdout).toContain('GitHub Copilot');
    expect(stdout).toContain('✗ PreToolUse  (node9 check)');
  });
});

describe('status — Antigravity wiring', () => {
  it('shows the Antigravity section from ~/.gemini/config/hooks.json', () => {
    writeJson(path.join(home, '.gemini', 'config', 'hooks.json'), {
      hooks: {
        PreToolUse: [
          {
            matcher: '.*',
            hooks: [
              { name: 'node9-check', type: 'command', command: 'node9 check --agent antigravity' },
            ],
          },
        ],
        PostToolUse: [
          {
            matcher: '.*',
            hooks: [
              { name: 'node9-log', type: 'command', command: 'node9 log --agent antigravity' },
            ],
          },
        ],
      },
    });
    const { status, stdout } = runStatus(home);
    expect(status).toBe(0);
    expect(stdout).toContain('Antigravity');
    expect(stdout).toContain('✓ PreToolUse  (node9 check)');
    expect(stdout).toContain('✓ PostToolUse (node9 log)');
    // agy shares ~/.gemini but legacy Gemini CLI is keyed on settings.json,
    // which is absent here — its section must not render.
    expect(stdout).not.toContain('Gemini CLI');
  });

  it('shows the Antigravity section from the install dir alone (no hooks.json yet)', () => {
    // agy creates antigravity-cli/ on first launch before node9 setup runs —
    // the section must still appear (as ✗) off the install-dir signal.
    fs.mkdirSync(path.join(home, '.gemini', 'antigravity-cli'), { recursive: true });
    const { status, stdout } = runStatus(home);
    expect(status).toBe(0);
    expect(stdout).toContain('Antigravity');
    expect(stdout).toContain('✗ PreToolUse  (node9 check)');
  });

  it('does not crash when a matcher entry has no hooks array', () => {
    // A hand-edited / foreign hooks.json with a matcher missing its `hooks`
    // field must not throw — status should render the section as unwired.
    writeJson(path.join(home, '.gemini', 'config', 'hooks.json'), {
      hooks: { PreToolUse: [{ matcher: '.*' }] },
    });
    const { status, stdout } = runStatus(home);
    expect(status).toBe(0);
    expect(stdout).toContain('Antigravity');
    expect(stdout).toContain('✗ PreToolUse  (node9 check)');
  });
});

describe('status — Hermes wiring', () => {
  it('shows the Hermes section from ~/.hermes/config.yaml, without an MCP line', () => {
    const yamlBody = [
      'hooks:',
      '  pre_tool_call:',
      "    - command: 'node9 check'",
      '      timeout: 600',
      '  post_tool_call:',
      "    - command: 'node9 log'",
      '      timeout: 600',
      '',
    ].join('\n');
    fs.mkdirSync(path.join(home, '.hermes'), { recursive: true });
    fs.writeFileSync(path.join(home, '.hermes', 'config.yaml'), yamlBody);
    const { status, stdout } = runStatus(home);
    expect(status).toBe(0);
    expect(stdout).toContain('Hermes Agent');
    expect(stdout).toContain('✓ pre_tool_call  (node9 check)');
    expect(stdout).toContain('✓ post_tool_call (node9 log)');
    // Hermes has no MCP surface — the section ends after the hook rows.
    const hermesSection = stdout.slice(stdout.indexOf('Hermes Agent'));
    expect(hermesSection).not.toContain('MCP proxied');
  });

  it('hides the Hermes section when config.yaml is absent', () => {
    const { status, stdout } = runStatus(home);
    expect(status).toBe(0);
    expect(stdout).not.toContain('Hermes Agent');
  });

  it('still renders the Hermes section (unwired) when config.yaml is corrupt', () => {
    // A present-but-broken config must not silently vanish the section —
    // that is exactly when the user needs to see Hermes is unprotected.
    fs.mkdirSync(path.join(home, '.hermes'), { recursive: true });
    fs.writeFileSync(path.join(home, '.hermes', 'config.yaml'), 'hooks: [: : not valid yaml');
    const { status, stdout, stderr } = runStatus(home);
    expect(status).toBe(0);
    expect(stdout).toContain('Hermes Agent');
    expect(stdout).toContain('✗ pre_tool_call  (node9 check)');
    expect(stderr).toContain('not valid YAML');
  });
});

describe('status — quoted hook form (post-#185)', () => {
  it('recognises quoted Claude hook commands as wired', () => {
    // fullPathCommand has emitted this quoted form since #185; the stale
    // local isNode9Hook copy in status.ts rendered it ✗ (not wired).
    writeJson(path.join(home, '.claude', 'settings.json'), {
      hooks: {
        PreToolUse: [
          {
            matcher: '',
            hooks: [
              {
                type: 'command',
                command:
                  '"/usr/local/bin/node" "/usr/local/lib/node_modules/@node9/proxy/dist/cli.js" check',
              },
            ],
          },
        ],
        PostToolUse: [
          {
            matcher: '',
            hooks: [
              {
                type: 'command',
                command:
                  '"/usr/local/bin/node" "/usr/local/lib/node_modules/@node9/proxy/dist/cli.js" log',
              },
            ],
          },
        ],
      },
    });
    const { status, stdout } = runStatus(home);
    expect(status).toBe(0);
    expect(stdout).toContain('Claude Code');
    expect(stdout).toContain('✓ PreToolUse  (node9 check)');
    expect(stdout).toContain('✓ PostToolUse (node9 log)');
  });
});
