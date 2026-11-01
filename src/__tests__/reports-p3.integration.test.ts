// Reports cleanup P3 (fw#421): sessions fold into report, blast folds into
// posture, one wiring registry, scan --json schemaVersion 2. Spawns the built
// CLI (dist/cli.js) against a synthetic HOME.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { claudeDesktopConfigPath } from '../setup';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
// A key the DLP recognises by shape; split so the literal never appears whole.
const FAKE_AWS_KEY = ['AKIA', 'QX7Z3BHD', 'M7NPLKV5'].join('');

let home: string;

function run(
  args: string[],
  extraEnv: Record<string, string> = {}
): { status: number | null; stdout: string; stderr: string } {
  const baseEnv = { ...process.env };
  delete baseEnv.NODE9_API_KEY;
  delete baseEnv.NODE9_API_URL;
  delete baseEnv.HERMES_HOME;
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: 90_000,
    cwd: home,
    env: {
      ...baseEnv,
      HOME: home,
      USERPROFILE: home,
      NODE9_TESTING: '1',
      NODE9_NO_AUTO_DAEMON: '1',
      NO_COLOR: '1',
      FORCE_COLOR: '0',
      ...extraEnv,
    },
  });
  expect(r.error).toBeUndefined();
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

const writeJson = (rel: string, obj: unknown) => {
  const p = path.join(home, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(obj));
};

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-p3-'));
  writeJson('.node9/config.json', { settings: { mode: 'standard' } });
  fs.mkdirSync(path.join(home, '.ssh'), { recursive: true });
  fs.writeFileSync(path.join(home, '.ssh', 'id_rsa'), 'not a real key\n', { mode: 0o600 });
  // One recent Claude session with a Bash call, laid out as Claude Code
  // writes it: ~/.claude/history.jsonl indexes the session by project, the
  // transcript sits under projects/<project path with / as ->/<id>.jsonl.
  const project = path.join(home, 'proj');
  const projDir = path.join(home, '.claude', 'projects', project.replace(/\//g, '-'));
  fs.mkdirSync(projDir, { recursive: true });
  const now = new Date().toISOString();
  fs.writeFileSync(
    path.join(home, '.claude', 'history.jsonl'),
    JSON.stringify({
      display: 'list the files',
      timestamp: Date.now(),
      project,
      sessionId: 'sess-p3-aaaa',
    }) + '\n'
  );
  fs.writeFileSync(
    path.join(projDir, 'sess-p3-aaaa.jsonl'),
    [
      JSON.stringify({
        type: 'user',
        timestamp: now,
        cwd: home,
        sessionId: 'sess-p3-aaaa',
        message: { content: [{ type: 'text', text: 'list the files' }] },
      }),
      JSON.stringify({
        type: 'assistant',
        timestamp: now,
        cwd: home,
        sessionId: 'sess-p3-aaaa',
        message: {
          model: 'claude-sonnet-4-6',
          content: [{ type: 'tool_use', id: 't1', name: 'Bash', input: { command: 'ls -la' } }],
          usage: { input_tokens: 100, output_tokens: 50 },
        },
      }),
    ].join('\n') + '\n'
  );
  // Cursor protected through MCP only (no hook file exists for it).
  writeJson('.cursor/mcp.json', {
    mcpServers: { node9: { command: 'node9', args: ['mcp-server'] } },
  });
});

afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

describe('sessions fold into report', () => {
  it('report --sessions lists the session in the report window', () => {
    const r = run(['report', '--sessions']);
    expect(r.status).toBe(0);
    // The list shows the first 8 characters of the id and the first prompt.
    expect(r.stdout).toContain('sess-p3-');
    expect(r.stdout).toContain('list the files');
    expect(r.stdout).toMatch(/last 30 days/i);
  });

  it('report --session <id> prints the tool trace', () => {
    const r = run(['report', '--session', 'sess-p3']);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('sess-p3-aaaa');
    expect(r.stdout).toContain('ls -la');
  });

  it('report --period 7d --sessions uses the 7-day window', () => {
    const r = run(['report', '--period', '7d', '--sessions']);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/last 7 days/i);
  });

  it('the sessions alias prints the same list, 30 days by default', () => {
    const r = run(['sessions']);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('sess-p3-');
    expect(r.stdout).toContain('list the files');
    expect(r.stdout).toMatch(/last 30 days/i);
    expect(run(['sessions', '--days', '7']).stdout).toMatch(/last 7 days/i);
  });

  it('--sessions with --json names the limit instead of printing a half envelope', () => {
    const r = run(['report', '--sessions', '--json']);
    expect(r.status).not.toBe(0);
    expect(r.stderr).toMatch(/--sessions.*--json|--json.*--sessions/);
  });
});

describe('blast folds into posture', () => {
  it('blast prints the posture Secrets rows and no score', () => {
    // Standard mode: node9's DLP covers the credential file, so the row is
    // the covered line, naming the file; the pointer and no score either way.
    const r = run(['blast']);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/Secrets/);
    expect(r.stdout).toContain('~/.ssh/id_rsa');
    expect(r.stdout).toMatch(/node9 posture/);
    expect(r.stdout).not.toMatch(/\/100/);
  });

  it('blast in audit mode shows the open Secrets row with posture wording', () => {
    writeJson('.node9/config.json', { settings: { mode: 'audit' } });
    const r = run(['blast']);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/credential file.*readable by the agent/);
    expect(r.stdout).toContain('~/.ssh/id_rsa');
    expect(r.stdout).not.toMatch(/\/100/);
  });

  it('posture reports a secret environment variable by name and pattern, never its value', () => {
    const r = run(['posture', '--json'], { MY_CLOUD_KEY: FAKE_AWS_KEY });
    const result = JSON.parse(r.stdout) as {
      findings: Array<{ category: string; title: string; detail: string[] }>;
    };
    const f = result.findings.find(
      (x) => x.category === 'Secrets' && /environment variable/.test(x.title)
    );
    expect(f).toBeDefined();
    expect(f!.detail.join('\n')).toContain('MY_CLOUD_KEY');
    expect(r.stdout).not.toContain(FAKE_AWS_KEY);
  });
});

describe('one wiring registry', () => {
  it('agents list shows all twelve agents and Cursor as wired through MCP', () => {
    const r = run(['agents', 'list']);
    expect(r.status).toBe(0);
    for (const label of ['Claude Code', 'Cursor', 'Windsurf', 'VSCode', 'Claude Desktop', 'Pi']) {
      expect(r.stdout).toContain(label);
    }
    const cursor = r.stdout.split('\n').find((l) => l.includes('Cursor')) ?? '';
    expect(cursor).toMatch(/✓.*✓.*mcp/);
  });

  it('claudeDesktopConfigPath resolves under the given home', () => {
    const p = claudeDesktopConfigPath(home);
    expect(p === null || p.startsWith(home)).toBe(true);
  });
});

describe('scan --json schemaVersion 2', () => {
  it('has no score or band anywhere', () => {
    const r = run(['scan', '--json', '--days', '7']);
    expect(r.status).toBe(0);
    const env = JSON.parse(r.stdout) as Record<string, unknown>;
    expect(env.schemaVersion).toBe(2);
    expect(env).not.toHaveProperty('score');
    expect(env).not.toHaveProperty('band');
    expect(env.blast as object).not.toHaveProperty('score');
    expect(JSON.stringify(env)).not.toMatch(/"band"/);
    // Cursor is protected through MCP only: the one registry counts that as wired.
    expect(env.isWired).toBe(true);
  });
});
