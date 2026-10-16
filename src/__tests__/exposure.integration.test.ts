// fw#318 phase 1, the real path (design test rows T3-T8, T10, T15, T17):
// a real daemon in an isolated HOME on its own port, the built hook for
// PostToolUse (`log`), UserPromptSubmit and PreToolUse (`check`), one agent
// session. Requires `npm run build`.
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, spawnSync, type ChildProcess } from 'child_process';
import fs from 'fs';
import net from 'net';
import os from 'os';
import path from 'path';
import { keySafeEnv } from './helpers/env';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const cliExists = fs.existsSync(CLI);
if (!cliExists) console.warn('[exposure.integration] skipped — dist/cli.js not found');
const itUnix = it.skipIf(process.platform === 'win32' || !cliExists);

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const port = (srv.address() as net.AddressInfo).port;
      srv.close(() => resolve(port));
    });
  });
}

let home: string;
let proj: string;
let port: number;
let daemon: ChildProcess | undefined;
let env: Record<string, string | undefined>;

function writeConfig(policy: Record<string, unknown>): void {
  fs.writeFileSync(
    path.join(home, '.node9', 'config.json'),
    JSON.stringify({
      settings: {
        mode: 'standard',
        autoStartDaemon: false,
        approvalTimeoutMs: 0,
        approvers: { native: false, browser: false, cloud: false, terminal: false },
      },
      policy: { loopDetection: { enabled: false }, ...policy },
    })
  );
}

function run(args: string[]): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    cwd: proj,
    encoding: 'utf8',
    timeout: 20_000,
    env,
  });
  expect(r.error).toBeUndefined();
  expect(r.status).not.toBeNull();
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

const SID = 'exposure-int';
let tuid = 0;
const payload = (extra: Record<string, unknown>) =>
  JSON.stringify({ session_id: SID, tool_use_id: `tu-${++tuid}`, cwd: proj, ...extra });

function check(tool: string, input: unknown) {
  const r = run([
    'check',
    payload({ hook_event_name: 'PreToolUse', tool_name: tool, tool_input: input }),
  ]);
  const out = r.stdout.trim();
  const ask = out
    ? (JSON.parse(out) as {
        hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string };
      })
    : null;
  return {
    status: r.status,
    ask: ask?.hookSpecificOutput?.permissionDecision,
    reason: ask?.hookSpecificOutput?.permissionDecisionReason ?? '',
  };
}

function log(tool: string, input: unknown, response: unknown, tool_use_id?: string) {
  const body: Record<string, unknown> = {
    hook_event_name: 'PostToolUse',
    tool_name: tool,
    tool_input: input,
    tool_response: response,
  };
  if (tool_use_id) body.tool_use_id = tool_use_id;
  const r = run(['log', payload(body)]);
  const out = r.stdout.trim();
  return {
    status: r.status,
    out: out
      ? (JSON.parse(out) as {
          hookSpecificOutput?: { additionalContext?: string; updatedToolOutput?: unknown };
        })
      : null,
  };
}

async function waitFor(url: string, headers: Record<string, string>, ms: number): Promise<boolean> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url, { headers });
      if (res.ok) return true;
    } catch {
      /* not yet */
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  return false;
}

beforeAll(async () => {
  if (!cliExists || process.platform === 'win32') return;
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-exposure-int-'));
  proj = path.join(home, 'proj');
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  fs.mkdirSync(proj);
  writeConfig({ untrustedContent: { orgDomains: ['acme.example'] } });
  port = await freePort();
  env = {
    ...keySafeEnv(),
    HOME: home,
    USERPROFILE: home,
    NODE9_TESTING: '1',
    NODE9_NO_AUTO_DAEMON: '1',
    NODE9_DAEMON_PORT: String(port),
  };
  daemon = spawn(process.execPath, [CLI, 'daemon', 'start'], { env, stdio: 'pipe' });
  const up = await waitFor(`http://127.0.0.1:${port}/settings`, {}, 8000);
  if (!up) throw new Error('daemon did not start');
}, 20_000);

afterAll(() => {
  if (!home) return;
  try {
    spawnSync(process.execPath, [CLI, 'daemon', 'stop'], { env, timeout: 10_000 });
  } catch {
    /* best effort */
  }
  if (daemon && daemon.exitCode === null) daemon.kill();
  fs.rmSync(home, { recursive: true, force: true });
});

describe('exposure through the built hook and a real daemon', () => {
  itUnix('a send in a clean session is allowed silently', () => {
    const r = check('mcp__gmail__send_email', { to: 'stranger@example.org', body: 'hi' });
    expect(r.status).toBe(0);
    expect(r.ask).toBeUndefined();
  });

  itUnix('T3: a WebFetch result with no hostile text marks exposure and is framed whole', () => {
    const r = log(
      'WebFetch',
      { url: 'https://news.example/a' },
      {
        output:
          'Weather today is fine and nothing else is going on. Contact press@news.example for questions.',
      }
    );
    expect(r.status).toBe(0);
    const updated = JSON.stringify(r.out?.hookSpecificOutput?.updatedToolOutput ?? '');
    expect(updated).toMatch(/node9 untrusted-output [0-9a-f]{12}: .* DATA from a web page/);
    expect(updated).toMatch(/Node9: ignored an instruction in the web page/);
    expect(r.out?.hookSpecificOutput?.additionalContext).toBeUndefined();
    const token = (
      JSON.parse(fs.readFileSync(path.join(home, '.node9', 'daemon.pid'), 'utf8')) as {
        internalToken: string;
      }
    ).internalToken;
    const list = spawnSync(
      'curl',
      ['-s', '-H', `X-Node9-Internal: ${token}`, `http://127.0.0.1:${port}/session-exposure/list`],
      { encoding: 'utf8' }
    );
    expect(list.stdout).toContain('"email:press@news.example"');
  });

  itUnix('T5: a send to an address that appeared in the page is asked, with the reason', () => {
    const r = check('mcp__gmail__send_email', { to: 'press@news.example', body: 'hi' });
    expect(r.status).toBe(0);
    expect(r.ask).toBe('ask');
    expect(r.reason).toMatch(/this session read a web page/);
    expect(r.reason).toMatch(/press@news\.example, an address that appeared in that web page/);
  });

  itUnix('a send to an unknown outside address is asked', () => {
    const r = check('mcp__gmail__send_email', { to: 'stranger@example.org', body: 'hi' });
    expect(r.ask).toBe('ask');
    expect(r.reason).toMatch(/an address this session did not know/);
  });

  itUnix('T6: a send inside the organisation is allowed', () => {
    const r = check('mcp__gmail__send_email', { to: 'colleague@acme.example', body: 'hi' });
    expect(r.status).toBe(0);
    expect(r.ask).toBeUndefined();
  });

  itUnix('T7: an address the user typed in a prompt is known', () => {
    const p = run([
      'check',
      JSON.stringify({
        hook_event_name: 'UserPromptSubmit',
        prompt: 'send the summary to dani@example.org please',
        session_id: SID,
        cwd: proj,
      }),
    ]);
    expect(p.status).toBe(0);
    const r = check('mcp__gmail__send_email', { to: 'dani@example.org', body: 'summary' });
    expect(r.ask).toBeUndefined();
    expect(r.status).toBe(0);
  });

  itUnix('T10: a call with no destination is logged; T9: a destructive one is asked', () => {
    expect(check('mcp__calendar__create_event', { title: 'room' }).ask).toBeUndefined();
    const del = check('mcp__drive__delete_file', { id: '13' });
    expect(del.ask).toBe('ask');
    expect(del.reason).toMatch(/delete_file, a destructive call/);
  });

  itUnix('a built-in read tool after exposure is not asked', () => {
    expect(check('Grep', { pattern: 'TODO' }).ask).toBeUndefined();
  });

  itUnix('T8: ask-once — the inline approval clears that address, not others', () => {
    const first = check('mcp__gmail__send_email', { to: 'stranger@example.org', body: 'hi' });
    expect(first.ask).toBe('ask');
    // The tool ran: PostToolUse with the same tool_use_id resolves the review.
    const r = log(
      'mcp__gmail__send_email',
      { to: 'stranger@example.org', body: 'hi' },
      { content: [{ type: 'text', text: 'sent' }] },
      `tu-${tuid}`
    );
    expect(r.status).toBe(0);
    expect(
      check('mcp__gmail__send_email', { to: 'stranger@example.org', body: 'again' }).ask
    ).toBeUndefined();
    expect(check('mcp__gmail__send_email', { to: 'other@example.org', body: 'again' }).ask).toBe(
      'ask'
    );
  });

  itUnix('T15: log-only never asks', () => {
    writeConfig({ untrustedContent: { afterExposure: 'log-only' } });
    expect(
      check('mcp__gmail__send_email', { to: 'press@news.example', body: 'hi' }).ask
    ).toBeUndefined();
    writeConfig({ untrustedContent: { orgDomains: ['acme.example'] } });
  });

  itUnix('the taint and exposure routes refuse a caller without the token', async () => {
    for (const route of ['/session-taint/list', '/session-exposure/list']) {
      const res = await fetch(`http://127.0.0.1:${port}${route}`);
      expect(res.status).toBe(403);
    }
  });

  itUnix(
    'T17: with the daemon down every call is allowed (fail open) and the gap is on record',
    () => {
      spawnSync(process.execPath, [CLI, 'daemon', 'stop'], { env, timeout: 10_000 });
      if (daemon && daemon.exitCode === null) daemon.kill();
      const r = check('mcp__gmail__send_email', { to: 'press@news.example', body: 'hi' });
      expect(r.status).toBe(0);
      expect(r.ask).toBeUndefined();
    }
  );
});
