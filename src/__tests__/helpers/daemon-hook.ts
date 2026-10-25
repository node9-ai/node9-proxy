// A real daemon in an isolated HOME on its own port, and the built hook
// (`check` for PreToolUse and UserPromptSubmit, `log` for PostToolUse) run
// against it in one agent session. For tests whose verdict depends on what
// the session read before the call (session taint, fw#318 exposure).
// Requires `npm run build`. Unix only (the callers skip on Windows).
import { spawn, spawnSync, type ChildProcess } from 'child_process';
import fs from 'fs';
import net from 'net';
import os from 'os';
import path from 'path';
import { expect } from 'vitest';
import { keySafeEnv } from './env';

export const CLI = path.resolve(__dirname, '../../../dist/cli.js');
export const cliExists = fs.existsSync(CLI);

export function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const port = (srv.address() as net.AddressInfo).port;
      srv.close(() => resolve(port));
    });
  });
}

export async function waitFor(url: string, ms: number): Promise<boolean> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.ok) return true;
    } catch {
      /* not yet */
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  return false;
}

export interface HookResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

export interface DaemonHook {
  home: string;
  proj: string;
  port: number;
  env: Record<string, string | undefined>;
  /** Overwrite ~/.node9/config.json; settings merge over the test defaults. */
  writeConfig(policy: Record<string, unknown>, settings?: Record<string, unknown>): void;
  run(args: string[]): HookResult;
  /** PreToolUse; `ask` is the permissionDecision when the hook answered one. */
  check(
    tool: string,
    input: unknown,
    tuid?: string
  ): { status: number | null; ask?: string; reason: string; stdout: string };
  /** PostToolUse with a tool result. */
  log(
    tool: string,
    input: unknown,
    response: unknown,
    tuid?: string
  ): {
    status: number | null;
    out: {
      hookSpecificOutput?: { additionalContext?: string; updatedToolOutput?: unknown };
    } | null;
  };
  /** UserPromptSubmit. */
  prompt(text: string): HookResult;
  /** The daemon's internal token (from daemon.pid). */
  token(): string;
  lastTuid(): string;
  stopDaemon(): void;
  dispose(): void;
}

/**
 * Start a daemon and return the hook helpers bound to one session id.
 * `settings` merge over: standard mode, no auto-start, approvals timing out
 * at once, every approver off.
 */
export async function startDaemonHook(opts: {
  sessionId: string;
  policy?: Record<string, unknown>;
  settings?: Record<string, unknown>;
}): Promise<DaemonHook> {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-daemon-hook-'));
  const proj = path.join(home, 'proj');
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  fs.mkdirSync(proj);
  const writeConfig = (policy: Record<string, unknown>, settings: Record<string, unknown> = {}) =>
    fs.writeFileSync(
      path.join(home, '.node9', 'config.json'),
      JSON.stringify({
        settings: {
          mode: 'standard',
          autoStartDaemon: false,
          approvalTimeoutMs: 0,
          approvers: { native: false, browser: false, cloud: false, terminal: false },
          ...settings,
        },
        policy: { loopDetection: { enabled: false }, ...policy },
      })
    );
  writeConfig(opts.policy ?? {}, opts.settings ?? {});
  const port = await freePort();
  const env: Record<string, string | undefined> = {
    ...keySafeEnv(),
    HOME: home,
    USERPROFILE: home,
    NODE9_TESTING: '1',
    NODE9_NO_AUTO_DAEMON: '1',
    NODE9_DAEMON_PORT: String(port),
    // The hook binds $TMPDIR/node9-activity.sock; a private directory keeps
    // the developer's own daemon out of the test (fw#399).
    TMPDIR: fs.mkdtempSync(path.join(os.tmpdir(), 'n9h-')),
  };
  const daemon: ChildProcess = spawn(process.execPath, [CLI, 'daemon', 'start'], {
    env,
    stdio: 'pipe',
  });
  if (!(await waitFor(`http://127.0.0.1:${port}/settings`, 8000))) {
    daemon.kill();
    throw new Error('daemon did not start');
  }

  let tuid = 0;
  const run = (args: string[]): HookResult => {
    const r = spawnSync(process.execPath, [CLI, ...args], {
      cwd: proj,
      encoding: 'utf8',
      timeout: 30_000,
      env,
    });
    expect(r.error).toBeUndefined();
    expect(r.status).not.toBeNull();
    return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
  };
  const payload = (extra: Record<string, unknown>, id?: string) =>
    JSON.stringify({
      session_id: opts.sessionId,
      tool_use_id: id ?? `tu-${++tuid}`,
      cwd: proj,
      ...extra,
    });
  const stopDaemon = () => {
    try {
      spawnSync(process.execPath, [CLI, 'daemon', 'stop'], { env, timeout: 10_000 });
    } catch {
      /* best effort */
    }
    if (daemon.exitCode === null) daemon.kill();
  };

  return {
    home,
    proj,
    port,
    env,
    writeConfig,
    run,
    check(tool, input, id) {
      const r = run([
        'check',
        payload({ hook_event_name: 'PreToolUse', tool_name: tool, tool_input: input }, id),
      ]);
      const out = r.stdout.trim();
      let parsed: {
        hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string };
      } | null = null;
      try {
        parsed = out ? JSON.parse(out) : null;
      } catch {
        parsed = null;
      }
      return {
        status: r.status,
        ask: parsed?.hookSpecificOutput?.permissionDecision,
        reason: parsed?.hookSpecificOutput?.permissionDecisionReason ?? '',
        stdout: r.stdout,
      };
    },
    log(tool, input, response, id) {
      const r = run([
        'log',
        payload(
          {
            hook_event_name: 'PostToolUse',
            tool_name: tool,
            tool_input: input,
            tool_response: response,
          },
          id
        ),
      ]);
      const out = r.stdout.trim();
      return { status: r.status, out: out ? JSON.parse(out) : null };
    },
    prompt(text) {
      return run([
        'check',
        JSON.stringify({
          hook_event_name: 'UserPromptSubmit',
          prompt: text,
          session_id: opts.sessionId,
          cwd: proj,
        }),
      ]);
    },
    token() {
      return (
        JSON.parse(fs.readFileSync(path.join(home, '.node9', 'daemon.pid'), 'utf8')) as {
          internalToken: string;
        }
      ).internalToken;
    },
    lastTuid: () => `tu-${tuid}`,
    stopDaemon,
    dispose() {
      stopDaemon();
      fs.rmSync(home, { recursive: true, force: true });
    },
  };
}
