/**
 * Executes the hook command that fullPathCommand emits, through the shells
 * Windows agents actually use. Windows-only; skipped elsewhere.
 *
 * This file exists because the string-comparison suite could not have caught
 * the bug it guards. fullPathCommand used to emit two quoted paths:
 *
 *   "C:/Program Files/nodejs/node.exe" "C:/.../cli.js" check
 *
 * which begins with a quote and contains four. Per the documented `cmd /?`
 * rules, quotes are preserved only when there are EXACTLY TWO; otherwise cmd
 * strips the leading quote and the last quote, and the remainder splits on the
 * space inside `Program Files`. cmd then tries to execute `C:/Program` and
 * exits 1. Codex Desktop discards a failed hook without surfacing anything, so
 * the result was no enforcement and no audit rows — on every Windows machine,
 * for every agent, silently.
 *
 * `cmd /s` never showed the bug (it only strips when the string also ENDS in a
 * quote), and neither does Node's own `shell: true`, which shells out via
 * `cmd.exe /d /s /c`. Both are why this went unnoticed. The tests below drive
 * cmd WITHOUT /s on purpose, with windowsVerbatimArguments so Node does not
 * re-quote the string on the way in.
 *
 * The broken form is asserted to FAIL. That assertion is the instrument's own
 * calibration: if it ever starts passing, these tests have stopped measuring
 * the thing they were written for.
 */
import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { spawn, spawnSync, type SpawnSyncReturns } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fullPathCommand } from '../setup.js';

const isWindows = process.platform === 'win32';

// A directory with a space in its name reproduces `C:\Program Files` without
// depending on where Node happens to be installed on the runner.
let dirWithSpace = '';
let stubScript = '';
// The stub appends a line here the moment it starts, so a failed run can say
// whether the shell ever got as far as launching node.
let marker = '';
let restore: () => void = () => {};

function stubProcess(execPath: string, argv1: string): () => void {
  const origExec = process.execPath;
  const origArgv = process.argv[1];
  Object.defineProperty(process, 'execPath', { value: execPath, configurable: true });
  process.argv[1] = argv1;
  return () => {
    Object.defineProperty(process, 'execPath', { value: origExec, configurable: true });
    process.argv[1] = origArgv;
  };
}

function toForwardSlashes(p: string): string {
  return p.replace(/\\/g, '/');
}

// Stands in for cli.js: drains stdin and exits 0 on EOF, with a 1s fallback exit
// so it can never be the thing that hangs. The question under test is whether the
// shell can LAUNCH the command; a zero exit from this script proves that. The
// pre-fix form still fails, because it never gets as far as running it.
const STUB_SOURCE =
  'process.stdin.resume();process.stdin.on("end",()=>process.exit(0));' +
  'setTimeout(()=>process.exit(0),1000);\n';

// Per spawn. A hung shell fails with a null status and ETIMEDOUT that names the
// runner, instead of a bare vitest timeout.
const RUN_TIMEOUT_MS = 20_000;

// Measured on windows-latest, 2026-09-25 (diagnostic branch, since deleted):
// 90 isolated powershell launches never stalled (PowerShell up in ~240ms, the hook
// command through it in ~300ms). Under the full suite's load, 1 of 12 runs stalled
// past 20s with NO output and the stub never started, and in that same window a
// bare `powershell -Command "exit 0"` stalled too. Two more runs took ~2.5s just to
// start PowerShell. cmd never stalled (<110ms). So PowerShell 5.1 itself sometimes
// fails to start on a loaded runner; it is not the command under test.
//
// That exact signature (timed out, node never started) is retried ONCE. Anything
// else is a real result: a quoting bug makes the shell fail fast with a non-zero
// status, or node start and exit non-zero, and neither is retried. Two stalls in a
// row fail the test, with the diagnostic line in the log.
export interface LaunchAttempt {
  result: SpawnSyncReturns<string>;
  nodeStarted: boolean;
}
export function isShellStall(a: LaunchAttempt): boolean {
  const code = (a.result.error as NodeJS.ErrnoException | undefined)?.code;
  return a.result.status === null && code === 'ETIMEDOUT' && !a.nodeStarted;
}
export function launchWithOneStallRetry(
  attempt: () => LaunchAttempt,
  log: (line: string) => void = console.log
): { final: LaunchAttempt; stalls: number } {
  let final = attempt();
  let stalls = 0;
  if (isShellStall(final)) {
    stalls++;
    log(`shell stalled before launching node (pid ${final.result.pid}); retrying once`);
    final = attempt();
    if (isShellStall(final)) {
      stalls++;
      log(`shell stalled again (pid ${final.result.pid}); failing`);
    }
  }
  return { final, stalls };
}

function markerLines(): number {
  try {
    return fs.readFileSync(marker, 'utf8').split('\n').filter(Boolean).length;
  } catch {
    return 0;
  }
}

// Each runner form, invoked the way an agent harness spawns a hook: the whole
// command as one verbatim string, with a JSON payload on stdin.
const RUNNERS: Array<{ name: string; run: (cmd: string) => SpawnSyncReturns<string> }> = [
  {
    name: 'cmd /d /c',
    run: (cmd) =>
      spawnSync('cmd.exe', ['/d', '/c', cmd], {
        input: '{"hook_event_name":"PreToolUse"}',
        windowsVerbatimArguments: true,
        encoding: 'utf-8',
        timeout: RUN_TIMEOUT_MS,
      }),
  },
  {
    name: 'cmd /d /s /c',
    run: (cmd) =>
      spawnSync('cmd.exe', ['/d', '/s', '/c', `"${cmd}"`], {
        input: '{"hook_event_name":"PreToolUse"}',
        windowsVerbatimArguments: true,
        encoding: 'utf-8',
        timeout: RUN_TIMEOUT_MS,
      }),
  },
  {
    // powershell.exe -Command is parsed TWICE: the Windows command-line
    // parser builds powershell's own argv first and consumes the quotes, then
    // powershell rejoins the remaining tokens with spaces. An unescaped
    // `node "C:/x y/cli.js" check` therefore reaches powershell as
    // `node C:/x y/cli.js check` and dies on the space — a property of how a
    // caller invokes powershell, not of the command being invoked. Escaping
    // the quotes is that caller's job, and is what the CLI docs prescribe.
    name: 'powershell -Command',
    run: (cmd) =>
      spawnSync('powershell.exe', ['-NoProfile', '-Command', cmd.replace(/"/g, '\\"')], {
        input: '{"hook_event_name":"PreToolUse"}',
        windowsVerbatimArguments: true,
        encoding: 'utf-8',
        timeout: RUN_TIMEOUT_MS,
      }),
  },
];

describe.skipIf(!isWindows)('hook command launches under every Windows shell', () => {
  beforeAll(() => {
    // vitest.config.mts pins env.NODE9_TESTING = '1', which makes
    // fullPathCommand short-circuit to a bare `node9 <sub>` that is not
    // installed on a CI runner. Without clearing it this file measures nothing
    // but "node9 is not on PATH" — which is how its first run failed. The
    // config has no unstubEnvs, so a beforeAll stub holds for the whole file.
    vi.stubEnv('NODE9_TESTING', '');
    dirWithSpace = fs.mkdtempSync(path.join(os.tmpdir(), 'node9 hook '));
    stubScript = path.join(dirWithSpace, 'cli.js');
    marker = path.join(dirWithSpace, 'started.log');
    fs.writeFileSync(
      stubScript,
      `require("fs").appendFileSync(${JSON.stringify(marker)}, "1\\n");` + STUB_SOURCE
    );
    restore = stubProcess(process.execPath, stubScript);
  });

  afterAll(() => {
    vi.unstubAllEnvs();
    restore();
    if (dirWithSpace) fs.rmSync(dirWithSpace, { recursive: true, force: true });
  });

  for (const runner of RUNNERS) {
    // Two spawns of up to RUN_TIMEOUT_MS each, plus margin, when the retry fires.
    it(
      `runs the emitted command under ${runner.name}`,
      () => {
        const cmd = fullPathCommand('check', 'win32');
        const { final } = launchWithOneStallRetry(
          () => {
            const before = markerLines();
            const result = runner.run(cmd);
            return { result, nodeStarted: markerLines() > before };
          },
          (line) => console.log(`[${runner.name}] ${line}`)
        );
        expect(final.result.status).toBe(0);
      },
      2 * RUN_TIMEOUT_MS + 10_000
    );
  }

  it('emits a command that does not begin with a quote', () => {
    // The property the runners above depend on, asserted directly so a failure
    // says which half broke: the shape, or its execution.
    expect(fullPathCommand('check', 'win32').startsWith('"')).toBe(false);
  });

  it('confirms the pre-fix form still fails, so these tests still measure something', () => {
    // Two quoted paths, which is what fullPathCommand used to emit. cmd's
    // rule-2 stripping removes the leading quote and the last one, leaving a
    // stray quote welded onto the first token; whether the runner's own node
    // path contains a space only changes which token ends up mangled.
    const broken = `"${toForwardSlashes(process.execPath)}" "${toForwardSlashes(stubScript)}" check`;
    // /s is the documented escape from rule 2 and keeps working — which is
    // exactly why Node's own `shell: true` never surfaced the bug. Only the
    // cmd /d /c runner is asserted: powershell fails this form too, but by a
    // different route (a leading quoted string is a string literal there, not
    // a command), and pinning a second mechanism to the same assertion would
    // make a future failure ambiguous.
    expect(RUNNERS[0].run(broken).status).not.toBe(0);
  });
});

// Runs on every platform: the stub must exit 0 even when stdin is never closed,
// so the stub can never be the process that hangs. The pipe is held open on
// purpose and only closed after the child has exited.
describe('Windows shell test stub', () => {
  it('exits 0 even when stdin never reaches EOF', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-stub-'));
    try {
      const script = path.join(dir, 'cli.js');
      fs.writeFileSync(script, STUB_SOURCE);
      const child = spawn(process.execPath, [script], { stdio: ['pipe', 'ignore', 'ignore'] });
      child.stdin.write('{"hook_event_name":"PreToolUse"}');
      const guard = setTimeout(() => child.kill(), 5_000);
      const code = await new Promise<number | null>((resolve) =>
        child.on('exit', (c) => resolve(c))
      );
      clearTimeout(guard);
      child.stdin.destroy();
      expect(code).toBe(0);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

// Runs on every platform: the retry policy, driven by synthetic results. Only a
// stall (timed out AND node never started) is retried, and only once.
describe('powershell stall retry policy', () => {
  const res = (status: number | null, code?: string): SpawnSyncReturns<string> =>
    ({
      pid: 1,
      output: [],
      stdout: '',
      stderr: '',
      status,
      signal: status === null ? 'SIGTERM' : null,
      error: code ? Object.assign(new Error(code), { code }) : undefined,
    }) as SpawnSyncReturns<string>;
  const seq = (...xs: LaunchAttempt[]) => {
    let i = 0;
    return () => xs[Math.min(i++, xs.length - 1)];
  };
  const quiet = () => {};

  it('a stall followed by a clean launch passes, with one stall recorded', () => {
    const r = launchWithOneStallRetry(
      seq(
        { result: res(null, 'ETIMEDOUT'), nodeStarted: false },
        { result: res(0), nodeStarted: true }
      ),
      quiet
    );
    expect(r.final.result.status).toBe(0);
    expect(r.stalls).toBe(1);
  });

  it('two stalls in a row fail: no second retry', () => {
    const calls: number[] = [];
    const stall = { result: res(null, 'ETIMEDOUT'), nodeStarted: false };
    const r = launchWithOneStallRetry(() => {
      calls.push(1);
      return stall;
    }, quiet);
    expect(r.final.result.status).toBeNull();
    expect(r.stalls).toBe(2);
    expect(calls.length).toBe(2);
  });

  it('a timeout AFTER node started is a real result, not retried', () => {
    const calls: number[] = [];
    const r = launchWithOneStallRetry(() => {
      calls.push(1);
      return { result: res(null, 'ETIMEDOUT'), nodeStarted: true };
    }, quiet);
    expect(calls.length).toBe(1);
    expect(r.stalls).toBe(0);
  });

  it('a fast non-zero exit (a real quoting bug) is not retried', () => {
    const calls: number[] = [];
    const r = launchWithOneStallRetry(() => {
      calls.push(1);
      return { result: res(1), nodeStarted: false };
    }, quiet);
    expect(calls.length).toBe(1);
    expect(r.final.result.status).toBe(1);
  });
});
