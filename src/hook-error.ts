// src/hook-error.ts
// What node9 does when node9 itself fails while checking a call
// (node9Firewall#383).
//
// The before-run hook used to end every internal error with a silent exit 0:
// the call ran, no audit row, no log line unless NODE9_DEBUG was set. This
// module holds the two parts of the fix that must work when everything else
// has failed: reading the fail policy, and recording that a check was not
// performed. Neither loads the config, the engine or the daemon, and neither
// throws.
import fs from 'fs';
import os from 'os';
import path from 'path';

/** `allow`: the call runs, as it always has. `block`: the call is stopped. */
export type HookErrorPolicy = 'allow' | 'block';

/** Where a `block` came from; `default` when nothing asked for one. */
export type HookErrorPolicySource = 'workspace' | 'env' | 'config' | 'default';

export interface HookErrorPolicyReading {
  policy: HookErrorPolicy;
  source: HookErrorPolicySource;
}

/** Set by IT (MDM, a shell profile) to stop unchecked calls on a machine. */
export const HOOK_ERROR_ENV = 'NODE9_ON_HOOK_ERROR';

/** `checkedBy` of the audit row a failed check leaves. */
export const HOOK_ERROR_CHECKED_BY = 'hook-error';

/**
 * The step that failed: reading the payload, anything after it, or (reported
 * by the after-run hook, checked-calls.ts) a before-run hook that never
 * finished at all.
 */
export type HookErrorStage = 'parse' | 'engine' | 'no-verdict';

function asksForBlock(value: unknown): boolean {
  return typeof value === 'string' && value.trim().toLowerCase() === 'block';
}

/** A JSON object from a file, or null for a missing, unreadable or malformed one. */
function readJsonObject(file: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(fs.readFileSync(file, 'utf-8'));
    return parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function child(obj: Record<string, unknown> | null, key: string): Record<string, unknown> | null {
  const v = obj?.[key];
  return v !== null && typeof v === 'object' && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : null;
}

/**
 * The fail policy of this machine. Three places can ask for `block`: the
 * workspace's managed settings (the daemon's `rules-cache.json`), the
 * `NODE9_ON_HOOK_ERROR` environment variable, and the user's own
 * `~/.node9/config.json`. The strictest wins, so none of them can loosen
 * another: an `allow` anywhere is the same as saying nothing.
 *
 * The files are read raw, without the config loader or its schema: that
 * loader may be the thing that failed. A file that cannot be read says
 * nothing. A project's `node9.config.json` is not read: the agent can write it.
 */
export function readHookErrorPolicy(
  home: string = os.homedir(),
  env: NodeJS.ProcessEnv = process.env
): HookErrorPolicyReading {
  const dir = path.join(home, '.node9');
  const managed = child(readJsonObject(path.join(dir, 'rules-cache.json')), 'managedConfig');
  if (asksForBlock(managed?.onHookError)) return { policy: 'block', source: 'workspace' };
  if (asksForBlock(env[HOOK_ERROR_ENV])) return { policy: 'block', source: 'env' };
  const settings = child(readJsonObject(path.join(dir, 'config.json')), 'settings');
  if (asksForBlock(settings?.onHookError)) return { policy: 'block', source: 'config' };
  return { policy: 'allow', source: 'default' };
}

/** The error's class and message, bounded and on one line. */
export function hookErrorText(err: unknown): string {
  const text =
    err instanceof Error ? `${err.name}: ${err.message}` : `non-error thrown: ${String(err)}`;
  return text.replace(/\s+/g, ' ').slice(0, 200);
}

/** The top frames of the stack: function names and file positions, with the
 *  home directory cut. A frame never holds an argument. */
function stackFrames(err: unknown, home: string): string[] {
  if (!(err instanceof Error) || typeof err.stack !== 'string') return [];
  return err.stack
    .split('\n')
    .filter((line) => /^\s*at /.test(line))
    .slice(0, 6)
    .map((line) => line.trim().split(home).join('~').slice(0, 200));
}

/**
 * One line in `~/.node9/hook-debug.log` for a check that was not performed.
 * Always written, with or without NODE9_DEBUG. Never throws.
 *
 * The line carries the error and where it was thrown, never the call's
 * arguments. A parse error's message can quote a few characters of the
 * payload, which is why only its class goes into the audit row (see
 * `check.ts`); this file stays on the machine.
 */
export function recordHookError(
  stage: HookErrorStage,
  err: unknown,
  ctx: { agent?: string; tool?: string; decision: 'allow' | 'deny'; policySource: string },
  home: string = os.homedir()
): void {
  try {
    const logPath = path.join(home, '.node9', 'hook-debug.log');
    fs.mkdirSync(path.dirname(logPath), { recursive: true });
    // No size ceiling: the file is shared, and other writers (every payload,
    // when debug logging is on) take it past any limit, which would drop this
    // line on the very machine someone is debugging. One short line per
    // failed check; each one already has an audit row.
    fs.appendFileSync(
      logPath,
      JSON.stringify({
        ts: new Date().toISOString(),
        event: HOOK_ERROR_CHECKED_BY,
        stage,
        decision: ctx.decision,
        policySource: ctx.policySource,
        ...(ctx.agent && { agent: ctx.agent }),
        ...(ctx.tool && { tool: ctx.tool.slice(0, 120) }),
        error: hookErrorText(err),
        stack: stackFrames(err, home),
      }) + '\n'
    );
  } catch {
    /* the log is unwritable: the audit row and the exit still happen */
  }
}

/** The hook event of a payload that could not be parsed, when its text still
 *  names one. A prompt or a session start is never stopped (see `check.ts`). */
export function eventFromRawPayload(raw: string): string | undefined {
  return /"hook_event_name"\s*:\s*"([A-Za-z_]{1,40})"/.exec(raw)?.[1];
}

/** Which agent wrote a payload that could not be parsed, from the field names
 *  only its dialect has. Undefined when the text names none. */
export function agentFromRawPayload(raw: string): string | undefined {
  if (/"turn_id"\s*:/.test(raw)) return 'Codex';
  if (/"(toolCall|conversationId)"\s*:/.test(raw)) return 'Antigravity';
  return undefined;
}

/**
 * How many checks were not performed since `sinceMs`, from the local audit
 * log, and the newest one. For `node9 doctor`. Never throws: an unreadable
 * log counts as none.
 */
export function recentHookErrors(
  sinceMs: number,
  home: string = os.homedir()
): { count: number; stopped: number; last?: { ts: string; what: string } } {
  const out: { count: number; stopped: number; last?: { ts: string; what: string } } = {
    count: 0,
    stopped: 0,
  };
  const marker = `"checkedBy":"${HOOK_ERROR_CHECKED_BY}"`;
  const take = (line: string): void => {
    if (!line.includes(marker)) return;
    try {
      const row = JSON.parse(line) as {
        ts?: unknown;
        checkedBy?: unknown;
        decision?: unknown;
        ruleName?: unknown;
      };
      if (row.checkedBy !== HOOK_ERROR_CHECKED_BY || typeof row.ts !== 'string') return;
      const at = Date.parse(row.ts);
      if (!Number.isFinite(at) || at < sinceMs) return;
      out.count++;
      if (row.decision === 'deny') out.stopped++;
      if (!out.last || row.ts > out.last.ts) {
        out.last = { ts: row.ts, what: typeof row.ruleName === 'string' ? row.ruleName : '' };
      }
    } catch {
      /* a torn line is not a row */
    }
  };
  // In pieces: the audit log grows to hundreds of megabytes, and this is a
  // count. latin1 keeps one byte per character, so a piece boundary inside a
  // multi-byte character cannot corrupt a line; the fields read here are ASCII.
  let fd: number;
  try {
    fd = fs.openSync(path.join(home, '.node9', 'audit.log'), 'r');
  } catch {
    return out;
  }
  try {
    const buf = Buffer.alloc(1024 * 1024);
    let carry = '';
    for (;;) {
      const n = fs.readSync(fd, buf, 0, buf.length, null);
      if (n <= 0) break;
      const lines = (carry + buf.toString('latin1', 0, n)).split('\n');
      carry = lines.pop() ?? '';
      for (const line of lines) take(line);
    }
    take(carry);
  } catch {
    /* what was counted so far */
  } finally {
    fs.closeSync(fd);
  }
  return out;
}

/** The fail policy in a person's words, for `node9 doctor`. */
export function describeHookErrorPolicy(reading: HookErrorPolicyReading): string {
  if (reading.policy === 'allow') {
    return 'If node9 itself fails on a call, the call runs and the failure is recorded (default)';
  }
  const by =
    reading.source === 'workspace'
      ? 'your workspace settings'
      : reading.source === 'env'
        ? `${HOOK_ERROR_ENV}=block`
        : 'onHookError in ~/.node9/config.json';
  return `If node9 itself fails on a call, the call is stopped (set by ${by})`;
}
