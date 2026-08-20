// src/__tests__/helpers/gauntlet.ts
//
// Shared harness for the enforcement gauntlets (task #19) — the sweep that probes
// each enforcement surface AT THE LAYER THAT GATES, in a real subprocess.
//
// Why this exists: every surface hammered this way so far turned up a real
// fail-open (managed-mode, shields, taint ×2). The pattern that found them is
// always the same, so it belongs in one place instead of being re-derived — and
// re-derived slightly wrong — per suite.
//
// The rules encoded here, each learned the hard way:
//   • Probe the REAL gate (`node9 check`), never a reporting command. `node9
//     explain` is documented as under-reporting and is not ground truth.
//   • Send the payload the REAL hook sends. A payload missing `hook_event_name`
//     is a silent no-op: check.ts returns without evaluating, so every probe
//     "passes" while nothing is enforced.
//   • Classify by exit code, not by output text: 0 = allowed, 2 = blocked,
//     timeout = held for a human. A silent exit 0 IS the fail-open signature.
//   • Always pair with a CONTROL that must block — otherwise "zero allows" can
//     be vacuously true because the setup never armed.
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

export const CLI = path.resolve(__dirname, '../../../dist/cli.js');

export type Verdict = 'allow' | 'block' | 'held' | 'error';

export interface ProbeResult {
  verdict: Verdict;
  status: number | null;
  stdout: string;
  stderr: string;
}

/** A per-test HOME with a .node9 dir. Callers seed config//cache into it. */
export function makeHome(prefix = 'node9-gauntlet-'): string {
  const h = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  fs.mkdirSync(path.join(h, '.node9'), { recursive: true });
  return h;
}

/** Write ~/.node9/config.json. Defaults keep every approver OFF so a review
 *  can't hang on a prompt — a held review then surfaces as a timeout, which is
 *  a distinct (and honest) signal rather than a stuck test. */
export function writeConfig(home: string, config: Record<string, unknown>): void {
  fs.writeFileSync(path.join(home, '.node9', 'config.json'), JSON.stringify(config));
}

/** Write ~/.node9/rules-cache.json — the file the daemon sync writes; this is
 *  how a test simulates cloud-managed policy reaching the device. */
export function writeCloudCache(home: string, cache: Record<string, unknown>): void {
  fs.writeFileSync(path.join(home, '.node9', 'rules-cache.json'), JSON.stringify(cache));
}

/** Run any node9 CLI command in this HOME (setup: `jail add`, `shield enable`…). */
export function runCli(home: string, args: string[], timeoutMs = 60000) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: timeoutMs,
    cwd: os.tmpdir(),
    env: {
      ...process.env,
      HOME: home,
      USERPROFILE: home,
      NODE9_TESTING: '1',
      NODE9_NO_AUTO_DAEMON: '1',
      NO_COLOR: '1',
    },
  });
}

/**
 * THE probe: drive the real PreToolUse gate exactly as an agent's hook does.
 *
 * `hook_event_name` is mandatory — check.ts no-ops without it, which silently
 * turns every probe into a false pass.
 */
export function probe(
  home: string,
  toolName: string,
  toolInput: Record<string, unknown>,
  opts: { cwd?: string; timeoutMs?: number; env?: Record<string, string> } = {}
): ProbeResult {
  const payload = JSON.stringify({
    hook_event_name: 'PreToolUse',
    session_id: 'gauntlet',
    cwd: opts.cwd ?? home,
    tool_name: toolName,
    tool_input: toolInput,
  });
  const r = spawnSync(process.execPath, [CLI, 'check'], {
    input: payload,
    encoding: 'utf-8',
    timeout: opts.timeoutMs ?? 15000,
    cwd: os.tmpdir(),
    env: {
      ...process.env,
      HOME: home,
      USERPROFILE: home,
      NODE9_TESTING: '1',
      NODE9_NO_AUTO_DAEMON: '1',
      NO_COLOR: '1',
      // No GUI/tail → no human approver reachable, so a review resolves
      // deterministically (fail-closed) instead of waiting on a dialog.
      ...opts.env,
    },
  });
  // A killed-by-timeout probe means the gate held the call for a human.
  const held = r.signal !== null || r.status === null;
  const verdict: Verdict = held
    ? 'held'
    : r.status === 0
      ? 'allow'
      : r.status === 2
        ? 'block'
        : 'error';
  return { verdict, status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

/** `node9 explain` — the REPORTING path. Kept only so a gauntlet can compare it
 *  against the real gate; never use it to assert enforcement. */
export function explain(home: string, tool: string, command: string) {
  return runCli(home, ['explain', tool, command]);
}

/** Assert a set of probes never leaked an allow. Fails with the verdict list so
 *  a flake is diagnosable rather than a bare "expected false to be true". */
export function expectNeverAllowed(results: ProbeResult[]): void {
  const allows = results.filter((r) => r.verdict === 'allow');
  if (allows.length > 0) {
    throw new Error(
      `FAIL-OPEN: ${allows.length}/${results.length} probe(s) allowed — verdicts: ` +
        results.map((r) => r.verdict).join(',')
    );
  }
}

export function cleanup(home: string): void {
  try {
    fs.rmSync(home, { recursive: true, force: true });
  } catch {
    /* Windows EBUSY */
  }
}
