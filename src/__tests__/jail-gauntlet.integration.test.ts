/**
 * Jail gauntlet (task #19, surface 1) — prove the credential jail AT THE GATE.
 *
 * Why this suite exists: jail's only gate-level coverage
 * (jail.integration.test.ts) asserts through `node9 explain`, which
 * [[project_jail_add_path]] records as under-reporting and not ground truth.
 * This probes `node9 check` — the layer that actually decides — with the payload
 * a real agent hook sends.
 *
 * ⚠️ IT FOUND A REAL BUG ON THE FIRST PROBE (see `read/grep` cases below):
 *   `node9 jail add <path>` prints "AI reads of this path now BLOCK", and Bash
 *   reads ARE blocked — but the `Read` and `Grep` tools are ALLOWED, because:
 *     • `jail add` enables the shield named `user-jail` (shields/jail.ts:18,
 *       USER_JAIL_SHIELD), while
 *     • the orchestrator guard that exists precisely to stop Read/Grep/Glob
 *       fast-pathing past a jail checks `readActiveShields().includes(
 *       'project-jail')` — the OTHER shield name.
 *   So `Read`/`Grep` hit the ignoredTools fast-path allow and never reach the
 *   jail's rules. Read is the primary way an agent reads a file, so the jail is
 *   inert on its main path while reporting success.
 *
 * Note on the earlier "bash bypass was a misdiagnosis" note: that investigation
 * checked BASH (which genuinely works) and concluded the jail was fine. The gap
 * is the opposite direction — the file tools, not the shell.
 */
import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import fs from 'fs';
import path from 'path';
import { CLI, makeHome, runCli, probe, explain, cleanup } from './helpers/gauntlet';

const homes: string[] = [];
function jailedHome(): { home: string; jailed: string } {
  const home = makeHome('node9-jail-gauntlet-');
  homes.push(home);
  const jailed = path.join(home, '.secrets');
  fs.mkdirSync(jailed, { recursive: true });
  const r = runCli(home, ['jail', 'add', jailed]);
  expect(r.error).toBeUndefined();
  expect(r.status).toBe(0);
  return { home, jailed };
}

beforeAll(() => {
  expect(fs.existsSync(CLI), `built CLI missing at ${CLI} — run npm run build`).toBe(true);
});
afterEach(() => {
  for (const h of homes.splice(0)) cleanup(h);
});

describe('jail gauntlet — the credential jail holds at the real gate', () => {
  // ── CONTROL: without this passing, every "not allowed" below is vacuous ────
  it('CONTROL: a shell read of a jailed path is blocked (proves the jail armed)', () => {
    const { home, jailed } = jailedHome();
    const r = probe(home, 'Bash', { command: `cat ${jailed}/key.txt` });
    expect(r.verdict).toBe('block');
  });

  it('CONTROL: an UNjailed path is allowed (proves we are not blanket-denying)', () => {
    const { home } = jailedHome();
    const r = probe(home, 'Bash', { command: 'cat /tmp/harmless.txt' });
    expect(r.verdict).toBe('allow');
  });

  // ── THE BUG (task #20, now fixed): the file tools bypassed the jail ───────
  // `jail add` promises reads BLOCK, so these assert `block` — not merely
  // "not allow" — matching the Bash CONTROL above.
  it('the Read tool is blocked on a jailed path', () => {
    const { home, jailed } = jailedHome();
    const r = probe(home, 'Read', { file_path: path.join(jailed, 'key.txt') });
    expect(r.verdict).toBe('block');
  });

  it('the Grep tool is blocked on a jailed path (pattern field)', () => {
    const { home, jailed } = jailedHome();
    const r = probe(home, 'Grep', { pattern: path.join(jailed, 'key.txt') });
    expect(r.verdict).toBe('block');
  });

  it('the Grep tool is blocked when the jailed dir rides in `path` (real Grep shape)', () => {
    const { home, jailed } = jailedHome();
    // Real Grep exfil shape: benign pattern, jailed directory as search root.
    const r = probe(home, 'Grep', { pattern: '.*', path: jailed });
    expect(r.verdict).toBe('block');
  });

  it('the Glob tool is blocked on a jailed path', () => {
    const { home, jailed } = jailedHome();
    const r = probe(home, 'Glob', { pattern: path.join(jailed, '*') });
    expect(r.verdict).toBe('block');
  });

  it('an unjailed Read still takes the fast path (no blanket regression)', () => {
    const { home } = jailedHome();
    const r = probe(home, 'Read', { file_path: '/tmp/harmless.txt' });
    expect(r.verdict).toBe('allow');
  });

  // ── Reporting vs reality ──────────────────────────────────────────────────
  // Not an enforcement assertion — a consistency one. `jail add` promises reads
  // block; whatever the gate does, the CLI and the gate must agree, or a user
  // is told they are protected when they are not.
  it('the gate agrees with what `jail add` promised about reads', () => {
    const { home, jailed } = jailedHome();
    const gate = probe(home, 'Read', { file_path: path.join(jailed, 'key.txt') });
    const e = explain(home, 'Read', path.join(jailed, 'key.txt'));
    const explainSaysAllow = /ALLOW/i.test(e.stdout ?? '');
    // The promise printed by `jail add` is "AI reads of this path now BLOCK".
    // So an allow at the gate is a broken promise regardless of what explain says.
    expect({ gate: gate.verdict, explainSaysAllow }, 'jail add promised reads BLOCK').toMatchObject(
      { gate: expect.not.stringMatching(/^allow$/) }
    );
  });
});
