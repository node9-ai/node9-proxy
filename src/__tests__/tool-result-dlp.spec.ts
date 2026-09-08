// The tool-result DLP path had two bugs two lines apart.
// Design: doc/roadmap/active/tool-result-dlp-design.md
//
// B: looksLikeFixtureToken was given maskSecret's OUTPUT, whose asterisks are
//    themselves "6+ repeated characters", so every credential of 14+ chars was
//    silently dropped. Measured: 75 of 75 real tool-result findings.
// A: a canary hit suppressed the regex pass for the same item, so a real leak
//    beside a decoy vanished. Reachable with no tampering, because plant lands
//    in ~/.aws/credentials.bak whenever a real ~/.aws/credentials exists.
//
// B must be fixed first or A cannot be witnessed: with the demoter in place
// every tool-result row reports zero regardless.
//
// No credential-shaped literal is written here: real-looking values come from
// the engine's own fixture generators, and the decoy is read back from a real
// planted registry.
import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { genAwsId } from '../../packages/policy-engine/src/dlp/canary.fixtures';
import { scanArgs } from '../dlp';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
let home: string;
let proj: string;

function run(args: string[]) {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    NODE9_TESTING: '1',
    NODE9_NO_AUTO_DAEMON: '1',
    NO_COLOR: '1',
  };
  delete env.NODE9_API_KEY;
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: 120000,
    cwd: os.tmpdir(),
    env,
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}
/** A transcript line carrying a tool_result. */
const toolResult = (text: string, id = 't1', ts = '2026-09-08T10:00:00Z') =>
  JSON.stringify({
    type: 'user',
    timestamp: ts,
    message: { content: [{ type: 'tool_result', tool_use_id: id, content: text }] },
  });
/** A transcript line carrying a tool_use (an input). */
const toolUse = (input: object, name = 'Bash', ts = '2026-09-08T10:00:00Z') =>
  JSON.stringify({
    type: 'assistant',
    timestamp: ts,
    message: { content: [{ type: 'tool_use', name, input }] },
  });
const transcript = (lines: string[], file = 'sess.jsonl') => {
  fs.mkdirSync(proj, { recursive: true });
  fs.writeFileSync(path.join(proj, file), lines.join('\n') + '\n');
};
const scan = () => {
  const r = run(['scan', '--json', '--days=0']);
  expect([0, 2], r.stderr.slice(0, 300)).toContain(r.status);
  return JSON.parse(r.stdout) as { totals: Record<string, number> };
};
const plantAws = () => {
  const r = run(['canary', 'plant', '--kind', 'aws-profile', '--json']);
  expect(r.status, r.stderr).toBe(0);
  const recs = (
    JSON.parse(fs.readFileSync(path.join(home, '.node9', 'canaries.json'), 'utf-8')) as {
      records: Array<{ kind: string; field: string; value: string; retiredAt?: string }>;
    }
  ).records;
  return recs.find(
    (x) => x.kind === 'aws-profile' && x.field === 'aws_access_key_id' && !x.retiredAt
  )!.value;
};

beforeAll(() => {
  if (!fs.existsSync(CLI)) throw new Error(`build first: ${CLI}`);
});
beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-trdlp-'));
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  proj = path.join(home, '.claude', 'projects', '-demo');
});
afterEach(() => fs.rmSync(home, { recursive: true, force: true }));

describe('T. the tool-result DLP path', () => {
  it('T1 KNOWN-TRUE: a real credential alone in a tool result is reported', () => {
    // The row that failed and exposed bug B. Nothing below means anything
    // until this passes.
    transcript([toolUse({ command: 'cat creds' }), toolResult(genAwsId('tool-result:T1'))]);
    expect(scan().totals.leaks).toBe(1);
  });

  it('T2 maskSecret output really does trip the removed demoter patterns', () => {
    // Why B was invisible: the check was fed the masking, not the secret.
    const m = scanArgs({ text: genAwsId('tool-result:T2') });
    expect(m, 'the engine must match the generated key').not.toBeNull();
    const stars = /(\*)\1{5,}/.test(m!.redactedSample);
    expect(
      stars,
      'the mask emits 6+ repeated characters, which is what demoted every finding'
    ).toBe(true);
  });

  it('T3 a decoy alone: one canary, no leak', () => {
    const decoy = plantAws();
    transcript([toolUse({ command: 'cat creds' }), toolResult(decoy)]);
    const t = scan().totals;
    expect(t.canaries).toBe(1);
    expect(t.leaks).toBe(0);
  });

  it('T4 a real credential AND a decoy in ONE tool result: BOTH reported', () => {
    const decoy = plantAws();
    const real = genAwsId('tool-result:T4');
    expect(real).not.toBe(decoy);
    transcript([toolUse({ command: 'cat ~/.aws/credentials*' }), toolResult(`${real}\n${decoy}`)]);
    const t = scan().totals;
    expect(t.canaries, 'the decoy must still be reported').toBe(1);
    expect(t.leaks, 'the real credential must NOT vanish because a decoy shared the item').toBe(1);
  });

  it('T5 control: the same two in SEPARATE tool results are both reported', () => {
    const decoy = plantAws();
    const real = genAwsId('tool-result:T5');
    transcript([
      toolUse({ command: 'cat a' }),
      toolResult(real, 't1'),
      toolUse({ command: 'cat b' }),
      toolResult(decoy, 't2'),
    ]);
    const t = scan().totals;
    expect(t.canaries).toBe(1);
    expect(t.leaks).toBe(1);
  });

  it('T6 the same, in a tool INPUT: the suppression was at eleven sites, not one', () => {
    const decoy = plantAws();
    const real = genAwsId('tool-result:T6');
    transcript([toolUse({ command: `echo ${real} ${decoy}` })]);
    const t = scan().totals;
    expect(t.canaries).toBe(1);
    expect(t.leaks).toBe(1);
  });

  it('T7 a template value is still suppressed, by the engine stopwords', () => {
    // The case the demoter was written for. The engine's DLP_STOPWORDS do this
    // on the RAW value, where it can actually be done.
    transcript([toolUse({ command: 'cat .env.example' }), toolResult('AKIAEXAMPLEEXAMPLE12')]);
    expect(scan().totals.leaks).toBe(0);
  });

  it('T9 non-regression: neither decoys nor credentials, totals unchanged', () => {
    transcript([toolUse({ command: 'ls -la' }), toolResult('total 8\ndrwxr-xr-x 2 u u 4096 .')]);
    const t = scan().totals;
    expect(t.leaks).toBe(0);
    expect(t.canaries).toBe(0);
  });
});
