// Gap 4 (2026-10-24): CI-2.agent-output-to-env. WRITTEN BEFORE THE TESTS WERE RUN.
// The workflow writes the agent's answer into $GITHUB_ENV or $GITHUB_PATH: every later step of
// the job runs with values the PR or issue author steered (NODE_OPTIONS, BASH_ENV, PATH), which
// is code execution in the job whatever tools the agent holds.

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { analyzeAgentOutputToEnv } from '../ci-check/workflows';
import { agentOutputSinks, commandsOf, logicalLines } from '../ci-check/env-sink';
import { scanTree } from '../ci-check';
import type { Severity } from '../ci-check/types';

const FX = path.join(__dirname, 'fixtures', 'ci-check', 'agent-output-env');
const run = (f: string) =>
  analyzeAgentOutputToEnv(`.github/workflows/${f}`, fs.readFileSync(path.join(FX, f), 'utf8'));
const sev = (f: string): Severity | null => run(f)[0]?.severity ?? null;

describe('gap 4: the agent answer written into the job environment', () => {
  it.each<[string, Severity]>([
    ['file-fixed-heredoc.yml', 'critical'],
    ['var-same-step.yml', 'high'],
    ['action-output-step-env.yml', 'high'],
    ['jq-raw-from-json.yml', 'high'],
    ['tee-to-path.yml', 'medium'],
    ['while-read-lines.yml', 'medium'],
    ['env-named-file.yml', 'medium'],
    ['one-line-no-name.yml', 'medium'],
  ])('%s: %s', (f, want) => {
    expect(sev(f)).toBe(want);
    expect(run(f)[0].rule).toBe('CI-2.agent-output-to-env');
  });

  it('names the sink and what the job holds', () => {
    const s = run('file-fixed-heredoc.yml')[0].signals.join(' ');
    expect(s).toMatch(/written to `\$GITHUB_ENV`/);
    expect(s).toMatch(/write token/);
    expect(run('tee-to-path.yml')[0].title).toMatch(/PATH/);
  });

  it('points at the line that writes it', () => {
    const f = 'var-same-step.yml';
    const line = run(f)[0].line;
    const text = fs.readFileSync(path.join(FX, f), 'utf8').split('\n');
    expect(text[(line ?? 0) - 1]).toMatch(/GITHUB_ENV/);
  });

  it('carries an explanation for the reader', () => {
    const e = run('file-fixed-heredoc.yml')[0].explain;
    expect(e?.headline).toMatch(/run code/);
    expect(e?.fix.join(' ')).toMatch(/strict parser/);
  });

  it('reaches the scan result', () => {
    const content = fs.readFileSync(path.join(FX, 'var-same-step.yml'), 'utf8');
    const r = scanTree({
      source: 'local',
      files: [{ path: '.github/workflows/var-same-step.yml', content }],
      notes: [],
    });
    expect(r.findings.map((f) => f.rule)).toContain('CI-2.agent-output-to-env');
  });
});

describe('gap 4: what stays quiet', () => {
  it.each([
    'safe-tr-fixed-name.yml',
    'safe-jq-compact.yml',
    'safe-numeric.yml',
    'safe-random-delimiter.yml',
    'safe-random-delimiter-lines.yml',
    'safe-unrelated-env.yml',
    'trusted-trigger.yml',
  ])('%s: no finding', (f) => {
    expect(run(f)).toEqual([]);
  });

  it('an actor-gated job: advisory', () => {
    expect(sev('gated-comment.yml')).toBe('advisory');
  });

  it('plain pull_request: advisory', () => {
    expect(sev('plain-pull-request.yml')).toBe('advisory');
  });

  it('a reusable template with no caller in view: medium at most', () => {
    expect(sev('reusable-template.yml')).toBe('medium');
  });
});

describe('gap 4: reading the shell', () => {
  it('joins continued lines and keeps a multi-line quoted prompt in one line', () => {
    expect(logicalLines('a \\\n  b\nclaude -p "x\ny" > f\n# c >> $GITHUB_ENV')).toEqual([
      'a    b',
      'claude -p "x\ny" > f',
    ]);
  });

  it('splits commands outside quotes only', () => {
    expect(commandsOf('a; b && c || d "e; f" 2>&1')).toEqual(['a', ' b ', ' c ', ' d "e; f" 2>&1']);
  });

  it('a write in the last step of a job with no action reaches no later step', () => {
    const steps = [
      { run: 'claude -p "x" > o.txt', agent: 'run' as const },
      { run: 'echo "X=$(cat o.txt)" >> "$GITHUB_ENV"', agent: null },
    ];
    expect(agentOutputSinks(steps, /claude\s+-p/)).toEqual([]);
    expect(agentOutputSinks([...steps, { run: 'next', agent: null }], /claude\s+-p/)).toHaveLength(
      1
    );
  });

  it('a shell heredoc body is read: an unquoted one expands, a quoted one does not', () => {
    const mk = (q: string) => [
      {
        run: 'R=$(claude -p "x")\ncat <<' + q + ' >> "$GITHUB_ENV"\nX=$R\nEOF',
        agent: 'run' as const,
      },
      { run: 'next', agent: null },
    ];
    expect(agentOutputSinks(mk('EOF'), /claude\s+-p/)).toHaveLength(1);
    expect(agentOutputSinks(mk("'EOF'"), /claude\s+-p/)).toEqual([]);
  });

  it('a hostile run block stays fast', () => {
    const big = 'echo "$(('.repeat(20_000) + '\n' + 'x=$y; '.repeat(20_000);
    const t = Date.now();
    agentOutputSinks(
      [
        { run: big, agent: 'run' },
        { run: big, agent: null },
      ],
      /claude\s+-p/
    );
    expect(Date.now() - t).toBeLessThan(3_000);
  });
});
