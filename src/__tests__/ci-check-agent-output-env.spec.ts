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
    ['diff-fetch-api.yml', 'high'],
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

  it('points at the line that writes a block, not the first `{` in the file', () => {
    const f = 'file-fixed-heredoc.yml';
    const line = run(f)[0].line;
    const text = fs.readFileSync(path.join(FX, f), 'utf8').split('\n');
    expect(text[(line ?? 0) - 1]).toMatch(/\} >> "\$GITHUB_ENV"/);
  });

  it('a prompt in a heredoc inside $( ) does not swallow the rest of the script', () => {
    const f = 'diff-fetch-api.yml';
    const r = run(f)[0];
    expect(r.signals[0]).toMatch(/review_summary=\$SUMMARY/);
    const text = fs.readFileSync(path.join(FX, f), 'utf8').split('\n');
    expect(text[(r.line ?? 0) - 1]).toMatch(/review_summary=.*GITHUB_ENV/);
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

describe('gap 4: review fixes (2026-10-24)', () => {
  const cli = /claude\s+-p/;
  const sinks = (steps: Parameters<typeof agentOutputSinks>[0]) =>
    agentOutputSinks([...steps, { run: 'next', agent: null }], cli).length;

  it('a prompt that names jq or tr does not clean the answer', () => {
    expect(
      sinks([
        {
          run: 'R=$(claude -p "Use jq and tr -d to read it")\necho "V=$R" >> $GITHUB_ENV',
          agent: 'run',
        },
      ])
    ).toBe(1);
  });

  it('an inline env assignment is not a fixed name for the written line', () => {
    expect(
      sinks([
        { run: 'claude -p "x" > o.txt', agent: 'run' },
        { run: "LC_ALL=C tr -d '\\n' < o.txt >> $GITHUB_ENV", agent: null },
      ])
    ).toBe(1);
  });

  it('a shell heredoc body line under a fixed name, one-line value: no finding', () => {
    expect(
      sinks([
        { run: 'claude -p "x" > o.txt', agent: 'run' },
        { run: 'V=$(head -n 1 o.txt)\ncat <<EOF >> $GITHUB_ENV\nSUMMARY=$V\nEOF', agent: null },
      ])
    ).toBe(0);
  });

  it('non-text outputs of an agent action are not its answer', () => {
    const write = (out: string) => [
      { id: 'claude', agent: 'action' as const },
      { run: `echo "X=\${{ steps.claude.outputs.${out} }}" >> $GITHUB_ENV`, agent: null },
    ];
    expect(sinks(write('branch_name'))).toBe(0);
    expect(sinks(write('execution_file'))).toBe(0);
    expect(sinks(write('result'))).toBe(1);
  });

  it('a path output read with jq -r is the answer', () => {
    expect(
      sinks([
        { id: 'claude', agent: 'action' },
        {
          run: 'echo "R=$(jq -r \'.[-1].result\' ${{ steps.claude.outputs.execution_file }})" >> $GITHUB_ENV',
          agent: null,
        },
      ])
    ).toBe(1);
  });

  it('a `>` inside a quoted message is not a redirect', () => {
    expect(
      sinks([
        { run: 'R=$(claude -p "x")\necho "score > 5 for $R"', agent: 'run' },
        { run: 'echo "Y=$(cat 5)" >> $GITHUB_ENV', agent: null },
      ])
    ).toBe(0);
  });

  it('a long chain of tainted copies over many steps stays fast', () => {
    const chain = Array.from({ length: 3000 }, (_, i) => `cat f${i} > f${i + 1}`).join('\n');
    const steps = [
      { run: 'claude -p "x" > f0', agent: 'run' as const },
      ...Array.from({ length: 50 }, () => ({ run: chain, agent: null })),
    ];
    const t = Date.now();
    agentOutputSinks(steps, cli);
    expect(Date.now() - t).toBeLessThan(3_000);
  });
});

describe('gap 4: independent review fixes (2026-10-24)', () => {
  const cli = /claude\s+-p/;
  const sinks = (steps: Parameters<typeof agentOutputSinks>[0]) =>
    agentOutputSinks([...steps, { run: 'next', agent: null }], cli).length;
  const agent = (run: string, id?: string) => ({ run, agent: 'run' as const, id });
  const step = (run: string) => ({ run, agent: null });

  it('a block redirected to GITHUB_OUTPUT carries the answer to a later step', () => {
    expect(
      sinks([
        agent(
          'R=$(claude -p "x")\n{\n  echo "summary<<EOF"\n  echo "$R"\n  echo "EOF"\n} >> "$GITHUB_OUTPUT"',
          'ai'
        ),
        step('echo "S=${{ steps.ai.outputs.summary }}" >> $GITHUB_ENV'),
      ])
    ).toBe(1);
  });

  it('a block redirected to a file carries the answer', () => {
    expect(
      sinks([
        agent('R=$(claude -p "x")\n{\n  echo "## Summary"\n  echo "$R"\n} > summary.md'),
        step('{\n  echo "S<<EOF"\n  cat summary.md\n  echo "EOF"\n} >> "$GITHUB_ENV"'),
      ])
    ).toBe(1);
  });

  it('tee inside a substitution writes the answer to its file', () => {
    expect(
      sinks([agent('R=$(claude -p "x" | tee out.txt)'), step('cat out.txt >> $GITHUB_ENV')])
    ).toBe(1);
  });

  it.each([
    ["jq '.result' -r out.json"],
    ["jq --arg k result -r '.[$k]' out.json"],
    ['jq .result --raw-output out.json'],
  ])('raw jq output wherever its flag sits: %s', (jq) => {
    expect(
      sinks([agent('claude -p "x" > out.json'), step(`echo "S=$(${jq})" >> $GITHUB_ENV`)])
    ).toBe(1);
  });

  it.each([
    ['jq -r \'.messages[] | select(.type | contains("final")) | .text\' out.json'],
    ['jq -r \'if (.result | length) > 0 then .result else "none" end\' out.json'],
  ])('a jq filter that only tests inside is not a number: %s', (jq) => {
    expect(
      sinks([agent('claude -p "x" > out.json'), step(`echo "S=$(${jq})" >> $GITHUB_ENV`)])
    ).toBe(1);
  });

  it('a jq filter that ends in a number or a test is quiet', () => {
    for (const jq of ["jq '.items | length' out.json", 'jq -r \'.ok | test("yes")\' out.json'])
      expect(
        sinks([agent('claude -p "x" > out.json'), step(`echo "S=$(${jq})" >> $GITHUB_ENV`)])
      ).toBe(0);
  });

  it('an unquoted expression redirect target does not taint every later expression', () => {
    expect(
      sinks([
        agent('claude -p "x" > ${{ runner.temp }}/out.txt'),
        step('echo "VERSION=${{ github.sha }}" >> $GITHUB_ENV'),
      ])
    ).toBe(0);
    expect(
      sinks([
        agent('claude -p "x" > ${{ runner.temp }}/out.txt'),
        step('cat ${{ runner.temp }}/out.txt >> $GITHUB_ENV'),
      ])
    ).toBe(1);
  });

  it('a path output handed over through the step env, then read', () => {
    expect(
      sinks([
        { id: 'ai', agent: 'action' },
        {
          run: 'R=$(jq -r \'.[-1].result\' "$F")\n{\n  echo "S<<EOF"\n  echo "$R"\n  echo "EOF"\n} >> "$GITHUB_ENV"',
          stepEnv: { F: '${{ steps.ai.outputs.execution_file }}' },
          agent: null,
        },
      ])
    ).toBe(1);
  });

  it.each([
    ['R="${R//$\'\\n\'/ }"\necho "S=$R" >> $GITHUB_ENV'],
    ['echo "S=$(base64 -w0 out.txt)" >> $GITHUB_ENV'],
    ['echo "S=$(sed -n 1p out.txt)" >> $GITHUB_ENV'],
    ['echo "S=$(cat out.txt | xargs)" >> $GITHUB_ENV'],
  ])('newline-free idioms under a fixed name are quiet: %s', (run) => {
    expect(
      sinks([
        agent('claude -p "x" > out.txt\nR=$(cat out.txt)'),
        step(run.replace(/^/, 'R=$(cat out.txt)\n')),
      ])
    ).toBe(0);
  });

  it('a random-delimiter heredoc does not hide a fixed one in the same block', () => {
    expect(
      sinks([
        agent('claude -p "x" > out.txt'),
        step(
          'D=$(openssl rand -hex 8)\n{\n  echo "A<<$D"\n  echo hi\n  echo "$D"\n  echo "B<<EOF"\n  cat out.txt\n  echo EOF\n} >> $GITHUB_ENV'
        ),
      ])
    ).toBe(1);
  });

  it('`cat<<EOF` is a shell heredoc, not a GITHUB_ENV block opener', () => {
    expect(
      sinks([
        agent('claude -p "x" > out.txt'),
        step(
          'cat<<EOF > note.txt\nhello\nEOF\nwhile read -r line; do\n  echo "$line" >> "$GITHUB_ENV"\ndone < out.txt'
        ),
      ])
    ).toBe(1);
  });

  it('crafted while-read lines stay fast', () => {
    const run =
      ('while read a' + ' '.repeat(185) + '= ').repeat(250) +
      '\n' +
      'done < out.txt\n'.repeat(1000);
    const t = Date.now();
    agentOutputSinks(
      [agent('claude -p "x" > out.txt'), ...Array.from({ length: 5 }, () => step(run))],
      cli
    );
    expect(Date.now() - t).toBeLessThan(3_000);
  });
});
