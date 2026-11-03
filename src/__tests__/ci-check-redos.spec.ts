// L — scans an attacker can stall (design: scanner-gaps-code-design.md §L; 2026-09-27).
//
// WRITTEN BEFORE THE IMPLEMENTATION. `A[^\n]*B` regexes backtrack: every `curl` on a line scans
// to its end and back, so many `curl`s and no `bash` cost quadratic time, and two unbounded
// parts (`curl … && … bash`) cubic — a 64 KB hook line took about 7 minutes. YAML's duplicate-key
// check is quadratic in the number of keys. The fix keeps every answer the same and makes the
// work linear. Two kinds of rows:
//   1. SAMENESS — the new finders give the old regexes' exact answers (index and matched text)
//      on tens of thousands of random lines where the old regexes are still fast; the new YAML parser gives
//      the old one's exact result, error or value.
//   2. SPEED — every crafted shape the sweep found finishes well under a budget that linear code
//      meets in milliseconds. Before §L the cubic shapes took minutes; the quadratic ones took
//      seconds on a 256 KB instruction file (a script's 64 KB cap bounded them there).

import { describe, it, expect } from 'vitest';
import { parse as parseYamlLegacy } from 'yaml';
import { findFetchObey, analyzeInstructionFile } from '../ci-check/instructions';
import { analyzeScript, hasCurlUpload, hasNetcatRead } from '../ci-check/scripts';
import { analyzeSkillGrants } from '../ci-check/agent-config';
import { analyzeWorkflow } from '../ci-check/workflows';
import { parseYamlStrict } from '../ci-check/yaml-strict';

// The regexes as they were (2.24.2 and dev before §L): the specification of the answers.
const LEGACY_FETCH_OBEY =
  /\b(curl|wget|iwr|invoke-webrequest)\b[^\n|]*\|\s*(bash|sh|zsh|python3?(?!\s+-m\s+json\.tool\b)|node|iex)\b|\b(curl|wget)\b[^\n]*&&[^\n]*\b(bash|sh)\b/i;
const LEGACY_CURL_UPLOAD =
  /\bcurl\b[^\n]*\s(?:-d|--data(?:-binary|-raw|-urlencode)?)\s*["']?@|\bcurl\b[^\n]*\s(?:-T|--upload-file)\s+\S/;
const LEGACY_NETCAT = /\b(nc|ncat|netcat)\b[^\n]*<\s*\S/;

// A small deterministic PRNG, so a failure names a reproducible seed.
function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const TOKENS = [
  'curl',
  'CURL',
  'wget',
  'iwr',
  'invoke-webrequest',
  'Invoke-WebRequest',
  'curlx',
  'xcurl',
  'nc',
  'ncat',
  'netcat',
  'ncx',
  '&&',
  '&',
  '&&&',
  '|',
  '||',
  'bash',
  'sh',
  'zsh',
  'Bash',
  'bashx',
  'python',
  'python3',
  'python3 -m json.tool',
  'python -m json.tool',
  'python3 -m  json.tool',
  'node',
  'iex',
  '-m',
  'json.tool',
  '-d',
  '--data',
  '--data-binary',
  '--data-raw',
  '--data-urlencode',
  '--datax',
  '-T',
  '--upload-file',
  '@',
  '"@',
  "'@",
  '<',
  '<<',
  'x',
  'a',
  '-c',
  '"',
  "'",
  '_',
  '.',
  '/',
  '$(',
  ')',
];
const SEPS = [' ', ' ', ' ', '', '  ', '\t', '\n', ' \n '];

// The pieces a match is made of, drawn often, so thousands of samples DO match.
const FOCUSED = [
  'curl',
  'wget',
  'iwr',
  'nc',
  '|',
  '&&',
  'bash',
  'sh',
  'python3',
  '-m json.tool',
  'node',
  'x',
  '-d @',
  '-T',
  '<',
];

const FETCH_FOCUSED = [
  'curl',
  'wget',
  'iwr',
  '|',
  '|',
  '&&',
  'bash',
  'sh',
  'python3',
  '-m json.tool',
  'node',
];

function randomLine(r: () => number, withNewlines: boolean, tokens = TOKENS): string {
  const n = 1 + Math.floor(r() * 14);
  let out = '';
  for (let i = 0; i < n; i++) {
    out += tokens[Math.floor(r() * tokens.length)];
    let sep = SEPS[Math.floor(r() * SEPS.length)];
    if (!withNewlines) sep = sep.replace(/\n/g, ' ');
    out += sep;
  }
  return out;
}

const shape = (m: { index: number; 0: string } | null) => (m ? `${m.index}:${m[0]}` : 'none');

describe('L — the new finders give the old answers', () => {
  it('fetch-and-obey: same index and matched text on 40,000 random texts (with newlines)', () => {
    const r = rng(20260927);
    let matched = 0;
    for (let i = 0; i < 40_000; i++) {
      const text = randomLine(r, true, i % 2 ? TOKENS : FETCH_FOCUSED);
      const legacy = LEGACY_FETCH_OBEY.exec(text);
      if (legacy) matched++;
      expect(shape(findFetchObey(text)), JSON.stringify(text)).toBe(shape(legacy));
    }
    expect(matched).toBeGreaterThan(2_000); // the sample exercises matches, not only misses
  });

  it('curl upload and netcat read: same answer on 20,000 random script lines', () => {
    const r = rng(7);
    let matched = 0;
    for (let i = 0; i < 20_000; i++) {
      // a logical script line has no newline
      const text = randomLine(r, false, i % 2 ? TOKENS : FOCUSED);
      const up = LEGACY_CURL_UPLOAD.test(text);
      const nc = LEGACY_NETCAT.test(text);
      if (up || nc) matched++;
      expect(hasCurlUpload(text), JSON.stringify(text)).toBe(up);
      expect(hasNetcatRead(text), JSON.stringify(text)).toBe(nc);
    }
    expect(matched).toBeGreaterThan(2_000);
  });

  it('YAML: the same value or the same failure as the strict parser, duplicates included', () => {
    const r = rng(99);
    const keys = ['a', 'b', 'on', 'allowed-tools', '"a"', "'a'", '1', '"1"', 'null', '~', 'x y'];
    const values = ['1', 'x', '[a, b]', '{a: 1}', '{a: 1, a: 2}', '"s"', '', '&k v', '*k', 'null'];
    const run = (f: () => unknown) => {
      try {
        return JSON.stringify(f()) ?? 'undefined';
      } catch {
        return 'THROWS';
      }
    };
    for (let i = 0; i < 5_000; i++) {
      const lines: string[] = [];
      const n = 1 + Math.floor(r() * 6);
      for (let j = 0; j < n; j++) {
        const indent = r() < 0.2 && j > 0 ? '  ' : '';
        lines.push(
          `${indent}${keys[Math.floor(r() * keys.length)]}: ${values[Math.floor(r() * values.length)]}`
        );
      }
      const doc = lines.join('\n');
      expect(
        run(() => parseYamlStrict(doc)),
        doc
      ).toBe(run(() => parseYamlLegacy(doc)));
    }
  });
});

describe('L — no crafted input stalls a scan', () => {
  const BUDGET_MS = 2000;
  // CPU time of this test process, not wall-clock time: on a loaded machine
  // (another full suite running alongside) the wait for a CPU counted as scan
  // time, and the 32,000-keys row failed at 2.3 to 5.6 s while its own work was
  // about 0.3 s (design: ci-check-redos-timing-code-design.md, 2026-11-02).
  // vitest runs each test file in its own process, so nothing else is counted.
  const timed = (f: () => unknown) => {
    const t0 = process.cpuUsage();
    f();
    const used = process.cpuUsage(t0);
    return (used.user + used.system) / 1000;
  };
  const fill = (unit: string, bytes: number) => unit.repeat(Math.ceil(bytes / unit.length));

  // cubic before §L: 32 KB took ~50 s
  const CUBIC = ['curl a && ', 'wget && '];
  // quadratic before §L: 256 KB took tens of seconds
  const QUADRATIC = [
    'curl a ',
    'curl | x ',
    'curl -d x ',
    'curl -T ',
    'nc x ',
    'curl | python3 -c "',
  ];

  for (const unit of CUBIC)
    it(`${JSON.stringify(unit)}: a 60 KB hook line and a 32 KB instruction line`, () => {
      expect(
        timed(() => analyzeScript('.claude/hooks/x.sh', fill(unit, 60_000), 'CI-1.hook-script'))
      ).toBeLessThan(BUDGET_MS);
      expect(timed(() => analyzeInstructionFile('CLAUDE.md', fill(unit, 32_768)))).toBeLessThan(
        BUDGET_MS
      );
    });

  for (const unit of QUADRATIC)
    it(`${JSON.stringify(unit)}: a 60 KB hook line and a 256 KB instruction line`, () => {
      expect(
        timed(() => analyzeScript('.claude/hooks/x.sh', fill(unit, 60_000), 'CI-1.hook-script'))
      ).toBeLessThan(BUDGET_MS);
      expect(timed(() => analyzeInstructionFile('CLAUDE.md', fill(unit, 262_144)))).toBeLessThan(
        BUDGET_MS
      );
    });

  const keyLines = (n: number, value: string) =>
    Array.from({ length: n }, (_, i) => `k${i}: ${value}`).join('\n');

  it('a SKILL.md frontmatter and a workflow with 32,000 keys', () => {
    const keys = keyLines(32_000, 'v');
    expect(
      timed(() => analyzeSkillGrants('.claude/skills/x/SKILL.md', `---\n${keys}\n---\n`))
    ).toBeLessThan(BUDGET_MS);
    expect(
      timed(() => analyzeWorkflow('.github/workflows/a.yml', `on: push\n${keys}\n`))
    ).toBeLessThan(BUDGET_MS);
  });

  // The duplicate-key check this row guards against was quadratic: 8 times the
  // keys took about 64 times as long. Linear code takes about 8 times as long
  // (measured 5 to 10, quiet and under load). Both sizes run under the same
  // load, so the ratio does not depend on how busy the machine is. A fresh
  // value per run keeps any cache out of the measurement.
  it('the time for 32,000 keys grows linearly from 4,000 keys', () => {
    const median = (xs: number[]) => [...xs].sort((a, b) => a - b)[1];
    const frontmatter = (n: number, run: number) => `---\n${keyLines(n, `v${run}`)}\n---\n`;
    analyzeSkillGrants('.claude/skills/x/SKILL.md', frontmatter(1_000, -1)); // warm the parser
    const small: number[] = [];
    const large: number[] = [];
    for (const run of [0, 1, 2]) {
      small.push(
        timed(() => analyzeSkillGrants('.claude/skills/x/SKILL.md', frontmatter(4_000, run)))
      );
      large.push(
        timed(() => analyzeSkillGrants('.claude/skills/x/SKILL.md', frontmatter(32_000, run)))
      );
    }
    // A floor of 1 ms keeps a near-zero small run from inflating the ratio.
    expect(median(large) / Math.max(1, median(small))).toBeLessThan(24);
  });
});
