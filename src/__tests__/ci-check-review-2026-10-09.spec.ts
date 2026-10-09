// The pre-release independent review of S.1–S.5 (2026-10-09). WRITTEN BEFORE THE FIXES.
// Every fixture is the reviewer's reproduction, run through analyzeWorkflow / gradeBroadGrant.
//
//  1–3 (S.2/S.5): a gate inside an `||` group covered the whole group, a `repo ==` prefix with
//      `&&` hid an ungated `||` branch, and a trusted-event pin was read across a nested group or
//      through `!`. Fixed by parsing the `if:` expression: `||` needs every branch gated, `&&` needs
//      one gated part, `!` is never a gate.
//  4   (S.3/S.4): quadratic regexes on scanned-repo text (a long `uses:`, a long allow entry).
//  5   (S.4): `workflow_run` decided for the whole workflow, not per job.
//  6   (S.4b): `@v0…` was given the benefit of the doubt; every v0 predates v1.0.185.
//  7–8 (S.1): codex's `prompt-file` input, `github.event.number`, a prompt built from
//      `$GITHUB_EVENT_PATH`.
//  9   (S.3): `node --eval`, `python3.12`, a path to the interpreter, `env`, `sudo`, `deno run`;
//      and a 12,000-deep `if:` threw "Maximum call stack size exceeded".

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { analyzeWorkflow } from '../ci-check/workflows';
import { gradeBroadGrant } from '../ci-check/agent-config';
import { SEVERITY_RANK } from '../ci-check/types';

const FX = path.join(__dirname, 'fixtures', 'ci-check', 'review-2026-10-09');
const read = (f: string) => fs.readFileSync(path.join(FX, f), 'utf8');
const rank = (f: string) => {
  const r = analyzeWorkflow(`.github/workflows/${f}`, read(f));
  return r ? SEVERITY_RANK[r.severity] : -1;
};
const MEDIUM = SEVERITY_RANK.medium;
const ADVISORY = SEVERITY_RANK.advisory;

describe('1–3 — the if: expression is parsed, not searched', () => {
  it('1: a gate inside an `||` group does not gate the needs chain', () => {
    expect(rank('b_needs.yml')).toBeGreaterThanOrEqual(MEDIUM);
    expect(rank('b_needs2.yml')).toBeGreaterThanOrEqual(MEDIUM);
  });
  it('2: a `github.repository ==` prefix with `&&` does not hide an ungated branch', () => {
    expect(rank('a_and_prefix.yml')).toBeGreaterThanOrEqual(MEDIUM);
    expect(rank('a_toplevel.yml')).toBeGreaterThanOrEqual(MEDIUM);
  });
  it('3: a trusted-event pin is not read across a nested `||` or through `!`', () => {
    expect(rank('c_nested_pin.yml')).toBeGreaterThanOrEqual(MEDIUM);
    expect(rank('d_negated_pin.yml')).toBeGreaterThanOrEqual(MEDIUM);
  });
  it('an `||` with an ungated issues branch is still ungated', () => {
    expect(rank('e_ok_split.yml')).toBeGreaterThanOrEqual(MEDIUM);
  });
  it('a 12,000-deep if: does not throw', () => {
    expect(() => analyzeWorkflow('.github/workflows/deep.yml', read('deep.yml'))).not.toThrow();
  });
  it('malformed if: values (number, array, object, unbalanced parens) do not throw', () => {
    for (const f of ['m1.yml', 'm2.yml', 'm3.yml'])
      expect(() => analyzeWorkflow(`.github/workflows/${f}`, read(f))).not.toThrow();
  });
});

describe('4 — no quadratic regex on scanned-repo text', () => {
  it('a 40 KB `uses:` value scans in well under a second', () => {
    const t = Date.now();
    analyzeWorkflow('.github/workflows/longuses.yml', read('longuses.yml'));
    expect(Date.now() - t).toBeLessThan(500);
  });
  it('a 60 KB allow entry grades in well under a second', () => {
    const allow = (JSON.parse(read('redos-settings.json')) as { permissions: { allow: string[] } })
      .permissions.allow;
    const t = Date.now();
    gradeBroadGrant(allow, []);
    expect(Date.now() - t).toBeLessThan(500);
  });
});

describe('5 — workflow_run is decided per job', () => {
  it('a job pinned to issue_comment keeps the entity-event gate in a workflow that also has workflow_run', () => {
    expect(rank('fp_mixed.yml')).toBeLessThanOrEqual(ADVISORY);
  });
});

describe('6 — every v0 predates v1.0.185', () => {
  it('@v0.0.63 and @v0 on workflow_run are ungated; @v1 stays gated', () => {
    expect(rank('s4c_v0.0.63.yml')).toBeGreaterThanOrEqual(MEDIUM);
    expect(rank('s4c_v0.yml')).toBeGreaterThanOrEqual(MEDIUM);
    expect(rank('s4c_v1.yml')).toBeLessThanOrEqual(ADVISORY);
  });
});

describe('7–8 — more ways the untrusted item reaches the agent', () => {
  it("codex's `prompt-file` input", () => {
    expect(rank('s1_codex_prompt-file.yml')).toBeGreaterThanOrEqual(MEDIUM);
  });
  it('`github.event.number` as the item handle', () => {
    expect(rank('s1_eventnumber.yml')).toBeGreaterThanOrEqual(MEDIUM);
  });
  it('a prompt file built from $GITHUB_EVENT_PATH', () => {
    expect(rank('s1_eventpath.yml')).toBeGreaterThanOrEqual(MEDIUM);
  });
});

describe('9 — more open-runner grants', () => {
  for (const g of [
    'Bash(node --eval:*)',
    'Bash(python3.12:*)',
    'Bash(/usr/bin/python3:*)',
    'Bash(env:*)',
    'Bash(sudo:*)',
    'Bash(deno run:*)',
  ])
    it(`${g} is broad`, () => {
      expect(gradeBroadGrant([g], [])?.broad).toEqual([g]);
    });
});

describe('A/B regression after the parser (eeea2222/systemd-clean, hand-verified clean)', () => {
  it('a label already on the PR is a gate alternative, like the label of a labeled event', () => {
    expect(rank('label-on-pr.yml')).toBeLessThanOrEqual(ADVISORY);
  });
});
