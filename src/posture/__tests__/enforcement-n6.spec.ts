// N6 — posture's fileRead coverage semantics and fix-string honesty.
//
// History matters here. The first version of this spec certified a policy
// fallthrough that was DEAD at the real gate (evaluatePolicy('Read',…)
// without the orchestrator's arming + skipIgnoredFastPath always answers
// 'allow' — the engine's ignored fast path fires first). The mock hid it
// because it keyed on file_path and discarded the tool argument. That
// fallthrough was reverted; what this spec now pins is:
//
//   1. fileRead coverage is DLP-only, and that UNDER-claims by design
//      (documented limitation: a jail-added path reads as open) — the
//      safe direction until a shared gate resolver exists
//      (doc/n6-f1-fix-plan.md).
//   2. The fix-string rewrite: when project-jail is already applied, the
//      static "enable project-jail" advice is replaced by a jail-add
//      pointer that NEVER carries a file path (ship.ts contract: `fix`
//      ships to the SaaS; detail[], which lists files, never leaves the
//      machine).
//
// Hermetic: config/dlp/agent-wiring are mocked so results are identical
// on the founder's 7-shield machine and a bare CI runner. The REAL-gate
// behavior (what the orchestrator actually blocks) is exercised by the
// jail gauntlet, not here — a mock cannot testify about the gate.
import { describe, it, expect, beforeEach, vi } from 'vitest';

const dlpHits = { current: new Set<string>() };
const applied = { current: [] as string[] };

vi.mock('../../dlp', () => ({
  scanFilePath: (p: string) => (dlpHits.current.has(p) ? { severity: 'block' } : null),
}));
vi.mock('../../config', () => ({
  getConfig: () => ({
    settings: { mode: 'standard' },
    policy: {
      egress: { enabled: false, mode: 'off' },
      appliedShields: applied.current,
    },
  }),
}));
vi.mock('../../agent-wiring', () => ({
  getAgentWiring: () => [{ isProtected: true }],
}));

import path from 'path';
import { annotateCoverage } from '../enforcement';
import type { Finding } from '../types';

const STATIC_FIX =
  'Fix it now: run `node9 shield enable project-jail` (blocks credential-file reads in-path).';

const HOME = path.sep === '\\' ? 'C:\\Users\\u' : '/home/u';
const P = {
  claude: path.join(HOME, '.claude.json'),
  codex: path.join(HOME, '.codex', 'config.toml'),
  aws: path.join(HOME, '.aws', 'credentials'),
};

function fileReadFinding(paths: string[]): Finding {
  return {
    category: 'Secrets',
    severity: 'critical',
    title: 't',
    detail: [],
    fix: STATIC_FIX,
    coverageProbe: { kind: 'fileRead', paths },
  };
}

const CTX = { home: HOME, cwd: HOME };

describe('N6 — fileRead coverage is DLP-only and under-claims by design', () => {
  beforeEach(() => {
    dlpHits.current = new Set();
    applied.current = [];
  });

  it('a DLP-covered file is covered via node9 DLP', async () => {
    dlpHits.current.add(P.aws);
    const f = fileReadFinding([P.aws]);
    await annotateCoverage([f], CTX);
    expect(f.coverage).toEqual({ state: 'covered', level: 'block', via: 'node9 DLP' });
  });

  it('a DLP-silent path is OPEN — even one the policy layer would gate (the documented limitation)', async () => {
    // If this row starts failing because coverage became 'covered', someone
    // re-added a policy consult. That is only correct if it goes through a
    // SHARED gate resolver proven against dist/cli.js check (see the plan
    // doc) — a direct evaluatePolicy call here is the dead code we removed.
    const f = fileReadFinding([P.claude]);
    await annotateCoverage([f], CTX);
    expect(f.coverage?.state).toBe('open');
  });

  it('one gated + one open path → the FINDING is open (any ungated path is the hole)', async () => {
    dlpHits.current.add(P.aws);
    const f = fileReadFinding([P.aws, P.claude]);
    await annotateCoverage([f], CTX);
    expect(f.coverage?.state).toBe('open');
  });
});

describe('N6 — fix-string honesty (the founder bug) + ship privacy contract', () => {
  beforeEach(() => {
    dlpHits.current = new Set();
    applied.current = [];
  });

  it('project-jail applied + uncovered files → fix points at jail add, never re-enables', async () => {
    applied.current = ['project-jail'];
    const f = fileReadFinding([P.claude, P.codex]);
    await annotateCoverage([f], CTX);
    expect(f.coverage?.state).toBe('open');
    expect(f.fix).toContain('node9 jail add');
    expect(f.fix).toContain('already enabled');
    expect(f.fix).not.toContain('shield enable project-jail');
  });

  it('the rewritten fix NEVER carries a file path — fix ships to the SaaS, detail[] does not', async () => {
    applied.current = ['project-jail'];
    const f = fileReadFinding([P.claude, P.codex]);
    await annotateCoverage([f], CTX);
    // No separator-bearing path fragments: not the absolute inputs, no
    // tilde-form, and no home fragment. `<file>` is the only allowed
    // angle-bracket placeholder.
    expect(f.fix).not.toContain(P.claude);
    expect(f.fix).not.toContain(P.codex);
    expect(f.fix).not.toContain('~' + path.sep);
    expect(f.fix).not.toContain(HOME);
    expect(f.fix).not.toContain('.claude.json');
  });

  it('project-jail NOT applied → the static enable advice stands (pre-install machines keep the right CTA)', async () => {
    const f = fileReadFinding([P.claude]);
    await annotateCoverage([f], CTX);
    expect(f.coverage?.state).toBe('open');
    expect(f.fix).toBe(STATIC_FIX);
  });

  it('rewrite only touches findings whose fix actually recommends project-jail', async () => {
    applied.current = ['project-jail'];
    const f = fileReadFinding([P.claude]);
    f.fix = 'Rotate this credential.'; // some other finding style
    await annotateCoverage([f], CTX);
    expect(f.fix).toBe('Rotate this credential.');
  });

  it('covered finding → fix untouched (no rewrite on a green)', async () => {
    applied.current = ['project-jail'];
    dlpHits.current.add(P.aws);
    const f = fileReadFinding([P.aws]);
    await annotateCoverage([f], CTX);
    expect(f.coverage?.state).toBe('covered');
    expect(f.fix).toBe(STATIC_FIX);
  });
});
