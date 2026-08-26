// N6 — posture's fileRead coverage probe and fix-string honesty.
//
// Two bugs, one evaluation:
// 1. The probe consulted DLP ONLY, but `node9 jail add` creates
//    `block-path-*` policy rules on file_path that DLP knows nothing
//    about — a jail-added file read as "uncovered" forever.
// 2. The static fix said "run `node9 shield enable project-jail`" even
//    when the gate testimony (policy.appliedShields) showed it already
//    enabled — the founder's machine recommended enabling an enabled
//    shield for two files it doesn't even cover.
//
// Fully hermetic: every gate the probe consults is mocked, so results
// do not depend on the machine's real ~/.node9 (the suite must pass
// identically on the founder's 7-shield machine and a bare CI runner).
import { describe, it, expect, beforeEach, vi } from 'vitest';

const dlpHits = { current: new Set<string>() };
const policyVerdicts = { current: new Map<string, { decision: string; ruleName?: string }>() };
const applied = { current: [] as string[] };

vi.mock('../../dlp', () => ({
  scanFilePath: (p: string) => (dlpHits.current.has(p) ? { severity: 'block' } : null),
}));
vi.mock('../../policy', () => ({
  evaluatePolicy: vi.fn(async (_tool: string, args: { file_path?: string }) => {
    return policyVerdicts.current.get(args.file_path ?? '') ?? { decision: 'allow' };
  }),
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

// Platform-native paths: tildePath splits on `home + path.sep` (the same
// boundary rule as displayPath in secrets.ts), so a hardcoded posix HOME
// broke exactly one assertion on the Windows CI legs. Build every path
// with path.join and derive the expected `~`-form with the same sep.
const HOME = path.sep === '\\' ? 'C:\\Users\\u' : '/home/u';
const P = {
  claude: path.join(HOME, '.claude.json'),
  codex: path.join(HOME, '.codex', 'config.toml'),
  aws: path.join(HOME, '.aws', 'credentials'),
};
const TILDE_CLAUDE = '~' + path.sep + '.claude.json';

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

describe('N6 — fileRead probe consults the POLICY gate, not DLP alone', () => {
  beforeEach(() => {
    dlpHits.current = new Set();
    policyVerdicts.current = new Map();
    applied.current = [];
  });

  it('a jail-added file (DLP-silent, policy BLOCK) counts as covered — fails on pre-N6 code', async () => {
    policyVerdicts.current.set(P.claude, {
      decision: 'block',
      ruleName: 'block-path-home-u-claude-json-anytool',
    });
    const f = fileReadFinding([P.claude]);
    await annotateCoverage([f], CTX);
    expect(f.coverage?.state).toBe('covered');
    expect(f.fix).toBe(STATIC_FIX); // covered → no rewrite
  });

  it('a DLP-covered file is still covered via node9 DLP (no regression)', async () => {
    dlpHits.current.add(P.aws);
    const f = fileReadFinding([P.aws]);
    await annotateCoverage([f], CTX);
    expect(f.coverage).toEqual({ state: 'covered', level: 'block', via: 'node9 DLP' });
  });

  it('one gated + one open path → the FINDING is open (any ungated path is the hole)', async () => {
    dlpHits.current.add(P.aws);
    const f = fileReadFinding([P.aws, P.claude]);
    await annotateCoverage([f], CTX);
    expect(f.coverage?.state).toBe('open');
  });
});

describe('N6 — fix-string honesty (the founder bug)', () => {
  beforeEach(() => {
    dlpHits.current = new Set();
    policyVerdicts.current = new Map();
    applied.current = [];
  });

  it('project-jail applied + uncovered file → fix becomes `node9 jail add <path>`, never re-enables', async () => {
    applied.current = ['project-jail'];
    const f = fileReadFinding([P.claude, P.codex]);
    await annotateCoverage([f], CTX);
    expect(f.coverage?.state).toBe('open');
    expect(f.fix).toContain('node9 jail add ' + TILDE_CLAUDE);
    expect(f.fix).toContain('+1 more');
    expect(f.fix).not.toContain('shield enable project-jail');
    expect(f.fix).toContain('already enabled');
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
});
