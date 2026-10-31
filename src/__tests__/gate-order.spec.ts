// node9Firewall#405: the hook's stateless gates and their combination with
// the engine verdict live in one module (policy/gate-order.ts) that the hook
// and `node9 explain` both run. These rows pin the order, what stops a call,
// what is carried as a review, and the labels, so a change there is a change
// to both call sites at once.

import { describe, it, expect } from 'vitest';
import type { DlpMatch, ProtectedFileVerdict } from '@node9/policy-engine';
import type { PackageCheckResult } from '../supply-chain/check';
import {
  PRE_ENGINE_GATES,
  GATE_LABELS,
  runStatelessGates,
  combineWithEngine,
  joinPackageReview,
  fileGateOutcome,
  type GateIo,
  type GateSettings,
} from '../policy/gate-order';

const settings = (over: Partial<GateSettings> = {}): GateSettings => ({
  panicMode: false,
  dlp: { enabled: true, reviewAction: 'review', pii: 'block', scanIgnoredTools: true },
  toolIgnored: false,
  ...over,
});

const reviewMatch: DlpMatch = {
  patternName: 'Bearer token',
  fieldPath: 'command',
  redactedSample: 'Bea***',
  severity: 'review',
};
const blockMatch: DlpMatch = { ...reviewMatch, patternName: 'AWS key', severity: 'block' };

const fileReview = {
  decision: 'review',
  reason: 'This file is protected',
  blockedByLabel: 'Node9 Files (Review)',
  ruleName: 'review-system-file',
} as ProtectedFileVerdict;
const fileBlock = {
  ...fileReview,
  decision: 'block',
  ruleName: 'block-read-aws',
} as ProtectedFileVerdict;

const pkgReview: PackageCheckResult = {
  verdict: 'review',
  reason: 'fresh package',
  findings: [],
  misses: [],
  checked: 1,
};
const pkgBlock: PackageCheckResult = { ...pkgReview, verdict: 'block', reason: 'malicious' };
const pkgClean: PackageCheckResult = { verdict: 'allow', findings: [], misses: [], checked: 1 };

function io(over: Partial<GateIo> = {}): GateIo {
  return {
    settings: settings(),
    file: () => null,
    dlp: () => null,
    pii: () => [],
    packageCheck: () => Promise.resolve(pkgClean),
    ...over,
  };
}

describe('the gate order', () => {
  it('is file, DLP, PII, package', () => {
    expect([...PRE_ENGINE_GATES]).toEqual(['file', 'dlp', 'pii', 'package']);
  });

  it('runs every gate in order when nothing stops the call', async () => {
    const r = await runStatelessGates(io());
    expect(r.stop).toBeUndefined();
    expect(r.ran.map((x) => x.gate)).toEqual(['file', 'dlp', 'pii', 'package']);
    expect(r.ran.every((x) => x.outcome === 'pass')).toBe(true);
    expect(r.packageResult).toBe(pkgClean);
  });

  it('a file block stops before DLP runs', async () => {
    let dlpRan = false;
    const r = await runStatelessGates(
      io({
        file: () => fileBlock,
        dlp: () => {
          dlpRan = true;
          return blockMatch;
        },
      })
    );
    expect(r.stop?.gate).toBe('file');
    expect(r.stop?.ruleName).toBe('block-read-aws');
    expect(dlpRan).toBe(false);
    expect(r.ran).toHaveLength(1);
  });

  it('a file review is carried, and stops under panic mode', async () => {
    const carried = await runStatelessGates(io({ file: () => fileReview }));
    expect(carried.stop).toBeUndefined();
    expect(carried.reviews.file).toBe(fileReview);
    const panic = await runStatelessGates(
      io({ settings: settings({ panicMode: true }), file: () => fileReview })
    );
    expect(panic.stop?.gate).toBe('file');
    expect(fileGateOutcome(fileReview, true)).toBe('stop');
  });

  it('a file analysis that throws is held as a review, and the later gates still run', async () => {
    const r = await runStatelessGates(
      io({
        file: () => {
          throw new Error('operand');
        },
      })
    );
    expect(r.stop).toBeUndefined();
    expect(r.reviews.fileIncomplete).toBe(true);
    expect(r.ran.map((x) => x.gate)).toEqual(['file', 'dlp', 'pii', 'package']);
  });

  it('without a file function the gate is recorded as decided by the caller', async () => {
    const r = await runStatelessGates({ ...io(), file: undefined });
    expect(r.ran[0]).toMatchObject({ gate: 'file', outcome: 'skip' });
  });

  it('a block-severity DLP match stops; PII and the package check do not run', async () => {
    let later = 0;
    const r = await runStatelessGates(
      io({
        dlp: () => blockMatch,
        pii: () => {
          later++;
          return ['SSN'];
        },
        packageCheck: () => {
          later++;
          return Promise.resolve(pkgBlock);
        },
      })
    );
    expect(r.stop).toMatchObject({
      gate: 'dlp',
      label: GATE_LABELS.dlpBlock,
      dlpMatch: blockMatch,
    });
    expect(r.stop?.reason).toContain('DATA LOSS PREVENTION: AWS key');
    expect(later).toBe(0);
  });

  it("reviewAction 'block' turns a review-severity match into a stop", async () => {
    const r = await runStatelessGates(
      io({
        settings: settings({ dlp: { enabled: true, reviewAction: 'block', pii: 'off' } }),
        dlp: () => reviewMatch,
      })
    );
    expect(r.stop?.gate).toBe('dlp');
  });

  it('a review-severity DLP match is carried with the DLP review label', async () => {
    const r = await runStatelessGates(io({ dlp: () => reviewMatch }));
    expect(r.stop).toBeUndefined();
    expect(r.reviews.dlp).toBe(reviewMatch);
    expect(r.label).toBe(GATE_LABELS.dlpReview);
  });

  it('DLP is skipped for an ignored tool when scanIgnoredTools is off, PII too', async () => {
    const r = await runStatelessGates(
      io({
        settings: settings({
          toolIgnored: true,
          dlp: { enabled: true, pii: 'block', scanIgnoredTools: false },
        }),
        dlp: () => blockMatch,
        pii: () => ['SSN'],
      })
    );
    expect(r.stop).toBeUndefined();
    expect(r.ran.filter((x) => x.outcome === 'skip').map((x) => x.gate)).toEqual(['dlp', 'pii']);
  });

  it('PII stops with its label, after DLP and before the package check', async () => {
    let pkgRan = false;
    const r = await runStatelessGates(
      io({
        dlp: () => reviewMatch,
        pii: () => ['SSN', 'Credit Card'],
        packageCheck: () => {
          pkgRan = true;
          return Promise.resolve(pkgBlock);
        },
      })
    );
    expect(r.stop).toMatchObject({
      gate: 'pii',
      label: GATE_LABELS.pii,
      pii: ['SSN', 'Credit Card'],
    });
    expect(r.stop?.reason).toContain('SSN, Credit Card');
    expect(r.reviews.dlp).toBe(reviewMatch);
    expect(pkgRan).toBe(false);
  });

  it("PII does not run unless dlp.pii is 'block'", async () => {
    const r = await runStatelessGates(
      io({ settings: settings({ dlp: { enabled: true, pii: 'off' } }), pii: () => ['SSN'] })
    );
    expect(r.stop).toBeUndefined();
    expect(r.ran.find((x) => x.gate === 'pii')?.outcome).toBe('skip');
  });

  it('a package block stops with the malicious label and the reason as rule text', async () => {
    const r = await runStatelessGates(io({ packageCheck: () => Promise.resolve(pkgBlock) }));
    expect(r.stop).toMatchObject({
      gate: 'package',
      label: GATE_LABELS.packageBlock,
      reason: 'malicious',
      ruleDescription: 'malicious',
      pkg: pkgBlock,
    });
  });

  it('a package review is carried; its label yields to a DLP review label', async () => {
    const alone = await runStatelessGates(io({ packageCheck: () => Promise.resolve(pkgReview) }));
    expect(alone.reviews.package).toBe(pkgReview);
    expect(alone.label).toBe(GATE_LABELS.packageReview);
    const withDlp = await runStatelessGates(
      io({ dlp: () => reviewMatch, packageCheck: () => Promise.resolve(pkgReview) })
    );
    expect(withDlp.label).toBe(GATE_LABELS.dlpReview);
    expect(withDlp.reviews.package).toBe(pkgReview);
  });

  it('a package result without a reason is not a stop or a review', async () => {
    const r = await runStatelessGates(
      io({ packageCheck: () => Promise.resolve({ ...pkgBlock, reason: undefined }) })
    );
    expect(r.stop).toBeUndefined();
    expect(r.reviews.package).toBeUndefined();
  });

  it('a null package result is a skip', async () => {
    const r = await runStatelessGates(io({ packageCheck: () => Promise.resolve(null) }));
    expect(r.ran.find((x) => x.gate === 'package')?.outcome).toBe('skip');
    expect(r.packageResult).toBeUndefined();
  });
});

describe('the engine stage', () => {
  const none = { reviews: {}, ran: [] };

  it('an engine allow with no review is an allow', () => {
    expect(combineWithEngine(none, { decision: 'allow' }).decision).toBe('allow');
  });

  it('an engine allow becomes a review under a gate review, with the gate label', () => {
    const gates = { reviews: { package: pkgReview }, ran: [], label: GATE_LABELS.packageReview };
    const r = combineWithEngine(gates, { decision: 'allow' });
    expect(r).toMatchObject({
      decision: 'review',
      blockedByLabel: GATE_LABELS.packageReview,
      ruleDescription: 'fresh package',
    });
  });

  it("an engine allow becomes a review under the caller's own flags (taint, exposure)", () => {
    const r = combineWithEngine(
      none,
      { decision: 'allow' },
      { panicMode: false, otherReviews: true }
    );
    expect(r.decision).toBe('review');
  });

  it('an engine block wins over every review', () => {
    const gates = { reviews: { package: pkgReview, dlp: reviewMatch }, ran: [] };
    const r = combineWithEngine(gates, {
      decision: 'block',
      blockedByLabel: 'Smart Rule: x',
      ruleDescription: 'x',
    });
    expect(r).toMatchObject({
      decision: 'block',
      blockedByLabel: 'Smart Rule: x',
      ruleDescription: 'x',
    });
  });

  it('an engine review keeps its label and gains the package text', () => {
    const gates = { reviews: { package: pkgReview }, ran: [], label: GATE_LABELS.packageReview };
    const r = combineWithEngine(gates, {
      decision: 'review',
      blockedByLabel: 'Smart Rule: review-force-push',
      ruleDescription: 'A force push rewrites history',
    });
    expect(r.blockedByLabel).toBe('Smart Rule: review-force-push');
    expect(r.ruleDescription).toBe('A force push rewrites history\nfresh package');
  });

  it('panic mode turns an engine review into a block, and leaves an allow alone', () => {
    const panicked = combineWithEngine(none, { decision: 'review' }, { panicMode: true });
    expect(panicked).toMatchObject({ decision: 'block', panicked: true });
    expect(panicked.blockedByLabel).toContain('Panic mode');
    expect(combineWithEngine(none, { decision: 'allow' }, { panicMode: true }).decision).toBe(
      'allow'
    );
  });

  it('joinPackageReview replaces an empty or package-labelled description and appends otherwise', () => {
    expect(joinPackageReview(undefined, undefined, 'p')).toBe('p');
    expect(joinPackageReview('old', GATE_LABELS.packageReview, 'p')).toBe('p');
    expect(joinPackageReview('old', 'Smart Rule: x', 'p')).toBe('old\np');
  });
});
