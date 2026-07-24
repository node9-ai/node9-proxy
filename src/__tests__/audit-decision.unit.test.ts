import { describe, it, expect } from 'vitest';
import { classifyDecision } from '../audit/decision';

/**
 * Fixtures are the EXACT (decision, checkedBy) pairs present in a real 101k-row
 * audit log, with their live counts — not invented shapes. The bug this covers
 * survived because every reader was self-consistent against synthetic input.
 */
const LIVE_PAIRS: Array<[string | null, string, string, string]> = [
  // decision, checkedBy, expected outcome, expected label
  ['allowed', 'post-hook', 'allow', 'Ran'], //                     37,312
  ['allow', 'local-policy', 'allow', 'Auto-allowed'], //           32,986
  ['allow', 'ignored', 'allow', 'Auto-allowed'], //                 9,948
  ['allow', 'observe-mode-would-block', 'observe', 'Would block'], //5,424
  ['deny', 'timeout', 'deny', 'Timed out'], //                      3,643
  ['deny', 'smart-rule-block', 'deny', 'Blocked'], //               2,885
  ['allow', 'observe-mode', 'observe', 'Would block'], //           2,712
  ['deny', 'app-permission-review', 'deny', 'Blocked'], //          2,649
  ['deny', 'observe-mode-dlp-would-block', 'observe', 'Would block'], // 904
  ['deny', 'persistent-deny', 'deny', 'Blocked'], //                  903
  ['deny', 'app-permission-block', 'deny', 'Blocked'], //             718
  ['deny', 'team-policy', 'deny', 'Blocked'], //                      336
  ['allow', 'daemon', 'allow', 'Approved'], //                        283
  ['allow', 'dlp-review-flagged', 'allow', 'Auto-allowed'], //        171
  ['allow', 'cloud', 'allow', 'Approved'], //                         171
  ['deny', 'dlp-block', 'deny', 'Blocked'], //                         55
  ['deny', 'smart-rule-block-override', 'deny', 'Blocked'], //         38
  ['dlp', 'response-dlp', 'info', 'Finding'], //                       30
  ['deny', 'daemon', 'deny', 'Denied'], //                             16
  ['deny', 'local-decision', 'deny', 'Denied'], //                     15
  ['deny', 'loop-detected', 'deny', 'Blocked'], //                     14
  ['auto-deny', 'daemon', 'deny', 'Denied'], //                        11
  ['mcp-discovered', 'daemon', 'info', 'Info'], //                      5
  ['allowed', 'inline-review-approved', 'allow', 'Approved'], //        1
];

describe('classifyDecision — every pair in a real log', () => {
  for (const [decision, checkedBy, outcome, label] of LIVE_PAIRS) {
    it(`${decision} + ${checkedBy} → ${label}`, () => {
      const v = classifyDecision(decision, checkedBy);
      expect(v.outcome).toBe(outcome);
      expect(v.label).toBe(label);
      expect(v.raw).toBe(String(decision));
    });
  }
});

describe('the two rules that must not be relaxed', () => {
  // THE bug: the reader this replaces had a fall-through `else` of `[allow]`,
  // so anything it didn't recognise reported as permitted — including all
  // 12,176 `deny` rows.
  it('never classifies an unrecognised decision as allow', () => {
    // NB: 'BLOCK' is deliberately absent — it IS a known value (check.ts writes
    // `block`, and matching is case-insensitive), so it must classify as deny.
    for (const raw of ['quarantined', 'escalated', '', 'somethingNew', null, undefined, 42, {}]) {
      const v = classifyDecision(raw, 'whatever');
      expect(v.outcome).not.toBe('allow');
      expect(v.outcome).toBe('unknown');
    }
  });

  it('keeps the raw value visible so nothing is hidden by the mapping', () => {
    expect(classifyDecision('escalated', 'x').label).toContain('escalated');
    expect(classifyDecision('escalated', 'x').raw).toBe('escalated');
  });

  // 3,643 rows. "A human refused this" and "nobody was watching" need
  // completely different responses.
  it('distinguishes a timeout from a human refusal', () => {
    const timedOut = classifyDecision('deny', 'timeout');
    const refused = classifyDecision('deny', 'daemon');
    expect(timedOut.label).toBe('Timed out');
    expect(refused.label).toBe('Denied');
    expect(timedOut.label).not.toBe(refused.label);
    // …but both are still refusals for counting purposes.
    expect(timedOut.outcome).toBe('deny');
    expect(refused.outcome).toBe('deny');
  });
});

describe('shadow mode is not an allow', () => {
  // 9,040 rows: node9 WOULD have blocked these but observe mode let them
  // through. Counting them as plain allows is what made shadow mode invisible.
  it('classifies observe-mode as its own outcome regardless of stored decision', () => {
    // one observe path writes `allow`, another writes `deny` — same concept
    expect(classifyDecision('allow', 'observe-mode-would-block').outcome).toBe('observe');
    expect(classifyDecision('deny', 'observe-mode-dlp-would-block').outcome).toBe('observe');
  });

  it('does not count a would-block as allowed', () => {
    expect(classifyDecision('allow', 'observe-mode').outcome).not.toBe('allow');
  });
});

describe('findings are not verdicts', () => {
  // The CLI used to bucket these as DENY, inventing refusals that never were.
  it('classifies dlp and mcp-discovered as info, not deny', () => {
    expect(classifyDecision('dlp', 'response-dlp').outcome).toBe('info');
    expect(classifyDecision('mcp-discovered', 'daemon').outcome).toBe('info');
  });
});

describe('robustness', () => {
  it('works without a checkedBy at all', () => {
    expect(classifyDecision('deny').label).toBe('Blocked');
    expect(classifyDecision('allow').label).toBe('Auto-allowed');
  });

  it('is case-insensitive on both fields', () => {
    expect(classifyDecision('DENY', 'TIMEOUT').label).toBe('Timed out');
    expect(classifyDecision('Allow', 'DAEMON').label).toBe('Approved');
  });

  // Golden: the distribution over the live pairs. A new producer that invents
  // an eighth spelling changes these counts and fails here, instead of
  // silently reporting as an allow in production.
  it('produces the expected outcome distribution over the live pairs', () => {
    const counts: Record<string, number> = {};
    for (const [d, cb] of LIVE_PAIRS) {
      const o = classifyDecision(d, cb).outcome;
      counts[o] = (counts[o] ?? 0) + 1;
    }
    expect(counts).toEqual({ allow: 7, deny: 12, observe: 3, info: 2 });
    expect(counts.unknown).toBeUndefined();
  });
});

/**
 * The row form exists because the pair form let each caller pick where the
 * second argument came from — and five callers made three different choices.
 * The gate writes `checkedBy`; the PostToolUse hook and the daemon write
 * `source`. Callers that read only `checkedBy` saw `undefined` on 37,576 rows
 * of one real log, so a human APPROVING an action rendered "Auto-allowed" and a
 * human REFUSING one rendered "Blocked".
 */
describe('row form — attribution comes from checkedBy OR source', () => {
  // Shapes taken from the live log, with their real row counts.
  const LIVE_ROWS: Array<[Record<string, unknown>, string, string]> = [
    [{ decision: 'allowed', source: 'post-hook' }, 'allow', 'Ran'],
    [{ decision: 'allow', source: 'daemon' }, 'allow', 'Approved'],
    [{ decision: 'deny', source: 'daemon' }, 'deny', 'Denied'],
    [{ decision: 'auto-deny', source: 'daemon' }, 'deny', 'Denied'],
    [{ decision: 'allowed', source: 'inline-review-approved' }, 'allow', 'Approved'],
    [{ decision: 'deny', source: 'timeout' }, 'deny', 'Timed out'],
  ];

  for (const [row, outcome, label] of LIVE_ROWS) {
    it(`${row.decision}/${row.source} → ${label}`, () => {
      const v = classifyDecision(row);
      expect(v.outcome).toBe(outcome);
      expect(v.label).toBe(label);
    });
  }

  it('a source-only row classifies identically to the same row with checkedBy', () => {
    for (const [row] of LIVE_ROWS) {
      const viaSource = classifyDecision(row);
      const viaCheckedBy = classifyDecision({ decision: row.decision, checkedBy: row.source });
      expect(viaSource).toEqual(viaCheckedBy);
    }
  });

  it('prefers checkedBy when a row carries both', () => {
    expect(
      classifyDecision({ decision: 'deny', checkedBy: 'timeout', source: 'daemon' }).label
    ).toBe('Timed out');
  });

  // A row with neither field must still bucket correctly — the outcome is
  // driven by `decision`, so attribution only ever costs the nuance.
  it('classifies a row with no attribution at all', () => {
    expect(classifyDecision({ decision: 'deny' }).outcome).toBe('deny');
    expect(classifyDecision({ decision: 'allow' }).outcome).toBe('allow');
  });

  // Regression: the row detector used to sniff for decision/checkedBy/source
  // keys. An event row has NONE of them, so it fell through to the legacy
  // branch and the whole object became the decision — the MCP audit reader
  // printed `? [object Object]`. 2 such rows in a real log, unfiltered.
  it('treats a keyless event row as a row, not as a decision value', () => {
    const eventRow = { ts: '2026-05-10T10:00:00Z', event: 'shield-create', shield: 'gmail' };
    const v = classifyDecision(eventRow);
    expect(v.raw).toBe('');
    expect(v.label).not.toContain('[object Object]');
    expect(v.outcome).toBe('unknown'); // never an allow
  });

  // A bare string is NOT a row — it must keep taking the legacy path.
  it('still accepts the legacy (decision, checkedBy) pair', () => {
    expect(classifyDecision('deny', 'timeout').label).toBe('Timed out');
    expect(classifyDecision('allow').label).toBe('Auto-allowed');
  });
});
