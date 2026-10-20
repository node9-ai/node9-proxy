import { describe, it, expect } from 'vitest';
import {
  abandonedRecord,
  legacyWaitFields,
  parseDecisionRecord,
  personRecord,
  recordFromLegacyWait,
  timerRecord,
  REDIRECT_LABEL,
  type DecisionRecord,
} from '../auth/decision-record';

describe('parseDecisionRecord', () => {
  it('accepts a full record and keeps only known fields', () => {
    const r = parseDecisionRecord({
      ...personRecord('terminal', 'deny', { redirect: 'run npm test first' }, 5),
      extra: 'dropped',
    });
    expect(r).toEqual({
      decision: 'deny',
      decidedBy: 'person',
      channel: 'terminal',
      redirect: 'run npm test first',
      label: REDIRECT_LABEL,
      decidedAt: 5,
    });
  });

  it.each([
    ['not an object', 'x'],
    ['bad decision', { decision: 'maybe', decidedBy: 'timer', label: 'L' }],
    ['bad decider', { decision: 'deny', decidedBy: 'someone', label: 'L' }],
    ['no label', { decision: 'deny', decidedBy: 'timer' }],
    ['a person with no channel', { decision: 'deny', decidedBy: 'person', label: 'L' }],
    [
      'a person on the cloud channel',
      { decision: 'deny', decidedBy: 'person', channel: 'cloud', label: 'L' },
    ],
  ])('rejects %s', (_name, value) => {
    expect(parseDecisionRecord(value)).toBeNull();
  });

  it('bounds long strings', () => {
    const r = parseDecisionRecord({
      decision: 'deny',
      decidedBy: 'policy',
      label: 'x'.repeat(500),
      reason: 'y'.repeat(5000),
    });
    expect(r?.label).toHaveLength(200);
    expect(r?.reason).toHaveLength(2000);
  });
});

describe('legacy /wait fields round trip', () => {
  const cases: Array<[string, DecisionRecord]> = [
    ['tail allow', personRecord('terminal', 'allow', {}, 1)],
    ['native deny', personRecord('native', 'deny', {}, 1)],
    ['redirect', personRecord('terminal', 'deny', { redirect: 'do X instead' }, 1)],
    ['timer', timerRecord(120_000, 1)],
    [
      'cloud deny',
      { decision: 'deny', decidedBy: 'cloud', label: 'Organization Policy (SaaS)', decidedAt: 1 },
    ],
    ['abandoned', abandonedRecord(1)],
  ];
  it.each(cases)('%s keeps who decided', (_n, record) => {
    const back = recordFromLegacyWait(legacyWaitFields(record), 1);
    expect(back?.decision).toBe(record.decidedBy === 'abandoned' ? 'deny' : record.decision);
    expect(back?.decidedBy).toBe(record.decidedBy);
    if (record.redirect) expect(back?.redirect).toBe(record.redirect);
  });

  it('a monitor decision reads as a person in the terminal family for older hooks', () => {
    expect(legacyWaitFields(personRecord('monitor', 'deny'))).toEqual({
      decision: 'deny',
      source: 'terminal',
    });
  });

  it('an older daemon answer with no source names no decider', () => {
    expect(recordFromLegacyWait({ decision: 'deny' })).toBeNull();
  });
});
