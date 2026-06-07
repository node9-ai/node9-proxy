// detectArgsPii — realtime PII detection over tool args (GAP-7).
//
// The PII detector (detectPii) already existed but was only used in the offline
// scan/report path. detectArgsPii adapts it for the realtime authorize path:
// it walks a tool-args value and returns only the HIGH-SIGNAL patterns worth
// gating in real time (SSN, Credit Card). Email/Phone are intentionally
// excluded — they appear constantly in normal dev work (commit author emails,
// configs, fixtures) and would make realtime enforcement too noisy.

import { describe, it, expect } from 'vitest';
import { detectArgsPii, REALTIME_PII_PATTERNS } from './pii';

describe('detectArgsPii — high-signal PII in tool args (GAP-7)', () => {
  it('flags an SSN inside a tool-args object', () => {
    expect(detectArgsPii({ command: 'echo 123-45-6789' })).toContain('SSN');
  });

  it('flags a credit-card number', () => {
    expect(detectArgsPii({ body: 'card 4111 1111 1111 1111' })).toContain('Credit Card');
  });

  it('does NOT flag email or phone (excluded from realtime gating)', () => {
    expect(detectArgsPii({ to: 'alice@example.com', tel: '415-555-1234' })).toEqual([]);
  });

  it('walks nested args', () => {
    expect(detectArgsPii({ outer: { inner: 'ssn is 123-45-6789' } })).toContain('SSN');
  });

  it('accepts a raw string and is safe on null/undefined', () => {
    expect(detectArgsPii('123-45-6789')).toContain('SSN');
    expect(detectArgsPii(null)).toEqual([]);
    expect(detectArgsPii(undefined)).toEqual([]);
  });

  it('REALTIME_PII_PATTERNS is the high-signal subset only', () => {
    expect(REALTIME_PII_PATTERNS).toContain('SSN');
    expect(REALTIME_PII_PATTERNS).toContain('Credit Card');
    expect(REALTIME_PII_PATTERNS).not.toContain('Email');
    expect(REALTIME_PII_PATTERNS).not.toContain('Phone');
  });
});
