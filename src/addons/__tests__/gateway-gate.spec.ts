// One card per server at the MCP gateway (node9Firewall#376 item 6, phase 3).
import { describe, it, expect } from 'vitest';
import { AddonSessionGate } from '../gateway-gate';
import type { AddonPolicy } from '../policy';

const list = (p: Partial<AddonPolicy>): AddonPolicy => ({
  unapproved: 'log',
  mcp: {},
  skills: {},
  plugins: {},
  ...p,
});

describe('AddonSessionGate', () => {
  it('asks once: after the person approves, later calls in the session pass', () => {
    const gate = new AddonSessionGate('npm:new');
    const p = list({ unapproved: 'review' });
    const first = gate.verdict(p);
    expect(first.action).toBe('review');
    gate.record(first, true);
    expect(gate.verdict(p)).toEqual({ action: 'allow' });
  });

  it('a denial holds nothing: the next call asks again', () => {
    const gate = new AddonSessionGate('npm:new');
    const p = list({ unapproved: 'review' });
    gate.record(gate.verdict(p), false);
    expect(gate.verdict(p).action).toBe('review');
  });

  it('an approved review never lifts a block the admin sets later', () => {
    const gate = new AddonSessionGate('npm:new');
    gate.record(gate.verdict(list({ unapproved: 'review' })), true);
    expect(gate.verdict(list({ mcp: { 'npm:new': 'blocked' } })).action).toBe('block');
    expect(gate.verdict(list({ unapproved: 'block' })).action).toBe('block');
  });

  it('an allowed call records nothing', () => {
    const gate = new AddonSessionGate('npm:ok');
    gate.record(gate.verdict(list({ mcp: { 'npm:ok': 'approved' } })), true);
    expect(gate.verdict(list({ unapproved: 'review' })).action).toBe('review');
  });
});
