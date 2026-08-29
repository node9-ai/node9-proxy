import { describe, it, expect } from 'vitest';
import { buildPolicySnapshot } from '../policy-snapshot/build';
import { DEFAULT_CONFIG } from '../config';

// Machine identity in the config mirror (login-v2 duplicate-key healing).
// The SaaS binds the reported machineId to a legacy key whose column is NULL —
// so the field must ride every snapshot, and its ABSENCE must leave the body
// byte-compatible with what pre-2.4 servers expect.
describe('buildPolicySnapshot — machine identity', () => {
  it('carries machineId + platform when the caller passes them', () => {
    const body = buildPolicySnapshot(DEFAULT_CONFIG, [], {}, {}, [], undefined, {
      machineId: '55dd7d61-0c92-44e3-a572-926295c83ca5',
      platform: 'win32',
    });
    expect(body.machineId).toBe('55dd7d61-0c92-44e3-a572-926295c83ca5');
    expect(body.platform).toBe('win32');
  });

  it('omits BOTH keys entirely when no identity is passed (old call sites)', () => {
    const body = buildPolicySnapshot(DEFAULT_CONFIG, [], {});
    expect('machineId' in body).toBe(false);
    expect('platform' in body).toBe(false);
  });
});
