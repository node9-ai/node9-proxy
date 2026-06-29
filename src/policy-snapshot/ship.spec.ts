import { describe, it, expect } from 'vitest';
import { policySnapshotUrlFrom } from './ship';

describe('policySnapshotUrlFrom', () => {
  it('derives the snapshot endpoint from the policies/sync base', () => {
    expect(policySnapshotUrlFrom('https://api.node9.ai/api/v1/intercept/policies/sync')).toBe(
      'https://api.node9.ai/api/v1/intercept/policy/snapshot'
    );
  });

  it('returns null for a non-policies/sync base (never POST to a stray URL)', () => {
    expect(policySnapshotUrlFrom('https://api.node9.ai/api/v1/intercept')).toBeNull();
    expect(policySnapshotUrlFrom('')).toBeNull();
  });
});
