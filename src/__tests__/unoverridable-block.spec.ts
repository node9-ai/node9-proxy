// A hard block softens into a review whenever a human approver is reachable.
// That is right for a smart-rule block and wrong for a floor, and the host
// could not tell the two apart: `overridable` was computed in egress/ssrf.ts,
// rendered into the reason sentence, and then dropped at the PolicyVerdict
// boundary.
//
// Measured before the fix, on a workspace-governed desktop:
//
//   node9 explain bash 'curl http://169.254.169.254/latest/meta-data/'
//     -> BLOCK, "This address cannot be allowlisted"
//   node9 check  (same machine, same input)
//     -> ALLOW,  checkedBy: daemon, "User Decision (Native)"
//
// The gate is tested through a pure function for the same reason
// resolveNativeDecision is: the live condition includes `isTestEnv`, which is
// true whenever VITEST / CI / NODE9_TESTING is set. Running under vitest is
// itself the condition that disables the downgrade, so a test driving the real
// path can never observe one. That is why this shipped with the suite green.
import { describe, it, expect } from 'vitest';
import { evaluatePolicy } from '../policy';
import { mayDowngradeHardBlock } from '../auth/orchestrator';

const METADATA = 'curl http://169.254.169.254/latest/meta-data/';

describe('the floor verdict carries its overridability across the seam', () => {
  it('marks the shell SSRF floor un-overridable', async () => {
    const v = await evaluatePolicy('Bash', { command: METADATA }, 'claude');
    expect(v.decision).toBe('block');
    expect(v.ruleName).toContain('ssrf:metadata');
    expect(v.overridable).toBe(false);
  });

  it('marks the declared-destination floor un-overridable', async () => {
    const v = await evaluatePolicy(
      'WebFetch',
      { url: 'http://169.254.169.254/latest/meta-data/' },
      'claude'
    );
    expect(v.decision).toBe('block');
    expect(v.overridable).toBe(false);
  });

  it('leaves an ordinary verdict with no opinion on overridability', async () => {
    const v = await evaluatePolicy('Bash', { command: 'ls -la' }, 'claude');
    expect(v.overridable).toBeUndefined();
  });
});

describe('mayDowngradeHardBlock', () => {
  const reachable = { daemonUp: true, isTestEnv: false, humanApproverReachable: true };

  it('THE BUG: refuses to downgrade an un-overridable block even with a human there', () => {
    expect(mayDowngradeHardBlock({ ...reachable, overridable: false })).toBe(false);
  });

  it('still downgrades an ordinary block when a human is reachable', () => {
    expect(mayDowngradeHardBlock({ ...reachable })).toBe(true);
    expect(mayDowngradeHardBlock({ ...reachable, overridable: true })).toBe(true);
  });

  it('refuses when no human is reachable, whatever the verdict says', () => {
    expect(mayDowngradeHardBlock({ ...reachable, humanApproverReachable: false })).toBe(false);
    expect(mayDowngradeHardBlock({ ...reachable, daemonUp: false })).toBe(false);
    expect(mayDowngradeHardBlock({ ...reachable, isTestEnv: true })).toBe(false);
  });

  it('treats an absent field as "no opinion", not as un-overridable', () => {
    // Every verdict in the codebase predates this field. None of them may
    // change behaviour, so the check is `!== false`, not `=== true`.
    expect(mayDowngradeHardBlock({ ...reachable, overridable: undefined })).toBe(true);
  });

  it('un-overridable wins over every other input', () => {
    for (const daemonUp of [true, false])
      for (const isTestEnv of [true, false])
        for (const humanApproverReachable of [true, false])
          expect(
            mayDowngradeHardBlock({
              daemonUp,
              isTestEnv,
              humanApproverReachable,
              overridable: false,
            })
          ).toBe(false);
  });
});
