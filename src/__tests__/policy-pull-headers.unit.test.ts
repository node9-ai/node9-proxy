// The CLI version has to reach the SaaS on the policy pull.
//
// It cannot ride in a body: GET /intercept/policies/sync has none, and turning
// it into a POST would break every client already in the field. A header
// degrades cleanly instead -- an older CLI simply omits it and the server
// leaves the column untouched.
//
// This is the only per-machine version signal that works. The policy SNAPSHOT
// carries `engineVersion`, but that is fed a hardcoded constant, so every
// machine in the field reports the same string.
import { describe, it, expect } from 'vitest';
import { buildPolicyPullHeaders, safeNode9Version } from '../daemon/sync';

describe('buildPolicyPullHeaders', () => {
  it('reports the CLI version so the SaaS can tell machines apart', () => {
    const h = buildPolicyPullHeaders('n9_live_abc', undefined, '2.11.0');
    expect(h['X-Node9-Version']).toBe('2.11.0');
  });

  it('still carries auth and the conditional-request etag', () => {
    const h = buildPolicyPullHeaders('n9_live_abc', 'etag123', '2.11.0');
    expect(h.Authorization).toBe('Bearer n9_live_abc');
    expect(h['If-None-Match']).toBe('"etag123"');
  });

  it('omits the etag header when there is no cached etag', () => {
    const h = buildPolicyPullHeaders('n9_live_abc', undefined, '2.11.0');
    expect('If-None-Match' in h).toBe(false);
  });

  // Version resolution reads package.json and can fail. A telemetry field must
  // never be able to stop a machine from pulling its security policy, so an
  // unresolved version drops the header rather than sending a junk value.
  it('omits the version header when the version cannot be resolved', () => {
    for (const bad of [undefined, '', 'unknown']) {
      const h = buildPolicyPullHeaders('n9_live_abc', undefined, bad);
      expect('X-Node9-Version' in h).toBe(false);
    }
  });
});

// The tests above inject the version, so they pass whether or not the CLI can
// actually resolve its own version. That gap is not theoretical: the first
// implementation walked up two directories, which is right for src/daemon/ and
// wrong for the bundle, where every file lands in dist/. Exercise the real
// resolver, or the header ships empty to every user.
describe('safeNode9Version', () => {
  it('resolves this package version rather than undefined', () => {
    expect(safeNode9Version()).toMatch(/^\d+\.\d+\.\d+/);
  });

  it('matches the version in package.json', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const pkg = JSON.parse(
      fs.readFileSync(path.join(__dirname, '..', '..', 'package.json'), 'utf-8')
    ) as { version: string };
    expect(safeNode9Version()).toBe(pkg.version);
  });
});
