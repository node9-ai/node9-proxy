// The SSRF knobs must be settable from the dashboard, not only from the local
// file that a managed machine ignores.
// Mapping and design: doc/roadmap/active/ssrf-managed-plumbing-design.md
//
// Two merge paths, both must be covered: `keyed` takes the workspace value
// verbatim (no ratchet, no locks); unkeyed goes through applyManagedEgress with
// per-field ratchet semantics. A change touching one path is half a change.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

type Egress = Record<string, unknown>;
let home: string;

async function load(opts: {
  local?: Egress;
  managed?: Egress;
  locked?: string[];
  keyed?: boolean;
}) {
  fs.writeFileSync(
    path.join(home, '.node9', 'config.json'),
    JSON.stringify({
      settings: { mode: 'standard' },
      policy: opts.local ? { egress: opts.local } : {},
    })
  );
  if (opts.managed || opts.locked) {
    fs.writeFileSync(
      path.join(home, '.node9', 'rules-cache.json'),
      JSON.stringify({
        managedConfig: {
          ...(opts.managed ? { egress: opts.managed } : {}),
          ...(opts.locked ? { locked: opts.locked } : {}),
        },
        fetchedAt: '2026-09-08T00:00:00Z',
      })
    );
  }
  if (opts.keyed) {
    fs.writeFileSync(
      path.join(home, '.node9', 'credentials.json'),
      JSON.stringify({
        default: { apiKey: 'k-not-real', apiUrl: 'https://api.node9.ai/api/v1/intercept' },
      })
    );
  }
  vi.resetModules();
  const core = await import('../core.js');
  core._resetConfigCache();
  return core.getConfig().policy.egress as Record<string, unknown>;
}

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-mgd-'));
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  vi.spyOn(os, 'homedir').mockReturnValue(home);
});
afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
  vi.restoreAllMocks();
});

describe('M. managed control of the SSRF knobs', () => {
  it('M10 known-true: the five existing egress fields still merge as before', async () => {
    const e = await load({
      local: {
        enabled: false,
        mode: 'review',
        allow: ['local.example'],
        deny: ['bad.example'],
        allowPrivate: true,
      },
      managed: {
        enabled: true,
        mode: 'block',
        allow: ['org.example'],
        deny: ['worse.example'],
        allowPrivate: false,
      },
    });
    expect(e.enabled, 'force-on').toBe(true);
    expect(e.mode, 'ordered floor').toBe('block');
    expect(e.allow, 'managed replaces').toEqual(['org.example']);
    expect(e.deny, 'union').toEqual(expect.arrayContaining(['bad.example', 'worse.example']));
    expect(e.allowPrivate, 'floor boolean').toBe(false);
  });

  it('M1 unkeyed: managed ssrfStrict true, local unset', async () => {
    const e = await load({ managed: { ssrfStrict: true } });
    expect(e.ssrfStrict).toBe(true);
  });

  it('M2 unkeyed: a managed false REPLACES a local true, with no lock', async () => {
    // Founder call 2026-09-08, after review: the lock is gone. It was
    // unreachable anyway — the backend 400s a `locked` key in the PUT body and
    // no write path ever set the column, so `lockIf('egressSsrfStrict')` was
    // dead code and the dashboard's "off" could not turn the tier off. Under
    // ONE-config the workspace value simply governs.
    const e = await load({ local: { ssrfStrict: true }, managed: { ssrfStrict: false } });
    expect(e.ssrfStrict, 'the dashboard can turn it off').toBe(false);
  });

  it('M3 unkeyed: a managed true REPLACES a local false, same rule both ways', async () => {
    const e = await load({ local: { ssrfStrict: false }, managed: { ssrfStrict: true } });
    expect(e.ssrfStrict).toBe(true);
  });

  it('M3b unkeyed: a workspace that says nothing leaves the local value alone', async () => {
    const e = await load({ local: { ssrfStrict: true }, managed: { mode: 'block' } });
    expect(e.ssrfStrict).toBe(true);
  });

  it('M4 unkeyed: managed ssrfAllow REPLACES local, it does not union', async () => {
    const e = await load({
      local: { ssrfAllow: ['100.64.0.9'] },
      managed: { ssrfAllow: ['100.64.0.1'] },
    });
    expect(e.ssrfAllow, 'the org owns the exemption list').toEqual(['100.64.0.1']);
  });

  it('M5 unkeyed: an EMPTY managed list CLEARS the device exemptions', async () => {
    // Founder call 2026-09-08. `allow` treats empty as "no opinion", but this
    // list is the floor: an admin who removes the last exemption in the
    // dashboard means "no address is exempt any more", and the old semantics
    // left the hole open on every machine forever with no way to close it.
    const e = await load({ local: { ssrfAllow: ['100.64.0.9'] }, managed: { ssrfAllow: [] } });
    expect(e.ssrfAllow, 'the org can revoke').toEqual([]);
  });

  it('M5b unkeyed: an ABSENT list still leaves the local one alone', async () => {
    // Absent and empty must stay distinguishable, or a workspace that never
    // touched the floor would wipe a member's exemption.
    const e = await load({ local: { ssrfAllow: ['100.64.0.9'] }, managed: { mode: 'block' } });
    expect(e.ssrfAllow).toEqual(['100.64.0.9']);
  });

  it('M6 KEYED: both applied verbatim, no ratchet', async () => {
    const e = await load({
      keyed: true,
      local: { ssrfStrict: true, ssrfAllow: ['100.64.0.9'] },
      managed: { ssrfStrict: false, ssrfAllow: ['100.64.0.1'] },
    });
    expect(e.ssrfStrict, 'keyed takes the workspace value as-is').toBe(false);
    expect(e.ssrfAllow).toEqual(['100.64.0.1']);
  });

  it('M6b KEYED: the value must come FROM the workspace, not from the default', async () => {
    // M6 alone is a weak witness: keyed already discards local, and `false` is
    // also the default, so dropping the keyed assignment entirely still passes
    // it (proven by mutation). This row disagrees with the default.
    const e = await load({ keyed: true, managed: { ssrfStrict: true } });
    expect(e.ssrfStrict).toBe(true);
  });

  it('M7 KEYED: a workspace that sets neither leaves the DEFAULTS, not the local values', async () => {
    // The old M7 could not fail: it asserted `typeof … === 'boolean'` and
    // `Array.isArray`, both guaranteed by the merge's own initialisation for
    // every input on every path, and its title claimed the local values
    // survive. They do not: a keyed machine drops the whole local policy layer
    // (config/index.ts, `if (keyed && !isCloud) return`), so what a workspace
    // does not set falls back to the shipped default.
    const e = await load({
      keyed: true,
      local: { ssrfStrict: true, ssrfAllow: ['100.64.0.9'] },
      managed: { mode: 'block' },
    });
    expect(e.ssrfStrict, 'the shipped default, not the local true').toBe(false);
    expect(e.ssrfAllow, 'the shipped default, not the local list').toEqual([]);
  });

  it('M7b KEYED: junk in a hand-edited cache is rejected per field', async () => {
    // The keyed branch has its own type validation, and M9 only exercised the
    // unkeyed one: dropping the keyed guard stayed green because managed.ts
    // re-guards the same field one layer down.
    const e = await load({
      keyed: true,
      managed: { ssrfStrict: 'yes', ssrfAllow: [1, {}] } as never,
    });
    expect(e.ssrfStrict).toBe(false);
    expect(e.ssrfAllow).toEqual([]);
  });

  it('M8 the org CANNOT exempt a tier-1 address, on either path', async () => {
    // The dashboard is a widening surface, but the metadata endpoint is the one
    // thing the floor exists to stop. Same filter as the local file.
    const unkeyed = await load({ managed: { ssrfAllow: ['169.254.169.254', '100.64.0.1'] } });
    expect(unkeyed.ssrfAllow).toEqual(['100.64.0.1']);
    const keyed = await load({
      keyed: true,
      managed: { ssrfAllow: ['169.254.169.254', '100.64.0.1'] },
    });
    expect(keyed.ssrfAllow).toEqual(['100.64.0.1']);
  });

  it('M9 garbage types are ignored, no throw, defaults kept', async () => {
    const e = await load({ managed: { ssrfStrict: 'yes', ssrfAllow: [1, 2, {}] } as Egress });
    expect(e.ssrfStrict).toBe(false);
    expect(e.ssrfAllow).toEqual([]);
  });
});
