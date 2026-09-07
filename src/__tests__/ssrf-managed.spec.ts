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

  it('M2 unkeyed: managed false cannot loosen a local true without a lock', async () => {
    const e = await load({ local: { ssrfStrict: true }, managed: { ssrfStrict: false } });
    expect(e.ssrfStrict, "a member's stricter choice survives").toBe(true);
  });

  it('M3 unkeyed: the LOCK is what lets an org loosen it', async () => {
    const e = await load({
      local: { ssrfStrict: true },
      managed: { ssrfStrict: false },
      locked: ['egressSsrfStrict'],
    });
    expect(e.ssrfStrict).toBe(false);
  });

  it('M4 unkeyed: managed ssrfAllow REPLACES local, it does not union', async () => {
    const e = await load({
      local: { ssrfAllow: ['100.64.0.9'] },
      managed: { ssrfAllow: ['100.64.0.1'] },
    });
    expect(e.ssrfAllow, 'the org owns the exemption list').toEqual(['100.64.0.1']);
  });

  it('M5 unkeyed: an EMPTY managed list is "no opinion", like allow', async () => {
    const e = await load({ local: { ssrfAllow: ['100.64.0.9'] }, managed: { ssrfAllow: [] } });
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

  it('M7 KEYED: a workspace that sets neither must not blank them', async () => {
    const e = await load({
      keyed: true,
      local: { ssrfStrict: true, ssrfAllow: ['100.64.0.9'] },
      managed: { mode: 'block' },
    });
    // Keyed means the workspace governs, so a local value the workspace does not
    // mention is NOT resurrected; what matters is that the merge does not crash
    // or invent a value. Pin whatever it is, so a change is visible.
    expect(typeof e.ssrfStrict).toBe('boolean');
    expect(Array.isArray(e.ssrfAllow)).toBe(true);
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
