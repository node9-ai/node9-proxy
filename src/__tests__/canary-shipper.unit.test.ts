// The outbox shipper forwards audit-row fields by an explicit whitelist
// (daemon/audit-shipper.ts buildWireRows). A canary row's attribution must
// survive that pick or the SaaS tile never sees it: the same class as the
// recorded piiPatterns gap. Pure over a Buffer; no HOME, no network.
import { describe, it, expect } from 'vitest';
import { buildWireRows } from '../daemon/audit-shipper';

const row = (extra: Record<string, unknown>) =>
  JSON.stringify({
    eid: 'evt-0123456789ab', // the shipper drops eids shorter than 8
    ts: '2026-09-07T00:00:00Z',
    tool: 'Bash',
    argsHash: 'h'.repeat(16),
    decision: 'deny',
    checkedBy: 'dlp-canary-block',
    ...extra,
  }) + '\n';

describe('shipper whitelist carries canary attribution', () => {
  it('canaryId, canaryHash, kind, path, view and retired survive the pick; the row is not skipped', () => {
    const { rows } = buildWireRows(
      Buffer.from(
        row({
          canaryId: 'id-1',
          canaryHash: 'a'.repeat(64),
          canaryKind: 'aws-profile',
          canaryPath: '/home/u/.aws/credentials',
          canaryView: 'raw',
          canaryRetired: true,
          dlpPattern: 'AWS Access Key ID',
        })
      )
    );
    expect(rows).toHaveLength(1);
    const w = rows[0] as unknown as Record<string, unknown>;
    expect(w.checkedBy).toBe('dlp-canary-block');
    expect(w.canaryId).toBe('id-1');
    expect(w.canaryHash).toBe('a'.repeat(64));
    expect(w.canaryKind).toBe('aws-profile');
    expect(w.canaryPath).toBe('/home/u/.aws/credentials');
    expect(w.canaryView).toBe('raw');
    expect(w.canaryRetired).toBe(true);
    expect(w.dlpPattern).toBe('AWS Access Key ID');
  });
  it('a row without canary fields carries none (no fabrication), and retired=false is omitted', () => {
    const { rows } = buildWireRows(
      Buffer.from(row({ canaryId: 'id-2', canaryRetired: false }) + row({}))
    );
    expect(rows).toHaveLength(2);
    const a = rows[0] as unknown as Record<string, unknown>;
    const b = rows[1] as unknown as Record<string, unknown>;
    expect(a.canaryId).toBe('id-2');
    expect(a).not.toHaveProperty('canaryRetired');
    for (const k of [
      'canaryId',
      'canaryHash',
      'canaryKind',
      'canaryPath',
      'canaryView',
      'canaryRetired',
    ])
      expect(b).not.toHaveProperty(k);
  });
});
