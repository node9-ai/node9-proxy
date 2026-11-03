// A canary row must SHIP, and must ship WITHOUT the canary fields.
//
// This file previously asserted the opposite: that buildWireRows forwards
// canaryId and friends. That was wrong, and it was wrong in the way my own
// mock-parity rule warns about. The SaaS AuditBatchRowSchema is `.strict()`
// and declares none of those keys, so the batch 400s; `shipOnce` treats a 400
// like a network error and returns before writeWatermark, which wedges audit
// shipping for that machine permanently: the rows before and after the canary
// row never ship either. The old test asserted only the local half of a
// two-repo contract and so was green while the pipeline was broken.
//
// The attribution is not lost: it stays on the local audit row and in
// `node9 scan`. Cross-repo parity is enforced by wire-schema-parity.spec.ts.
//
// node9Firewall#320 (OWASP report): the BE now declares two canary fields,
// `canary` (a flag) and `canaryKind` (aws-profile, env-file, ssh-key), and
// the shipper resends without them on a 400 from an older server. The five
// fields that locate or identify the decoy (id, hash, path, view, retired)
// still never leave the machine.
import { describe, it, expect } from 'vitest';
import { buildWireRows } from '../daemon/audit-shipper';

/** Fields that identify or locate the decoy: never on the wire. */
const CANARY_KEYS = ['canaryId', 'canaryHash', 'canaryPath', 'canaryView', 'canaryRetired'];

const row = (extra: Record<string, unknown>) =>
  JSON.stringify({
    eid: 'evt-0123456789ab',
    ts: '2026-09-07T00:00:00Z',
    tool: 'Bash',
    argsHash: 'h'.repeat(16),
    decision: 'deny',
    checkedBy: 'dlp-canary-block',
    ...extra,
  }) + '\n';

const CANARY_META = {
  canaryId: 'id-1',
  canaryHash: 'a'.repeat(64),
  canaryKind: 'aws-profile',
  canaryPath: '/home/u/.aws/credentials',
  canaryView: 'raw',
  canaryRetired: true,
  dlpPattern: 'AWS Access Key ID',
};

describe('canary rows on the audit wire', () => {
  it('the row ships, and keeps the fields the BE does declare', () => {
    const { rows } = buildWireRows(Buffer.from(row(CANARY_META)));
    expect(rows, 'the row must not be dropped').toHaveLength(1);
    const w = rows[0] as unknown as Record<string, unknown>;
    expect(w.checkedBy).toBe('dlp-canary-block');
    expect(w.dlpPattern).toBe('AWS Access Key ID');
    expect(w.eid).toBe('evt-0123456789ab');
  });

  it('none of the five identifying canary fields reaches the wire', () => {
    const { rows } = buildWireRows(Buffer.from(row(CANARY_META)));
    const w = rows[0] as unknown as Record<string, unknown>;
    for (const k of CANARY_KEYS) expect(w, `${k} must not leave the machine`).not.toHaveProperty(k);
  });

  it('the decoy hit ships as a flag and its kind only', () => {
    const { rows } = buildWireRows(Buffer.from(row(CANARY_META)));
    const w = rows[0] as unknown as Record<string, unknown>;
    expect(w.canary).toBe(true);
    expect(w.canaryKind).toBe('aws-profile');
    expect(JSON.stringify(w)).not.toContain('.aws/credentials');
  });

  it('and the decoy value could never reach it either', () => {
    const { rows } = buildWireRows(
      Buffer.from(row({ ...CANARY_META, canaryValue: 'should-not-exist' }))
    );
    expect(JSON.stringify(rows).includes('should-not-exist')).toBe(false);
  });

  it('a batch containing a canary row still ships every OTHER row', () => {
    const buf = Buffer.from(row({}) + row(CANARY_META) + row({ checkedBy: 'dlp-block' }));
    const { rows } = buildWireRows(buf);
    expect(rows).toHaveLength(3);
    for (const r of rows) {
      const w = r as unknown as Record<string, unknown>;
      for (const k of CANARY_KEYS) expect(w).not.toHaveProperty(k);
    }
    // Only the decoy row carries the flag.
    expect(rows.map((r) => (r as unknown as Record<string, unknown>).canary)).toEqual([
      undefined,
      true,
      undefined,
    ]);
  });
});
