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
// `node9 scan`. Putting it on the wire requires the BE schema to land and
// deploy first. Cross-repo parity is enforced by wire-schema-parity.spec.ts.
import { describe, it, expect } from 'vitest';
import { buildWireRows } from '../daemon/audit-shipper';

const CANARY_KEYS = [
  'canaryId',
  'canaryHash',
  'canaryKind',
  'canaryPath',
  'canaryView',
  'canaryRetired',
];

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

  it('none of the six canary fields reaches the wire', () => {
    const { rows } = buildWireRows(Buffer.from(row(CANARY_META)));
    const w = rows[0] as unknown as Record<string, unknown>;
    for (const k of CANARY_KEYS) expect(w, `${k} would 400 the whole batch`).not.toHaveProperty(k);
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
  });
});
