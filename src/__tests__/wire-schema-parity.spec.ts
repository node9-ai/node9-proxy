// Wire parity: every key buildWireRows can emit must be accepted by the SaaS
// AuditBatchRowSchema, which is `.strict()`.
//
// This exists because the canary work shipped six new fields the BE had never
// heard of. A strict schema turns an unknown key into a 400, `shipOnce` treats
// a 400 like a network error and returns BEFORE writeWatermark, so one such row
// wedges audit shipping for that machine permanently: the rows before and after
// it stop shipping too. The unit test that was supposed to cover this asserted
// only the local half of a two-repo contract, which is exactly the mock-parity
// failure it was meant to prevent.
//
// The BE lives in a sibling checkout. When it is absent this test SKIPS WITH A
// RECORDED REASON rather than passing: a check that could not run is a third
// state, not a green one.
import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { buildWireRows } from '../daemon/audit-shipper';

// Where the BE lives. Not `os.homedir()`: the test setup (isolate-home.ts)
// replaces HOME with an empty temp dir before this file loads, so a
// HOME-relative path never exists and this test skipped on every run without
// anyone noticing (found 2026-11-03, node9Firewall#320). In order: an explicit
// override, the checkout beside this repository (~/node9/node9-proxy or a
// worktree beside it), the real user home from the passwd entry.
const REL = 'be/src/firewall/firewall.controller.ts';
const BE_CANDIDATES = [
  process.env.NODE9_BE_SCHEMA,
  path.resolve(__dirname, '../../../node9Firewall', REL),
  path.join(os.userInfo().homedir, 'node9/node9Firewall', REL),
].filter((p): p is string => !!p);
const BE_SCHEMA = BE_CANDIDATES.find((p) => fs.existsSync(p)) ?? BE_CANDIDATES[0];
const beAvailable = fs.existsSync(BE_SCHEMA);

/** The keys the BE's AuditBatchRowSchema declares, parsed from its source. */
function beAcceptedKeys(): { keys: Set<string>; strict: boolean } {
  const src = fs.readFileSync(BE_SCHEMA, 'utf-8');
  const start = src.indexOf('const AuditBatchRowSchema');
  expect(start, 'AuditBatchRowSchema not found in the BE controller').toBeGreaterThan(-1);
  // The row schema runs up to the next top-level declaration. Not the first
  // `.strict()`: a nested object (`exposure`) has its own, and cutting there
  // hid every key declared after it (found when this test first ran for real).
  const next = src.indexOf('\nconst ', start + 1);
  const block = src.slice(start, next > -1 ? next : undefined);
  // Top-level keys only: the row object's own properties sit at four spaces.
  const keys = new Set([...block.matchAll(/^ {4}([A-Za-z_][A-Za-z0-9_]*)\s*:/gm)].map((m) => m[1]));
  return { keys, strict: /\.strict\(\);\s*$/.test(block.trimEnd()) };
}

/** A row carrying every optional field the local audit writer can produce. */
const MAXIMAL_ROW = {
  eid: 'evt-0123456789ab',
  ts: '2026-09-07T00:00:00Z',
  tool: 'Bash',
  argsHash: 'h'.repeat(16),
  argsPreview: 'redacted preview',
  decision: 'deny',
  checkedBy: 'dlp-block',
  ruleName: 'egress:curl:example.com',
  agent: 'Claude Code',
  mcpServer: 'srv',
  sessionId: 's1',
  dlpPattern: 'AWS Access Key ID',
  dlpSample: 'AKIA****WXYZ',
  cloudRequestId: 'req-1',
  workingDir: '/tmp',
  platform: 'linux',
  shellType: 'bash',
  editFilePath: '/tmp/x.txt',
  loopCount: 3,
  transcriptPath: '/tmp/t.jsonl',
  taintFromEid: 'evt-aaaaaaaaaaaa',
  taintSource: 'DLP:AWS Access Key ID',
  exposure: { kind: 'logged', destinations: 1 },
  exposureFromEid: 'evt-bbbbbbbbbbbb',
  // OWASP report (node9Firewall#320): the check id and a decoy hit.
  checkId: 'data.canary',
  canaryId: 'c-1',
  canaryKind: 'aws-profile',
};

describe('audit wire parity with the SaaS schema', () => {
  it('instrument self-check: buildWireRows emits a row at all', () => {
    const { rows } = buildWireRows(Buffer.from(JSON.stringify(MAXIMAL_ROW) + '\n'));
    expect(rows).toHaveLength(1);
    expect((rows[0] as unknown as Record<string, unknown>).eid).toBe(MAXIMAL_ROW.eid);
  });

  it.skipIf(!beAvailable)('every emitted key is declared by the BE schema', () => {
    const { keys, strict } = beAcceptedKeys();
    expect(keys.size, 'parsed no keys from the BE schema').toBeGreaterThan(5);
    // Self-check the parser on a key everyone agrees on before grading with it.
    expect(keys.has('checkedBy')).toBe(true);
    const { rows } = buildWireRows(Buffer.from(JSON.stringify(MAXIMAL_ROW) + '\n'));
    const emitted = Object.keys(rows[0] as unknown as Record<string, unknown>);
    const unknown = emitted.filter((k) => !keys.has(k));
    expect(
      unknown,
      `these keys would 400 against a ${strict ? 'strict' : 'non-strict'} BE schema`
    ).toEqual([]);
  });

  it.skipIf(!beAvailable)(
    'the canary fields are NOT on the wire while the BE does not declare them',
    () => {
      const { keys } = beAcceptedKeys();
      const canaryKeys = [
        'canaryId',
        'canaryHash',
        'canaryKind',
        'canaryPath',
        'canaryView',
        'canaryRetired',
      ];
      const beKnows = canaryKeys.filter((k) => keys.has(k));
      const { rows } = buildWireRows(
        Buffer.from(
          JSON.stringify({
            ...MAXIMAL_ROW,
            checkedBy: 'dlp-canary-block',
            canaryId: 'c1',
            canaryHash: 'a'.repeat(64),
            canaryKind: 'aws-profile',
            canaryPath: '/home/u/.aws/credentials',
            canaryView: 'raw',
            canaryRetired: true,
          }) + '\n'
        )
      );
      const emitted = Object.keys(rows[0] as unknown as Record<string, unknown>);
      const shipped = canaryKeys.filter((k) => emitted.includes(k));
      // When the BE learns them, this flips: shipped may then be non-empty, but
      // only for the keys the BE actually declares.
      expect(
        shipped.filter((k) => !beKnows.includes(k)),
        'shipping a key the BE rejects wedges the shipper'
      ).toEqual([]);
      // The row itself must still ship, and still carry its checkedBy.
      expect((rows[0] as unknown as Record<string, unknown>).checkedBy).toBe('dlp-canary-block');
    }
  );

  it('records the reason when the BE checkout is absent, instead of passing silently', () => {
    if (beAvailable) return;
    console.warn(
      `[wire-parity] SKIPPED: BE schema not found at ${BE_SCHEMA}. Parity is UNVERIFIED, not verified.`
    );
    expect(beAvailable).toBe(false);
  });
});
