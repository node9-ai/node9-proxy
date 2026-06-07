// Outbox shipper — delivery-guarantee tests.
// The contract under test: a row written to the local logbook WILL reach the
// SaaS exactly once (at-least-once delivery + eid dedup server-side), no
// matter how the shipper fails between ticks.
import { describe, it, expect, beforeEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  buildWireRows,
  shipOnce,
  readWatermark,
  shipLagBytes,
  buildBatchEndpoint,
} from '../daemon/audit-shipper';
import { generateEventId, buildArgsPreview } from '../audit';

const CREDS = { apiKey: 'n9_live_test', apiUrl: 'https://api.example.com/api/v1/intercept' };

function row(over: Record<string, unknown> = {}): string {
  return (
    JSON.stringify({
      eid: generateEventId(),
      ts: '2026-06-07T10:00:00.000Z',
      tool: 'Bash',
      args: { command: 'ls' },
      decision: 'allow',
      checkedBy: 'local-policy',
      agent: 'Claude Code',
      hostname: 'test-host',
      ...over,
    }) + '\n'
  );
}

function makeFetch(failTimes = 0) {
  const calls: Array<{ url: string; rows: unknown[] }> = [];
  let fails = failTimes;
  const impl = (async (url: unknown, init?: { body?: unknown }) => {
    if (fails > 0) {
      fails--;
      throw new Error('network down');
    }
    calls.push({
      url: String(url),
      rows: (JSON.parse(String(init?.body)) as { rows: unknown[] }).rows,
    });
    return { ok: true, status: 200 } as Response;
  }) as typeof fetch;
  return { impl, calls };
}

describe('buildWireRows', () => {
  it('parses complete lines only — a torn tail line waits for the writer', () => {
    const full = row() + row();
    const torn = '{"eid":"truncated-no-newline","ts":"2026';
    const { rows, consumed } = buildWireRows(Buffer.from(full + torn));
    expect(rows).toHaveLength(2);
    expect(consumed).toBe(Buffer.byteLength(full));
  });

  it('skips rows the SaaS must not receive', () => {
    const content =
      row() + // ships
      row({ eid: undefined }) + // pre-shipper history: no eid
      row({ testRun: true }) + // test noise
      row({ checkedBy: 'ignored' }) + // read/grep noise — never synced
      row({ checkedBy: 'cloud' }) + // legacy: no cloudRequestId → BE row can't be linked
      row({ ts: undefined }) + // malformed: no event time — skip, don't fabricate
      'not-json at all\n'; // corrupt line must not wedge the shipper
    const { rows } = buildWireRows(Buffer.from(content));
    expect(rows).toHaveLength(1);
    expect(rows[0].checkedBy).toBe('local-policy');
  });

  it('ships cloud-linked rows WITH cloudRequestId so the BE enriches its origin row', () => {
    // Any request that opened a pending cloud entry already has a BE-origin
    // AuditLog row. Shipping the local row with its cloudRequestId lets the
    // BE ENRICH that row (set clientEventId) instead of inserting a
    // duplicate — regardless of which racer ultimately decided:
    const content =
      row({ checkedBy: 'cloud', cloudRequestId: 'req-cloud-won' }) + // cloud resolved it
      row({ checkedBy: 'native', cloudRequestId: 'req-local-won' }); // native popup won the race
    const { rows } = buildWireRows(Buffer.from(content));
    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({
      checkedBy: 'cloud',
      cloudRequestId: 'req-cloud-won',
    });
    expect(rows[1]).toMatchObject({
      checkedBy: 'native',
      cloudRequestId: 'req-local-won',
    });
  });

  it('carries attribution: ruleName, dlp pattern + sample, argsHash', () => {
    const content = row({
      args: undefined,
      argsHash: 'h123',
      decision: 'deny',
      checkedBy: 'dlp-block',
      ruleName: 'shield:x',
      dlpPattern: 'GitHub Token',
      dlpSample: 'ghp_****',
    });
    const { rows } = buildWireRows(Buffer.from(content));
    expect(rows[0]).toMatchObject({
      argsHash: 'h123',
      decision: 'deny',
      checkedBy: 'dlp-block',
      ruleName: 'shield:x',
      dlpPattern: 'GitHub Token',
      dlpSample: 'ghp_****',
    });
    expect(rows[0].args).toBeUndefined();
  });

  it('carries the redacted preview for hash-mode rows (dashboard readability)', () => {
    const content = row({
      args: undefined,
      argsHash: 'h456',
      argsPreview: 'npm run build',
    });
    const { rows } = buildWireRows(Buffer.from(content));
    expect(rows[0]).toMatchObject({ argsHash: 'h456', argsPreview: 'npm run build' });
  });
});

describe('buildBatchEndpoint', () => {
  it('builds the batch URL from the raw intercept base', () => {
    expect(buildBatchEndpoint('https://api.node9.ai/api/v1/intercept')).toBe(
      'https://api.node9.ai/api/v1/intercept/audit/batch'
    );
  });

  it('strips the /policies/sync suffix readCredentials() appends for the sync route', () => {
    // REGRESSION: the shipper reuses sync.ts readCredentials(), which
    // rewrites the stored apiUrl to its OWN route (…/intercept →
    // …/intercept/policies/sync). The first release shipped to
    // …/policies/sync/audit/batch and 404'd on every tick — found live on
    // the founder's machine; unit tests missed it because deps.creds was
    // always injected.
    expect(buildBatchEndpoint('https://api.node9.ai/api/v1/intercept/policies/sync')).toBe(
      'https://api.node9.ai/api/v1/intercept/audit/batch'
    );
  });

  it('returns null for invalid/unsafe URLs', () => {
    expect(buildBatchEndpoint('http://evil.example.com/intercept')).toBeNull();
    expect(buildBatchEndpoint('not a url')).toBeNull();
  });
});

describe('buildArgsPreview', () => {
  it('prefers the primary field and redacts secrets', () => {
    expect(buildArgsPreview({ command: 'npm test' })).toBe('npm test');
    expect(buildArgsPreview({ file_path: '/tmp/a.txt' })).toBe('/tmp/a.txt');
    expect(
      buildArgsPreview({ command: 'curl -H "authorization: bearer abc123def456" https://x' })
    ).toContain('********');
  });

  it('caps the preview at 120 chars', () => {
    expect(buildArgsPreview({ command: 'x'.repeat(500) })?.length).toBe(120);
  });
});

describe('shipOnce', () => {
  let dir: string;
  let auditLogPath: string;
  let watermarkPath: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-ship-'));
    auditLogPath = path.join(dir, 'audit.log');
    watermarkPath = path.join(dir, 'audit-ship.json');
  });

  const deps = (fetchImpl: typeof fetch) => ({
    auditLogPath,
    watermarkPath,
    fetchImpl,
    cloudEnabled: true,
    creds: CREDS,
  });

  it('ships the backlog to /audit/batch and advances the watermark', async () => {
    fs.writeFileSync(auditLogPath, row() + row() + row());
    const { impl, calls } = makeFetch();

    const res = await shipOnce(deps(impl));

    expect(res).toEqual({ status: 'shipped', shipped: 3 });
    expect(calls[0].url).toBe('https://api.example.com/api/v1/intercept/audit/batch');
    expect(calls[0].rows).toHaveLength(3);
    const wm = readWatermark(watermarkPath);
    expect(wm?.offset).toBe(fs.statSync(auditLogPath).size);
    expect(shipLagBytes(auditLogPath, watermarkPath)).toBe(0);
  });

  it('is incremental: a second pass ships only new rows', async () => {
    fs.writeFileSync(auditLogPath, row());
    const { impl, calls } = makeFetch();
    await shipOnce(deps(impl));

    fs.appendFileSync(auditLogPath, row({ checkedBy: 'loop-detected', decision: 'deny' }));
    const res = await shipOnce(deps(impl));

    expect(res.shipped).toBe(1);
    expect(calls[1].rows).toHaveLength(1);
    expect((calls[1].rows[0] as { checkedBy: string }).checkedBy).toBe('loop-detected');
  });

  it('does NOT advance the watermark on failure — rows re-ship on recovery (nothing lost)', async () => {
    fs.writeFileSync(auditLogPath, row() + row());
    const failing = makeFetch(99);

    const res = await shipOnce(deps(failing.impl));
    expect(res.status).toBe('error');
    expect(readWatermark(watermarkPath)).toBeNull();

    const ok = makeFetch();
    const retry = await shipOnce(deps(ok.impl));
    expect(retry).toEqual({ status: 'shipped', shipped: 2 });
  });

  it('detects rotation (file signature change) and re-ships from the top', async () => {
    fs.writeFileSync(auditLogPath, row());
    const { impl, calls } = makeFetch();
    await shipOnce(deps(impl));

    // Rotation: a brand-new file with different first bytes.
    fs.writeFileSync(auditLogPath, row({ checkedBy: 'smart-rule-block', decision: 'deny' }));
    const res = await shipOnce(deps(impl));

    expect(res.shipped).toBe(1);
    expect((calls[1].rows[0] as { checkedBy: string }).checkedBy).toBe('smart-rule-block');
  });

  it('respects the gates: shipper disabled / not logged in', async () => {
    fs.writeFileSync(auditLogPath, row());
    const { impl, calls } = makeFetch();

    expect(await shipOnce({ ...deps(impl), cloudEnabled: false })).toEqual({
      status: 'disabled',
      shipped: 0,
    });
    expect(await shipOnce({ ...deps(impl), creds: null })).toEqual({
      status: 'no-creds',
      shipped: 0,
    });
    expect(calls).toHaveLength(0);
  });
});
