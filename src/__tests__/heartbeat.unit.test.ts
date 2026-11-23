import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { outboxBacklog, fileSignature, writeWatermark } from '../daemon/audit-shipper';
import { heartbeatOnce, startHeartbeat, _resetHeartbeatReads } from '../daemon/heartbeat';
import { buildWireRows } from '../daemon/audit-shipper';
import { _resetReadsOutside, noteReadOutside, takeReadsOutside } from '../daemon/reads-outside';

vi.mock('../daemon/sync', () => ({
  readCredentials: () => null,
  readCachedEtag: () => 'old',
  safeNode9Version: () => '2.27.0',
  triggerSyncNow: vi.fn(),
}));
vi.mock('../daemon/service', () => ({ autostartState: () => 'disabled' }));
vi.mock('../config', () => ({ getConfig: () => ({ settings: { approvers: { cloud: true } } }) }));

describe('heartbeat outbox sampling', () => {
  let dir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-heartbeat-'));
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));
  const row = (overrides = {}) =>
    JSON.stringify({
      eid: 'event-12345',
      tool: 'bash',
      ts: '2026-10-06T10:00:00Z',
      decision: 'allow',
      ...overrides,
    }) + '\n';
  it('counts only shippable complete rows and never changes the watermark', () => {
    const log = path.join(dir, 'audit.log');
    const wm = path.join(dir, 'wm.json');
    const first = row();
    fs.writeFileSync(
      log,
      first +
        row({ checkedBy: 'ignored' }) +
        row({ testRun: true }) +
        row({ checkedBy: 'cloud' }) +
        row({ ts: '2026-10-06T09:00:00Z' }) +
        '{partial'
    );
    writeWatermark(wm, {
      fileSig: fileSignature(log),
      offset: Buffer.byteLength(first),
      updatedAt: 'now',
    });
    const before = fs.readFileSync(wm, 'utf8');
    expect(outboxBacklog(log, wm)).toEqual({
      outboxPending: 1,
      outboxOldestAt: '2026-10-06T09:00:00.000Z',
      outboxTruncated: false,
    });
    expect(fs.readFileSync(wm, 'utf8')).toBe(before);
  });
  it('handles rotation, scan caps and read failures without inventing zero', () => {
    const log = path.join(dir, 'audit.log');
    const wm = path.join(dir, 'wm.json');
    fs.writeFileSync(log, row() + row());
    writeWatermark(wm, { fileSig: 'old-file', offset: 999, updatedAt: 'now' });
    expect(outboxBacklog(log, wm).outboxPending).toBe(2);
    expect(outboxBacklog(log, wm, Buffer.byteLength(row())).outboxTruncated).toBe(true);
    expect(outboxBacklog(dir, wm).outboxPending).toBeNull();
  });
});

describe('heartbeat transport and cadence', () => {
  afterEach(() => vi.useRealTimers());
  const deps = {
    cloudEnabled: true,
    creds: {
      apiKey: 'n9_live_test',
      apiUrl: 'https://api.node9.ai/api/v1/intercept/policies/sync',
    },
    backlog: () => ({ outboxPending: 0, outboxOldestAt: null, outboxTruncated: false }),
  };
  it('uses the real sync credential URL shape and sends operational fields only', async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValue(new Response(JSON.stringify({ policyChanged: true }), { status: 200 }));
    const syncNow = vi.fn().mockResolvedValue(undefined);
    expect(await heartbeatOnce({ ...deps, fetchImpl, syncNow })).toBe('sent');
    expect(fetchImpl.mock.calls[0][0]).toBe('https://api.node9.ai/api/v1/intercept/heartbeat');
    const body = JSON.parse(fetchImpl.mock.calls[0][1].body);
    expect(Object.keys(body).sort()).toEqual(
      [
        'autostart',
        'cliVersion',
        'daemonStartedAt',
        'outboxOldestAt',
        'outboxPending',
        'outboxTruncated',
        'policyEtag',
      ].sort()
    );
    expect(body.autostart).toBe('disabled');
    expect(syncNow).toHaveBeenCalledOnce();
  });
  it('skips network when cloud is disabled or credentials are absent', async () => {
    const fetchImpl = vi.fn();
    await heartbeatOnce({ ...deps, fetchImpl, cloudEnabled: false });
    await heartbeatOnce({ ...deps, fetchImpl, creds: null });
    expect(fetchImpl).not.toHaveBeenCalled();
  });
  it('starts after ten seconds, repeats after five minutes and cleans up', async () => {
    vi.useFakeTimers();
    const once = vi.fn().mockResolvedValue('sent');
    const stop = startHeartbeat(once);
    startHeartbeat(once);
    await vi.advanceTimersByTimeAsync(9_999);
    expect(once).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(once).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(300_000);
    expect(once).toHaveBeenCalledTimes(2);
    stop();
    await vi.advanceTimersByTimeAsync(300_000);
    expect(once).toHaveBeenCalledTimes(2);
  });
});

// Cases-session stage 2, change 6: reads outside the project ride the beat.
describe('heartbeat reads outside the project', () => {
  beforeEach(() => {
    _resetReadsOutside();
    _resetHeartbeatReads();
  });
  const deps = {
    cloudEnabled: true,
    creds: {
      apiKey: 'n9_live_test',
      apiUrl: 'https://api.node9.ai/api/v1/intercept/policies/sync',
    },
    backlog: () => ({ outboxPending: 0, outboxOldestAt: null, outboxTruncated: false }),
  };
  const ok = () => new Response(JSON.stringify({ policyChanged: false }), { status: 200 });
  const bodyOf = (fetchImpl: ReturnType<typeof vi.fn>, call = 0) =>
    JSON.parse(fetchImpl.mock.calls[call][1].body);

  // The row the log hook writes (log.ts): a post-hook row with no eid.
  const postHookRow = (sessionId: string, readOutside: string) =>
    JSON.stringify({
      ts: '2026-11-23T10:00:00Z',
      tool: 'Read',
      decision: 'allowed',
      source: 'post-hook',
      sessionId,
      readOutside,
    }) + '\n';

  it('the shipper notes a marked post-hook row and never ships it', () => {
    const { rows } = buildWireRows(Buffer.from(postHookRow('sess-1', '.aws/config')));
    expect(rows).toEqual([]);
    expect(takeReadsOutside()).toEqual([{ sessionId: 'sess-1', paths: ['.aws/config'] }]);
  });

  it('sends pending reads once, then not again after delivery', async () => {
    noteReadOutside('sess-1', '.aws/config');
    noteReadOutside('sess-1', '.aws/config');
    noteReadOutside('sess-2', 'other/notes.md');
    const fetchImpl = vi.fn().mockImplementation(async () => ok());
    expect(await heartbeatOnce({ ...deps, fetchImpl })).toBe('sent');
    expect(bodyOf(fetchImpl).readsOutside).toEqual([
      { sessionId: 'sess-1', paths: ['.aws/config'] },
      { sessionId: 'sess-2', paths: ['other/notes.md'] },
    ]);
    // Read again in the same session: already delivered, not resent.
    noteReadOutside('sess-1', '.aws/config');
    await heartbeatOnce({ ...deps, fetchImpl });
    expect(bodyOf(fetchImpl, 1)).not.toHaveProperty('readsOutside');
  });

  it('keeps the reads for the next beat when the beat fails', async () => {
    noteReadOutside('sess-1', '.aws/config');
    const down = vi.fn().mockRejectedValue(new Error('offline'));
    expect(await heartbeatOnce({ ...deps, fetchImpl: down })).toBe('error');
    const up = vi.fn().mockImplementation(async () => ok());
    await heartbeatOnce({ ...deps, fetchImpl: up });
    expect(bodyOf(up).readsOutside).toEqual([{ sessionId: 'sess-1', paths: ['.aws/config'] }]);
  });

  it('an older server that refuses the list still gets the beat, and the list rests an hour', async () => {
    noteReadOutside('sess-1', '.aws/config');
    const fetchImpl = vi
      .fn()
      .mockImplementation(async (_url: string, init: { body: string }) =>
        'readsOutside' in JSON.parse(init.body) ? new Response('{}', { status: 400 }) : ok()
      );
    expect(await heartbeatOnce({ ...deps, fetchImpl })).toBe('sent');
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(bodyOf(fetchImpl, 1)).not.toHaveProperty('readsOutside');
    noteReadOutside('sess-1', 'other/notes.md');
    await heartbeatOnce({ ...deps, fetchImpl });
    expect(fetchImpl).toHaveBeenCalledTimes(3);
    expect(bodyOf(fetchImpl, 2)).not.toHaveProperty('readsOutside');
  });

  it('caps one beat at the server bounds and keeps the rest', () => {
    for (let i = 0; i < 120; i++) noteReadOutside(`s${i}`, 'a/b');
    for (let i = 0; i < 60; i++) noteReadOutside('s0', `p/${i}`);
    const first = takeReadsOutside();
    expect(first).toHaveLength(100);
    expect(first[0].paths).toHaveLength(50);
    const rest = takeReadsOutside();
    expect(rest.map((r) => r.sessionId)).toContain('s0');
    expect(rest).toHaveLength(21);
  });

  it('drops a malformed session id or path', () => {
    noteReadOutside('a b', 'x/y');
    noteReadOutside('sess', 'x'.repeat(257));
    noteReadOutside(undefined, 'x/y');
    expect(takeReadsOutside()).toEqual([]);
  });
});
