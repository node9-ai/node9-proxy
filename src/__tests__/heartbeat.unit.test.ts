import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { outboxBacklog, fileSignature, writeWatermark } from '../daemon/audit-shipper';
import { heartbeatOnce, startHeartbeat } from '../daemon/heartbeat';

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
