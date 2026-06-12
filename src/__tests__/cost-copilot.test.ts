// src/__tests__/cost-copilot.test.ts
// cost-multi-agent Phase 2 — Copilot cost source reads ~/.copilot/session-state.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { parseCopilotSession, copilotSource } from '../cost-copilot';

const START =
  '{"type":"session.start","timestamp":"2026-06-06T19:44:21.535Z","data":{"sessionId":"sess-c1","startTime":"2026-06-06T19:44:21.535Z","context":{"cwd":"/home/nadav/node9"}}}';
const MSG =
  '{"type":"assistant.message","timestamp":"2026-06-06T19:45:00Z","data":{"model":"claude-haiku-4.5","outputTokens":169}}';
const SHUTDOWN =
  '{"type":"session.shutdown","timestamp":"2026-06-06T19:50:00Z","data":{"modelMetrics":{' +
  '"claude-haiku-4.5":{"requests":{"cost":0.33},"usage":{"inputTokens":32482,"outputTokens":900,"cacheReadTokens":1000,"cacheWriteTokens":50}},' +
  '"gpt-5-mini":{"requests":{"cost":0},"usage":{"inputTokens":0,"outputTokens":0,"cacheReadTokens":0,"cacheWriteTokens":0}}' +
  '}}}';

describe('parseCopilotSession', () => {
  it('emits one row per USED model from the shutdown rollup, trusting its cost', () => {
    const rows = parseCopilotSession([START, MSG, SHUTDOWN]);
    expect(rows).toHaveLength(1); // gpt-5-mini had zero usage → skipped
    const e = rows[0];
    expect(e.model).toMatch(/claude-haiku-4\.5/i);
    expect(e.costUSD).toBe(0.33); // Copilot's pre-computed cost
    expect(e.inputTokens).toBe(32482);
    expect(e.outputTokens).toBe(900);
    expect(e.cacheReadTokens).toBe(1000);
    expect(e.cacheWriteTokens).toBe(50);
    expect(e.date).toBe('2026-06-06');
    expect(e.workingDir).toBe('/home/nadav/node9');
    expect(e.runId).toBe('sess-c1');
  });

  it('returns [] for a session that has not shut down (no rollup yet)', () => {
    expect(parseCopilotSession([START, MSG])).toEqual([]);
  });

  it('prices the tokens when Copilot omits a cost', () => {
    const noCost =
      '{"type":"session.shutdown","timestamp":"2026-06-06T19:50:00Z","data":{"modelMetrics":{' +
      '"claude-haiku-4.5":{"usage":{"inputTokens":1000,"outputTokens":100,"cacheReadTokens":0,"cacheWriteTokens":0}}}}}';
    const rows = parseCopilotSession([START, noCost]);
    expect(rows).toHaveLength(1);
    expect(rows[0].costUSD).toBeGreaterThanOrEqual(0); // priced via pricingFor (>0 if model known)
  });
});

describe('copilotSource.collect', () => {
  let TMP: string;
  const homeSpy = vi.spyOn(os, 'homedir');

  beforeEach(() => {
    TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-cop-'));
    homeSpy.mockReturnValue(TMP);
  });
  afterEach(() => {
    homeSpy.mockReset();
    try {
      fs.rmSync(TMP, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  });

  function writeSession(sid: string, lines: string[]) {
    const dir = path.join(TMP, '.copilot', 'session-state', sid);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'events.jsonl'), lines.join('\n') + '\n');
  }

  it('available() reflects ~/.copilot/session-state presence', () => {
    expect(copilotSource.available()).toBe(false);
    writeSession('sess-c1', [START, SHUTDOWN]);
    expect(copilotSource.available()).toBe(true);
  });

  it('collects finished sessions, skips in-flight ones', () => {
    writeSession('done', [START, SHUTDOWN]);
    writeSession('inflight', [START, MSG]);
    const entries = copilotSource.collect();
    expect(entries).toHaveLength(1);
    expect(entries[0].costUSD).toBe(0.33);
  });

  it('returns [] with no copilot dir', () => {
    expect(copilotSource.collect()).toEqual([]);
  });
});
