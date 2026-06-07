// src/__tests__/cost-codex.test.ts
// GAP-3 Phase 2 — Codex cost source: OTel-log parsing + normalization.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { parseCodexUsageLine, codexSource } from '../cost-codex';

// Real-shape sample line from ~/.codex/log/codex-tui.log.
const SAMPLE =
  '2026-05-17T09:29:53.357678Z  INFO session_loop{thread_id=019e3544-7c98-7cb2-b199-6c72e6bafa08}:' +
  'turn{otel.name="session_task.turn" thread.id=019e3544-7c98-7cb2-b199-6c72e6bafa08 ' +
  'turn.id=019e3544-8b99-7990-bb49-3b42778595cd model=gpt-5.4 codex.turn.reasoning_effort=medium ' +
  'codex.turn.token_usage.input_tokens=46925 codex.turn.token_usage.cached_input_tokens=30848 ' +
  'codex.turn.token_usage.non_cached_input_tokens=16077 codex.turn.token_usage.output_tokens=463 ' +
  'codex.turn.token_usage.reasoning_output_tokens=65 codex.turn.token_usage.total_tokens=47388}:';

describe('parseCodexUsageLine', () => {
  it('maps Codex usage to DailyEntry with correct cached/non-cached split', () => {
    const e = parseCodexUsageLine(SAMPLE)!;
    expect(e).not.toBeNull();
    // THE TRAP: input must be non_cached (16077), NOT input_tokens (46925),
    // and not mis-captured from the "input_tokens" substring inside
    // non_cached_input_tokens / cached_input_tokens.
    expect(e.inputTokens).toBe(16077);
    expect(e.cacheReadTokens).toBe(30848);
    expect(e.cacheWriteTokens).toBe(0); // OpenAI has no cache-write
    expect(e.outputTokens).toBe(463); // includes reasoning; not double-counted
    expect(e.runId).toBe('019e3544-7c98-7cb2-b199-6c72e6bafa08');
    expect(e.date).toBe('2026-05-17');
    expect(e.workingDir).toBe('');
    expect(typeof e.costUSD).toBe('number');
    expect(e.costUSD).toBeGreaterThanOrEqual(0);
  });

  it('falls back to (total - cached) when non_cached is absent', () => {
    const line =
      '2026-05-01T00:00:00.0Z INFO turn{model=gpt-5.4 ' +
      'codex.turn.token_usage.input_tokens=1000 codex.turn.token_usage.cached_input_tokens=300 ' +
      'codex.turn.token_usage.output_tokens=20}';
    const e = parseCodexUsageLine(line)!;
    expect(e.inputTokens).toBe(700); // 1000 - 300
    expect(e.cacheReadTokens).toBe(300);
    expect(e.outputTokens).toBe(20);
  });

  it('returns null for a non-usage line', () => {
    expect(parseCodexUsageLine('2026-05-17T09:29:53Z INFO some unrelated log line')).toBeNull();
  });

  it('returns null when timestamp or model is missing', () => {
    expect(parseCodexUsageLine('no-timestamp model=gpt-5.4 token_usage.input_tokens=5')).toBeNull();
    expect(
      parseCodexUsageLine('2026-05-17T09:29:53Z token_usage.input_tokens=5 (no model)')
    ).toBeNull();
  });
});

describe('codexSource.collect', () => {
  let TMP: string;
  const homeSpy = vi.spyOn(os, 'homedir');

  beforeEach(() => {
    TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-codex-'));
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

  function writeLog(lines: string[]) {
    const dir = path.join(TMP, '.codex', 'log');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'codex-tui.log'), lines.join('\n') + '\n');
  }

  it('available() reflects the log file presence', () => {
    expect(codexSource.available()).toBe(false);
    writeLog([SAMPLE]);
    expect(codexSource.available()).toBe(true);
  });

  it('aggregates usage lines per (date, model, session)', () => {
    writeLog([SAMPLE, SAMPLE, 'unrelated noise line']);
    const entries = codexSource.collect();
    expect(entries).toHaveLength(1); // same date/model/thread → merged
    expect(entries[0].inputTokens).toBe(16077 * 2);
    expect(entries[0].cacheReadTokens).toBe(30848 * 2);
    expect(entries[0].outputTokens).toBe(463 * 2);
  });

  it('returns [] when no codex log exists', () => {
    expect(codexSource.collect()).toEqual([]);
  });
});
