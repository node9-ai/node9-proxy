// src/__tests__/cost-registry.test.ts
// cost-multi-agent Phase 4 — anti-drift guards for the upload cost registry.
//
// The Claude-only-cost bug happened because the upload registry (COST_SOURCES)
// silently lost parity with the agents the local dashboard reads. These tests
// are the tripwire: they fail if a known agent source is dropped, and they
// prove collectEntries() actually merges across multiple agents.

import { describe, it, expect, vi, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { COST_SOURCES, collectEntries } from '../costSync';

describe('cost source registry — parity tripwire', () => {
  it('covers every agent we know how to read (claude, codex, gemini, copilot)', () => {
    const ids = COST_SOURCES.map((s) => s.id).sort();
    // Removing an agent here without removing its reader is the drift we guard
    // against. The local dashboard reads claude+codex+gemini; copilot is
    // upload-only today. Antigravity flows through gemini (~/.gemini/tmp).
    expect(ids).toEqual(['claude', 'codex', 'copilot', 'gemini']);
  });

  it('every source has a string id and the CostSource shape', () => {
    for (const s of COST_SOURCES) {
      expect(typeof s.id).toBe('string');
      expect(typeof s.available).toBe('function');
      expect(typeof s.collect).toBe('function');
    }
  });
});

describe('collectEntries — multi-agent merge', () => {
  let TMP: string;
  const homeSpy = vi.spyOn(os, 'homedir');

  afterEach(() => {
    homeSpy.mockReset();
    try {
      fs.rmSync(TMP, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  });

  function setup(): void {
    TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-reg-'));
    homeSpy.mockReturnValue(TMP);
  }

  it('returns [] when no agent has data on disk', () => {
    setup();
    expect(collectEntries()).toEqual([]);
  });

  it('merges rows from two different agents (codex + gemini) in one call', () => {
    setup();
    // codex session
    const cdir = path.join(TMP, '.codex', 'sessions', '2026', '06', '11');
    fs.mkdirSync(cdir, { recursive: true });
    fs.writeFileSync(
      path.join(cdir, 'rollout-a.jsonl'),
      [
        '{"type":"session_meta","payload":{"timestamp":"2026-06-11T10:00:00Z","id":"cx","cwd":"/w"}}',
        '{"type":"turn_context","payload":{"model":"gpt-5.4"}}',
        '{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":1000,"cached_input_tokens":0,"output_tokens":50}}}}',
      ].join('\n') + '\n'
    );
    // gemini session
    const gdir = path.join(TMP, '.gemini', 'tmp', 'proj', 'chats');
    fs.mkdirSync(gdir, { recursive: true });
    fs.writeFileSync(
      path.join(gdir, 'session-x.jsonl'),
      [
        '{"sessionId":"gx","startTime":"2026-06-11T10:00:00Z"}',
        '{"id":"t1","timestamp":"2026-06-11T10:01:00Z","type":"gemini","model":"gemini-2.5-pro","tokens":{"input":800,"output":40,"cached":0}}',
      ].join('\n') + '\n'
    );

    const rows = collectEntries();
    const models = rows.map((r) => r.model).sort();
    expect(models.some((m) => /gpt-5/i.test(m))).toBe(true);
    expect(models.some((m) => /gemini/i.test(m))).toBe(true);
    expect(rows.length).toBe(2); // one per agent, distinct model keys
    expect(rows.every((r) => r.costUSD > 0)).toBe(true);
  });
});
