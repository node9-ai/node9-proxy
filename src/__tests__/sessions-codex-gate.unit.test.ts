// Regression: `node9 sessions` used to hard-bail when ~/.claude/history.jsonl
// was absent (the command action returned "No Claude session history found",
// and buildSessions returned [] before merging Codex/Gemini). So a Codex-only
// or Gemini-only user — no Claude Code installed — saw nothing, even though
// buildSessions otherwise merges those agents. This verifies a Codex session
// still shows with no Claude history (and re-pins its per-model cost).

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { buildSessions } from '../cli/commands/sessions';
import { _resetPricingCache } from '../pricing/litellm';

let tmpHome: string;

beforeEach(() => {
  _resetPricingCache(); // deterministic bundled pricing
  tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-sessions-gate-'));
  vi.spyOn(os, 'homedir').mockReturnValue(tmpHome);
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(tmpHome, { recursive: true, force: true });
});

function writeCodexSession(model: string, inputTokens: number): void {
  const dir = path.join(tmpHome, '.codex', 'sessions', '2026', '06', '14');
  fs.mkdirSync(dir, { recursive: true });
  const lines = [
    '{"type":"session_meta","payload":{"timestamp":"2026-06-14T10:00:00Z","id":"cx","cwd":"/p"}}',
    `{"type":"turn_context","payload":{"model":"${model}"}}`,
    `{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":${inputTokens},"cached_input_tokens":0,"output_tokens":0}}}}`,
  ];
  fs.writeFileSync(path.join(dir, 'r.jsonl'), lines.join('\n') + '\n');
}

describe('buildSessions — Codex sessions show without a Claude history file', () => {
  it('returns a Codex session even when ~/.claude/history.jsonl is absent', () => {
    // No .claude/history.jsonl written — the Codex-only user case.
    writeCodexSession('gpt-5-codex', 1_000_000);

    // No historyPath override → exercises the real homedir path + the merge.
    const summaries = buildSessions(null);

    const codex = summaries.find((s) => s.agent === 'codex');
    expect(codex).toBeDefined();
    expect(codex!.sessionId).toBe('cx');
    // Per-model price: 1,000,000 input * $1.25/M = $1.25 (not the old flat $5).
    expect(codex!.costUSD).toBeCloseTo(1.25, 6);
  });

  it('returns an empty list (no throw) when there are no sessions of any agent', () => {
    expect(buildSessions(null)).toEqual([]);
  });
});
