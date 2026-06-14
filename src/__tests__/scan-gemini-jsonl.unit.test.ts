// Regression: scanGeminiHistory read ONLY legacy single-object `.json` chat
// files and skipped the current line-delimited `.jsonl` format Gemini CLI now
// writes — so `node9 scan` silently missed every current Gemini session's cost
// AND findings, while `node9 report` (reads `.jsonl`) showed them. Manual
// testing caught scan's Gemini cost as $0. This pins both formats + dedup.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { scanGeminiHistory } from '../cli/commands/scan';
import { _resetPricingCache } from '../pricing/litellm';

let tmpHome: string;

beforeEach(() => {
  _resetPricingCache(); // deterministic bundled pricing
  tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-gemini-scan-'));
  vi.spyOn(os, 'homedir').mockReturnValue(tmpHome);
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(tmpHome, { recursive: true, force: true });
});

function chatsDir(slug = 'proj'): string {
  const dir = path.join(tmpHome, '.gemini', 'tmp', slug, 'chats');
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

// Current format: one JSON message per line, leading session header.
function jsonlSession(model: string, input: number): string {
  return (
    [
      '{"sessionId":"gx","startTime":"2026-06-14T10:00:00Z","kind":"chat"}',
      '{"id":"u1","timestamp":"2026-06-14T10:00:05Z","type":"user","content":[{"text":"hi"}]}',
      `{"id":"g1","timestamp":"2026-06-14T10:00:10Z","type":"gemini","model":"${model}","tokens":{"input":${input},"output":0,"cached":0}}`,
    ].join('\n') + '\n'
  );
}

// Legacy format: a single object with a messages[] array.
function jsonSession(model: string, input: number): string {
  return JSON.stringify({
    sessionId: 'gx',
    startTime: '2026-06-14T10:00:00Z',
    messages: [
      {
        type: 'gemini',
        timestamp: '2026-06-14T10:00:10Z',
        model,
        tokens: { input, output: 0, cached: 0 },
      },
    ],
  });
}

describe('scanGeminiHistory — reads current .jsonl format (not just legacy .json)', () => {
  it('prices a .jsonl Gemini session (gemini-2.5-flash, $0.30/M) — was $0 before', () => {
    fs.writeFileSync(
      path.join(chatsDir(), 'session-a.jsonl'),
      jsonlSession('gemini-2.5-flash', 1_000_000)
    );
    const res = scanGeminiHistory(null);
    expect(res.sessions).toBe(1);
    // 1,000,000 input * $0.30/M = $0.30.
    expect(res.totalCostUSD).toBeCloseTo(0.3, 6);
  });

  it('still reads the legacy .json single-object format (no regression)', () => {
    fs.writeFileSync(
      path.join(chatsDir(), 'session-b.json'),
      jsonSession('gemini-2.5-flash', 1_000_000)
    );
    const res = scanGeminiHistory(null);
    expect(res.sessions).toBe(1);
    expect(res.totalCostUSD).toBeCloseTo(0.3, 6);
  });

  it('counts a session once when it exists in BOTH formats (prefers .jsonl)', () => {
    const dir = chatsDir();
    // Same basename, both extensions — e.g. a migrated session.
    fs.writeFileSync(path.join(dir, 'session-c.json'), jsonSession('gemini-2.5-flash', 1_000_000));
    fs.writeFileSync(
      path.join(dir, 'session-c.jsonl'),
      jsonlSession('gemini-2.5-flash', 1_000_000)
    );
    const res = scanGeminiHistory(null);
    expect(res.sessions).toBe(1); // not double-counted
    expect(res.totalCostUSD).toBeCloseTo(0.3, 6);
  });
});
