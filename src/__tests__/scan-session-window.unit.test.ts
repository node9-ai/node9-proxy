// fw#401: `sessions` counts the sessions with activity inside the window, not
// the transcript files opened. `filesScanned` keeps counting every file.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { scanClaudeHistory, scanCopilotHistory, scanCodexHistory } from '../cli/commands/scan';

const home = () => os.homedir();
const DAY = 24 * 3600 * 1000;
const OLD = new Date(Date.now() - 60 * DAY).toISOString();
const RECENT = new Date(Date.now() - 1 * DAY).toISOString();
const WINDOW = new Date(Date.now() - 7 * DAY);

function claudeLine(ts: string, command: string): string {
  return JSON.stringify({
    type: 'assistant',
    timestamp: ts,
    message: { content: [{ type: 'tool_use', id: 'u', name: 'Bash', input: { command } }] },
  });
}

beforeEach(() => {
  for (const d of ['.claude', '.copilot', '.codex'])
    fs.rmSync(path.join(home(), d), { recursive: true, force: true });
});
afterEach(() => {
  for (const d of ['.claude', '.copilot', '.codex'])
    fs.rmSync(path.join(home(), d), { recursive: true, force: true });
});

describe('sessions follow the window', () => {
  it('Claude: two files, one before the window; sessions 1, filesScanned 2', async () => {
    const proj = path.join(home(), '.claude', 'projects', '-tmp-proj');
    fs.mkdirSync(proj, { recursive: true });
    fs.writeFileSync(path.join(proj, 'old.jsonl'), claudeLine(OLD, 'ls') + '\n');
    fs.writeFileSync(path.join(proj, 'new.jsonl'), claudeLine(RECENT, 'ls') + '\n');
    const r = await scanClaudeHistory(WINDOW);
    expect(r.filesScanned).toBe(2);
    expect(r.sessions).toBe(1);
    expect(r.totalToolCalls).toBe(1);
    const all = await scanClaudeHistory(null);
    expect(all.sessions).toBe(2);
  });

  it('Copilot: a session whose events all predate the window is not counted', async () => {
    const write = (id: string, ts: string) => {
      const dir = path.join(home(), '.copilot', 'session-state', id);
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(
        path.join(dir, 'events.jsonl'),
        [
          {
            type: 'session.start',
            data: { sessionId: id, context: { cwd: '/tmp/p' } },
            timestamp: ts,
          },
          {
            type: 'tool.execution_start',
            data: { toolCallId: 't', toolName: 'bash', arguments: { command: 'ls' } },
            timestamp: ts,
          },
        ]
          .map((e) => JSON.stringify(e))
          .join('\n')
      );
    };
    write('old-session', OLD);
    write('new-session', RECENT);
    const r = await scanCopilotHistory(WINDOW);
    expect(r.filesScanned).toBe(2);
    expect(r.sessions).toBe(1);
  });

  it('Codex: the session start decides, as the window filter does', async () => {
    const dir = path.join(home(), '.codex', 'sessions', '2026', '01', '01');
    fs.mkdirSync(dir, { recursive: true });
    const session = (id: string, ts: string) =>
      [
        { type: 'session_meta', payload: { id, timestamp: ts, cwd: '/tmp/p' } },
        {
          type: 'response_item',
          timestamp: ts,
          payload: {
            type: 'function_call',
            name: 'shell',
            arguments: JSON.stringify({ cmd: 'ls' }),
          },
        },
      ]
        .map((e) => JSON.stringify(e))
        .join('\n');
    fs.writeFileSync(path.join(dir, 'rollout-old.jsonl'), session('old', OLD));
    fs.writeFileSync(path.join(dir, 'rollout-new.jsonl'), session('new', RECENT));
    const r = await scanCodexHistory(WINDOW);
    expect(r.filesScanned).toBe(2);
    expect(r.sessions).toBe(1);
  });
});
