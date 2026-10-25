// fw#402: the progress-bar total counts the same files the parsers scan:
// nested Claude transcripts (subagents, workflows) and Gemini `.jsonl` included.
import { describe, it, expect, beforeEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { countScanFiles, scanClaudeHistory, scanGeminiHistory } from '../cli/commands/scan';

const home = () => os.homedir();
const RECENT = new Date(Date.now() - 3600_000).toISOString();

beforeEach(() => {
  for (const d of ['.claude', '.gemini'])
    fs.rmSync(path.join(home(), d), { recursive: true, force: true });
});

describe('countScanFiles matches the parsers', () => {
  it('nested Claude transcripts and both Gemini formats', async () => {
    const proj = path.join(home(), '.claude', 'projects', '-tmp-proj');
    fs.mkdirSync(path.join(proj, 'subagents'), { recursive: true });
    fs.mkdirSync(path.join(proj, 'wf_1'), { recursive: true });
    const line = JSON.stringify({ type: 'user', timestamp: RECENT, message: { content: [] } });
    fs.writeFileSync(path.join(proj, 'main.jsonl'), line);
    fs.writeFileSync(path.join(proj, 'subagents', 'agent-x.jsonl'), line);
    fs.writeFileSync(path.join(proj, 'wf_1', 'step.jsonl'), line);

    const chats = path.join(home(), '.gemini', 'tmp', 'slug', 'chats');
    fs.mkdirSync(chats, { recursive: true });
    const msg = JSON.stringify({ type: 'gemini', timestamp: RECENT, toolCalls: [] });
    fs.writeFileSync(path.join(chats, 'a.jsonl'), msg);
    fs.writeFileSync(path.join(chats, 'b.json'), JSON.stringify({ messages: [JSON.parse(msg)] }));
    // the same session in both formats counts once
    fs.writeFileSync(path.join(chats, 'a.json'), JSON.stringify({ messages: [] }));

    const claude = await scanClaudeHistory(null);
    const gemini = await scanGeminiHistory(null);
    expect(claude.filesScanned).toBe(3);
    expect(gemini.filesScanned).toBe(2);
    expect(countScanFiles()).toBe(claude.filesScanned + gemini.filesScanned);
  });
});
