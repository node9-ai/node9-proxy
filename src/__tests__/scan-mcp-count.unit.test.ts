// fw#403: the MCP number is the count of mcp__* tool calls, from the same tally
// as the shell count, not the number of findings on MCP tools.
import { describe, it, expect, beforeEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { scanClaudeHistory } from '../cli/commands/scan';
import { buildScanSummary } from '../scan-summary';

const home = () => os.homedir();
const RECENT = new Date(Date.now() - 3600_000).toISOString();

beforeEach(() => fs.rmSync(path.join(home(), '.claude'), { recursive: true, force: true }));

describe('MCP activity', () => {
  it('counts calls per server; none of them is a finding', async () => {
    const proj = path.join(home(), '.claude', 'projects', '-tmp-proj');
    fs.mkdirSync(proj, { recursive: true });
    // Distinct arguments: identical repeats would be a loop, which the gate
    // blocks, and that verdict is not what this test is about.
    const call = (name: string, i: number) =>
      JSON.stringify({
        type: 'assistant',
        timestamp: RECENT,
        message: { content: [{ type: 'tool_use', id: `u${i}`, name, input: { q: `x${i}` } }] },
      });
    const lines = [
      ...[0, 1, 2, 3, 4].map((i) => call('mcp__gmail__search_emails', i)),
      ...[5, 6].map((i) => call('mcp__github__list_issues', i)),
      call('Read', 7),
    ];
    fs.writeFileSync(path.join(proj, 's.jsonl'), lines.join('\n'));
    const r = await scanClaudeHistory(null);
    expect(r.totalToolCalls).toBe(8);
    expect(r.mcpCalls).toBe(7);
    expect(r.mcpByServer).toEqual({ gmail: 5, github: 2 });
    // The tally is independent of what the gate says about these calls.
    const mcpFindings = r.findings.filter((f) => f.toolName.startsWith('mcp__'));
    expect(mcpFindings.length).toBeLessThan(r.mcpCalls ?? 0);
    expect(mcpFindings.map((f) => f.checkId)).not.toContain('behavior.loops');
    const s = buildScanSummary([{ id: 'claude', label: 'Claude', icon: 'c', scan: r }]);
    expect(s.stats.mcpCalls).toBe(7);
    expect(s.stats.mcpByServer.gmail).toBe(5);
  });
});
