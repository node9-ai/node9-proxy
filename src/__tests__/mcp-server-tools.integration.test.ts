/**
 * Integration test: the node9 MCP server exposes node9_posture + node9_explain.
 * Spawns `node9 mcp-server`, drives it over stdio JSON-RPC, asserts the new tools
 * appear in tools/list and that node9_explain returns an allow/review/block verdict.
 * Requires `npm run build` (spawns dist/cli.js).
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

interface McpResponse {
  id?: number;
  result?: {
    tools?: { name: string }[];
    content?: { type: string; text: string }[];
  };
}

let home: string;

function driveMcp(requests: object[]): Record<number, McpResponse> {
  const input = requests.map((r) => JSON.stringify(r)).join('\n') + '\n';
  const r = spawnSync(process.execPath, [CLI, 'mcp-server'], {
    input,
    encoding: 'utf-8',
    timeout: 60000,
    env: {
      ...process.env,
      HOME: home,
      USERPROFILE: home,
      NODE9_TESTING: '1',
      NODE9_NO_AUTO_DAEMON: '1',
      NO_COLOR: '1',
    },
  });
  const byId: Record<number, McpResponse> = {};
  for (const line of (r.stdout ?? '').split('\n').filter(Boolean)) {
    try {
      const msg = JSON.parse(line) as McpResponse;
      if (typeof msg.id === 'number') byId[msg.id] = msg;
    } catch {
      /* ignore non-JSON lines */
    }
  }
  return byId;
}

beforeAll(() => {
  if (!fs.existsSync(CLI)) throw new Error('dist/cli.js missing — run `npm run build` first');
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-mcp-'));
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  fs.writeFileSync(
    path.join(home, '.node9', 'config.json'),
    JSON.stringify({ settings: { mode: 'standard' } })
  );
});
afterAll(() => {
  try {
    fs.rmSync(home, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
});

describe('node9 MCP server — posture + explain tools', () => {
  it('tools/list includes node9_posture and node9_explain', () => {
    const res = driveMcp([
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
      { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
    ]);
    const names = (res[2]?.result?.tools ?? []).map((t) => t.name);
    expect(names).toContain('node9_posture');
    expect(names).toContain('node9_explain');
  });

  it('node9_explain returns the allow/review/block verdict for a command', () => {
    const res = driveMcp([
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
      {
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: { name: 'node9_explain', arguments: { args: 'git status' } },
      },
    ]);
    const text = res[2]?.result?.content?.[0]?.text ?? '';
    expect(text).toContain('Node9 Explain');
    expect(text).toMatch(/ALLOW|REVIEW|BLOCK/);
  });
});
