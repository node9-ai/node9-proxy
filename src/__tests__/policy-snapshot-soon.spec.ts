// The snapshot push a seen-server change asks for (daemon/sync.ts
// pushPolicySnapshotIfKeyed): the same snapshot the policy sync sends, to the
// same endpoint, and nothing without a key. A real local server, a temp HOME.
import { afterEach, describe, expect, it, vi } from 'vitest';
import fs from 'fs';
import http from 'http';
import os from 'os';
import path from 'path';
import type { AddressInfo } from 'net';
import { pushPolicySnapshotIfKeyed } from '../daemon/sync';
import { _resetMcpSeenCursor, refreshMcpSeen } from '../addons/mcp-seen';
import { readMcpIndex } from '../addons/index-file';
import { _resetConfigCache } from '../config';

const cleanup: Array<() => void> = [];
afterEach(() => {
  for (const c of cleanup.splice(0)) c();
  vi.unstubAllEnvs();
  _resetConfigCache();
});

interface Received {
  url?: string;
  auth?: string;
  body: Record<string, unknown>;
}

async function fakeApi(): Promise<{ port: number; received: Received[] }> {
  const received: Received[] = [];
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (c: Buffer) => (raw += c.toString()));
    req.on('end', () => {
      received.push({
        url: req.url,
        auth: req.headers.authorization,
        body: JSON.parse(raw || '{}') as Record<string, unknown>,
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{}');
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  cleanup.push(() => server.close());
  return { port: (server.address() as AddressInfo).port, received };
}

function home(): string {
  const h = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-push-soon-'));
  cleanup.push(() => fs.rmSync(h, { recursive: true, force: true }));
  fs.mkdirSync(path.join(h, '.node9'), { recursive: true });
  vi.stubEnv('HOME', h);
  vi.stubEnv('USERPROFILE', h);
  vi.stubEnv('NODE9_API_KEY', '');
  vi.stubEnv('NODE9_POLICY_MIRROR_DISABLE', '');
  _resetConfigCache();
  return h;
}

/** A call the hook audited to a server no agent config names. */
function auditedCall(h: string, tool: string): void {
  fs.appendFileSync(
    path.join(h, '.node9', 'audit.log'),
    JSON.stringify({ ts: new Date().toISOString(), tool, decision: 'allow', agent: 'Codex' }) + '\n'
  );
  _resetMcpSeenCursor();
  expect(refreshMcpSeen(h)).toBe(true);
}

describe('pushPolicySnapshotIfKeyed', () => {
  it('sends the policy snapshot, with the server seen in calls, to the snapshot endpoint', async () => {
    const api = await fakeApi();
    const h = home();
    fs.writeFileSync(
      path.join(h, '.node9', 'credentials.json'),
      JSON.stringify({
        default: { apiKey: 'test-key', apiUrl: `http://127.0.0.1:${api.port}/api/v1/intercept` },
      })
    );
    auditedCall(h, 'mcp__codex_apps__open');
    expect(await pushPolicySnapshotIfKeyed()).toBe(true);
    expect(api.received).toHaveLength(1);
    const [got] = api.received;
    expect(got.url).toBe('/api/v1/intercept/policy/snapshot');
    expect(got.auth).toBe('Bearer test-key');
    const addons = got.body.addons as { mcp: Array<Record<string, unknown>> };
    expect(addons.mcp).toContainEqual(
      expect.objectContaining({ name: 'codex_apps', identity: 'name:codex_apps', state: 'seen' })
    );
  });

  it("reports a Claude Code project's server and keeps it out of the hook's index", async () => {
    const api = await fakeApi();
    const h = home();
    fs.writeFileSync(
      path.join(h, '.node9', 'credentials.json'),
      JSON.stringify({
        default: { apiKey: 'test-key', apiUrl: `http://127.0.0.1:${api.port}/api/v1/intercept` },
      })
    );
    // A project as Claude Code keeps it: listed in ~/.claude.json, with a
    // `.mcp.json` in its folder.
    const proj = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-proj-'));
    cleanup.push(() => fs.rmSync(proj, { recursive: true, force: true }));
    fs.writeFileSync(
      path.join(proj, '.mcp.json'),
      JSON.stringify({ mcpServers: { files: { command: 'npx', args: ['-y', '@acme/files-mcp'] } } })
    );
    fs.writeFileSync(
      path.join(h, '.claude.json'),
      JSON.stringify({ projects: { [proj]: { mcpServers: {} } } })
    );
    expect(await pushPolicySnapshotIfKeyed()).toBe(true);
    const addons = api.received[0].body.addons as { mcp: Array<Record<string, unknown>> };
    expect(addons.mcp).toContainEqual(
      expect.objectContaining({ name: 'files', identity: 'npm:@acme/files-mcp', state: 'outside' })
    );
    // The push writes the index too. A project's server in it would be
    // judged for a call from any folder, and for any agent.
    expect(readMcpIndex(h)).toEqual([]);
  });

  it('sends nothing from a machine with no key', async () => {
    const api = await fakeApi();
    const h = home();
    auditedCall(h, 'mcp__codex_apps__open');
    expect(await pushPolicySnapshotIfKeyed()).toBe(false);
    // Give a stray request time to arrive.
    await new Promise((r) => setTimeout(r, 200));
    expect(api.received).toHaveLength(0);
  });

  it('sends nothing when the policy mirror is switched off', async () => {
    const api = await fakeApi();
    const h = home();
    fs.writeFileSync(
      path.join(h, '.node9', 'credentials.json'),
      JSON.stringify({
        default: { apiKey: 'test-key', apiUrl: `http://127.0.0.1:${api.port}/api/v1/intercept` },
      })
    );
    vi.stubEnv('NODE9_POLICY_MIRROR_DISABLE', '1');
    auditedCall(h, 'mcp__codex_apps__open');
    expect(await pushPolicySnapshotIfKeyed()).toBe(false);
    await new Promise((r) => setTimeout(r, 200));
    expect(api.received).toHaveLength(0);
  });
});
