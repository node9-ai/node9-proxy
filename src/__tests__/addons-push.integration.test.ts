// fw#376 item 6: `node9 policy push` at the real CLI ships the add-ons report.
// A local listener stands in for the dashboard; the test reads the body the
// CLI actually sent. A skill carrying a token and an MCP server whose argument
// carries a password must arrive as names and hashes only.
import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { spawn } from 'child_process';
import http from 'http';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { AddressInfo } from 'net';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const TOKEN = 'ghp_' + 'Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2';
const homes: string[] = [];

afterEach(() => {
  for (const h of homes.splice(0)) fs.rmSync(h, { recursive: true, force: true });
});

function seededHome(): string {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-addons-push-'));
  homes.push(home);
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  const skill = path.join(home, '.claude', 'skills', 'deploy');
  fs.mkdirSync(skill, { recursive: true });
  fs.writeFileSync(
    path.join(skill, 'SKILL.md'),
    `---\nname: deploy-helper\nallowed-tools: Bash\n---\nAuthenticate with ${TOKEN}.\n`
  );
  fs.writeFileSync(
    path.join(home, '.claude.json'),
    JSON.stringify({
      mcpServers: {
        db: {
          command: 'npx',
          args: ['-y', '@modelcontextprotocol/server-postgres', 'postgres://u:hunter2@db/x'],
        },
      },
    })
  );
  return home;
}

function run(home: string, apiUrl: string): Promise<{ code: number | null; out: string }> {
  const env: Record<string, string> = {
    ...(process.env as Record<string, string>),
    HOME: home,
    USERPROFILE: home,
    NODE9_API_KEY: 'n9_test_key',
    NODE9_API_URL: apiUrl,
    NODE9_NO_AUTO_DAEMON: '1',
    NO_COLOR: '1',
  };
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, 'policy', 'push'], { env });
    let out = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (out += d));
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, out }));
  });
}

async function listener(
  answer: (body: Record<string, unknown>) => number
): Promise<{ url: string; bodies: Array<Record<string, unknown>>; close: () => void }> {
  const bodies: Array<Record<string, unknown>> = [];
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (d) => (raw += d));
    req.on('end', () => {
      const body = JSON.parse(raw) as Record<string, unknown>;
      if (req.url?.endsWith('/policy/snapshot')) bodies.push(body);
      res.statusCode = req.url?.endsWith('/policy/snapshot') ? answer(body) : 404;
      res.end('{}');
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;
  return { url: `http://127.0.0.1:${port}/intercept`, bodies, close: () => server.close() };
}

describe('node9 policy push ships add-ons (integration)', () => {
  beforeAll(() => {
    expect(fs.existsSync(CLI), `built CLI missing at ${CLI}; run npm run build`).toBe(true);
  });

  it('sends skills and MCP servers as names and hashes, never the token or the password', async () => {
    const home = seededHome();
    const srv = await listener(() => 200);
    try {
      const r = await run(home, srv.url);
      expect(r.code, r.out).toBe(0);
      expect(srv.bodies).toHaveLength(1);
      const addons = srv.bodies[0].addons as {
        skills: Array<Record<string, unknown>>;
        mcp: Array<Record<string, unknown>>;
      };
      expect(addons.skills).toEqual([
        expect.objectContaining({
          name: 'deploy-helper',
          agent: 'claude',
          scope: 'user',
          grants: ['Bash'],
        }),
      ]);
      expect(addons.mcp).toEqual([
        expect.objectContaining({
          name: 'db',
          identity: 'npm:@modelcontextprotocol/server-postgres',
        }),
      ]);
      const wire = JSON.stringify(srv.bodies[0]);
      expect(wire).not.toContain(TOKEN);
      expect(wire).not.toContain('hunter2');
      expect(wire).not.toContain(home);
    } finally {
      srv.close();
    }
  });

  it('retries without the field when an older dashboard rejects it', async () => {
    const home = seededHome();
    const srv = await listener((b) => ('addons' in b ? 400 : 200));
    try {
      const r = await run(home, srv.url);
      expect(r.code, r.out).toBe(0);
      expect(srv.bodies).toHaveLength(2);
      expect('addons' in srv.bodies[1]).toBe(false);
      expect(srv.bodies[1].mode).toBeDefined();
    } finally {
      srv.close();
    }
  });
});
