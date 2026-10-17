// fw#318 P5 (design untrusted-content-proxy-p2-p5-code-design.md section 7,
// rows B1-B3) through a real daemon: a card that carries exposure
// destinations and the session id, answered with "allow + trust", writes the
// trusted-recipients file and clears those destinations for the session.
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'fs';
import path from 'path';
import { startDaemonHook, cliExists, type DaemonHook } from './helpers/daemon-hook';

const itUnix = it.skipIf(process.platform === 'win32' || !cliExists);
let h: DaemonHook;

beforeAll(async () => {
  if (!cliExists || process.platform === 'win32') return;
  // A card must outlive the test's decision: the default timeout is 0.
  h = await startDaemonHook({ sessionId: 'trust-btn', settings: { approvalTimeoutMs: 10_000 } });
}, 20_000);

afterAll(() => h?.dispose());

async function post(route: string, body: unknown): Promise<{ status: number; json: unknown }> {
  const res = await fetch(`http://127.0.0.1:${h.port}${route}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Node9-Internal': h.token() },
    body: JSON.stringify(body),
  });
  let json: unknown = null;
  try {
    json = await res.json();
  } catch {
    json = null;
  }
  return { status: res.status, json };
}

describe('allow + trust this address', () => {
  itUnix('B1/B2: the file is written and the session exposure is cleared', async () => {
    // The session read a page naming the address.
    expect(
      h.log(
        'WebFetch',
        { url: 'https://news.example/a' },
        { output: 'Contact press@news.example for questions about this page and more.' }
      ).status
    ).toBe(0);
    // A card as the hook registers one for an exposure review.
    const reg = await post('/check', {
      toolName: 'mcp__gmail__send_email',
      args: { to: 'press@news.example' },
      agent: 'Claude Code',
      mcpServer: 'gmail',
      fromCLI: false,
      skipBackgroundAuth: true,
      sessionId: 'trust-btn',
      riskMetadata: {
        intent: 'EXEC',
        tier: 6,
        blockedByLabel: '🛡️ Node9 Exposure',
        ruleName: 'exposure',
        ruleDescription: 'this session read a web page',
        exposureDestinations: ['email:press@news.example'],
      },
    });
    expect(reg.status).toBe(200);
    const id = (reg.json as { id: string }).id;
    const dec = await post(`/decision/${id}`, {
      decision: 'allow',
      source: 'terminal',
      trustRecipients: true,
    });
    expect(dec.status).toBe(200);
    const file = JSON.parse(
      fs.readFileSync(path.join(h.home, '.node9', 'trusted-recipients.json'), 'utf8')
    ) as { entries: { value: string; addedBy: string }[] };
    expect(file.entries).toEqual([
      expect.objectContaining({ value: 'email:press@news.example', addedBy: 'approval' }),
    ]);
    // The session's record holds the approval key.
    const list = await fetch(`http://127.0.0.1:${h.port}/session-exposure/list`, {
      headers: { 'X-Node9-Internal': h.token() },
    });
    const records = (
      (await list.json()) as { records: { sessionId: string; approved: string[] }[] }
    ).records;
    expect(records.find((r) => r.sessionId === 'trust-btn')?.approved).toEqual([
      'mcp__gmail__send_email|email:press@news.example',
    ]);
    // And the next send to that address, through the hook, is not held.
    expect(
      h.check('mcp__gmail__send_email', { to: 'press@news.example', body: 'x' }).ask
    ).toBeUndefined();
  });

  itUnix('a card without destinations ignores the flag', async () => {
    const reg = await post('/check', {
      toolName: 'Bash',
      args: { command: 'git push --force' },
      fromCLI: false,
      skipBackgroundAuth: true,
      riskMetadata: { intent: 'EXEC', tier: 4, blockedByLabel: 'Smart Rule' },
    });
    const id = (reg.json as { id: string }).id;
    const before = fs.readFileSync(path.join(h.home, '.node9', 'trusted-recipients.json'), 'utf8');
    await post(`/decision/${id}`, { decision: 'allow', source: 'terminal', trustRecipients: true });
    expect(fs.readFileSync(path.join(h.home, '.node9', 'trusted-recipients.json'), 'utf8')).toBe(
      before
    );
  });
});
