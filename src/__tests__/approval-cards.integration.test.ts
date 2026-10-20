/**
 * Approval cards on a real daemon (approval-card design, step 2).
 *
 * Each row was wrong before the CardStore:
 * - a review card of node9's own hook was checked again by the daemon,
 *   without the project's config, and a project rule's review or block was
 *   allowed (defect 1, a security bypass);
 * - a decision made before the hook's /wait was deleted with the card (404);
 * - a late /resolve overwrote a person's decision;
 * - a second /wait replaced the first;
 * - node9 monitor's trust key wrote a permanent deny;
 * - closing node9 tail abandoned cards Slack could still answer.
 *
 * A real daemon from dist/cli.js in an isolated HOME on its own port
 * (NODE9_DAEMON_PORT, honoured under NODE9_TESTING=1).
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, spawnSync, type ChildProcess } from 'child_process';
import fs from 'fs';
import http from 'http';
import net from 'net';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      server.close(() => resolve(port));
    });
  });
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

interface Record_ {
  decision: string;
  decidedBy: string;
  channel?: string;
  label?: string;
  reason?: string;
  standing?: string;
}

interface Daemon {
  port: number;
  base: string;
  token: string;
  check(body: Record<string, unknown>): Promise<{ id: string; deadline: number | null }>;
  wait(id: string, opts?: { token?: boolean; signal?: AbortSignal }): Promise<Response>;
  decision(id: string, body: Record<string, unknown>): Promise<Response>;
  resolve(id: string, body: Record<string, unknown>): Promise<Response>;
  stop(): void;
}

async function startDaemon(config: Record<string, unknown>): Promise<Daemon> {
  if (!fs.existsSync(CLI)) {
    throw new Error(`dist/cli.js not found. Run "npm run build" first.\nExpected: ${CLI}`);
  }
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-cards-'));
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  fs.writeFileSync(path.join(home, '.node9', 'config.json'), JSON.stringify(config));
  const port = await freePort();
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    NODE9_TESTING: '1',
    NODE9_DAEMON_PORT: String(port),
  };
  // The daemon runs from HOME, never from a project directory: a project's
  // config can only reach it through the cwd a caller sends.
  const proc: ChildProcess = spawn(process.execPath, [CLI, 'daemon', 'start'], {
    env,
    cwd: home,
    stdio: 'pipe',
  });
  const base = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 8000;
  for (;;) {
    try {
      if ((await fetch(`${base}/settings`)).status < 500) break;
    } catch {
      /* not up yet */
    }
    if (Date.now() > deadline) {
      proc.kill();
      throw new Error('Daemon did not start within 8s');
    }
    await sleep(100);
  }
  const pid = JSON.parse(fs.readFileSync(path.join(home, '.node9', 'daemon.pid'), 'utf-8')) as {
    internalToken?: string;
  };
  const token = pid.internalToken ?? '';
  const post = (url: string, body: Record<string, unknown>, withToken = true) =>
    fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(withToken && { 'X-Node9-Internal': token }),
      },
      body: JSON.stringify(body),
    });
  return {
    port,
    base,
    token,
    async check(body) {
      const res = await post(`${base}/check`, body, false);
      expect(res.ok).toBe(true);
      return (await res.json()) as { id: string; deadline: number | null };
    },
    wait: (id, opts = {}) =>
      fetch(`${base}/wait/${id}`, {
        ...(opts.signal && { signal: opts.signal }),
        headers: opts.token === false ? {} : { 'X-Node9-Internal': token },
      }),
    decision: (id, body) => post(`${base}/decision/${id}`, body),
    resolve: (id, body) => post(`${base}/resolve/${id}`, body),
    stop() {
      spawnSync(process.execPath, [CLI, 'daemon', 'stop'], { env, timeout: 3000 });
      if (proc.exitCode === null) proc.kill();
      fs.rmSync(home, { recursive: true, force: true });
    },
  };
}

function projectWith(rules: Array<Record<string, unknown>>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-cards-proj-'));
  fs.writeFileSync(
    path.join(dir, 'node9.config.json'),
    JSON.stringify({ policy: { smartRules: rules } })
  );
  return dir;
}

const rule = (verdict: 'review' | 'block', prefix: string) => ({
  name: `${verdict}-${prefix}`,
  tool: 'bash',
  conditions: [{ field: 'command', op: 'matches', value: `^echo ${prefix}` }],
  conditionMode: 'all',
  verdict,
  reason: `the project rule ${verdict}s this`,
});

/** Still open after a moment: a person's answer is accepted. */
async function stillOpen(d: Daemon, id: string): Promise<boolean> {
  await sleep(1500);
  const res = await d.decision(id, { decision: 'deny', source: 'terminal' });
  return res.status === 200;
}

describe('approval cards on a real daemon', () => {
  let d: Daemon;
  let project: string;
  beforeAll(async () => {
    d = await startDaemon({
      settings: {
        mode: 'standard',
        autoStartDaemon: false,
        approvalTimeoutMs: 60_000,
        approvers: { native: false, browser: false, cloud: false, terminal: true },
      },
    });
    project = projectWith([rule('review', 'proj-review'), rule('block', 'proj-block')]);
  }, 15_000);
  afterAll(() => {
    d?.stop();
    if (project) fs.rmSync(project, { recursive: true, force: true });
  });

  // Defect 1 (security). Before: the daemon checked the card again without
  // the project's config, found no rule, and allowed it within milliseconds.
  it.each([
    ['review', 'echo proj-review now'],
    ['block (softened to a review by the hook)', 'echo proj-block now'],
  ])("a hook's card for a project %s rule waits for a person", async (_name, command) => {
    const { id } = await d.check({
      toolName: 'bash',
      args: { command },
      cwd: project,
      fromCLI: true,
      localSmartRuleMatched: true,
    });
    expect(await stillOpen(d, id)).toBe(true);
    const body = (await (await d.wait(id)).json()) as { record: Record_ };
    expect(body.record).toMatchObject({
      decision: 'deny',
      decidedBy: 'person',
      channel: 'terminal',
    });
  });

  // The Python SDK sends no fromCLI: the daemon checks its call, now with the
  // SDK's working directory.
  it("an SDK card is checked with the caller's project config", async () => {
    const blocked = await d.check({
      toolName: 'bash',
      args: { command: 'echo proj-block x' },
      cwd: project,
    });
    const b = (await (await d.wait(blocked.id)).json()) as { record: Record_; source?: string };
    expect(b.record).toMatchObject({ decision: 'deny', decidedBy: 'policy' });
    expect(b.source).toBe('policy');

    const reviewed = await d.check({
      toolName: 'bash',
      args: { command: 'echo proj-review x' },
      cwd: project,
    });
    expect(await stillOpen(d, reviewed.id)).toBe(true);

    const plain = await d.check({
      toolName: 'bash',
      args: { command: 'echo plain' },
      cwd: project,
    });
    const p = (await (await d.wait(plain.id)).json()) as { record: Record_ };
    expect(p.record).toMatchObject({ decision: 'allow', decidedBy: 'policy' });
  });

  // Defect 5. Before: the timer stored its deny and deleted the card at once,
  // so a /wait a moment later got 404 ("Approval Unavailable").
  it('a timer that fires before the hook waits is still read', async () => {
    const { id, deadline } = await d.check({
      toolName: 'bash',
      args: { command: 'echo late-wait' },
      fromCLI: true,
      timeoutMs: 800,
    });
    expect(typeof deadline).toBe('number');
    await sleep(1300);
    const res = await d.wait(id);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { record: Record_; source?: string };
    expect(body.record.decidedBy).toBe('timer');
    expect(body.source).toBe('timeout');
  });

  // Defect 6. Before: /resolve did not check for an earlier decision and
  // overwrote it.
  it("a late /resolve cannot overwrite a person's decision, and learns it", async () => {
    const { id } = await d.check({
      toolName: 'bash',
      args: { command: 'echo race' },
      fromCLI: true,
    });
    expect((await d.decision(id, { decision: 'allow', source: 'terminal' })).status).toBe(200);
    const r = await d.resolve(id, { decision: 'deny' });
    const rb = (await r.json()) as { won: boolean; record: Record_ };
    expect(rb.won).toBe(false);
    expect(rb.record).toMatchObject({ decision: 'allow', decidedBy: 'person' });
    const w = (await (await d.wait(id)).json()) as { record: Record_ };
    expect(w.record).toMatchObject({ decision: 'allow', decidedBy: 'person' });
  });

  // Defect 10. Before: a second /wait replaced the first.
  it('two waiters both get the decision', async () => {
    const { id } = await d.check({
      toolName: 'bash',
      args: { command: 'echo two' },
      fromCLI: true,
    });
    const a = d.wait(id);
    const b = d.wait(id);
    await sleep(200);
    await d.decision(id, { decision: 'deny', source: 'terminal' });
    for (const res of await Promise.all([a, b])) {
      const body = (await res.json()) as { decision: string };
      expect(body.decision).toBe('deny');
    }
  });

  // Defect 2. Before: trust with no duration fell through to a PERMANENT deny.
  it("node9 monitor's trust needs a duration; monitor is a person", async () => {
    const { id } = await d.check({
      toolName: 'bash',
      args: { command: 'echo monitor' },
      fromCLI: true,
    });
    const bad = await d.decision(id, { decision: 'trust', persist: true, source: 'dashboard' });
    expect(bad.status).toBe(400);
    const ok = await d.decision(id, {
      decision: 'trust',
      trustDuration: '30m',
      source: 'dashboard',
    });
    expect(ok.status).toBe(200);
    const body = (await (await d.wait(id)).json()) as { record: Record_ };
    expect(body.record).toMatchObject({
      decision: 'allow',
      decidedBy: 'person',
      channel: 'monitor',
      standing: 'trust',
    });
    // A trust is a standing decision: it does not count toward the "[a]
    // creates a permanent rule" hint, as before the card protocol.
    const next = (await (
      await fetch(`${d.base}/check`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          toolName: 'bash',
          args: { command: 'echo monitor' },
          fromCLI: true,
        }),
      })
    ).json()) as { allowCount: number };
    expect(next.allowCount).toBe(1);
  });

  it("a protocol-2 card's /wait needs the internal token", async () => {
    const { id } = await d.check({
      toolName: 'bash',
      args: { command: 'echo token' },
      fromCLI: true,
      protocol: 2,
    });
    expect((await d.wait(id, { token: false })).status).toBe(403);
    await d.decision(id, { decision: 'allow', source: 'terminal' });
    expect((await d.wait(id)).status).toBe(200);
  });
});

describe('closing node9 tail', () => {
  let d: Daemon;
  beforeAll(async () => {
    d = await startDaemon({
      settings: { mode: 'standard', autoStartDaemon: false, approvalTimeoutMs: 0 },
    });
  }, 15_000);
  afterAll(() => d?.stop());

  // Defect 8. Before: every card was abandoned, Slack's included.
  it('abandons only cards no other channel can answer', async () => {
    const localOnly = await d.check({
      toolName: 'bash',
      args: { command: 'echo local' },
      fromCLI: true,
      channels: ['terminal', 'monitor'],
    });
    const withSlack = await d.check({
      toolName: 'bash',
      args: { command: 'echo slack' },
      fromCLI: true,
      channels: ['terminal', 'monitor', 'cloud'],
    });
    // A tail connects, then closes.
    await new Promise<void>((resolve) => {
      const req = http.get(
        `${d.base}/events?capabilities=input`,
        { headers: { 'X-Node9-Internal': d.token } },
        (res) => {
          res.once('data', () => {
            req.destroy();
            resolve();
          });
        }
      );
    });
    await sleep(10_800);
    const a = (await (await d.wait(localOnly.id)).json()) as { record: Record_ };
    expect(a.record.decidedBy).toBe('abandoned');
    expect(await stillOpen(d, withSlack.id)).toBe(true);
  }, 20_000);
});
