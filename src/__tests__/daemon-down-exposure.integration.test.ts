// A daemon that does not answer must not quietly switch the outside-content
// check off (node9Firewall#445 follow-up, part 2). With no daemon nobody knows
// what the session read: Standard lets the call through and records that in
// hook-debug.log; Strict holds a send to an unknown destination, as after
// reading outside content. The real built hook, a real daemon on its own
// port that the test stops. Requires `npm run build`.
import { describe, it, expect, afterEach } from 'vitest';
import fs from 'fs';
import path from 'path';
import { startDaemonHook, cliExists, type DaemonHook } from './helpers/daemon-hook';

const itUnix = it.skipIf(process.platform === 'win32' || !cliExists);
let h: DaemonHook | undefined;

afterEach(() => {
  h?.dispose();
  h = undefined;
});

const debugLog = (home: string) => {
  const p = path.join(home, '.node9', 'hook-debug.log');
  return fs.existsSync(p) ? fs.readFileSync(p, 'utf-8') : '';
};

describe('the daemon is down', () => {
  itUnix('the agent stopping the daemon is held (part 1, through the hook)', async () => {
    h = await startDaemonHook({ sessionId: 'down-1' });
    const r = h.check('Bash', { command: 'node9 daemon stop' });
    expect(r.status).toBe(0);
    expect(r.ask).toBe('ask');
    expect(r.reason).toMatch(/wants to stop node9/);
  });

  itUnix('Standard: a send goes through and the unknown state is recorded', async () => {
    h = await startDaemonHook({ sessionId: 'down-2' });
    h.stopDaemon();
    const r = h.check('mcp__gmail__send_email', { to: 'stranger@example.org', body: 'hi' });
    expect(r.status).toBe(0);
    expect(r.ask).toBeUndefined();
    expect(debugLog(h.home)).toMatch(/exposure-unavailable/);
  });

  itUnix('Strict: a send to an unknown address is held while the daemon is down', async () => {
    h = await startDaemonHook({ sessionId: 'down-3', settings: { mode: 'strict' } });
    h.stopDaemon();
    const r = h.check('mcp__gmail__send_email', { to: 'stranger@example.org', body: 'hi' });
    expect(r.status).toBe(0);
    expect(r.ask).toBe('ask');
    expect(r.reason).toMatch(/daemon is not running/);
    expect(r.reason).toMatch(/stranger@example\.org/);
  });

  itUnix('Strict: with the daemon up and nothing read, the same send is allowed', async () => {
    h = await startDaemonHook({ sessionId: 'down-4', settings: { mode: 'strict' } });
    const r = h.check('mcp__gmail__send_email', { to: 'stranger@example.org', body: 'hi' });
    expect(r.status).toBe(0);
    expect(r.ask).toBeUndefined();
  });
});
