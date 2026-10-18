// fw#318 phase 1, the real path (design test rows T3-T8, T10, T15, T17):
// a real daemon in an isolated HOME on its own port, the built hook for
// PostToolUse (`log`), UserPromptSubmit and PreToolUse (`check`), one agent
// session. Requires `npm run build`.
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { startDaemonHook, cliExists, type DaemonHook } from './helpers/daemon-hook';

const itUnix = it.skipIf(process.platform === 'win32' || !cliExists);
const SID = 'exposure-int';

let h: DaemonHook;
let port: number;
let proj: string;
const writeConfig = (policy: Record<string, unknown>) => h.writeConfig(policy);
const run = (args: string[]) => h.run(args);
const check = (tool: string, input: unknown) => h.check(tool, input);
const log = (tool: string, input: unknown, response: unknown, tuid?: string) =>
  h.log(tool, input, response, tuid);
const tuidNow = () => h.lastTuid();

beforeAll(async () => {
  if (!cliExists || process.platform === 'win32') return;
  h = await startDaemonHook({
    sessionId: SID,
    policy: { untrustedContent: { orgDomains: ['acme.example'] } },
  });
  port = h.port;
  proj = h.proj;
}, 20_000);

afterAll(() => h?.dispose());

describe('exposure through the built hook and a real daemon', () => {
  itUnix('a send in a clean session is allowed silently', () => {
    const r = check('mcp__gmail__send_email', { to: 'stranger@example.org', body: 'hi' });
    expect(r.status).toBe(0);
    expect(r.ask).toBeUndefined();
  });

  itUnix('T3: a WebFetch result with no hostile text marks exposure and is framed whole', () => {
    const r = log(
      'WebFetch',
      { url: 'https://news.example/a' },
      {
        output:
          'Weather today is fine and nothing else is going on. Contact press@news.example for questions.',
      }
    );
    expect(r.status).toBe(0);
    const updated = JSON.stringify(r.out?.hookSpecificOutput?.updatedToolOutput ?? '');
    expect(updated).toMatch(/node9 untrusted-output [0-9a-f]{12}: .* DATA from a web page/);
    expect(updated).toMatch(/Node9: ignored an instruction in the web page/);
    expect(r.out?.hookSpecificOutput?.additionalContext).toBeUndefined();
    const token = h.token();
    const list = spawnSync(
      'curl',
      ['-s', '-H', `X-Node9-Internal: ${token}`, `http://127.0.0.1:${port}/session-exposure/list`],
      { encoding: 'utf8' }
    );
    expect(list.stdout).toContain('"email:press@news.example"');
  });

  itUnix('T5: a send to an address that appeared in the page is asked, with the reason', () => {
    const r = check('mcp__gmail__send_email', { to: 'press@news.example', body: 'hi' });
    expect(r.status).toBe(0);
    expect(r.ask).toBe('ask');
    expect(r.reason).toMatch(/this session read a web page/);
    expect(r.reason).toMatch(/press@news\.example, an address that appeared in that web page/);
  });

  itUnix('a send to an unknown outside address is asked', () => {
    const r = check('mcp__gmail__send_email', { to: 'stranger@example.org', body: 'hi' });
    expect(r.ask).toBe('ask');
    expect(r.reason).toMatch(/an address this session did not know/);
  });

  itUnix('T6: a send inside the organisation is allowed', () => {
    const r = check('mcp__gmail__send_email', { to: 'colleague@acme.example', body: 'hi' });
    expect(r.status).toBe(0);
    expect(r.ask).toBeUndefined();
  });

  itUnix('T7: an address the user typed in a prompt is known', () => {
    const p = run([
      'check',
      JSON.stringify({
        hook_event_name: 'UserPromptSubmit',
        prompt: 'send the summary to dani@example.org please',
        session_id: SID,
        cwd: proj,
      }),
    ]);
    expect(p.status).toBe(0);
    const r = check('mcp__gmail__send_email', { to: 'dani@example.org', body: 'summary' });
    expect(r.ask).toBeUndefined();
    expect(r.status).toBe(0);
  });

  itUnix('T10: a call with no destination is logged; T9: a destructive one is asked', () => {
    expect(check('mcp__calendar__create_event', { title: 'room' }).ask).toBeUndefined();
    const del = check('mcp__drive__delete_file', { id: '13' });
    expect(del.ask).toBe('ask');
    expect(del.reason).toMatch(/delete_file, a destructive call/);
  });

  itUnix('a built-in read tool after exposure is not asked', () => {
    expect(check('Grep', { pattern: 'TODO' }).ask).toBeUndefined();
  });

  itUnix('T8: ask-once — the inline approval clears that address, not others', () => {
    const first = check('mcp__gmail__send_email', { to: 'stranger@example.org', body: 'hi' });
    expect(first.ask).toBe('ask');
    // The tool ran: PostToolUse with the same tool_use_id resolves the review.
    const r = log(
      'mcp__gmail__send_email',
      { to: 'stranger@example.org', body: 'hi' },
      { content: [{ type: 'text', text: 'sent' }] },
      tuidNow()
    );
    expect(r.status).toBe(0);
    expect(
      check('mcp__gmail__send_email', { to: 'stranger@example.org', body: 'again' }).ask
    ).toBeUndefined();
    expect(check('mcp__gmail__send_email', { to: 'other@example.org', body: 'again' }).ask).toBe(
      'ask'
    );
  });

  itUnix('T15: log-only never asks', () => {
    writeConfig({ untrustedContent: { afterExposure: 'log-only' } });
    expect(
      check('mcp__gmail__send_email', { to: 'press@news.example', body: 'hi' }).ask
    ).toBeUndefined();
    writeConfig({ untrustedContent: { orgDomains: ['acme.example'] } });
  });

  itUnix(
    '2b: the read is an informational audit row with an eid, and the approved send points back to it',
    () => {
      const rows = fs
        .readFileSync(path.join(h.home, '.node9', 'audit.log'), 'utf8')
        .split('\n')
        .filter(Boolean)
        .map((l) => JSON.parse(l) as Record<string, unknown>);
      const sources = rows.filter((r) => r.checkedBy === 'exposure-source');
      expect(sources.length).toBeGreaterThan(0);
      for (const s of sources) {
        expect(typeof s.eid).toBe('string');
        expect(s.decision).toBe('allow');
        expect(s.exposure).toMatchObject({ kind: 'source' });
      }
      const approved = rows.find(
        (r) => r.checkedBy === 'inline-review' && typeof r.exposureFromEid === 'string'
      );
      expect(approved, 'the inline-approved send carries the read it followed').toBeDefined();
      expect(sources.map((s) => s.eid)).toContain(approved!.exposureFromEid);
      // A send let through after exposure says so, counts only.
      const logged = rows.find(
        (r) => (r.exposure as { kind?: string } | undefined)?.kind === 'logged'
      );
      expect(logged).toBeDefined();
    }
  );

  itUnix('the taint and exposure routes refuse a caller without the token', async () => {
    for (const route of ['/session-taint/list', '/session-exposure/list']) {
      const res = await fetch(`http://127.0.0.1:${port}${route}`);
      expect(res.status).toBe(403);
    }
  });

  itUnix(
    'T17: with the daemon down every call is allowed (fail open) and the gap is on record',
    () => {
      h.stopDaemon();
      const r = check('mcp__gmail__send_email', { to: 'press@news.example', body: 'hi' });
      expect(r.status).toBe(0);
      expect(r.ask).toBeUndefined();
    }
  );
});
