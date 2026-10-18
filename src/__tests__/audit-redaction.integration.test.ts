// Integration cover for the redactArgs fix: the unit spec proves the returned
// object is shaped right, this proves the field actually lands in the file on
// disk. CLAUDE.md requires an integration test for anything that writes
// audit.log, and the whole point of the fix is that a field was reaching
// JSON.stringify and not the record.
//
// Runs under a temp HOME so it never touches the developer's real
// ~/.node9/audit.log; AUDIT_LOG_FILE is bound at module load from os.homedir(),
// which reads $HOME on POSIX, so HOME is set before the dynamic import.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

let tmpHome: string;
let originalHome: string | undefined;
let originalUserProfile: string | undefined;
let state: typeof import('../daemon/state.js');

beforeEach(async () => {
  tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-audit-redaction-'));
  originalHome = process.env.HOME;
  originalUserProfile = process.env.USERPROFILE;
  process.env.HOME = tmpHome;
  process.env.USERPROFILE = tmpHome;
  // Force re-import so the module-level AUDIT_LOG_FILE rebinds to tmpHome.
  vi.resetModules();
  state = await import('../daemon/state.js');
});

afterEach(() => {
  if (originalHome !== undefined) process.env.HOME = originalHome;
  else delete process.env.HOME;
  if (originalUserProfile !== undefined) process.env.USERPROFILE = originalUserProfile;
  else delete process.env.USERPROFILE;
  try {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  } catch {
    // best effort
  }
});

/** Read back what actually landed on disk, the way getAuditHistory does. */
function readAuditLog(): Array<Record<string, unknown>> {
  const file = path.join(tmpHome, '.node9', 'audit.log');
  return fs
    .readFileSync(file, 'utf-8')
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l) as Record<string, unknown>);
}

describe('appendAuditLog redaction (on-disk)', () => {
  it('writes an argument named __proto__ into the record', () => {
    // Args reach the daemon through readBody -> JSON.parse, which is the only
    // way `__proto__` exists as an own key. An object literal cannot express it.
    const args = JSON.parse('{"__proto__":"payload","command":"ls -la"}') as unknown;
    state.appendAuditLog({ toolName: 'Bash', args, decision: 'allow' });

    const [entry] = readAuditLog();
    const logged = entry.args as Record<string, unknown>;
    expect(Object.keys(logged)).toContain('__proto__');
    expect(logged.__proto__).toBe('payload');
    expect(logged.command).toBe('ls -la');
    expect(entry.tool).toBe('Bash');
    expect(entry.decision).toBe('allow');
  });

  it('still redacts secret-shaped keys on the way to disk', () => {
    const args = JSON.parse('{"apiKey":"sk-live-abcd","command":"curl x"}') as unknown;
    state.appendAuditLog({ toolName: 'Bash', args, decision: 'deny' });

    const logged = readAuditLog()[0].args as Record<string, unknown>;
    expect(logged.apiKey).toBe('[REDACTED]');
    expect(logged.command).toBe('curl x');
  });

  // fw#318 review P1: personal data is masked in the daemon's row too.
  it('masks an email address on the way to disk', () => {
    state.appendAuditLog({
      toolName: 'mcp__gmail__send_email',
      args: { to: 'dana@acme.example', body: 'hi' },
      decision: 'allow',
    });
    expect(readAuditLog()[0].args).toEqual({ to: 'd***@acme.example', body: 'hi' });
  });

  it('redacts secrets nested under a __proto__ argument', () => {
    const args = JSON.parse('{"__proto__":{"authToken":"sk-live-abcd"}}') as unknown;
    state.appendAuditLog({ toolName: 'Bash', args, decision: 'allow' });

    const logged = readAuditLog()[0].args as Record<string, unknown>;
    expect((logged.__proto__ as Record<string, unknown>).authToken).toBe('[REDACTED]');
  });

  it('leaves the entry readable by getAuditHistory', () => {
    const args = JSON.parse('{"__proto__":"payload","command":"ls"}') as unknown;
    state.appendAuditLog({ toolName: 'Bash', args, decision: 'allow' });

    const history = state.getAuditHistory(10);
    expect(history).toHaveLength(1);
    expect(Object.keys(history[0].args as Record<string, unknown>)).toContain('__proto__');
  });
});
