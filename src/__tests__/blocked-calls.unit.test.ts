/**
 * Unit tests: the blocked-call marker store behind the "ran after a block"
 * audit row (enforcement-proof-design.md, node9Firewall#461).
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  blockedCallKey,
  noteBlockedCall,
  resolveBlockedCall,
  BLOCKED_CALL_TTL_MS,
} from '../blocked-calls';

let dir: string;
let store: string;
const T0 = 1_800_000_000_000;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-blocked-calls-'));
  store = path.join(dir, 'blocked-calls.json');
  process.env.NODE9_BLOCKED_CALLS_STORE = store;
});
afterEach(() => {
  delete process.env.NODE9_BLOCKED_CALLS_STORE;
  fs.rmSync(dir, { recursive: true, force: true });
});

const marker = (key: string, ts = T0) => ({
  key,
  tool: 'Bash',
  agent: 'Codex',
  sessionId: 's1',
  checkId: 'commands.force-push',
  ruleName: 'block-force-push',
  ts,
});

describe('blockedCallKey', () => {
  it('is the per-call id for an agent whose after-run contract is verified', () => {
    expect(blockedCallKey({ tool_use_id: 'call_1' }, 'Codex')).toBe('tuid:call_1');
    expect(blockedCallKey({ tool_use_id: 'toolu_1' }, 'Claude Code')).toBe('tuid:toolu_1');
  });

  it('is null without a per-call id: a session, tool and args hash can match another call', () => {
    expect(
      blockedCallKey({ session_id: 's', tool_name: 'Bash', tool_input: { command: 'ls' } }, 'Codex')
    ).toBeNull();
    expect(blockedCallKey({ tool_use_id: '' }, 'Codex')).toBeNull();
  });

  it('is null for an agent whose after-run contract is not verified', () => {
    expect(blockedCallKey({ tool_use_id: 'x1' }, 'Gemini CLI')).toBeNull();
    expect(blockedCallKey({ tool_use_id: 'x1' }, undefined)).toBeNull();
  });
});

describe('blocked-call markers', () => {
  it('a noted block resolves once, with what the block recorded', () => {
    noteBlockedCall(marker('tuid:a'));
    const hit = resolveBlockedCall({ tool_use_id: 'a' }, T0 + 1000);
    expect(hit).toMatchObject({
      key: 'tuid:a',
      tool: 'Bash',
      agent: 'Codex',
      checkId: 'commands.force-push',
      ruleName: 'block-force-push',
    });
    expect(resolveBlockedCall({ tool_use_id: 'a' }, T0 + 2000)).toBeNull();
  });

  it('a call that was never blocked does not resolve', () => {
    noteBlockedCall(marker('tuid:a'));
    expect(resolveBlockedCall({ tool_use_id: 'b' }, T0 + 1000)).toBeNull();
    expect(resolveBlockedCall({ tool_use_id: 'a' }, T0 + 1000)).not.toBeNull();
  });

  it('with no store on disk, resolving reads nothing and returns null', () => {
    expect(fs.existsSync(store)).toBe(false);
    expect(resolveBlockedCall({ tool_use_id: 'a' }, T0)).toBeNull();
    expect(fs.existsSync(store)).toBe(false);
  });

  it('an expired marker does not resolve', () => {
    noteBlockedCall(marker('tuid:a'));
    expect(resolveBlockedCall({ tool_use_id: 'a' }, T0 + BLOCKED_CALL_TTL_MS + 1)).toBeNull();
  });

  it('the same call blocked twice resolves to one finding', () => {
    noteBlockedCall(marker('tuid:a'));
    noteBlockedCall(marker('tuid:a', T0 + 10));
    expect(resolveBlockedCall({ tool_use_id: 'a' }, T0 + 1000)).not.toBeNull();
    expect(resolveBlockedCall({ tool_use_id: 'a' }, T0 + 2000)).toBeNull();
  });

  it('the store file goes away with its last marker', () => {
    noteBlockedCall(marker('tuid:a'));
    expect(fs.existsSync(store)).toBe(true);
    resolveBlockedCall({ tool_use_id: 'a' }, T0 + 1000);
    expect(fs.existsSync(store)).toBe(false);
  });

  it('keeps the newest markers when the store is full', () => {
    for (let i = 0; i < 520; i++) noteBlockedCall(marker(`tuid:${i}`, T0 + i));
    expect(resolveBlockedCall({ tool_use_id: '0' }, T0 + 600)).toBeNull();
    expect(resolveBlockedCall({ tool_use_id: '519' }, T0 + 600)).not.toBeNull();
  });

  it('a corrupt store reads as empty and is replaced by the next note', () => {
    fs.writeFileSync(store, '{not json');
    expect(resolveBlockedCall({ tool_use_id: 'a' }, T0)).toBeNull();
    noteBlockedCall(marker('tuid:a'));
    expect(resolveBlockedCall({ tool_use_id: 'a' }, T0 + 1)).not.toBeNull();
  });

  it('a store that cannot be written never throws', () => {
    process.env.NODE9_BLOCKED_CALLS_STORE = path.join(dir, 'missing', 'x', '\0bad', 'store.json');
    expect(() => noteBlockedCall(marker('tuid:a'))).not.toThrow();
    expect(resolveBlockedCall({ tool_use_id: 'a' }, T0)).toBeNull();
  });

  it('stores no arguments of the call', () => {
    noteBlockedCall(marker('tuid:a'));
    const raw = fs.readFileSync(store, 'utf-8');
    expect(Object.keys(JSON.parse(raw).entries[0]).sort()).toEqual(
      ['agent', 'checkId', 'key', 'ruleName', 'sessionId', 'tool', 'ts'].sort()
    );
  });
});
