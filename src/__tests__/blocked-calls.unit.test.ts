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

let root: string;
let dir: string;
const T0 = 1_800_000_000_000;

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-blocked-calls-'));
  dir = path.join(root, 'blocked-calls');
  process.env.NODE9_BLOCKED_CALLS_DIR = dir;
});
afterEach(() => {
  delete process.env.NODE9_BLOCKED_CALLS_DIR;
  fs.rmSync(root, { recursive: true, force: true });
});

const call = (id: string, session = 's1') => ({ tool_use_id: id, session_id: session });
const marker = (id: string, ts = T0, session = 's1') => ({
  key: blockedCallKey(call(id, session), 'Codex')!,
  tool: 'Bash',
  agent: 'Codex',
  sessionId: session,
  checkId: 'commands.force-push',
  ruleName: 'block-force-push',
  ts,
});
const files = () => (fs.existsSync(dir) ? fs.readdirSync(dir) : []);

describe('blockedCallKey', () => {
  it('is the per-call id within its session, for an agent whose after-run contract is verified', () => {
    expect(blockedCallKey(call('call_1'), 'Codex')).toBe('tuid:s1|call_1');
    expect(blockedCallKey(call('toolu_1'), 'Claude Code')).toBe('tuid:s1|toolu_1');
    expect(blockedCallKey({ tool_use_id: 'x' }, 'Codex')).toBe('tuid:|x');
  });

  it('is null without a per-call id: a session, tool and args hash can match another call', () => {
    expect(
      blockedCallKey({ session_id: 's', tool_name: 'Bash', tool_input: { command: 'ls' } }, 'Codex')
    ).toBeNull();
    expect(blockedCallKey({ tool_use_id: '' }, 'Codex')).toBeNull();
  });

  it('is null for an agent whose after-run contract is not verified', () => {
    expect(blockedCallKey(call('x1'), 'Gemini CLI')).toBeNull();
    expect(blockedCallKey(call('x1'), undefined)).toBeNull();
  });
});

describe('blocked-call markers', () => {
  it('a noted block resolves once, with what the block recorded', () => {
    noteBlockedCall(marker('a'));
    expect(resolveBlockedCall(call('a'), T0 + 1000)).toMatchObject({
      tool: 'Bash',
      agent: 'Codex',
      checkId: 'commands.force-push',
      ruleName: 'block-force-push',
    });
    expect(resolveBlockedCall(call('a'), T0 + 2000)).toBeNull();
  });

  it('a call that was never blocked does not resolve', () => {
    noteBlockedCall(marker('a'));
    expect(resolveBlockedCall(call('b'), T0 + 1000)).toBeNull();
    expect(resolveBlockedCall(call('a'), T0 + 1000)).not.toBeNull();
  });

  it('the same call id in another session is another call', () => {
    // A provider that numbers its calls from zero in every session.
    noteBlockedCall(marker('call_0', T0, 'session-a'));
    expect(resolveBlockedCall(call('call_0', 'session-b'), T0 + 1000)).toBeNull();
    expect(resolveBlockedCall(call('call_0', 'session-a'), T0 + 1000)).not.toBeNull();
  });

  it('with no store on disk, resolving creates nothing and returns null', () => {
    expect(resolveBlockedCall(call('a'), T0)).toBeNull();
    expect(fs.existsSync(dir)).toBe(false);
  });

  it('an expired marker does not resolve', () => {
    noteBlockedCall(marker('a'));
    expect(resolveBlockedCall(call('a'), T0 + BLOCKED_CALL_TTL_MS + 1)).toBeNull();
  });

  it('the same call blocked twice resolves to one finding', () => {
    noteBlockedCall(marker('a'));
    noteBlockedCall(marker('a', T0 + 10));
    expect(files()).toHaveLength(1);
    expect(resolveBlockedCall(call('a'), T0 + 1000)).not.toBeNull();
    expect(resolveBlockedCall(call('a'), T0 + 2000)).toBeNull();
  });

  it('markers of calls blocked together do not overwrite each other', () => {
    // One file per call: nothing is read, changed and written back.
    for (let i = 0; i < 5; i++) noteBlockedCall(marker(`p${i}`));
    expect(files()).toHaveLength(5);
    for (let i = 0; i < 5; i++) expect(resolveBlockedCall(call(`p${i}`), T0 + 1000)).not.toBeNull();
    expect(files()).toHaveLength(0);
  });

  it('a marker another hook already claimed is not a second finding', () => {
    noteBlockedCall(marker('a'));
    // The other hook read the marker and removed it between this hook's read
    // and its own removal: the removal fails and nothing is reported.
    const realUnlink = fs.unlinkSync;
    fs.unlinkSync = ((p: fs.PathLike) => {
      realUnlink(p);
      throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    }) as typeof fs.unlinkSync;
    try {
      expect(resolveBlockedCall(call('a'), T0 + 1000)).toBeNull();
    } finally {
      fs.unlinkSync = realUnlink;
    }
  });

  it('a new block sweeps expired markers, files a crashed hook left, and the oldest past the cap', () => {
    noteBlockedCall(marker('old', T0));
    fs.writeFileSync(path.join(dir, 'abc.json.123.tmp'), '{}');
    fs.utimesSync(path.join(dir, 'abc.json.123.tmp'), T0 / 1000, T0 / 1000);
    noteBlockedCall(marker('new', T0 + BLOCKED_CALL_TTL_MS + 5));
    expect(files()).toHaveLength(1);
    expect(resolveBlockedCall(call('new'), T0 + BLOCKED_CALL_TTL_MS + 10)).not.toBeNull();

    for (let i = 0; i < 505; i++) noteBlockedCall(marker(`c${i}`, T0 + i * 1000));
    expect(files()).toHaveLength(500);
    expect(resolveBlockedCall(call('c0'), T0 + 600_000)).toBeNull();
    expect(resolveBlockedCall(call('c504'), T0 + 600_000)).not.toBeNull();
  });

  it('a corrupt marker, or one planted under another call, resolves to nothing and is removed', () => {
    noteBlockedCall(marker('a'));
    const file = path.join(dir, files()[0]);
    fs.writeFileSync(file, '{not json');
    expect(resolveBlockedCall(call('a'), T0 + 1)).toBeNull();
    noteBlockedCall(marker('a'));
    fs.writeFileSync(file, JSON.stringify({ ...marker('other'), ts: T0 }));
    expect(resolveBlockedCall(call('a'), T0 + 1)).toBeNull();
    expect(files()).toHaveLength(0);
  });

  it('a store that cannot be written never throws', () => {
    fs.writeFileSync(path.join(root, 'file'), 'x');
    process.env.NODE9_BLOCKED_CALLS_DIR = path.join(root, 'file', 'sub');
    expect(() => noteBlockedCall(marker('a'))).not.toThrow();
    expect(resolveBlockedCall(call('a'), T0)).toBeNull();
  });

  it('the file name is a hash and the marker stores no arguments of the call', () => {
    noteBlockedCall({ ...marker('a'), key: blockedCallKey(call('../../x'), 'Codex')! });
    expect(files()).toHaveLength(1);
    expect(files()[0]).toMatch(/^[0-9a-f]{64}\.json$/);
    noteBlockedCall(marker('b'));
    const raw = files().map((f) => JSON.parse(fs.readFileSync(path.join(dir, f), 'utf-8')));
    for (const m of raw)
      expect(Object.keys(m).sort()).toEqual(
        ['agent', 'checkId', 'key', 'ruleName', 'sessionId', 'tool', 'ts'].sort()
      );
  });
});
