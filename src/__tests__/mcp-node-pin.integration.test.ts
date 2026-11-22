/**
 * node9's MCP entries must start where the agent's PATH holds an old Node.
 *
 * The incident (2026-11-21): the Claude desktop app starts MCP servers with
 * the Node its PATH holds, Node 18 on that machine. node9 wrote its entries as
 * `{ command: 'node9' }`, the bin's `#!/usr/bin/env node` picked that Node,
 * node9 refuses to run on it, and the agent reported only "failed to connect"
 * for node9's own server and for every server node9 had wrapped.
 *
 * These rows write the entries through the real CLI (no NODE9_TESTING, so the
 * real launcher is written), read them back from the agent's config file, and
 * spawn exactly `command` + `args` with an old Node first on PATH.
 *
 * The old Node is a fake: an executable named `node` that answers `--version`
 * and fails on everything else. It proves that the entry never reaches PATH's
 * node, and needs no real Node 18 on CI. Set NODE9_TEST_OLD_NODE to the path
 * of a real old Node to also run the rows against it.
 *
 * Requires `npm run build` (the suite checks for dist/cli.js).
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, type SpawnSyncReturns } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const NODE = process.execPath;

const cliExists = fs.existsSync(CLI);
if (!cliExists) {
  console.warn(
    `[mcp-node-pin] All integration tests skipped: dist/cli.js not found. Run "npm run build" first.\nExpected: ${CLI}`
  );
}
if (process.platform === 'win32') {
  console.warn('[mcp-node-pin] All integration tests skipped on Windows: the launcher is POSIX');
}
const skip = process.platform === 'win32' || !cliExists;
const itUnix = it.skipIf(skip);
const REAL_OLD_NODE = process.env.NODE9_TEST_OLD_NODE ?? '';
const itRealOldNode = it.skipIf(skip || REAL_OLD_NODE === '');

const FAKE_NODE_MARK = 'fake old node: refusing to run';

let root: string;
let home: string;
let oldNodeDir: string; // holds the fake `node`
let bareBinDir: string; // holds a `node9` that links to the built CLI
let upstreamScript: string;

const cursorMcp = () => path.join(home, '.cursor', 'mcp.json');
const launcher = () => path.join(home, '.node9', 'bin', 'node9');

interface Entry {
  command: string;
  args: string[];
  env?: Record<string, string>;
}
const readEntry = (name: string): Entry =>
  (JSON.parse(fs.readFileSync(cursorMcp(), 'utf-8')) as { mcpServers: Record<string, Entry> })
    .mcpServers[name];

/** The developer's environment minus everything that could steer node9. */
function baseEnv(h: string = home): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v === undefined || k.startsWith('NODE9_') || k === 'NODE_OPTIONS' || k === 'NODE_PATH') {
      continue;
    }
    env[k] = v;
  }
  return { ...env, HOME: h, USERPROFILE: h, NODE9_NO_AUTO_DAEMON: '1' };
}

/** A node9 command a person runs: the real setup path, no NODE9_TESTING. */
function node9(args: string[], h: string = home): SpawnSyncReturns<string> {
  return spawnSync(NODE, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: 60000,
    cwd: h,
    env: { ...baseEnv(h), NODE9_NONINTERACTIVE: '1' },
  });
}

/** What an agent does with an MCP entry: spawn it, no shell, on its own PATH. */
function startEntry(
  entry: { command: string; args: string[] },
  pathDirs: string[],
  requests: object[]
): SpawnSyncReturns<string> {
  return spawnSync(entry.command, entry.args, {
    input: requests.map((r) => JSON.stringify(r)).join('\n') + '\n',
    encoding: 'utf-8',
    timeout: 30000,
    cwd: home,
    // NODE9_TESTING=1 here only keeps node9's approvers and the daemon out of
    // the test. The entry was already written; this is the agent's side.
    env: { ...baseEnv(), NODE9_TESTING: '1', PATH: [...pathDirs, '/usr/bin', '/bin'].join(':') },
  });
}

const INITIALIZE = {
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: { name: 'node-pin-test', version: '0' },
  },
};
const TOOLS_LIST = { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} };

interface Reply {
  id?: unknown;
  result?: { serverInfo?: { name?: string }; tools?: Array<{ name?: string }> };
  error?: unknown;
}
/** The JSON-RPC replies on stdout. A line that is not JSON fails the test:
 *  stdout must stay clean. */
function replies(stdout: string): Reply[] {
  return stdout
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line) as Reply);
}

beforeAll(() => {
  if (skip) return;
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-node-pin-'));
  home = path.join(root, 'home');
  oldNodeDir = path.join(root, 'old-node');
  bareBinDir = path.join(root, 'bare-bin');
  for (const dir of [path.join(home, '.cursor'), oldNodeDir, bareBinDir]) {
    fs.mkdirSync(dir, { recursive: true });
  }

  fs.writeFileSync(
    path.join(oldNodeDir, 'node'),
    '#!/bin/sh\n' +
      'if [ "$1" = "--version" ]; then echo v18.19.1; exit 0; fi\n' +
      `echo "${FAKE_NODE_MARK} $*" >&2\n` +
      'exit 1\n',
    { mode: 0o755 }
  );
  // What a global install puts on PATH: a link named node9 to the CLI, which
  // starts through `#!/usr/bin/env node`.
  fs.symlinkSync(CLI, path.join(bareBinDir, 'node9'));

  // A tiny stdio MCP server, the upstream of the wrapped entry.
  upstreamScript = path.join(root, 'upstream.js');
  fs.writeFileSync(
    upstreamScript,
    `
const rl = require('readline').createInterface({ input: process.stdin, terminal: false });
rl.on('line', (line) => {
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  if (msg.id === undefined || msg.id === null) return;
  const result = msg.method === 'tools/list'
    ? { tools: [{ name: 'echo', description: 'Echo', inputSchema: { type: 'object' } }] }
    : msg.method === 'initialize'
      ? { protocolVersion: '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'stub-upstream', version: '0' } }
      : {};
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result }) + '\\n');
});
`
  );

  // Wire Cursor the way a person does. Cursor is MCP-only, so the entry in
  // ~/.cursor/mcp.json is everything node9 writes for it.
  const added = node9(['agents', 'add', 'cursor']);
  if (added.error || added.status !== 0) {
    throw new Error(
      `agents add cursor failed: ${added.error?.message ?? added.status}\n${added.stderr}`
    );
  }
});

afterAll(() => {
  if (root) fs.rmSync(root, { recursive: true, force: true });
});

describe("node9's own MCP server under an old Node on PATH", () => {
  itUnix("the fixture reproduces the incident: the bare `node9` runs on PATH's node", () => {
    const r = startEntry(
      { command: 'node9', args: ['mcp-server'] },
      [oldNodeDir, bareBinDir],
      [INITIALIZE]
    );
    expect(r.error).toBeUndefined();
    expect(r.status).toBe(1);
    expect(r.stderr).toContain(FAKE_NODE_MARK);
    expect(r.stdout).toBe('');
  });

  itUnix('setup writes the launcher, not the bare name', () => {
    expect(readEntry('node9')).toEqual({ command: launcher(), args: ['mcp-server'] });
    expect(fs.statSync(launcher()).mode & 0o777).toBe(0o755);
  });

  itUnix('the entry setup wrote answers initialize', () => {
    const r = startEntry(readEntry('node9'), [oldNodeDir], [INITIALIZE]);
    expect(r.error).toBeUndefined();
    expect(r.stderr).not.toContain(FAKE_NODE_MARK);
    expect(r.status).toBe(0);
    const init = replies(r.stdout).find((m) => m.id === 1);
    expect(init?.error).toBeUndefined();
    expect(init?.result?.serverInfo?.name).toBe('node9');
  });

  itUnix('a second setup run leaves the entry and the launcher as they are', () => {
    const before = fs.readFileSync(cursorMcp(), 'utf-8');
    const launcherBefore = fs.readFileSync(launcher(), 'utf-8');
    const r = node9(['agents', 'add', 'cursor']);
    expect(r.error).toBeUndefined();
    expect(r.status).toBe(0);
    // The own entry is not wrapped by the wrap pass and not added twice.
    expect(fs.readFileSync(cursorMcp(), 'utf-8')).toBe(before);
    expect(fs.readFileSync(launcher(), 'utf-8')).toBe(launcherBefore);
  });
});

describe('a wrapped MCP server under an old Node on PATH', () => {
  itUnix('`mcp gateway` wraps through the launcher and the server answers', () => {
    const config = JSON.parse(fs.readFileSync(cursorMcp(), 'utf-8')) as {
      mcpServers: Record<string, Entry>;
    };
    config.mcpServers['stub'] = { command: NODE, args: [upstreamScript], env: { STUB: '1' } };
    fs.writeFileSync(cursorMcp(), JSON.stringify(config, null, 2) + '\n');

    const wrap = node9(['mcp', 'gateway', 'stub']);
    expect(wrap.error).toBeUndefined();
    expect(wrap.status).toBe(0);

    const entry = readEntry('stub');
    expect(entry.command).toBe(launcher());
    expect(entry.args.slice(0, 4)).toEqual(['mcp-gateway', '--config-name', 'stub', '--upstream']);
    expect(entry.args).toHaveLength(5);
    expect(entry.env).toEqual({ STUB: '1' });

    const r = startEntry(entry, [oldNodeDir], [INITIALIZE, TOOLS_LIST]);
    expect(r.error).toBeUndefined();
    expect(r.stderr).not.toContain(FAKE_NODE_MARK);
    const out = replies(r.stdout);
    expect(out.find((m) => m.id === 1)?.result?.serverInfo?.name).toBe('stub-upstream');
    expect(out.find((m) => m.id === 2)?.result?.tools?.[0]?.name).toBe('echo');
  });

  itUnix('`mcp status` reads the launcher entries as node9 and governed', () => {
    const r = node9(['mcp', 'status']);
    expect(r.error).toBeUndefined();
    expect(r.status).toBe(0);
    expect(r.stderr).toMatch(/Cursor\s+node9\s+node9/);
    expect(r.stderr).toMatch(/Cursor\s+stub\s+governed/);
    expect(r.stderr).not.toContain('UNGOVERNED');
  });
});

describe('the launcher when its pinned Node is gone', () => {
  itUnix('falls back to the first node on PATH, as a global install would', () => {
    const body = fs.readFileSync(launcher(), 'utf-8');
    const pinned = /^node="([^"]+)"$/m.exec(body)?.[1];
    expect(pinned).toBeTruthy();
    fs.writeFileSync(launcher(), body.replace(pinned as string, path.join(root, 'gone', 'node')));
    try {
      const r = startEntry(readEntry('node9'), [oldNodeDir], [INITIALIZE]);
      expect(r.error).toBeUndefined();
      expect(r.status).toBe(1);
      expect(r.stderr).toContain(FAKE_NODE_MARK);
    } finally {
      fs.writeFileSync(launcher(), body, { mode: 0o755 });
    }
  });
});

// A person who hit the incident before this fix pinned the Node by hand:
// `<node> <node9 bin> mcp-server`. Setup compared the command with the literal
// "node9", so it put the bare entry back over the pinned one and wrapped the
// pinned wraps a second time.
describe('setup on a config whose entries pin their Node by hand', () => {
  const PIN = ['/opt/node-v25/bin/node', '/opt/node-v25/bin/node9'];
  const handPinned = {
    node9: { command: PIN[0], args: [PIN[1], 'mcp-server'] },
    pg: {
      command: PIN[0],
      args: [PIN[1], 'mcp-gateway', '--config-name', 'pg', '--upstream', 'npx -y pg-mcp'],
      env: { PGHOST: 'db' },
    },
    remote: { url: 'https://example.invalid/mcp' },
  };
  let home2: string;
  const file = () => path.join(home2, '.cursor', 'mcp.json');
  const servers = () =>
    (JSON.parse(fs.readFileSync(file(), 'utf-8')) as { mcpServers: Record<string, Entry> })
      .mcpServers;

  beforeAll(() => {
    if (skip) return;
    home2 = path.join(root, 'home-hand-pinned');
    fs.mkdirSync(path.join(home2, '.cursor'), { recursive: true });
    fs.writeFileSync(
      file(),
      JSON.stringify(
        { mcpServers: { ...handPinned, plain: { command: 'npx', args: ['-y', 'plain-mcp'] } } },
        null,
        2
      )
    );
  });

  itUnix('`agents add` leaves them as they are and wraps only the plain server', () => {
    const r = node9(['agents', 'add', 'cursor'], home2);
    expect(r.error).toBeUndefined();
    expect(r.status).toBe(0);
    const after = servers();
    expect(Object.keys(after).sort()).toEqual(['node9', 'pg', 'plain', 'remote']);
    expect(after.node9).toEqual(handPinned.node9);
    expect(after.pg).toEqual(handPinned.pg);
    expect(after.remote).toEqual(handPinned.remote);
    expect(after.plain.args).toContain('mcp-gateway');
    expect(after.plain.args[after.plain.args.indexOf('--upstream') + 1]).toBe('npx -y plain-mcp');
  });

  itUnix("`agents remove` takes node9's own entry out, whatever starts it", () => {
    const r = node9(['agents', 'remove', 'cursor'], home2);
    expect(r.error).toBeUndefined();
    expect(r.status).toBe(0);
    const after = servers();
    expect(after.node9).toBeUndefined();
    expect(after.remote).toEqual(handPinned.remote);
    expect(after.plain).toEqual({ command: 'npx', args: ['-y', 'plain-mcp'] });
  });
});

describe('against a real old Node (NODE9_TEST_OLD_NODE)', () => {
  itRealOldNode('the bare name is refused, the launcher entry answers', () => {
    const realOldDir = path.dirname(REAL_OLD_NODE);
    const version = spawnSync(REAL_OLD_NODE, ['--version'], { encoding: 'utf-8' });
    expect(version.error).toBeUndefined();

    const bare = startEntry(
      { command: 'node9', args: ['mcp-server'] },
      [realOldDir, bareBinDir],
      [INITIALIZE]
    );
    expect(bare.error).toBeUndefined();
    expect(bare.status).not.toBe(0);
    expect(bare.stdout).toBe('');
    expect(bare.stderr).toContain(version.stdout.trim());

    const pinned = startEntry(readEntry('node9'), [realOldDir], [INITIALIZE]);
    expect(pinned.error).toBeUndefined();
    expect(pinned.status).toBe(0);
    expect(replies(pinned.stdout).find((m) => m.id === 1)?.result?.serverInfo?.name).toBe('node9');
  });
});

// The launcher is a file an agent could rewrite to point node9's MCP entries
// at anything. It sits in ~/.node9, so the rule that guards the hook shim
// guards it: a change of node9's own files is held for the user.
describe('self-protection of the launcher', () => {
  function writeVerdict(target: string): { decision: string; reason: string } {
    const r = spawnSync(
      NODE,
      [
        CLI,
        'check',
        JSON.stringify({
          hook_event_name: 'PreToolUse',
          tool_name: 'Write',
          tool_input: { file_path: target, content: '#!/bin/sh\nexit 0\n' },
          cwd: home,
        }),
      ],
      {
        encoding: 'utf-8',
        timeout: 60000,
        cwd: home,
        env: { ...baseEnv(), NODE9_TESTING: '1' },
      }
    );
    expect(r.error).toBeUndefined();
    expect(r.status).toBe(0);
    const out = JSON.parse(r.stdout.trim()) as {
      hookSpecificOutput: { permissionDecision: string; permissionDecisionReason: string };
    };
    return {
      decision: out.hookSpecificOutput.permissionDecision,
      reason: out.hookSpecificOutput.permissionDecisionReason,
    };
  }

  itUnix('a write to ~/.node9/bin/node9 gets the verdict of a write to the hook shim', () => {
    const hook = writeVerdict(path.join(home, '.node9', 'bin', 'hook'));
    const node9Launcher = writeVerdict(launcher());
    expect(hook.decision).toBe('ask');
    expect(node9Launcher.decision).toBe(hook.decision);
    expect(node9Launcher.reason).toBe(hook.reason);
  });
});
