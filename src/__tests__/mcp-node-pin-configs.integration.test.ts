/**
 * Setup and teardown on real agent config files, one per format node9 writes:
 *
 *   Cursor          ~/.cursor/mcp.json                 JSON, key `mcpServers`
 *   VS Code         ~/.vscode/mcp.json                 JSON, key `servers`, `type`
 *   Codex           ~/.codex/config.toml               TOML, key `mcp_servers`
 *   Claude Desktop  per-platform config                JSON, key `mcpServers`
 *
 * Each file starts with every shape an entry has in the field: node9's own
 * server (as node9 used to write it, and with a Node pinned in front by
 * hand), wraps with and without `--config-name`, a wrap pinned by hand, a
 * wrap whose upstream holds an argument with a space, a server node9 has not
 * wrapped yet, and a remote one.
 *
 * Setup and teardown each carried nine copies of "is this entry node9's" and
 * "undo this wrap", written against the literal command "node9" and a split
 * on spaces. What that got wrong, and these rows pin:
 *   - setup wrapped a hand-pinned wrap a second time;
 *   - setup built the upstream of five agents with a bare join, so an
 *     argument with a space came back from the gateway as two;
 *   - teardown skipped every wrap that carries `--config-name` (all of the
 *     ones `mcp gateway` and the daemon write) and still printed "Unwrapped";
 *   - teardown split the upstream on spaces, breaking a quoted argument.
 *
 * The commands run through the built CLI without NODE9_TESTING, so the real
 * launcher is written. Requires `npm run build`.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, type SpawnSyncReturns } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { parse as parseToml, stringify as stringifyToml } from 'smol-toml';
import { tokenize } from '../mcp-cmd';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const NODE = process.execPath;
const FAKE_CODEX = path.resolve(__dirname, 'fixtures', 'fake-codex-app-server.mjs');

const cliExists = fs.existsSync(CLI);
if (!cliExists) {
  console.warn(
    `[mcp-node-pin-configs] All integration tests skipped: dist/cli.js not found. Run "npm run build" first.\nExpected: ${CLI}`
  );
}
const skip = process.platform === 'win32' || !cliExists;

interface Entry {
  type?: string;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
}
type Servers = Record<string, Entry>;

const PIN = ['/opt/node-v25/bin/node', '/opt/node-v25/bin/node9'];
const SPACED_DIR = '/Users/Some User/docs';

/** What a config holds before node9 touches the plain server. */
function fixture(): Servers {
  return {
    node9: { command: 'node9', args: ['mcp-server'] },
    'node9-pinned': { command: PIN[0], args: [PIN[1], 'mcp-server'] },
    stamped: {
      command: 'node9',
      args: ['mcp-gateway', '--config-name', 'stamped', '--upstream', 'npx -y stamped-mcp'],
      env: { A: '1' },
    },
    unstamped: { command: 'node9', args: ['mcp-gateway', '--upstream', 'npx -y unstamped-mcp'] },
    pinned: {
      command: PIN[0],
      args: [PIN[1], 'mcp-gateway', '--config-name', 'pinned', '--upstream', 'npx -y pinned-mcp'],
    },
    quoted: {
      command: 'node9',
      args: [
        'mcp-gateway',
        '--config-name',
        'quoted',
        '--upstream',
        `npx -y fs-mcp "${SPACED_DIR}"`,
      ],
    },
    plain: { command: 'npx', args: ['-y', 'plain-mcp', SPACED_DIR], env: { TOKEN_NAME: 'x' } },
    remote: { url: 'https://example.invalid/mcp' },
  };
}

/** The same servers with no node9 in the file. */
function withoutNode9(): Servers {
  return {
    stamped: { command: 'npx', args: ['-y', 'stamped-mcp'], env: { A: '1' } },
    unstamped: { command: 'npx', args: ['-y', 'unstamped-mcp'] },
    pinned: { command: 'npx', args: ['-y', 'pinned-mcp'] },
    quoted: { command: 'npx', args: ['-y', 'fs-mcp', SPACED_DIR] },
    plain: { command: 'npx', args: ['-y', 'plain-mcp', SPACED_DIR], env: { TOKEN_NAME: 'x' } },
    remote: { url: 'https://example.invalid/mcp' },
  };
}

interface Format {
  /** The name `node9 agents add` takes. */
  agent: string;
  file: (home: string) => string;
  /** Keys a format puts on every stdio entry. */
  entryExtra: Partial<Entry>;
  write: (file: string, servers: Servers) => void;
  read: (file: string) => { servers: Servers; rest: Record<string, unknown> };
}

const jsonFormat = (key: 'mcpServers' | 'servers') => ({
  write: (file: string, servers: Servers) =>
    fs.writeFileSync(
      file,
      JSON.stringify({ unrelated: { keep: [1, 2, 3] }, [key]: servers }, null, 2) + '\n'
    ),
  read: (file: string) => {
    const { [key]: servers, ...rest } = JSON.parse(fs.readFileSync(file, 'utf-8')) as Record<
      string,
      unknown
    >;
    return { servers: servers as Servers, rest };
  },
});

const FORMATS: Format[] = [
  {
    agent: 'cursor',
    file: (home) => path.join(home, '.cursor', 'mcp.json'),
    entryExtra: {},
    ...jsonFormat('mcpServers'),
  },
  {
    agent: 'vscode',
    file: (home) => path.join(home, '.vscode', 'mcp.json'),
    entryExtra: { type: 'stdio' },
    ...jsonFormat('servers'),
  },
  {
    agent: 'codex',
    file: (home) => path.join(home, '.codex', 'config.toml'),
    entryExtra: {},
    write: (file, servers) =>
      fs.writeFileSync(
        file,
        stringifyToml({ unrelated: { keep: [1, 2, 3] }, mcp_servers: servers })
      ),
    read: (file) => {
      const { mcp_servers: servers, ...rest } = parseToml(fs.readFileSync(file, 'utf-8')) as Record<
        string,
        unknown
      >;
      return { servers: servers as Servers, rest };
    },
  },
  {
    agent: 'claudeDesktop',
    file: (home) =>
      process.platform === 'darwin'
        ? path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')
        : path.join(home, '.config', 'Claude', 'claude_desktop_config.json'),
    entryExtra: {},
    ...jsonFormat('mcpServers'),
  },
];

let root = '';

// `agents add codex` waits about 17 s on Codex's app-server (measured with the
// fake one, before this file existed). The budgets leave room for a loaded
// machine.
const SPAWN_TIMEOUT_MS = 90_000;
const ROW_TIMEOUT_MS = 120_000;

beforeAll(() => {
  if (skip) return;
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-pin-configs-'));
});

afterAll(() => {
  if (root) fs.rmSync(root, { recursive: true, force: true });
});

function node9(home: string, args: string[]): SpawnSyncReturns<string> {
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v === undefined || k.startsWith('NODE9_') || k === 'NODE_OPTIONS' || k === 'NODE_PATH') {
      continue;
    }
    env[k] = v;
  }
  return spawnSync(NODE, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: SPAWN_TIMEOUT_MS,
    cwd: home,
    env: {
      ...env,
      HOME: home,
      USERPROFILE: home,
      NODE9_NO_AUTO_DAEMON: '1',
      NODE9_NONINTERACTIVE: '1',
      // Codex setup asks Codex's own app-server to trust node9's hooks; the
      // fake stands in for it, so no real Codex is started. It reads the hooks
      // from CODEX_HOME, as the real one does.
      NODE9_CODEX_BIN: `${NODE} ${FAKE_CODEX}`,
      CODEX_HOME: path.join(home, '.codex'),
      NODE9_SCAN_DISABLE: '1',
    },
  });
}

const upstreamOf = (entry: Entry): string => {
  const args = entry.args ?? [];
  return args[args.indexOf('--upstream') + 1];
};

describe.skipIf(skip).each(FORMATS)('setup and teardown on a real $agent config', (format) => {
  let home = '';
  let file = '';
  const launcher = () => path.join(home, '.node9', 'bin', 'node9');
  const withExtra = (servers: Servers): Servers =>
    Object.fromEntries(
      Object.entries(servers).map(([name, entry]) => [
        name,
        entry.url ? entry : { ...format.entryExtra, ...entry },
      ])
    );

  beforeAll(() => {
    home = path.join(root, format.agent);
    file = format.file(home);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    format.write(file, withExtra(fixture()));
  });

  it(
    '`agents add` wraps the plain server once and leaves every node9 entry working',
    () => {
      const before = format.read(file).servers;
      const r = node9(home, ['agents', 'add', format.agent]);
      expect(r.error).toBeUndefined();
      expect(r.status).toBe(0);

      const { servers, rest } = format.read(file);
      expect(Object.keys(servers).sort()).toEqual(Object.keys(before).sort());
      expect(rest).toEqual({ unrelated: { keep: [1, 2, 3] } });

      // node9's own server: under the keys it had, not a second copy, and
      // started by the launcher now (the pinned Node of the fixture is gone).
      expect(servers.node9).toEqual({
        ...format.entryExtra,
        command: launcher(),
        args: ['mcp-server'],
      });
      expect(servers['node9-pinned']).toEqual(servers.node9);

      // No wrap is wrapped a second time. Each moves to the launcher, named by
      // its config key, with the upstream and the env it had: the upstream is
      // what the serverKey is hashed from, so pins and rules stay attached.
      for (const name of ['stamped', 'unstamped', 'pinned', 'quoted']) {
        expect(servers[name], name).toEqual({
          ...format.entryExtra,
          ...(before[name].env ? { env: before[name].env } : {}),
          command: launcher(),
          args: ['mcp-gateway', '--config-name', name, '--upstream', upstreamOf(before[name])],
        });
      }

      // The plain server: wrapped through the launcher, named, and its argument
      // with a space survives the trip through the gateway's tokenizer.
      expect(servers.plain.command).toBe(launcher());
      expect(servers.plain.args?.slice(0, 4)).toEqual([
        'mcp-gateway',
        '--config-name',
        'plain',
        '--upstream',
      ]);
      expect(servers.plain.args).toHaveLength(5);
      expect(tokenize(upstreamOf(servers.plain))).toEqual(['npx', '-y', 'plain-mcp', SPACED_DIR]);
      expect(servers.plain.env).toEqual({ TOKEN_NAME: 'x' });

      expect(servers.remote).toEqual(before.remote);
    },
    ROW_TIMEOUT_MS
  );

  it(
    'a second `agents add` changes nothing',
    () => {
      const before = fs.readFileSync(file, 'utf-8');
      const r = node9(home, ['agents', 'add', format.agent]);
      expect(r.error).toBeUndefined();
      expect(r.status).toBe(0);
      expect(fs.readFileSync(file, 'utf-8')).toBe(before);
    },
    ROW_TIMEOUT_MS
  );

  it(
    '`mcp status` reads the file the way setup left it',
    () => {
      // VS Code and Claude Desktop are not in the inventory (mcpInventory: false).
      if (format.agent === 'vscode' || format.agent === 'claudeDesktop') return;
      const r = node9(home, ['mcp', 'status']);
      expect(r.error).toBeUndefined();
      expect(r.status).toBe(0);
      for (const name of ['stamped', 'unstamped', 'pinned', 'quoted', 'plain']) {
        expect(r.stderr, name).toMatch(new RegExp(`\\s${name}\\s+governed`));
      }
      expect(r.stderr).toMatch(/\snode9\s+node9/);
      expect(r.stderr).toMatch(/\snode9-pinned\s+node9/);
      expect(r.stderr).not.toContain('UNGOVERNED');
    },
    ROW_TIMEOUT_MS
  );

  it(
    '`agents remove` restores every server and takes node9 out of the file',
    () => {
      const r = node9(home, ['agents', 'remove', format.agent]);
      expect(r.error).toBeUndefined();
      expect(r.status).toBe(0);

      const { servers, rest } = format.read(file);
      expect(servers).toEqual(withExtra(withoutNode9()));
      expect(rest).toEqual({ unrelated: { keep: [1, 2, 3] } });
    },
    ROW_TIMEOUT_MS
  );
});

// T7. setup.ts held 22 comparisons with the literal "node9" and agent-wiring
// one more, each a private answer to "is this entry node9's". They disagreed
// with the inventory and with each other. One parser answers now; this row
// keeps a twenty-third from coming back unnoticed.
describe('one judge for "does this entry start node9"', () => {
  it.each(['src/setup.ts', 'src/agent-wiring.ts'])('%s compares no command with "node9"', (rel) => {
    const source = fs.readFileSync(path.resolve(__dirname, '../..', rel), 'utf-8');
    expect(source).not.toMatch(/[!=]==\s*['"]node9['"]/);
    expect(source).not.toMatch(/['"]node9['"]\s*[!=]==/);
  });
});

// `agents add` printed "Unknown agent" for the one name with a capital in it.
describe.skipIf(skip)('agent names', () => {
  it(
    '`agents add claudeDesktop` is the name the help text prints, and it works',
    () => {
      const home = path.join(root, 'names');
      fs.mkdirSync(home, { recursive: true });
      for (const name of ['claudeDesktop', 'claudedesktop', 'CURSOR']) {
        const r = node9(home, ['agents', 'add', name]);
        expect(r.error, name).toBeUndefined();
        expect(r.status, name).toBe(0);
        expect(r.stdout + r.stderr, name).not.toContain('Unknown agent');
      }
      const unknown = node9(home, ['agents', 'add', 'nope']);
      expect(unknown.error).toBeUndefined();
      expect(unknown.status).toBe(1);
      expect(unknown.stderr).toContain('Unknown agent');
    },
    ROW_TIMEOUT_MS
  );
});
