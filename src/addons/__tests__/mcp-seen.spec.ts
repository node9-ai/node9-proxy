// MCP servers no agent config names, found in the calls the hook audited
// (node9Firewall#376 item 6, docs roadmap/active/addons-mcp-seen-in-calls-plan.md):
// the stored list, the names of claude.ai connectors, the rows of the report
// and the index, and what the hook does with a call to one.
import { describe, it, expect, afterEach, beforeEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  _resetMcpSeenCursor,
  connectorNames,
  desktopSessionRoots,
  mcpCallsIn,
  mcpSeenPath,
  readSeenServers,
  refreshMcpSeen,
  seenMcpRows,
} from '../mcp-seen';
import { collectAddons } from '../collect';
import { readMcpIndex, writeMcpIndex } from '../index-file';
import { addonVerdictForHookCall } from '../resolve';
import { seenMcpVerdict, type AddonPolicy } from '../policy';
import { refreshAddonsIndex } from '../../daemon/addons-index';

const CONNECTOR = 'f39ead4b-3003-4639-9d3b-d0425096c1bd';
const OTHER = '5ffd0f7a-89e7-4a3e-9fa8-7dadfa8bdb95';
const NOW = Date.parse('2026-11-27T12:00:00Z');

const homes: string[] = [];
beforeEach(() => _resetMcpSeenCursor());
afterEach(() => {
  for (const h of homes.splice(0)) fs.rmSync(h, { recursive: true, force: true });
});

function home(): string {
  const h = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-mcp-seen-'));
  fs.mkdirSync(path.join(h, '.node9'), { recursive: true });
  homes.push(h);
  return h;
}

/** An audit row as the hook writes it for one tool call (src/audit/index.ts;
 *  the fields are the ones a real row of ~/.node9/audit.log carries). */
function row(tool: string, agent = 'Claude Code', ts = '2026-11-27T10:42:21.510Z'): string {
  return JSON.stringify({
    eid: 'e1',
    ts,
    tool,
    argsHash: 'abc',
    argsPreview: '{"query":"is:unread"}',
    decision: 'allow',
    checkedBy: 'default',
    agent,
    sessionId: 's-1',
    hostname: 'laptop',
    platform: 'linux',
  });
}

function audit(h: string, lines: string[], append = false): void {
  const file = path.join(h, '.node9', 'audit.log');
  const text = lines.map((l) => l + '\n').join('');
  if (append) fs.appendFileSync(file, text);
  else fs.writeFileSync(file, text);
}

/** A Code session file as the Claude desktop app writes it: the layout
 *  `<root>/<account>/<org>/local_<id>.json` and the three fields read. */
function sessionFile(root: string, servers: object[], id = 'one'): void {
  const dir = path.join(root, 'acct', 'org');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, `local_${id}.json`),
    JSON.stringify({
      sessionId: `local_${id}`,
      cliSessionId: 's-1',
      remoteMcpServersConfig: servers,
    })
  );
}

function policy(p: Partial<AddonPolicy>): AddonPolicy {
  return { unapproved: 'log', mcp: {}, skills: {}, plugins: {}, ...p };
}

describe('mcpCallsIn: the MCP calls in the audit log', () => {
  it('reads the server, the agent and the day of each call, and nothing else', () => {
    const calls = mcpCallsIn(
      [
        row(`mcp__${CONNECTOR}__search_threads`),
        row('mcp__Claude_Browser__navigate'),
        row('mcp__codex_apps__open', 'Codex', '2026-11-20T08:00:00Z'),
        row('Bash'),
        // The gateway's row: a bare tool name, its server is configured.
        JSON.stringify({ ts: '2026-11-27T10:00:00Z', tool: 'query', mcpServer: 'postgres' }),
        'not json "mcp__x__y"',
        // An agent the inventory has no id for.
        row('mcp__x__y', 'Some Other Agent'),
      ].join('\n'),
      '2026-11-27'
    );
    expect(calls).toEqual([
      { agent: 'claude', name: CONNECTOR, day: '2026-11-27' },
      { agent: 'claude', name: 'Claude_Browser', day: '2026-11-27' },
      { agent: 'codex', name: 'codex_apps', day: '2026-11-20' },
    ]);
  });

  it('takes an agent named like an Object member as unknown', () => {
    const calls = mcpCallsIn(
      ['constructor', 'toString', 'valueOf'].map((a) => row('mcp__x__y', a)).join('\n'),
      '2026-11-27'
    );
    expect(calls).toEqual([]);
  });

  it('keeps a server name with single underscores whole', () => {
    const calls = mcpCallsIn(row('mcp__plugin_reviewer_search__find'), '2026-11-27');
    expect(calls[0]?.name).toBe('plugin_reviewer_search');
  });
});

describe('refreshMcpSeen: the stored list', () => {
  it('records each server once, with its first and newest day', () => {
    const h = home();
    audit(h, [
      row('mcp__ccd_turn__wrap_up', 'Claude Code', '2026-11-20T10:00:00Z'),
      row('mcp__ccd_turn__wrap_up', 'Claude Code', '2026-11-27T10:00:00Z'),
      row('mcp__terminal__read_terminal', 'Claude Code', '2026-11-25T10:00:00Z'),
    ]);
    expect(refreshMcpSeen(h, NOW, [])).toBe(true);
    expect(readSeenServers(h)).toEqual([
      { agent: 'claude', name: 'ccd_turn', first: '2026-11-20', last: '2026-11-27' },
      { agent: 'claude', name: 'terminal', first: '2026-11-25', last: '2026-11-25' },
    ]);
    expect(fs.statSync(mcpSeenPath(h)).mode & 0o077).toBe(process.platform === 'win32' ? 0o066 : 0);
  });

  it('reads only what the log gained since the last round', () => {
    const h = home();
    audit(h, [row('mcp__ccd_turn__wrap_up')]);
    refreshMcpSeen(h, NOW, []);
    // Nothing new: nothing changes, and nothing is written.
    const before = fs.statSync(mcpSeenPath(h)).mtimeMs;
    expect(refreshMcpSeen(h, NOW, [])).toBe(false);
    expect(fs.statSync(mcpSeenPath(h)).mtimeMs).toBe(before);
    // A row for a server already known, on the same day: still no change.
    audit(h, [row('mcp__ccd_turn__update_plan')], true);
    expect(refreshMcpSeen(h, NOW, [])).toBe(false);
    audit(h, [row('mcp__visualize__show_widget')], true);
    expect(refreshMcpSeen(h, NOW, [])).toBe(true);
    expect(readSeenServers(h).map((s) => s.name)).toEqual(['ccd_turn', 'visualize']);
  });

  it('leaves a row that is still being written for the next round', () => {
    const h = home();
    const whole = row('mcp__ccd_turn__wrap_up');
    const half = row('mcp__terminal__read_terminal');
    fs.writeFileSync(path.join(h, '.node9', 'audit.log'), `${whole}\n${half.slice(0, 40)}`);
    refreshMcpSeen(h, NOW, []);
    expect(readSeenServers(h).map((s) => s.name)).toEqual(['ccd_turn']);
    fs.appendFileSync(path.join(h, '.node9', 'audit.log'), `${half.slice(40)}\n`);
    refreshMcpSeen(h, NOW, []);
    expect(readSeenServers(h).map((s) => s.name)).toEqual(['ccd_turn', 'terminal']);
  });

  it('starts over when the log was replaced, and after a restart reads from the saved place', () => {
    const h = home();
    audit(h, [row('mcp__ccd_turn__wrap_up')]);
    refreshMcpSeen(h, NOW, []);
    // A restart: the in-memory place is gone, the saved one is used.
    _resetMcpSeenCursor();
    audit(h, [row('mcp__terminal__read_terminal')], true);
    refreshMcpSeen(h, NOW, []);
    expect(readSeenServers(h).map((s) => s.name)).toEqual(['ccd_turn', 'terminal']);
    // The log replaced by a shorter one: read from its start.
    fs.rmSync(path.join(h, '.node9', 'audit.log'));
    audit(h, [row('mcp__visualize__show_widget')]);
    refreshMcpSeen(h, NOW, []);
    expect(readSeenServers(h).map((s) => s.name)).toContain('visualize');
  });

  it('drops a server with no call for 30 days', () => {
    const h = home();
    audit(h, [
      row('mcp__old_one__x', 'Claude Code', '2026-10-01T10:00:00Z'),
      row('mcp__ccd_turn__wrap_up'),
    ]);
    refreshMcpSeen(h, NOW, []);
    expect(readSeenServers(h).map((s) => s.name)).toEqual(['ccd_turn']);
  });

  it('never dates a call after today: a row from the future would never age out', () => {
    const h = home();
    audit(h, [row('mcp__ccd_turn__wrap_up', 'Claude Code', '2099-01-01T00:00:00Z')]);
    refreshMcpSeen(h, NOW, []);
    expect(readSeenServers(h)[0]).toMatchObject({ first: '2026-11-27', last: '2026-11-27' });
  });

  it('brings a stored day from the future back to today, so the server can age out', () => {
    const h = home();
    fs.writeFileSync(
      mcpSeenPath(h),
      JSON.stringify({
        v: 1,
        audit: { size: 0, ino: 0 },
        servers: [{ agent: 'claude', name: 'ccd_turn', first: '2999-01-01', last: '2999-01-01' }],
      })
    );
    expect(refreshMcpSeen(h, NOW, [])).toBe(true);
    expect(readSeenServers(h)[0]).toMatchObject({ first: '2026-11-27', last: '2026-11-27' });
    expect(refreshMcpSeen(h, NOW + 31 * 86_400_000, [])).toBe(true);
    expect(readSeenServers(h)).toEqual([]);
  });

  it('never throws on a missing log or a broken file', () => {
    const h = home();
    expect(refreshMcpSeen(h, NOW, [])).toBe(false);
    fs.writeFileSync(mcpSeenPath(h), '{not json');
    expect(readSeenServers(h)).toEqual([]);
    audit(h, [row('mcp__ccd_turn__wrap_up')]);
    expect(refreshMcpSeen(h, NOW, [])).toBe(true);
  });
});

describe('claude.ai connectors get their name from the desktop app', () => {
  it('names an id the session files list, with the host of its URL only', () => {
    const h = home();
    const root = path.join(h, 'sessions');
    sessionFile(root, [
      {
        uuid: CONNECTOR,
        name: 'Gmail',
        url: 'https://mail.connectors.example.com/mcp?token=secret',
        tools: [],
      },
      { uuid: 'ffffffff-0000-0000-0000-000000000000', name: 'Slack', url: 'https://x.example.com' },
    ]);
    audit(h, [row(`mcp__${CONNECTOR}__search_threads`), row(`mcp__${OTHER}__read`)]);
    refreshMcpSeen(h, NOW, [root]);
    const servers = readSeenServers(h);
    expect(servers.find((s) => s.name === CONNECTOR)).toMatchObject({
      label: 'Gmail',
      host: 'mail.connectors.example.com',
    });
    // Nothing of the URL but its host is kept.
    expect(fs.readFileSync(mcpSeenPath(h), 'utf8')).not.toContain('secret');
    // An id no file lists stays unnamed, and is not searched for again soon.
    const other = servers.find((s) => s.name === OTHER);
    expect(other?.label).toBeUndefined();
    expect(other?.triedAt).toBe(NOW);
  });

  it('keeps only a host the stored file keeps, so a row never changes identity between rounds', () => {
    const h = home();
    const root = path.join(h, 'sessions');
    sessionFile(root, [{ uuid: CONNECTOR, name: 'Local', url: 'http://my_host.internal/mcp' }]);
    audit(h, [row(`mcp__${CONNECTOR}__read`)]);
    refreshMcpSeen(h, NOW, [root]);
    const first = seenMcpRows(new Set(), h);
    _resetMcpSeenCursor();
    refreshMcpSeen(h, NOW + 60_000, [root]);
    expect(seenMcpRows(new Set(), h)).toEqual(first);
    expect(first[0]).toMatchObject({ identity: `name:${CONNECTOR}`, label: 'Local' });
  });

  it('looks an unnamed id up again only after six hours', () => {
    const h = home();
    const root = path.join(h, 'sessions');
    audit(h, [row(`mcp__${CONNECTOR}__search_threads`)]);
    refreshMcpSeen(h, NOW, [root]);
    sessionFile(root, [{ uuid: CONNECTOR, name: 'Gmail', url: 'https://mail.example.com/x' }]);
    expect(refreshMcpSeen(h, NOW + 60_000, [root])).toBe(false);
    expect(readSeenServers(h)[0]?.label).toBeUndefined();
    expect(refreshMcpSeen(h, NOW + 7 * 3_600_000, [root])).toBe(true);
    expect(readSeenServers(h)[0]).toMatchObject({ label: 'Gmail', host: 'mail.example.com' });
  });

  it('a lookup that finds nothing is saved for its next try and changes no row', () => {
    const h = home();
    const root = path.join(h, 'sessions');
    audit(h, [row(`mcp__${CONNECTOR}__search_threads`)]);
    // The first round reports the new server.
    expect(refreshMcpSeen(h, NOW, [root])).toBe(true);
    // Six hours on the lookup runs again and still finds nothing: the time
    // of the try is stored, and the index is not asked to rebuild.
    const later = NOW + 7 * 3_600_000;
    expect(refreshMcpSeen(h, later, [root])).toBe(false);
    expect(readSeenServers(h)[0]?.triedAt).toBe(later);
  });

  it('reads nothing from a file of another shape, a missing folder, or a name that is not an id', () => {
    const h = home();
    const root = path.join(h, 'sessions');
    fs.mkdirSync(path.join(root, 'a', 'b'), { recursive: true });
    fs.writeFileSync(path.join(root, 'a', 'b', 'local_x.json'), '{"remoteMcpServersConfig":"no"}');
    fs.writeFileSync(path.join(root, 'a', 'b', 'local_y.json'), 'not json');
    expect(connectorNames(new Set([CONNECTOR]), [root, path.join(h, 'missing')]).size).toBe(0);
    // `terminal` is not an id: the session files are never opened for it.
    audit(h, [row('mcp__terminal__read_terminal')]);
    refreshMcpSeen(h, NOW, [root]);
    expect(readSeenServers(h)[0]?.triedAt).toBeUndefined();
  });

  it('knows where the app keeps its sessions on each platform', () => {
    expect(desktopSessionRoots('/home/u', {}, 'linux')).toEqual([
      '/home/u/.config/Claude/claude-code-sessions',
    ]);
    expect(desktopSessionRoots('/Users/u', {}, 'darwin')).toEqual([
      '/Users/u/Library/Application Support/Claude/claude-code-sessions',
    ]);
    // Windows, a Microsoft Store install: found by pattern, not by a fixed id.
    const h = home();
    const local = path.join(h, 'AppData', 'Local');
    fs.mkdirSync(path.join(local, 'Claude-Data', 'claude_pzs8sxrjxfjjc'), { recursive: true });
    fs.mkdirSync(path.join(local, 'Claude-Data', 'unrelated'), { recursive: true });
    const roots = desktopSessionRoots(h, { LOCALAPPDATA: local }, 'win32');
    expect(roots).toContain(
      path.join(local, 'Claude-Data', 'claude_pzs8sxrjxfjjc', 'claude-code-sessions')
    );
    expect(roots.some((r) => r.includes('unrelated'))).toBe(false);
    expect(roots[roots.length - 1]).toBe(
      path.join(h, 'AppData', 'Roaming', 'Claude', 'claude-code-sessions')
    );
  });
});

describe('the rows of the report and of the index', () => {
  it('gives a named connector the identity of its host, any other server its name', () => {
    const h = home();
    const root = path.join(h, 'sessions');
    sessionFile(root, [{ uuid: CONNECTOR, name: 'Gmail', url: 'https://mail.example.com/mcp' }]);
    audit(h, [
      row(`mcp__${CONNECTOR}__search_threads`),
      row('mcp__ccd_turn__wrap_up', 'Claude Code', '2026-11-26T10:00:00Z'),
    ]);
    refreshMcpSeen(h, NOW, [root]);
    expect(seenMcpRows(new Set(), h)).toEqual([
      {
        name: CONNECTOR,
        identity: 'url:mail.example.com',
        agents: ['claude'],
        state: 'seen',
        label: 'Gmail',
        lastSeenDay: '2026-11-27',
      },
      {
        name: 'ccd_turn',
        identity: 'name:ccd_turn',
        agents: ['claude'],
        state: 'seen',
        lastSeenDay: '2026-11-26',
      },
    ]);
  });

  it('leaves out a server an agent config names: the report lists it by what it runs', () => {
    const h = home();
    fs.writeFileSync(
      path.join(h, '.claude.json'),
      JSON.stringify({
        mcpServers: { 'my db': { command: 'npx', args: ['-y', 'some-db-server'] } },
        projects: { [path.join(h, 'proj')]: { mcpServers: { local_one: { command: 'x' } } } },
      })
    );
    fs.mkdirSync(path.join(h, 'proj'), { recursive: true });
    fs.writeFileSync(
      path.join(h, 'proj', '.mcp.json'),
      JSON.stringify({ mcpServers: { project_one: { command: 'y' } } })
    );
    audit(h, [
      // The name as a tool call spells it: `my db` is `my_db`.
      row('mcp__my_db__query'),
      row('mcp__local_one__a'),
      row('mcp__project_one__b'),
      row('mcp__node9__node9_status'),
      row('mcp__ccd_turn__wrap_up'),
    ]);
    refreshMcpSeen(h, NOW, []);
    fs.writeFileSync(
      path.join(h, '.claude.json'),
      JSON.stringify({
        mcpServers: {
          'my db': { command: 'npx', args: ['-y', 'some-db-server'] },
          node9: { command: 'node9', args: ['mcp-server'] },
        },
        projects: { [path.join(h, 'proj')]: { mcpServers: { local_one: { command: 'x' } } } },
      })
    );
    const mcp = collectAddons(h, {}).mcp;
    expect(mcp.filter((m) => m.state === 'seen').map((m) => m.name)).toEqual(['ccd_turn']);
    expect(mcp.some((m) => m.identity === 'npm:some-db-server')).toBe(true);
  });

  it('reaches the index the hook reads, and survives the round trip', () => {
    const h = home();
    audit(h, [row('mcp__ccd_turn__wrap_up')]);
    refreshMcpSeen(h, NOW, []);
    refreshAddonsIndex(undefined, h, {});
    expect(readMcpIndex(h)).toEqual([
      { name: 'ccd_turn', identity: 'name:ccd_turn', state: 'seen', agents: ['claude'] },
    ]);
  });
});

describe('the hook and a server no config names', () => {
  const call = (server: string) => ({
    toolName: `mcp__${server}__do`,
    toolInput: {},
    mcpServer: server,
    agent: 'Claude Code',
  });

  it('is never stopped by the rule for add-ons nobody approved: an agent tool must not break', async () => {
    const h = home();
    const v = await addonVerdictForHookCall(policy({ unapproved: 'block' }), call('ccd_turn'), h);
    expect(v.action).toBe('allow');
    writeMcpIndex(
      [{ name: 'ccd_turn', identity: 'name:ccd_turn', state: 'seen', agents: ['claude'] }],
      h
    );
    expect(
      (await addonVerdictForHookCall(policy({ unapproved: 'block' }), call('ccd_turn'), h)).action
    ).toBe('allow');
    expect(
      (await addonVerdictForHookCall(policy({ unapproved: 'review' }), call('ccd_turn'), h)).action
    ).toBe('allow');
  });

  it('is stopped by a block on its name, from the first call (no index yet)', async () => {
    const h = home();
    const v = await addonVerdictForHookCall(
      policy({ mcp: { 'name:plugin_reviewer_search': 'blocked' } }),
      call('plugin_reviewer_search'),
      h
    );
    expect(v).toMatchObject({ action: 'block', ruleName: 'addon:mcp:name:plugin_reviewer_search' });
    // Another server is not touched by that block.
    expect(
      (
        await addonVerdictForHookCall(
          policy({ mcp: { 'name:plugin_reviewer_search': 'blocked' } }),
          call('ccd_turn'),
          h
        )
      ).action
    ).toBe('allow');
  });

  it('a connector is stopped by a block on its host, once the index names it', async () => {
    const h = home();
    const blocked = policy({ mcp: { 'url:mail.example.com': 'blocked' } });
    // Before the daemon named the id: the block does not reach it yet.
    expect((await addonVerdictForHookCall(blocked, call(CONNECTOR), h)).action).toBe('allow');
    writeMcpIndex(
      [{ name: CONNECTOR, identity: 'url:mail.example.com', state: 'seen', agents: ['claude'] }],
      h
    );
    expect(await addonVerdictForHookCall(blocked, call(CONNECTOR), h)).toMatchObject({
      action: 'block',
      ruleName: 'addon:mcp:url:mail.example.com',
    });
    // Approved, or not decided under the block rule: it runs.
    expect(
      (
        await addonVerdictForHookCall(
          policy({ unapproved: 'block', mcp: { 'url:mail.example.com': 'approved' } }),
          call(CONNECTOR),
          h
        )
      ).action
    ).toBe('allow');
  });

  it('a server a config names is judged by what it runs, whatever the index says of the name', async () => {
    const h = home();
    fs.writeFileSync(
      path.join(h, '.claude.json'),
      JSON.stringify({ mcpServers: { terminal: { command: 'npx', args: ['-y', 'evil-server'] } } })
    );
    writeMcpIndex(
      [{ name: 'terminal', identity: 'name:terminal', state: 'seen', agents: ['claude'] }],
      h
    );
    const v = await addonVerdictForHookCall(policy({ unapproved: 'block' }), call('terminal'), h);
    expect(v).toMatchObject({ action: 'block', ruleName: 'addon:mcp:npm:evil-server' });
  });

  it('seenMcpVerdict allows everything but an explicit block', () => {
    expect(seenMcpVerdict(undefined, 'name:x').action).toBe('allow');
    expect(seenMcpVerdict(policy({ unapproved: 'block' }), 'name:x').action).toBe('allow');
    expect(
      seenMcpVerdict(policy({ mcp: { 'name:x': 'approved' }, unapproved: 'block' }), 'name:x')
        .action
    ).toBe('allow');
    const v = seenMcpVerdict(policy({ mcp: { 'name:x': 'blocked' } }), 'name:x');
    expect(v.action).toBe('block');
    expect(v.action === 'block' && v.reason).toContain('"x"');
  });
});
