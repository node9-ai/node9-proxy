// P3 Phase 2.6 — the reconcile pass: detect NEW ungoverned MCP servers, nudge
// (default) or auto-wrap, dedup via the baseline. BASELINE_FILE resolves
// os.homedir() at import, so spy homedir + resetModules + dynamic import.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

vi.mock('../ui/native', () => ({
  sendDesktopNotification: vi.fn(),
  askNativePopup: vi.fn(),
}));

describe('mcp reconcile pass', () => {
  let home: string;
  let runMcpReconcile: () => void;
  let sendSpy: ReturnType<typeof vi.fn>;

  const writeConfig = (settings: Record<string, unknown>) =>
    fs.writeFileSync(
      path.join(home, '.node9', 'config.json'),
      JSON.stringify({ settings, policy: {} })
    );
  const writeClaude = (servers: Record<string, unknown>) =>
    fs.writeFileSync(path.join(home, '.claude.json'), JSON.stringify({ mcpServers: servers }));
  const gmailEntry = () =>
    JSON.parse(fs.readFileSync(path.join(home, '.claude.json'), 'utf-8')).mcpServers.gmail;

  beforeEach(async () => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-reconpass-'));
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    vi.spyOn(os, 'homedir').mockReturnValue(home);
    vi.resetModules();
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    runMcpReconcile = (await import('../daemon/mcp-reconciler.js')).runMcpReconcile;
    sendSpy = (await import('../ui/native.js')).sendDesktopNotification as ReturnType<typeof vi.fn>;
    sendSpy.mockClear();
  });
  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  it('NUDGES a new ungoverned server once, then dedups on the next pass', () => {
    writeConfig({ mode: 'standard' }); // mcpAutoWrap unset → nudge
    writeClaude({
      gmail: { command: 'npx', args: ['gmail-mcp'] },
      node9: { command: 'node9', args: ['mcp-server'] }, // self — ignored
    });
    runMcpReconcile();
    expect(sendSpy).toHaveBeenCalledTimes(1);
    expect(String(sendSpy.mock.calls[0][0])).toMatch(/ungoverned/);
    expect(gmailEntry().command).toBe('npx'); // NOT wrapped in nudge mode

    sendSpy.mockClear();
    runMcpReconcile(); // nothing new → no notification
    expect(sendSpy).toHaveBeenCalledTimes(0);
  });

  it('AUTO-WRAPS when settings.mcpAutoWrap is true', () => {
    writeConfig({ mode: 'standard', mcpAutoWrap: true });
    writeClaude({ gmail: { command: 'npx', args: ['gmail-mcp'], env: { A: '1' } } });
    runMcpReconcile();
    expect(sendSpy).toHaveBeenCalledTimes(1);
    expect(String(sendSpy.mock.calls[0][0])).toMatch(/governed/);
    const wrapped = gmailEntry();
    expect(wrapped.command).toBe('node9');
    expect(wrapped.args[0]).toBe('mcp-gateway');
    expect(wrapped.env).toEqual({ A: '1' }); // preserved
  });

  // A wrap written as the bare `node9` starts on the agent's PATH Node. Where
  // that is an old Node the wrap does not start, and the user's server is down.
  it.skipIf(process.platform === 'win32')(
    'auto-wraps through the launcher when setup left one, and never writes it',
    () => {
      const launcher = path.join(home, '.node9', 'bin', 'node9');
      const cli = path.join(home, 'cli.js');
      fs.writeFileSync(cli, '');
      fs.mkdirSync(path.dirname(launcher), { recursive: true });
      const body = `#!/bin/sh\nnode="${process.execPath}"\n[ -x "$node" ] || node=node\nexec "$node" "${cli}" "$@"\n`;
      fs.writeFileSync(launcher, body, { mode: 0o755 });

      writeConfig({ mode: 'standard', mcpAutoWrap: true });
      writeClaude({ gmail: { command: 'npx', args: ['gmail-mcp'], env: { A: '1' } } });
      runMcpReconcile();
      expect(gmailEntry()).toEqual({
        command: launcher,
        args: ['mcp-gateway', '--config-name', 'gmail', '--upstream', 'npx gmail-mcp'],
        env: { A: '1' },
      });
      // The daemon may run on another Node than setup did: the body is not its to write.
      expect(fs.readFileSync(launcher, 'utf-8')).toBe(body);
    }
  );

  it.skipIf(process.platform === 'win32')(
    'auto-wraps with the bare name when the launcher is missing or points nowhere',
    () => {
      writeConfig({ mode: 'standard', mcpAutoWrap: true });
      writeClaude({ gmail: { command: 'npx', args: ['gmail-mcp'] } });
      runMcpReconcile();
      expect(gmailEntry().command).toBe('node9');
      expect(fs.existsSync(path.join(home, '.node9', 'bin'))).toBe(false);

      // A launcher whose node9 is gone: the bare name may still find an install.
      const launcher = path.join(home, '.node9', 'bin', 'node9');
      fs.mkdirSync(path.dirname(launcher), { recursive: true });
      fs.writeFileSync(
        launcher,
        `#!/bin/sh\nnode="${process.execPath}"\n[ -x "$node" ] || node=node\nexec "$node" "${path.join(home, 'gone.js')}" "$@"\n`,
        { mode: 0o755 }
      );
      writeClaude({ slack: { command: 'npx', args: ['slack-mcp'] } });
      runMcpReconcile();
      const slack = JSON.parse(fs.readFileSync(path.join(home, '.claude.json'), 'utf-8')).mcpServers
        .slack;
      expect(slack.command).toBe('node9');
    }
  );

  it('a failed auto-wrap is NOT baselined (retried next tick) and NOT counted (fix #3)', () => {
    writeConfig({ mode: 'standard', mcpAutoWrap: true });
    writeClaude({ gmail: { command: 'npx', args: ['gmail-mcp'] } });
    // Make the write fail: chmod the config file read-only so writeMcpEntry's
    // rename into place throws.
    const f = path.join(home, '.claude.json');
    fs.chmodSync(f, 0o400);
    // Also make the dir read-only so the tmp+rename can't succeed.
    fs.chmodSync(home, 0o500);
    try {
      runMcpReconcile();
    } finally {
      fs.chmodSync(home, 0o700);
      fs.chmodSync(f, 0o600);
    }
    // baseline must be empty (so it retries) — the server wasn't governed.
    const baselineFile = path.join(home, '.node9', 'mcp-baseline.json');
    const baseline = fs.existsSync(baselineFile)
      ? JSON.parse(fs.readFileSync(baselineFile, 'utf-8'))
      : [];
    // A failed wrap IS baselined (nudge-once) so it doesn't storm the popup every
    // tick — but it's not counted as "Wrapped" and the user is still alerted once.
    expect(baseline).toHaveLength(1);
    const wrapped = sendSpy.mock.calls.some((c) => /Wrapped/.test(String(c[1])));
    expect(wrapped).toBe(false);
    const alerted = sendSpy.mock.calls.some((c) => /ungoverned/.test(String(c[1])));
    expect(alerted).toBe(true);

    // second tick with the same (still read-only) config → NO repeat popup (no storm)
    sendSpy.mockClear();
    runMcpReconcile();
    expect(sendSpy).toHaveBeenCalledTimes(0);
  });

  it('does nothing (no notification) when everything is already governed / self', () => {
    writeConfig({ mode: 'standard' });
    writeClaude({
      fs: { command: 'node9', args: ['mcp-gateway', '--upstream', 'npx x'] },
      node9: { command: 'node9', args: ['mcp-server'] },
    });
    runMcpReconcile();
    expect(sendSpy).toHaveBeenCalledTimes(0);
  });

  // R1 Layer 1 — the refresh pass: back-fill --config-name on governed servers.
  const claudeServer = (name: string) =>
    JSON.parse(fs.readFileSync(path.join(home, '.claude.json'), 'utf-8')).mcpServers[name];

  it('refresh: back-fills --config-name on a governed server that lacks it — SILENTLY, upstream preserved', () => {
    writeClaude({
      redis: {
        command: 'node9',
        args: ['mcp-gateway', '--upstream', 'npx redis-mcp redis://h:6379'],
      },
    });
    runMcpReconcile();
    const args = claudeServer('redis').args as string[];
    expect(args).toContain('--config-name');
    expect(args[args.indexOf('--config-name') + 1]).toBe('redis'); // stamped with the config key
    expect(args[args.indexOf('--upstream') + 1]).toBe('npx redis-mcp redis://h:6379'); // serverKey preserved
    expect(sendSpy).toHaveBeenCalledTimes(0); // NO popup (R2 fatigue)
  });

  it('refresh: leaves an already-stamped server untouched (idempotent, no double)', () => {
    writeClaude({
      redis: {
        command: 'node9',
        args: ['mcp-gateway', '--config-name', 'redis', '--upstream', 'npx x'],
      },
    });
    runMcpReconcile();
    const args = claudeServer('redis').args as string[];
    expect(args.filter((a) => a === '--config-name')).toHaveLength(1);
  });

  it("refresh: never overrides a user's custom --config-name (don't fight the user)", () => {
    writeClaude({
      redis: {
        command: 'node9',
        args: ['mcp-gateway', '--config-name', 'my-custom', '--upstream', 'npx x'],
      },
    });
    runMcpReconcile();
    const args = claudeServer('redis').args as string[];
    expect(args[args.indexOf('--config-name') + 1]).toBe('my-custom');
  });

  it('refresh: does NOT auto-rewrite a governed TOML (Codex) server (fix #8)', () => {
    const codexDir = path.join(home, '.codex');
    fs.mkdirSync(codexDir, { recursive: true });
    const toml =
      '[mcp_servers.git]\ncommand = "node9"\nargs = ["mcp-gateway", "--upstream", "uvx git"]\n';
    fs.writeFileSync(path.join(codexDir, 'config.toml'), toml);
    runMcpReconcile();
    // TOML untouched — no --config-name injected (smol-toml would reformat the file).
    expect(fs.readFileSync(path.join(codexDir, 'config.toml'), 'utf-8')).not.toContain(
      '--config-name'
    );
  });

  // Entries that pin their Node: `<node> <node9 bin> <subcommand>`. Found on a
  // machine whose PATH held Node 18: the hand-pinned own server was baselined
  // and nudged as a new third-party server, and auto-wrap would have wrapped it.
  const NODE = '/home/u/.nvm/versions/node/v25.9.0/bin/node';
  const BIN = '/home/u/.nvm/versions/node/v25.9.0/bin/node9';
  const baselineIds = (): string[] => {
    const f = path.join(home, '.node9', 'mcp-baseline.json');
    return fs.existsSync(f) ? (JSON.parse(fs.readFileSync(f, 'utf-8')) as string[]) : [];
  };

  it("pinned: node9's own hand-pinned server is not nudged and not baselined", () => {
    writeConfig({ mode: 'standard' });
    writeClaude({ node9: { command: NODE, args: [BIN, 'mcp-server'] } });
    runMcpReconcile();
    expect(sendSpy).toHaveBeenCalledTimes(0);
    expect(baselineIds()).toEqual([]);
  });

  it('pinned: auto-wrap leaves hand-pinned and launcher entries exactly as they are', () => {
    writeConfig({ mode: 'standard', mcpAutoWrap: true });
    const servers = {
      node9: { command: NODE, args: [BIN, 'mcp-server'] },
      pg: {
        command: NODE,
        args: [BIN, 'mcp-gateway', '--config-name', 'pg', '--upstream', 'npx -y pg-mcp'],
      },
      viaLauncher: {
        command: path.join(home, '.node9', 'bin', 'node9'),
        args: ['mcp-gateway', '--config-name', 'viaLauncher', '--upstream', 'npx x'],
      },
    };
    writeClaude(servers);
    runMcpReconcile();
    expect(sendSpy).toHaveBeenCalledTimes(0);
    expect(
      JSON.parse(fs.readFileSync(path.join(home, '.claude.json'), 'utf-8')).mcpServers
    ).toEqual(servers);
  });

  it('refresh: a legacy `mcp --upstream` wrap is rewritten to the subcommand that starts', () => {
    // `node9 mcp` has no --upstream option, so this wrap dies on startup. It now
    // reads as a wrap, and the refresh that stamps --config-name repairs it.
    writeClaude({ redis: { command: 'node9', args: ['mcp', '--upstream', 'npx redis-mcp'] } });
    runMcpReconcile();
    expect(claudeServer('redis')).toEqual({
      command: 'node9',
      args: ['mcp-gateway', '--config-name', 'redis', '--upstream', 'npx redis-mcp'],
    });
    expect(sendSpy).toHaveBeenCalledTimes(0);
  });

  it('pinned: the --config-name refresh keeps the Node pin of a hand-pinned wrap', () => {
    writeClaude({
      redis: { command: NODE, args: [BIN, 'mcp-gateway', '--upstream', 'npx redis-mcp'] },
    });
    runMcpReconcile();
    const redis = claudeServer('redis');
    // Rewriting it to `command: "node9"` would put it back on PATH's Node.
    expect(redis.command).toBe(NODE);
    expect(redis.args).toEqual([
      BIN,
      'mcp-gateway',
      '--config-name',
      'redis',
      '--upstream',
      'npx redis-mcp',
    ]);
    expect(sendSpy).toHaveBeenCalledTimes(0);
  });

  // ── Launcher pass ───────────────────────────────────────────────────────────
  // An npm upgrade runs no setup command. A user who runs none keeps MCP
  // entries written as the bare `node9`, which start on the Node the agent's
  // PATH holds and, under an old one, do not start. The daemon is the only
  // node9 code that runs for that user without being asked.
  describe.skipIf(process.platform === 'win32')('launcher pass', () => {
    const DAY = 24 * 60 * 60 * 1000;
    let setupNode: string; // the Node an attended setup pinned: NOT the one running this test
    let cli: string;
    let origArgv1: string;
    const bin = (name: 'hook' | 'node9') => path.join(home, '.node9', 'bin', name);
    const body = (node: string, script: string) =>
      `#!/bin/sh\nnode="${node}"\n[ -x "$node" ] || node=node\nexec "$node" "${script}" "$@"\n`;
    const writeShim = (name: 'hook' | 'node9', text: string) => {
      fs.mkdirSync(path.dirname(bin(name)), { recursive: true });
      fs.writeFileSync(bin(name), text, { mode: 0o755 });
    };
    const claudeServers = () =>
      JSON.parse(fs.readFileSync(path.join(home, '.claude.json'), 'utf-8')).mcpServers;
    const logged = (event: string): Array<Record<string, unknown>> => {
      let text = '';
      try {
        text = fs.readFileSync(path.join(home, '.node9', 'hook-debug.log'), 'utf-8');
      } catch {
        return [];
      }
      return text
        .split('\n')
        .filter((l) => l.startsWith('{'))
        .map((l) => JSON.parse(l) as Record<string, unknown>)
        .filter((e) => e.event === event);
    };
    const refusal = (msAgo: number) =>
      `[${new Date(Date.now() - msAgo).toISOString()}] UNSUPPORTED NODE (mcp-gateway): node9: Node.js v18.19.1 (/usr/bin/node) cannot run node9; it needs Node.js 22.12 or later.\n`;
    // What starts each entry. (The --config-name refresh, a separate pass,
    // may stamp a wrap; it keeps the launcher an entry has.)
    const commands = (): Record<string, string> =>
      Object.fromEntries(
        Object.entries(claudeServers() as Record<string, { command: string }>).map(([k, v]) => [
          k,
          v.command,
        ])
      );
    const bare = () => ({
      node9: { command: 'node9', args: ['mcp-server'] },
      gmail: {
        command: 'node9',
        args: ['mcp-gateway', '--upstream', 'npx gmail-mcp'],
        env: { A: '1' },
      },
    });

    beforeEach(() => {
      setupNode = path.join(home, 'nvm', 'v25', 'bin', 'node');
      fs.mkdirSync(path.dirname(setupNode), { recursive: true });
      fs.writeFileSync(setupNode, '', { mode: 0o755 });
      cli = path.join(home, 'prefix', 'lib', 'node_modules', 'node9-ai', 'dist', 'cli.js');
      fs.mkdirSync(path.dirname(cli), { recursive: true });
      fs.writeFileSync(cli, '');
      writeConfig({ mode: 'standard' });
      // The daemon as an install runs it: node + cli.js. The nudge asks whether
      // this node9 could be pinned at all.
      origArgv1 = process.argv[1];
      process.argv[1] = cli;
    });
    afterEach(() => {
      process.argv[1] = origArgv1;
    });

    it('makes the launcher from the hook shim and moves the bare entries, in one pass', () => {
      writeShim('hook', body(setupNode, cli));
      writeClaude(bare());
      runMcpReconcile();

      // The Node and the node9 that attended setup chose, not the daemon's own.
      const launcher = fs.readFileSync(bin('node9'), 'utf-8');
      expect(launcher).toContain(`node="${setupNode}"`);
      expect(launcher).toContain(`exec "$node" "${cli}" "$@"`);
      expect(launcher).not.toContain(process.execPath);
      expect(fs.statSync(bin('node9')).mode & 0o777).toBe(0o755);
      expect(logged('mcp-launcher-created')).toEqual([
        { event: 'mcp-launcher-created', node: setupNode, cli },
      ]);

      expect(claudeServers()).toEqual({
        node9: { command: bin('node9'), args: ['mcp-server'] },
        gmail: {
          command: bin('node9'),
          args: ['mcp-gateway', '--config-name', 'gmail', '--upstream', 'npx gmail-mcp'],
          env: { A: '1' },
        },
      });
      expect(logged('mcp-launcher-migrated').map((e) => [e.agent, e.name, e.from])).toEqual([
        ['claude', 'node9', 'bin'],
        ['claude', 'gmail', 'bin'],
      ]);
      // Silent: nothing here is new or ungoverned.
      expect(sendSpy).not.toHaveBeenCalled();

      // The next tick finds nothing to do.
      const before = fs.readFileSync(path.join(home, '.claude.json'), 'utf-8');
      runMcpReconcile();
      expect(fs.readFileSync(path.join(home, '.claude.json'), 'utf-8')).toBe(before);
      expect(logged('mcp-launcher-migrated')).toHaveLength(2);
      expect(logged('mcp-launcher-created')).toHaveLength(1);
    });

    it('reads the older hook shim body too', () => {
      writeShim('hook', `#!/bin/sh\nexec "${setupNode}" "${cli}" "$@"\n`);
      writeClaude(bare());
      runMcpReconcile();
      expect(fs.readFileSync(bin('node9'), 'utf-8')).toContain(`node="${setupNode}"`);
      expect(claudeServers().gmail.command).toBe(bin('node9'));
    });

    it('never rewrites a launcher that exists, and moves nothing to a stale one', () => {
      writeShim('hook', body(setupNode, cli));
      const stale = body(path.join(home, 'removed', 'node'), cli);
      writeShim('node9', stale);
      writeClaude(bare());
      runMcpReconcile();
      // Rewriting is attended setup's job: one writer of the pinned Node.
      expect(fs.readFileSync(bin('node9'), 'utf-8')).toBe(stale);
      expect(commands()).toEqual({ node9: 'node9', gmail: 'node9' });
      expect(logged('mcp-launcher-created')).toEqual([]);

      // A healthy one written by setup, with another Node than the hook shim's.
      const otherNode = path.join(home, 'nvm', 'v26', 'node');
      fs.mkdirSync(path.dirname(otherNode), { recursive: true });
      fs.writeFileSync(otherNode, '', { mode: 0o755 });
      const healthy = body(otherNode, cli);
      writeShim('node9', healthy);
      runMcpReconcile();
      expect(fs.readFileSync(bin('node9'), 'utf-8')).toBe(healthy);
      expect(claudeServers().gmail.command).toBe(bin('node9'));
    });

    it('writes nothing when the hook shim is missing, stale, or not one node9 wrote', () => {
      writeClaude(bare());
      runMcpReconcile();
      expect(fs.existsSync(path.join(home, '.node9', 'bin'))).toBe(false);

      writeShim('hook', body(path.join(home, 'removed', 'node'), cli));
      runMcpReconcile();
      expect(fs.existsSync(bin('node9'))).toBe(false);

      writeShim('hook', '#!/bin/sh\necho something a person wrote\n');
      runMcpReconcile();
      expect(fs.existsSync(bin('node9'))).toBe(false);
      expect(commands()).toEqual({ node9: 'node9', gmail: 'node9' });
    });

    it('leaves an entry a person pinned that works, and moves one whose Node is gone', () => {
      writeShim('hook', body(setupNode, cli));
      const binLink = path.join(home, 'prefix', 'bin', 'node9');
      fs.mkdirSync(path.dirname(binLink), { recursive: true });
      fs.symlinkSync(cli, binLink);
      const working = { command: setupNode, args: [binLink, 'mcp-server'] };
      const viaHook = {
        command: bin('hook'),
        args: ['mcp-gateway', '--config-name', 'viaHook', '--upstream', 'npx a'],
      };
      writeClaude({
        node9: working,
        viaHook,
        dead: {
          command: path.join(home, 'removed', 'node'),
          args: [binLink, 'mcp-gateway', '--config-name', 'dead', '--upstream', 'npx b'],
        },
      });
      runMcpReconcile();
      const after = claudeServers();
      expect(after.node9).toEqual(working);
      expect(after.viaHook).toEqual(viaHook);
      expect(after.dead.command).toBe(bin('node9'));
      expect(logged('mcp-launcher-migrated').map((e) => [e.name, e.from])).toEqual([
        ['dead', 'runtime'],
      ]);
    });

    it('does not rewrite a TOML config, and tells the user when node9 failed there', () => {
      writeShim('hook', body(setupNode, cli));
      const codex = path.join(home, '.codex', 'config.toml');
      fs.mkdirSync(path.dirname(codex), { recursive: true });
      const toml = '# my notes\n[mcp_servers.node9]\ncommand = "node9"\nargs = [ "mcp-server" ]\n';
      fs.writeFileSync(codex, toml);
      fs.appendFileSync(path.join(home, '.node9', 'hook-debug.log'), refusal(DAY));
      runMcpReconcile();
      // smol-toml would reformat the whole file and drop the comment.
      expect(fs.readFileSync(codex, 'utf-8')).toBe(toml);
      expect(sendSpy).toHaveBeenCalledTimes(1);
      expect(String(sendSpy.mock.calls[0][1])).toMatch(/Codex/);
      expect(String(sendSpy.mock.calls[0][1])).toMatch(/Run: node9 heal/);
    });

    it('logs a config it cannot write and carries on', () => {
      writeShim('hook', body(setupNode, cli));
      writeClaude(bare());
      const cursor = path.join(home, '.cursor', 'mcp.json');
      fs.mkdirSync(path.dirname(cursor), { recursive: true });
      fs.writeFileSync(cursor, JSON.stringify({ mcpServers: { node9: bare().node9 } }));
      // ~/.claude.json sits in HOME itself: a read-only HOME fails its
      // temp-file-and-rename, and nothing else.
      fs.mkdirSync(path.join(home, '.node9', 'bin'), { recursive: true });
      fs.writeFileSync(bin('node9'), body(setupNode, cli), { mode: 0o755 });
      fs.chmodSync(home, 0o555);
      try {
        expect(() => runMcpReconcile()).not.toThrow();
      } finally {
        fs.chmodSync(home, 0o755);
      }
      expect(commands()).toEqual({ node9: 'node9', gmail: 'node9' });
      expect(JSON.parse(fs.readFileSync(cursor, 'utf-8')).mcpServers.node9.command).toBe(
        bin('node9')
      );
      const failed = logged('mcp-launcher-migrate-failed');
      expect(failed.map((e) => [e.agent, e.name])).toEqual([
        ['claude', 'node9'],
        ['claude', 'gmail'],
      ]);
    });

    it('nudges once when it cannot fix a machine where node9 already failed to start', () => {
      // No hook shim: setup has not run since the shim shipped.
      writeClaude(bare());
      fs.writeFileSync(path.join(home, '.node9', 'hook-debug.log'), refusal(DAY));
      runMcpReconcile();
      expect(sendSpy).toHaveBeenCalledTimes(1);
      expect(String(sendSpy.mock.calls[0][0])).toMatch(/MCP servers fail to start/);
      const text = String(sendSpy.mock.calls[0][1]);
      expect(text).toMatch(/Node\.js v18\.19\.1 is too old for node9/);
      expect(text).toMatch(/2 MCP entries \(Claude Code\)/);
      expect(text).toMatch(/Run: node9 heal/);

      sendSpy.mockClear();
      runMcpReconcile();
      expect(sendSpy).not.toHaveBeenCalled();

      // Setup runs: the entries move, and the flag clears for a later regression.
      writeShim('hook', body(setupNode, cli));
      runMcpReconcile();
      expect(claudeServers().node9.command).toBe(bin('node9'));
      expect(fs.existsSync(path.join(home, '.node9', 'mcp-node-nudged.json'))).toBe(false);
      expect(sendSpy).not.toHaveBeenCalled();
    });

    it('does not nudge a user whose bare entries have not failed', () => {
      writeClaude(bare());
      runMcpReconcile();
      expect(sendSpy).not.toHaveBeenCalled();
      // A refusal older than 7 days, and a hook refusal, are not this.
      fs.writeFileSync(
        path.join(home, '.node9', 'hook-debug.log'),
        refusal(8 * DAY) + refusal(DAY).replace('(mcp-gateway)', '(check)')
      );
      runMcpReconcile();
      expect(sendSpy).not.toHaveBeenCalled();
    });

    it('does not nudge when this node9 has no Node to pin (pnpm wrapper, bun)', () => {
      const wrapper = path.join(home, 'pnpm', 'node9');
      fs.mkdirSync(path.dirname(wrapper), { recursive: true });
      fs.writeFileSync(wrapper, '#!/bin/sh\nexec node "$basedir/cli.js" "$@"\n', { mode: 0o755 });
      process.argv[1] = wrapper;
      writeClaude(bare());
      fs.writeFileSync(path.join(home, '.node9', 'hook-debug.log'), refusal(DAY));
      runMcpReconcile();
      // `node9 heal` would change nothing here: naming it would be a false fix.
      expect(sendSpy).not.toHaveBeenCalled();
    });
  });
});
