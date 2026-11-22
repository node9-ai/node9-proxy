/**
 * Integration tests for `node9 doctor`.
 * Spawns the built CLI binary with a controlled HOME directory so we can
 * assert on stdout/stderr and exit codes without touching real user files.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { renderOpencodeShim } from '../setup-opencode-shim';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const NODE = process.execPath;

/** Run `node9 doctor` with an isolated HOME. Returns stdout+stderr and exit code. */
function runDoctor(homeDir: string, cwd?: string): { output: string; exitCode: number } {
  const result = spawnSync(NODE, [CLI, 'doctor'], {
    env: {
      ...process.env,
      HOME: homeDir,
      USERPROFILE: homeDir,
      NODE9_TESTING: '1',
      XDG_CONFIG_HOME: '', // OpenCode's config dir must come from the temp HOME
    },
    cwd: cwd ?? homeDir,
    encoding: 'utf-8',
    timeout: 15000,
  });
  const output = (result.stdout ?? '') + (result.stderr ?? '');
  return { output, exitCode: result.status ?? 1 };
}

/** Write a JSON file, creating parent dirs as needed. */
function writeJson(filePath: string, data: unknown) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

let tmpBase: string;

beforeAll(() => {
  // One temp directory per test run — subdirs created per-test
  tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-doctor-test-'));
});

// ── Binary checks ─────────────────────────────────────────────────────────────

describe('node9 doctor — binary section', () => {
  it('always passes Node.js and git checks (they exist in CI)', () => {
    const home = path.join(tmpBase, 'empty');
    fs.mkdirSync(home, { recursive: true });
    const { output } = runDoctor(home);
    expect(output).toMatch(/Node\.js/);
    expect(output).toMatch(/git version/);
  });
});

// ── Config checks ─────────────────────────────────────────────────────────────

describe('node9 doctor — configuration section', () => {
  it('warns (not fails) when global config is missing', () => {
    const home = path.join(tmpBase, 'no-config');
    fs.mkdirSync(home, { recursive: true });
    const { output } = runDoctor(home);
    expect(output).toMatch(/config\.json not found/);
    expect(output).toMatch(/⚠️/);
  });

  it('passes when valid global config exists', () => {
    const home = path.join(tmpBase, 'valid-config');
    writeJson(path.join(home, '.node9', 'config.json'), { settings: { mode: 'standard' } });
    const { output } = runDoctor(home);
    expect(output).toMatch(/config\.json found and valid/);
  });

  it('fails when global config is invalid JSON', () => {
    const home = path.join(tmpBase, 'bad-config');
    const configDir = path.join(home, '.node9');
    fs.mkdirSync(configDir, { recursive: true });
    fs.writeFileSync(path.join(configDir, 'config.json'), 'this is not json');
    const { output, exitCode } = runDoctor(home);
    expect(output).toMatch(/invalid JSON/);
    expect(output).toMatch(/❌/);
    expect(exitCode).toBe(1);
  });

  it('reports cloud credentials when present', () => {
    const home = path.join(tmpBase, 'with-creds');
    writeJson(path.join(home, '.node9', 'config.json'), { settings: {} });
    writeJson(path.join(home, '.node9', 'credentials.json'), { default: { apiKey: 'test' } });
    const { output } = runDoctor(home);
    expect(output).toMatch(/credentials found/i);
  });

  it('warns (not fails) when credentials are missing', () => {
    const home = path.join(tmpBase, 'no-creds');
    writeJson(path.join(home, '.node9', 'config.json'), { settings: {} });
    const { output } = runDoctor(home);
    expect(output).toMatch(/local-only mode/i);
    expect(output).not.toMatch(/❌.*credentials/);
  });
});

// ── Hook checks ───────────────────────────────────────────────────────────────

describe('node9 doctor — agent hooks section', () => {
  it('passes Claude hook check when PreToolUse hook contains node9', () => {
    const home = path.join(tmpBase, 'claude-ok');
    writeJson(path.join(home, '.claude', 'settings.json'), {
      hooks: {
        PreToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 check' }] }],
      },
    });
    const { output } = runDoctor(home);
    expect(output).toMatch(/Claude Code.*PreToolUse hook active/);
  });

  it('fails Claude hook check when settings.json has no node9 hook', () => {
    const home = path.join(tmpBase, 'claude-bad');
    writeJson(path.join(home, '.claude', 'settings.json'), {
      hooks: { PreToolUse: [{ matcher: '.*', hooks: [{ command: 'some-other-tool' }] }] },
    });
    const { output, exitCode } = runDoctor(home);
    expect(output).toMatch(/Claude Code.*hook missing/);
    expect(exitCode).toBe(1);
  });

  it('lists Claude in the "Not configured" summary (not a failure) when absent', () => {
    const home = path.join(tmpBase, 'claude-absent');
    fs.mkdirSync(home, { recursive: true });
    const { output } = runDoctor(home);
    // Absent agents collapse into one summary line, never an ❌.
    expect(output).toMatch(/Not configured:.*Claude Code/);
    expect(output).not.toMatch(/❌.*Claude/);
  });

  it('passes Gemini hook check when BeforeTool hook contains node9', () => {
    const home = path.join(tmpBase, 'gemini-ok');
    writeJson(path.join(home, '.gemini', 'settings.json'), {
      hooks: {
        BeforeTool: [{ matcher: '.*', hooks: [{ command: 'node9 check' }] }],
      },
    });
    const { output } = runDoctor(home);
    expect(output).toMatch(/Gemini CLI.*BeforeTool hook active/);
  });

  it('passes Cursor via MCP (node9 wraps it through ~/.cursor/mcp.json, not a hook)', () => {
    const home = path.join(tmpBase, 'cursor-ok');
    writeJson(path.join(home, '.cursor', 'mcp.json'), {
      mcpServers: { node9: { command: 'node9', args: ['mcp-server'] } },
    });
    const { output } = runDoctor(home);
    expect(output).toMatch(/Cursor.*MCP proxy active/);
  });

  // Issue #480: the file existing is not OpenCode loading it.
  it('warns, not passes, when the OpenCode shim predates the OpenCode 2 shape', () => {
    const home = path.join(tmpBase, 'opencode-old-shim');
    const shim = path.join(home, '.config', 'opencode', 'plugins', 'node9.js');
    fs.mkdirSync(path.dirname(shim), { recursive: true });
    // The pre-#480 shim: v1 shape only, no shape marker.
    fs.writeFileSync(
      shim,
      '// NODE9_SHIM_VERSION = "2.64.0"\nmodule.exports = { id: "node9", server: async () => ({}) };\n'
    );
    const { output } = runDoctor(home);
    expect(output).toMatch(/OpenCode: node9 plugin is outdated\. OpenCode 2\.x refuses to load it/);
    expect(output).toMatch(/node9 agents add opencode/);
    expect(output).not.toMatch(/✅.*OpenCode/);
  });

  it('passes OpenCode when the shim carries the current shape', () => {
    const home = path.join(tmpBase, 'opencode-new-shim');
    const shim = path.join(home, '.config', 'opencode', 'plugins', 'node9.js');
    fs.mkdirSync(path.dirname(shim), { recursive: true });
    fs.writeFileSync(shim, renderOpencodeShim({ node9Argv: ['node9'], version: '0.0.0' }));
    const { output } = runDoctor(home);
    expect(output).toMatch(/✅.*OpenCode.*node9 plugin active/);
  });

  // Issue #480: a node9 hook whose binary is gone still read as "active".
  it('warns about a dead node9 Claude hook next to a working one', () => {
    const home = path.join(tmpBase, 'claude-dead-beside-live');
    writeJson(path.join(home, '.claude', 'settings.json'), {
      hooks: {
        PreToolUse: [
          {
            matcher: '.*',
            hooks: [{ command: `"${home.replace(/\\/g, '/')}/.bun/bin/node9" check` }],
          },
          { matcher: '.*', hooks: [{ command: 'node9 check' }] },
        ],
      },
    });
    const { output } = runDoctor(home);
    expect(output).toMatch(
      /⚠️.*Claude Code: 1 node9 hook\(s\) point at a file that no longer exists/
    );
    expect(output).toMatch(/node9 agents add claude/);
  });

  it('fails when every node9 Claude PreToolUse hook is dead', () => {
    const home = path.join(tmpBase, 'claude-all-dead');
    writeJson(path.join(home, '.claude', 'settings.json'), {
      hooks: {
        PreToolUse: [
          {
            matcher: '.*',
            hooks: [{ command: `"${home.replace(/\\/g, '/')}/.bun/bin/node9" check` }],
          },
        ],
      },
    });
    const { output, exitCode } = runDoctor(home);
    // agent-wiring reads an all-dead install as unwired: no tick, a failure.
    expect(output).not.toMatch(/✅.*Claude Code/);
    expect(output).toMatch(/❌.*Claude Code.*hook missing/);
    expect(exitCode).toBe(1);
  });
});

// ── Summary ───────────────────────────────────────────────────────────────────

describe('node9 doctor — summary', () => {
  // runDoctor spawns a subprocess that calls `ss` for port checking — can be slow
  // on CI runners. Raise Vitest timeout to 20s to avoid flaky failures.
  // Since the verdict-honesty change (founder QA 2026-08-28), a configured
  // machine with NO RUNNING DAEMON gets the warnings verdict, not the green
  // one — the test env can't run a daemon, so that is the expected outcome
  // here. Exit code stays 0: warnings never flip doctor red.
  it('exits 0 with the warnings verdict when configured but the daemon is down', () => {
    const home = path.join(tmpBase, 'all-good');
    writeJson(path.join(home, '.node9', 'config.json'), { settings: { mode: 'standard' } });
    writeJson(path.join(home, '.node9', 'credentials.json'), { default: { apiKey: 'k' } });
    writeJson(path.join(home, '.claude', 'settings.json'), {
      hooks: {
        PreToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 check' }] }],
      },
    });
    writeJson(path.join(home, '.gemini', 'settings.json'), {
      hooks: {
        BeforeTool: [{ matcher: '.*', hooks: [{ command: 'node9 check' }] }],
      },
    });
    writeJson(path.join(home, '.cursor', 'mcp.json'), {
      mcpServers: { node9: { command: 'node9', args: ['mcp-server'] } },
    });

    const { output, exitCode } = runDoctor(home);
    expect(output).toMatch(/warning\(s\)/);
    expect(output).not.toMatch(/All checks passed/);
    expect(exitCode).toBe(0);
  }, 20000);

  it('exits 1 and prints failure count when checks fail', () => {
    const home = path.join(tmpBase, 'has-failures');
    const configDir = path.join(home, '.node9');
    fs.mkdirSync(configDir, { recursive: true });
    // Bad JSON → failure
    fs.writeFileSync(path.join(configDir, 'config.json'), '{bad json}');

    const { output, exitCode } = runDoctor(home);
    expect(output).toMatch(/check\(s\) failed/);
    expect(exitCode).toBe(1);
  });

  it('prints version in header', () => {
    const home = path.join(tmpBase, 'version-check');
    fs.mkdirSync(home, { recursive: true });
    const { output } = runDoctor(home);
    expect(output).toMatch(/Node9 Doctor\s+v\d+\.\d+\.\d+/);
  });
});

// ── Verdict honesty (founder QA 2026-08-28) ──────────────────────────────────
// A Windows machine with no daemon and an empty dashboard got:
//   ⚠️ Daemon not running … ⚠️ node9 not in PATH … "All checks passed."
// The verdict may not contradict the findings, and zero ship-lag without a
// daemon may not claim the dashboard "matches".
describe('node9 doctor — verdict honesty', () => {
  function cloudHome(name: string): string {
    const home = path.join(tmpBase, name);
    writeJson(path.join(home, '.node9', 'config.json'), {
      settings: { approvers: { native: true, terminal: true, cloud: true } },
    });
    writeJson(path.join(home, '.node9', 'credentials.json'), {
      default: { apiKey: 'n9_live_doctor_test', apiUrl: 'https://api.node9.ai/api/v1/intercept' },
    });
    return home;
  }

  it('never prints "All checks passed" when any warning fired', () => {
    // Isolated HOME guarantees at least one warning (daemon not running).
    const { output, exitCode } = runDoctor(cloudHome('verdict-warn'));
    expect(output).toMatch(/⚠️/);
    expect(output).not.toMatch(/All checks passed/);
    expect(output).toMatch(/warning\(s\)/);
    // Warnings still exit 0 — a warned machine keeps enforcing.
    expect(exitCode).toBe(0);
  });

  it('zero ship-lag without a daemon is NOT "caught up"', () => {
    const { output } = runDoctor(cloudHome('verdict-lag'));
    expect(output).not.toMatch(/dashboard matches the local log/);
    expect(output).toMatch(/daemon is not running — new activity will not reach the dashboard/);
  });

  it('with cloud on, the daemon section is not labelled optional', () => {
    const { output } = runDoctor(cloudHome('verdict-header'));
    expect(output).toMatch(/\nDaemon\n|\bDaemon\b(?! \(optional\))/);
    expect(output).not.toMatch(/Daemon \(optional\)/);
  });

  it('the binary locator never leaks a missing-command shell error', () => {
    // On win32 the old code ran `which`, which does not exist — cmd printed
    // "'which' is not recognized" above a false "not found" warning. Runs on
    // every platform; the Windows CI runner is the one that proves the fix.
    const home = path.join(tmpBase, 'locator');
    fs.mkdirSync(home, { recursive: true });
    const { output } = runDoctor(home);
    expect(output).not.toMatch(/is not recognized as an internal or external command/);
  });
});

// ── Stalled shipping + rejected key (founder QA 2026-08-29) ──────────────────
// A running daemon that CANNOT ship printed "Shipping in progress" over 334 KB
// stuck for 12 hours, while Policy sync showed "API returned 401" — the raw
// code, leaving the reader to work out it meant "this machine is disconnected".
describe('node9 doctor — stalled shipping and rejected keys', () => {
  /** A cloud-enabled HOME with an audit log, a watermark of a given age, and
   *  an optional sync-health record. `lagBytes` sits past the watermark
   *  offset, which is exactly how shipLagBytes computes a real lag. */
  function stalledHome(
    name: string,
    opts: {
      ageMin: number;
      lagBytes: number;
      lastError?: string;
      /** Fake a LIVE daemon: isDaemonRunning() reads this pid file and probes
       *  the pid with signal 0, so our own (definitely alive) pid satisfies it.
       *  Without this the suite can only ever observe a DEAD daemon, which is
       *  how the first version of these tests passed against the old
       *  daemon-coupled condition. */
      daemonRunning?: boolean;
    }
  ): string {
    const home = path.join(tmpBase, name);
    const dir = path.join(home, '.node9');
    fs.mkdirSync(dir, { recursive: true });
    writeJson(path.join(dir, 'config.json'), {
      settings: { approvers: { native: true, terminal: true, cloud: true } },
    });
    writeJson(path.join(dir, 'credentials.json'), {
      default: { apiKey: 'n9_live_probe', apiUrl: 'https://api.node9.ai/api/v1/intercept' },
    });
    const auditLog = path.join(dir, 'audit.log');
    fs.writeFileSync(auditLog, 'x'.repeat(opts.lagBytes));
    // fileSig must match what the shipper computes, else lag = whole file —
    // which is still a lag, and is the state we want either way.
    writeJson(path.join(dir, 'audit-ship.json'), {
      fileSig: 'stale-signature',
      offset: 0,
      updatedAt: new Date(Date.now() - opts.ageMin * 60_000).toISOString(),
    });
    if (opts.daemonRunning) {
      writeJson(path.join(dir, 'daemon.pid'), { pid: process.pid, port: 7391 });
    }
    if (opts.lastError) {
      writeJson(path.join(dir, 'sync-health.json'), {
        lastCheckedAt: new Date(Date.now() - opts.ageMin * 60_000).toISOString(),
        consecutiveFailures: 2,
        lastError: opts.lastError,
      });
    }
    return home;
  }

  it('a long-stalled queue is a WARNING even though the queue is moving-looking', () => {
    const { output } = runDoctor(stalledHome('stalled', { ageMin: 765, lagBytes: 40_000 }));
    expect(output).not.toMatch(/Shipping in progress/);
    expect(output).toMatch(/NOT shipped \(last ship 765m ago\)/);
  });

  it('warns on a stalled queue even when the daemon IS running (the founder case)', () => {
    // The exact reported state: daemon up, 334 KB queued, last ship 765m ago,
    // and doctor said "Shipping in progress". The old condition only warned
    // when the daemon was DOWN, so this is the case that proves the fix.
    const { output } = runDoctor(
      stalledHome('stalled-live-daemon', {
        ageMin: 765,
        lagBytes: 40_000,
        daemonRunning: true,
      })
    );
    expect(output).not.toMatch(/Shipping in progress/);
    expect(output).toMatch(/NOT shipped/);
    // …and the hint addresses a RUNNING daemon, not "start it".
    expect(output).toMatch(/daemon is running but/i);
    expect(output).not.toMatch(/start it: node9 daemon --background/);
  });

  it('names the revoked key as the reason when the daemon is up and shipping fails', () => {
    const { output } = runDoctor(
      stalledHome('stalled-401-live', {
        ageMin: 765,
        lagBytes: 40_000,
        lastError: 'API returned 401',
        daemonRunning: true,
      })
    );
    expect(output).toMatch(/rejects this machine's key/);
    expect(output).toMatch(/node9 login/);
  });

  it('a FRESH lag still reads as in-progress — no nagging a healthy machine', () => {
    const { output } = runDoctor(stalledHome('fresh-lag', { ageMin: 2, lagBytes: 40_000 }));
    expect(output).toMatch(/Shipping in progress/);
  });

  it('a 401 in sync-health is named: disconnected, with `node9 login` as the fix', () => {
    const { output } = runDoctor(
      stalledHome('rejected', { ageMin: 765, lagBytes: 40_000, lastError: 'API returned 401' })
    );
    // Policy sync stops calling it merely STALE…
    expect(output).toMatch(/DISCONNECTED/);
    expect(output).toMatch(/node9 login/);
    // …and never suggests the command that cannot fix a revoked key.
    expect(output).not.toMatch(/Run: node9 policy sync/);
  });

  it('a non-401 failure is NOT called disconnected — 401 is the only special case', () => {
    // 12h of ETIMEDOUT is a network problem, not a revoked key. (It is also
    // under the staleness threshold, so Policy sync stays green here — the
    // point of this case is that the DISCONNECTED verdict is reserved.)
    const { output } = runDoctor(
      stalledHome('etimedout', { ageMin: 765, lagBytes: 40_000, lastError: 'ETIMEDOUT' })
    );
    expect(output).not.toMatch(/DISCONNECTED/);
    expect(output).not.toMatch(/node9 login/);
    // The stalled QUEUE is still reported — that half does not depend on why.
    expect(output).toMatch(/NOT shipped/);
  });

  it('a 401 is called out even when the sync is too RECENT to be stale', () => {
    // The first version of this fix nested the check inside the staleness
    // branch, so a machine disconnected an hour ago still read "Cloud policy
    // fresh" until the staleness clock (up to 15h) caught up.
    const { output } = runDoctor(
      stalledHome('fresh-401', { ageMin: 20, lagBytes: 40_000, lastError: 'API returned 401' })
    );
    expect(output).toMatch(/DISCONNECTED/);
    expect(output).not.toMatch(/Cloud policy fresh/);
  });
});

// ── Codex trust ───────────────────────────────────────────────────────────────
// A wired Codex hook is not a running one: Codex skips any hook the user has
// not trusted, trust is keyed to hooks.json content, and node9 rewrites that
// file on every init/add/self-heal. doctor used to print "hook active" on
// machines where Codex was running every command unchecked. These rows pin
// the three honest states and the absence of the old "/hooks" instruction.

describe('node9 doctor — Codex trust', () => {
  const hooksJson = {
    hooks: {
      PreToolUse: [
        { matcher: '^Bash$', hooks: [{ type: 'command', command: 'node9 check', timeout: 600 }] },
      ],
    },
  };
  const trusted =
    'model = "x"\n' +
    '[hooks.state."hooks.json:pre_tool_use:0:0"]\n' +
    'trusted_hash = "sha256:aaa"\n';

  function codexHome(name: string, configToml: string, auditRows: object[] = []): string {
    const home = path.join(tmpBase, name);
    writeJson(path.join(home, '.codex', 'hooks.json'), hooksJson);
    fs.writeFileSync(path.join(home, '.codex', 'config.toml'), configToml);
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    fs.writeFileSync(
      path.join(home, '.node9', 'audit.log'),
      auditRows.map((r) => JSON.stringify(r)).join('\n') + (auditRows.length ? '\n' : '')
    );
    return home;
  }

  it('fails, not passes, when Codex has never trusted the hooks', () => {
    const home = codexHome('codex-never', 'model = "x"\n');
    const { output } = runDoctor(home);
    expect(output).toMatch(/Codex — hooks wired but Codex has never trusted them/);
    expect(output).not.toMatch(/Codex — PreToolUse hook active/);
    expect(output).not.toMatch(/run \/hooks/);
    expect(output).toMatch(/Trust all and continue/);
  });

  it('warns when trust entries exist but nothing from Codex has arrived since the rewrite', () => {
    const home = codexHome('codex-unverified', trusted);
    const { output } = runDoctor(home);
    expect(output).toMatch(/Codex — hooks written .*; no Codex activity has reached node9 since/);
    expect(output).toMatch(/NOT trusted/);
    expect(output).not.toMatch(/Codex — PreToolUse hook active/);
  });

  it('passes only when a Codex audit row is newer than hooks.json', () => {
    const future = new Date(Date.now() + 60_000).toISOString();
    const home = codexHome('codex-observed', trusted, [
      { ts: future, tool: 'Bash', decision: 'allow', agent: 'Codex' },
    ]);
    const { output } = runDoctor(home);
    expect(output).toMatch(/Codex — PreToolUse hook active and trusted/);
  });

  it('fails when hooks are disabled in config.toml even though they are wired', () => {
    const home = codexHome('codex-disabled', '[features]\nhooks = false\n');
    const { output } = runDoctor(home);
    expect(output).toMatch(/Codex — hooks wired but DISABLED/);
  });
});

// ── MCP servers ──────────────────────────────────────────────────────────────
// An MCP entry written as the bare `node9` starts on the Node the agent's PATH
// holds. Under an old Node node9 refuses to run and the agent reports only
// "failed to connect". The entry is still in the config, so every other
// section read the agent as protected (found 2026-11-21, with 78 refusals in
// hook-debug.log and a doctor that printed a tick for the agent).
describe.skipIf(process.platform === 'win32')('node9 doctor — MCP servers', () => {
  const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();
  const HOUR = 60 * 60 * 1000;
  const refusal = (when: string, sub: string) =>
    `[${when}] UNSUPPORTED NODE (${sub}): node9: Node.js v18.19.1 (/usr/bin/node) cannot run node9; it needs Node.js 22.12 or later.`;
  const bareServers = {
    node9: { command: 'node9', args: ['mcp-server'] },
    gmail: {
      command: 'node9',
      args: ['mcp-gateway', '--config-name', 'gmail', '--upstream', 'npx -y gmail-mcp'],
    },
  };
  function homeWith(name: string, servers: Record<string, unknown>, log: string[] = []): string {
    const home = path.join(tmpBase, name);
    writeJson(path.join(home, '.node9', 'config.json'), { settings: { mode: 'standard' } });
    writeJson(path.join(home, '.cursor', 'mcp.json'), { mcpServers: servers });
    if (log.length > 0) {
      fs.writeFileSync(path.join(home, '.node9', 'hook-debug.log'), log.join('\n') + '\n');
    }
    return home;
  }
  const section = (output: string): string => /MCP servers\n([\s\S]*?)\n\n/.exec(output)?.[1] ?? '';

  it('warns about entries that depend on the agent PATH, and fails when node9 already refused to start', () => {
    const quoted = refusal(iso(HOUR), 'mcp-gateway');
    const home = homeWith('mcp-bare', bareServers, [
      refusal(iso(9 * 24 * HOUR), 'mcp-gateway'), // older than 7 days
      refusal(iso(2 * HOUR), 'mcp-server'),
      refusal(iso(HOUR), 'mcp-gateway'),
      refusal(iso(HOUR), 'check'), // a hook, not an MCP entry
      `[${iso(HOUR)}] STDIN: ${JSON.stringify(`a prompt that quotes: ${quoted}`)}`,
    ]);
    const { output, exitCode } = runDoctor(home);
    const mcp = section(output);
    expect(mcp).toMatch(/⚠️ {2}2 node9 MCP entries start on whatever Node the agent's PATH holds/);
    expect(mcp).toContain('Cursor: node9, gmail');
    expect(mcp).toContain('Run: node9 heal');
    expect(mcp).toMatch(
      /❌ node9's MCP entries failed to start 2 times in the last 7 days: Node\.js v18\.19\.1 \(\/usr\/bin\/node\) is too old for node9/
    );
    expect(exitCode).toBe(1);
  }, 20000);

  it('only warns when nothing has failed: the entries may be working', () => {
    const { output } = runDoctor(homeWith('mcp-bare-quiet', bareServers));
    const mcp = section(output);
    expect(mcp).toMatch(/2 node9 MCP entries start on whatever Node/);
    expect(mcp).not.toContain('❌');
  }, 20000);

  it('passes once the entries start through a launcher that points somewhere', () => {
    const home = path.join(tmpBase, 'mcp-launcher');
    const launcher = path.join(home, '.node9', 'bin', 'node9');
    const cli = path.join(home, 'cli.js');
    writeJson(cli, {});
    writeJson(path.join(home, '.node9', 'config.json'), { settings: { mode: 'standard' } });
    // The refusals are from before the entries were moved.
    fs.writeFileSync(
      path.join(home, '.node9', 'hook-debug.log'),
      refusal(iso(HOUR), 'mcp-gateway') + '\n'
    );
    fs.mkdirSync(path.dirname(launcher), { recursive: true });
    fs.writeFileSync(
      launcher,
      `#!/bin/sh\nnode="${NODE}"\n[ -x "$node" ] || node=node\nexec "$node" "${cli}" "$@"\n`,
      { mode: 0o755 }
    );
    writeJson(path.join(home, '.cursor', 'mcp.json'), {
      mcpServers: {
        node9: { command: launcher, args: ['mcp-server'] },
        gmail: {
          command: launcher,
          args: ['mcp-gateway', '--config-name', 'gmail', '--upstream', 'npx -y gmail-mcp'],
        },
      },
    });
    const mcp = section(runDoctor(home).output);
    expect(mcp).toContain(
      `✅ node9 MCP entries: 2 start through ~/.node9/bin/node9 (Node: ${NODE})`
    );
    expect(mcp).toMatch(/✅ MCP entries failed to start on an old Node until 1 hour ago/);
    expect(mcp).not.toContain('❌');
    expect(mcp).not.toContain('⚠️');

    // The same machine after the pinned Node was removed.
    fs.writeFileSync(
      launcher,
      `#!/bin/sh\nnode="${path.join(home, 'gone', 'node')}"\n[ -x "$node" ] || node=node\nexec "$node" "${cli}" "$@"\n`,
      { mode: 0o755 }
    );
    const stale = section(runDoctor(home).output);
    expect(stale).toMatch(
      /⚠️ {2}The node9 launcher points at a Node or a node9 that no longer exists/
    );
    expect(stale).toContain('Run: node9 init');
    expect(stale).toMatch(/❌ node9's MCP entries failed to start 1 time in the last 7 days/);
  }, 40000);

  it('says so when an entry still fails and no config node9 reads explains it', () => {
    const home = path.join(tmpBase, 'mcp-elsewhere');
    const launcher = path.join(home, '.node9', 'bin', 'node9');
    const cli = path.join(home, 'cli.js');
    writeJson(cli, {});
    writeJson(path.join(home, '.node9', 'config.json'), { settings: { mode: 'standard' } });
    fs.mkdirSync(path.dirname(launcher), { recursive: true });
    fs.writeFileSync(
      launcher,
      `#!/bin/sh\nnode="${NODE}"\n[ -x "$node" ] || node=node\nexec "$node" "${cli}" "$@"\n`,
      { mode: 0o755 }
    );
    const config = path.join(home, '.cursor', 'mcp.json');
    writeJson(config, { mcpServers: { node9: { command: launcher, args: ['mcp-server'] } } });
    // The config was last changed a day ago; node9 refused to start a minute ago.
    const dayAgo = new Date(Date.now() - 24 * HOUR);
    fs.utimesSync(config, dayAgo, dayAgo);
    fs.writeFileSync(
      path.join(home, '.node9', 'hook-debug.log'),
      refusal(iso(60_000), 'mcp-gateway') + '\n'
    );
    const mcp = section(runDoctor(home).output);
    expect(mcp).toMatch(/⚠️ {2}A node9 MCP entry failed to start 1 time in the last 7 days/);
    expect(mcp).toContain('project-scoped server');
    expect(mcp).not.toContain('❌');
  }, 20000);

  it('prints no section on a machine with no node9 MCP entry and no refusal', () => {
    const home = homeWith('mcp-none', { plain: { command: 'npx', args: ['plain-mcp'] } });
    expect(runDoctor(home).output).not.toContain('MCP servers');
  }, 20000);
});
