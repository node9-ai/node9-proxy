// `node9 heal` must surface an MCP wrap that an older node9 corrupted, and must
// not pretend it can repair it.
//
// BACKGROUND. Until the fix in this release, four agent setup flows built the
// `--upstream` string with a bare join. The gateway re-splits it with
// tokenize(), which treats `\` as an escape, so a Windows path lost every
// separator between config write and spawn:
//
//   C:\Users\m\...\srv.exe   →   C:Usersm...srv.exe   →   ENOENT
//
// The wrap REPLACES the user's command, so those servers are dead right now on
// every machine that ran the old code. ⚠️ The damage is NOT recoverable: the
// separators are gone from the only copy node9 kept. Re-quoting the stored
// string would just re-quote a broken path, and unwrapping would write that
// broken path back as the user's command — worse, because it would no longer
// look like node9's doing.
//
// So heal DETECTS and REPORTS. Calling that "healing" would be the same class
// of lie this codebase has been chasing all week.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { isCorruptedUpstream, findCorruptedMcpWraps } from '../mcp-wrap.js';

describe('isCorruptedUpstream — the signature of a lost separator', () => {
  it('flags a Windows path whose separators were eaten', () => {
    // The real one, from Codex's log on 2026-09-24.
    expect(isCorruptedUpstream('C:UsersmatanAppDataLocalOpenAICodexruntimesbinnode_repl.exe')).toBe(
      true
    );
    // With arguments after it.
    expect(isCorruptedUpstream('C:Usersmsrv.exe --root C:datamcp')).toBe(true);
    // Lower-case drive letter.
    expect(isCorruptedUpstream('d:toolsserver.exe')).toBe(true);
  });

  it('does not flag a correctly quoted Windows wrap', () => {
    // What the fixed code writes. Separators intact inside the quotes.
    expect(isCorruptedUpstream('"C:\\Program Files\\Acme\\srv.exe" --root "C:\\data"')).toBe(false);
  });

  it('does not flag an unquoted but intact Windows path', () => {
    // Written by an even older node9, or by hand. Ugly, still spawnable —
    // tokenize eats the backslashes, but that is the wrap bug, not this one.
    // The point of this predicate is "the separators are already GONE from the
    // stored string", which is the unrecoverable case.
    expect(isCorruptedUpstream('C:\\Users\\m\\srv.exe')).toBe(false);
  });

  it('does not flag POSIX, relative or bare commands', () => {
    for (const s of [
      '/usr/bin/srv --port 8080',
      'npx -y @modelcontextprotocol/server-github',
      'node ./server.js',
      'uvx git',
      '',
    ]) {
      expect(isCorruptedUpstream(s), s).toBe(false);
    }
  });

  it('does not flag a bare word that merely contains a colon', () => {
    // `http://…` and `redis://…` style arguments are common; only a DRIVE
    // LETTER followed by no separator anywhere is the signature.
    expect(isCorruptedUpstream('npx redis-mcp redis://host:6379')).toBe(false);
    expect(isCorruptedUpstream('mcp-server --url https://example.com/x')).toBe(false);
  });
});

describe('findCorruptedMcpWraps — reads real agent configs', () => {
  let home = '';

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-corrupt-'));
    vi.spyOn(os, 'homedir').mockReturnValue(home);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    fs.rmSync(home, { recursive: true, force: true });
  });

  // ~/.claude.json, which is what inventoryMcp reads (agent-wiring's mcpFile
  // for claude) and what Claude Code loads. setupClaude used to write a
  // different file, ~/.claude/.mcp.json, so the inventory (and this detector,
  // `mcp status` and the reconciler) did not see what setup wrapped for
  // Claude. It writes ~/.claude.json now.
  function writeClaudeMcp(servers: Record<string, unknown>): void {
    const p = path.join(home, '.claude.json');
    fs.writeFileSync(p, JSON.stringify({ mcpServers: servers }, null, 2));
  }

  it('finds a corrupted wrap and names the agent, file and server', () => {
    writeClaudeMcp({
      acme: {
        command: 'node9',
        args: ['mcp-gateway', '--upstream', 'C:UsersmAppDataAcmesrv.exe --root C:data'],
      },
    });
    const found = findCorruptedMcpWraps(home);
    expect(found).toHaveLength(1);
    expect(found[0].name).toBe('acme');
    expect(found[0].agentLabel).toBe('Claude Code');
    expect(found[0].mcpFile).toContain('.claude.json');
  });

  it('ignores healthy wraps, unwrapped servers and node9 s own entry', () => {
    writeClaudeMcp({
      good: {
        command: 'node9',
        args: ['mcp-gateway', '--upstream', '"C:\\Program Files\\Acme\\srv.exe"'],
      },
      posix: { command: 'node9', args: ['mcp-gateway', '--upstream', '/usr/bin/srv --port 1'] },
      plain: { command: 'npx', args: ['-y', 'server-github'] },
      node9: { command: 'node9', args: ['mcp-server'] },
    });
    expect(findCorruptedMcpWraps(home)).toEqual([]);
  });

  it('returns nothing when no agent has an MCP config at all', () => {
    expect(findCorruptedMcpWraps(home)).toEqual([]);
  });
});

// ── heal reports it ───────────────────────────────────────────────────────────
// Spawned, not imported: per CLAUDE.md, anything that reads HOME and writes to
// a real config is tested against the built CLI. Mocking os.homedir() here left
// parts of heal still reading the developer's own home and the test hung.

describe('node9 heal surfaces a corrupted wrap', () => {
  const CLI = path.resolve(__dirname, '../../dist/cli.js');

  it('reports the server, says node9 cannot recover it, and leaves the file alone', () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-healmcp-'));
    const mcpPath = path.join(home, '.claude.json');
    const original = JSON.stringify(
      {
        mcpServers: {
          acme: {
            command: 'node9',
            args: ['mcp-gateway', '--upstream', 'C:UsersmAcmesrv.exe'],
          },
        },
      },
      null,
      2
    );
    fs.writeFileSync(mcpPath, original);

    const r = spawnSync(process.execPath, [CLI, 'heal'], {
      env: {
        ...process.env,
        HOME: home,
        USERPROFILE: home,
        NODE9_TESTING: '1',
        NODE9_SCAN_DISABLE: '1',
        NODE9_NO_AUTO_DAEMON: '1',
      },
      encoding: 'utf-8',
      timeout: 30000,
    });
    expect(r.error).toBeUndefined();

    const out = (r.stdout ?? '') + (r.stderr ?? '');
    expect(out).toMatch(/acme/);
    expect(out).toMatch(/cannot recover/i);
    // ⚠️ The file must be untouched: a "repair" that rewrites a broken path is
    // worse than the breakage, because it stops looking like node9's doing.
    expect(fs.readFileSync(mcpPath, 'utf-8')).toBe(original);

    fs.rmSync(home, { recursive: true, force: true });
  });

  it('says nothing about corruption on a healthy machine', () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-healok-'));
    fs.writeFileSync(
      path.join(home, '.claude.json'),
      JSON.stringify({
        mcpServers: {
          good: { command: 'node9', args: ['mcp-gateway', '--upstream', '/usr/bin/srv'] },
        },
      })
    );
    const r = spawnSync(process.execPath, [CLI, 'heal'], {
      env: {
        ...process.env,
        HOME: home,
        USERPROFILE: home,
        NODE9_TESTING: '1',
        NODE9_SCAN_DISABLE: '1',
        NODE9_NO_AUTO_DAEMON: '1',
      },
      encoding: 'utf-8',
      timeout: 30000,
    });
    expect(r.error).toBeUndefined();
    expect((r.stdout ?? '') + (r.stderr ?? '')).not.toMatch(/cannot recover/i);
    fs.rmSync(home, { recursive: true, force: true });
  });
});
