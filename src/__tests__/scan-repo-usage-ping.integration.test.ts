/**
 * Integration: the scan-repo usage ping (fw#388) through the REAL CLI (`dist/cli.js`).
 *
 * The runs that send the ping happen inside `unshare -rn` (a network namespace with no
 * network), so no test ever reaches api.node9.ai and none is counted. The machine-id file
 * in a throwaway HOME is the witness: getMachineId() creates it only on the ping path.
 *
 * Requires `npm run build` (the `pretest` script does it).
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const NOTICE = 'node9 sends an anonymous usage count';

const canUnshare = spawnSync('unshare', ['-rn', 'true']).status === 0;
const canScript = canUnshare && spawnSync('script', ['-qec', 'true', '/dev/null']).status === 0;
// The DNS-hang case needs the system resolver to be a loopback address we can occupy
// inside the namespace (systemd-resolved's 127.0.0.53 on most Linux desktops).
const LOOPBACK_DNS = (() => {
  try {
    const m = /^nameserver\s+(127\.\d+\.\d+\.\d+)\s*$/m.exec(
      fs.readFileSync('/etc/resolv.conf', 'utf8')
    );
    return m ? m[1] : null;
  } catch {
    return null;
  }
})();

let repo = '';
let home = '';

/** The environment of a user who never opted out: no NODE9_TESTING, no CI markers. */
function userEnv(extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const e: NodeJS.ProcessEnv = { ...process.env, HOME: home, ...extra };
  for (const k of [
    'NODE9_TESTING',
    'NODE9_NO_TELEMETRY',
    'DO_NOT_TRACK',
    'CI',
    'GITHUB_ACTIONS',
    'GITHUB_BASE_REF',
    'GITHUB_EVENT_NAME',
    'NODE9_USAGE_SOURCE',
  ]) {
    if (!(k in extra)) delete e[k];
  }
  return e;
}

const machineIdFile = () => path.join(home, '.node9', 'machine-id');

function run(cmd: string[], env: NodeJS.ProcessEnv) {
  const started = Date.now();
  const r = spawnSync(cmd[0], cmd.slice(1), { encoding: 'utf8', env, timeout: 60_000 });
  return { ...r, ms: Date.now() - started };
}

beforeAll(() => {
  expect(fs.existsSync(CLI), 'dist/cli.js missing: run npm run build').toBe(true);
  repo = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-ping-int-'));
  fs.writeFileSync(
    path.join(repo, '.mcp.json'),
    JSON.stringify({ mcpServers: { lookup: { command: 'npx', args: ['-y', '@acme/lookup-mcp'] } } })
  );
});

afterAll(() => {
  for (const d of [repo, home]) if (d) fs.rmSync(d, { recursive: true, force: true });
});

function freshHome(): void {
  if (home) fs.rmSync(home, { recursive: true, force: true });
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-ping-home-'));
}

describe('scan-repo usage ping, real CLI', () => {
  it('opted out: the ping path never runs and output is the plain scan', () => {
    for (const optOut of [{ NODE9_NO_TELEMETRY: '1' }, { DO_NOT_TRACK: '1' }]) {
      freshHome();
      const r = run([process.execPath, CLI, 'scan-repo', repo, '--json'], userEnv(optOut));
      expect(r.error).toBeUndefined();
      expect(r.status).not.toBe(0); // an unpinned MCP server is a finding
      expect(JSON.parse(r.stdout).worst).toBe('medium');
      expect(r.stderr).not.toContain(NOTICE);
      expect(fs.existsSync(machineIdFile())).toBe(false);
    }
  });

  it.skipIf(!canUnshare)(
    'on, with no network: same stdout and exit code, no notice in --json, never slow',
    () => {
      freshHome();
      const off = run(
        [process.execPath, CLI, 'scan-repo', repo, '--json'],
        userEnv({ NODE9_NO_TELEMETRY: '1' })
      );
      freshHome();
      const on = run(
        ['unshare', '-rn', process.execPath, CLI, 'scan-repo', repo, '--json'],
        userEnv()
      );
      expect(on.error).toBeUndefined();
      expect(on.status).toBe(off.status);
      const strip = (s: string) => {
        const j = JSON.parse(s);
        delete j.scannedAt;
        return j;
      };
      expect(strip(on.stdout)).toEqual(strip(off.stdout));
      expect(on.stderr).not.toContain(NOTICE);
      expect(fs.existsSync(machineIdFile()), 'the ping path ran').toBe(true);
      expect(on.ms).toBeLessThan(10_000);
    }
  );

  it.skipIf(!canScript)('on, in a terminal: the notice is the last line, on stderr', () => {
    freshHome();
    const r = run(
      [
        'unshare',
        '-rn',
        'script',
        '-qec',
        `${process.execPath} ${CLI} scan-repo ${repo}`,
        '/dev/null',
      ],
      userEnv()
    );
    expect(r.error).toBeUndefined();
    const lines = r.stdout.trim().split(/\r?\n/);
    expect(lines[lines.length - 1]).toContain(NOTICE);
    expect(lines[lines.length - 1]).toContain('NODE9_NO_TELEMETRY=1');
  });

  it.skipIf(!canScript)('opted out, in a terminal: no notice', () => {
    freshHome();
    const r = run(
      [
        'unshare',
        '-rn',
        'script',
        '-qec',
        `${process.execPath} ${CLI} scan-repo ${repo}`,
        '/dev/null',
      ],
      userEnv({ NODE9_NO_TELEMETRY: '1' })
    );
    expect(r.error).toBeUndefined();
    expect(r.stdout).not.toContain(NOTICE);
  });

  // Review finding: a resolver that never answers kept the process alive ~20 s after the
  // scan (getaddrinfo cannot be cancelled). The lookup is now a cancellable c-ares query.
  it.skipIf(!canUnshare || !LOOPBACK_DNS)(
    'a DNS server that never answers does not hold the run open',
    () => {
      freshHome();
      const script = [
        'ip link set lo up',
        `node -e "const s=require('dgram').createSocket('udp4');s.bind(53,'${LOOPBACK_DNS}');setTimeout(()=>{},60000)" &`,
        'sleep 0.4',
        `"${process.execPath}" "${CLI}" scan-repo "${repo}" --json > /dev/null`,
        'kill %1',
      ].join('\n');
      const r = run(['unshare', '-rn', 'bash', '-c', script], userEnv());
      expect(r.error).toBeUndefined();
      expect(fs.existsSync(machineIdFile()), 'the ping path ran').toBe(true);
      expect(r.ms).toBeLessThan(6_000);
    }
  );

  it.skipIf(!canUnshare)('in CI or the Action: no machine id is created on the runner', () => {
    for (const extra of [
      { NODE9_USAGE_SOURCE: 'action', GITHUB_REPOSITORY_ID: '42' },
      { CI: 'true', GITHUB_REPOSITORY_ID: '42' },
      { CI: 'true' },
    ]) {
      freshHome();
      const r = run(
        ['unshare', '-rn', process.execPath, CLI, 'scan-repo', repo, '--json'],
        userEnv(extra)
      );
      expect(r.error).toBeUndefined();
      expect(JSON.parse(r.stdout).worst).toBe('medium');
      expect(fs.existsSync(machineIdFile())).toBe(false);
    }
  });
});
