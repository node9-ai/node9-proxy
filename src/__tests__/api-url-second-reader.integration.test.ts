// Integration: the daemon's credentials reader, through the built CLI.
// CLAUDE.md: behaviour that depends on HOME gets a spawnSync against
// dist/cli.js, not only an in-process import. `node9 policy sync` is the CLI
// entry to runCloudSync, which reads through daemon/sync.ts readCredentials.
//
// Two observables: getCredentials logs `REFUSED apiUrl, using the default
// instead: <raw>` to hook-debug.log under the temp HOME exactly when the pin
// fires, and a preload records the host each outgoing request was aimed at.
// The preload sends every request to a dead local port instead, so the test
// never reaches the real API: a fake key there only adds auth errors to the
// production logs on every suite run.
//
// Measured by hand on 2026-09-20 before this test existed: on the parent the
// same run ended in `getaddrinfo ENOTFOUND evil.example.com`.
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { DEFAULT_API_URL } from '../auth/api-url';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const DEFAULT_HOST = new URL(DEFAULT_API_URL).hostname;
const HOSTILE = 'https://evil.example.com/api/v1/intercept';

// Records the target host of every request, then points the request at a
// closed local port so it fails fast with ECONNREFUSED.
const NO_NETWORK_PRELOAD = `const fs = require('fs');
const http = require('http');
const closedPortRequest = http.request.bind(http);
const note = (host) => fs.appendFileSync(process.env.N9_TEST_HOSTS_FILE, host + '\\n');
const redirect = function (target, options, callback) {
  if (typeof options === 'function') callback = options;
  const url = typeof target === 'string' || target instanceof URL ? new URL(String(target)) : null;
  note(url ? url.hostname : String(target.hostname || target.host));
  return closedPortRequest({ hostname: '127.0.0.1', port: 9, path: '/' }, callback);
};
http.request = redirect;
require('https').request = redirect;
globalThis.fetch = async (input) => {
  note(new URL(typeof input === 'string' || input instanceof URL ? input : input.url).hostname);
  throw new Error('fetch is disabled in this test');
};
`;

function runPolicySync(apiUrl: string) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-reader2-int-'));
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  fs.writeFileSync(
    path.join(home, '.node9', 'credentials.json'),
    JSON.stringify({ default: { apiKey: 'nk_probe_not_a_real_key', apiUrl } })
  );
  const preload = path.join(home, 'no-network.cjs');
  fs.writeFileSync(preload, NO_NETWORK_PRELOAD);
  const hostsFile = path.join(home, 'hosts.txt');
  const env: Record<string, string> = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    NODE9_TESTING: '1',
    NODE9_NO_AUTO_DAEMON: '1',
    NO_COLOR: '1',
    N9_TEST_HOSTS_FILE: hostsFile,
    // A fresh HOME per spawn would fill a new compile cache every time
    // (about 2 s on Windows); the suite runs without one (fw#425).
    NODE_DISABLE_COMPILE_CACHE: '1',
    // Only the policy fetch; the piggyback pushes would each make a request.
    NODE9_BLAST_DISABLE: '1',
    NODE9_SCAN_DISABLE: '1',
    NODE9_POSTURE_DISABLE: '1',
    NODE9_POLICY_MIRROR_DISABLE: '1',
  };
  delete env.NODE9_API_KEY;
  delete env.NODE9_API_URL;
  delete env.NODE9_PROFILE;
  delete env.NODE9_API_HOST_ALLOW;

  const r = spawnSync(process.execPath, ['--require', preload, CLI, 'policy', 'sync'], {
    encoding: 'utf-8',
    env,
    timeout: 30_000,
  });
  const logPath = path.join(home, '.node9', 'hook-debug.log');
  const log = fs.existsSync(logPath) ? fs.readFileSync(logPath, 'utf-8') : '';
  const hosts = fs.existsSync(hostsFile)
    ? fs.readFileSync(hostsFile, 'utf-8').split('\n').filter(Boolean)
    : [];
  try {
    fs.rmSync(home, { recursive: true, force: true });
  } catch {
    /* best effort */
  }
  return { r, log, hosts, out: `${r.stdout}${r.stderr}` };
}

describe('node9 policy sync reads credentials through the pin (integration)', () => {
  beforeAll(() => {
    expect(fs.existsSync(CLI), `built CLI missing at ${CLI} — run npm run build`).toBe(true);
  });

  it('KNOWN-TRUE: the real host produces no REFUSED line', () => {
    const { r, log, hosts } = runPolicySync(DEFAULT_API_URL);
    expect(r.error).toBeUndefined();
    expect(log).not.toContain('REFUSED apiUrl');
    expect(hosts).toEqual([DEFAULT_HOST]);
  });

  it('THE ROW: a hostile apiUrl is refused, logged, and never contacted', () => {
    const { r, log, hosts, out } = runPolicySync(HOSTILE);
    expect(r.error).toBeUndefined();
    // The request was aimed at the default host, never the hostile one; the
    // preload made it fail, so the command fails.
    expect(hosts).toEqual([DEFAULT_HOST]);
    expect(r.status).not.toBe(0);
    expect(out).not.toContain('evil.example.com');
    expect(log).toContain('REFUSED apiUrl');
    expect(log).toContain('evil.example.com');
  });
});
