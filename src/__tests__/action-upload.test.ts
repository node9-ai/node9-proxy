// Package 3 of the repository dashboard (node9Firewall#320, plan section 14):
// the Action sends a push scan to the connected node9 workspace. upload.js is
// plain CommonJS run by action.yml with `node`, outside the TS build, like
// comment.js. These tests drive it with injected I/O, and check that action.yml
// hands the key to the upload step alone.

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { spawnSync } from 'child_process';
import { createRequire } from 'module';
import { parse } from 'yaml';

type Deps = {
  fetch: (url: string, init?: RequestInit) => Promise<Response>;
  sleep: (ms: number) => Promise<void>;
  gitHead: (cwd: string) => string;
  readFile: (file: string) => string;
};
const ROOT = path.resolve(__dirname, '../..');
const upload = createRequire(__filename)(path.join(ROOT, 'upload.js')) as {
  run: (env: Record<string, string>, deps: Deps) => Promise<{ uploaded: boolean; line: string }>;
  apiOrigin: (input: string | undefined) => string | null;
  INGEST_PATH: string;
};

const KEY = 'n9r_' + 'A'.repeat(43);
const SHA = 'a'.repeat(40);
const OIDC_URL = 'https://token.actions.example/request?api-version=2.0';
// Shaped like a compact JWS (three dot-separated parts), as GitHub's tokens are.
const TOKEN = 'header.payload.signature';
const RESULT = JSON.stringify({
  source: '/home/runner/work/repo/repo',
  findings: [{ check: 'CI-2', rule: 'CI-2.injectable-workflow', severity: 'high' }],
  inspected: ['.github/workflows/ci.yml'],
  notes: ['a local note'],
  worst: 'high',
  incomplete: false,
});

const baseEnv = (): Record<string, string> => ({
  NODE9_UPLOAD_KEY: KEY,
  NODE9_API_URL: 'https://api.node9.ai',
  NODE9_RESULT: '/tmp/node9-result.json',
  NODE9_SCANNER_VERSION: '2.28.1',
  NODE9_SCAN_STARTED_AT: '2026-10-09T12:00:00Z',
  NODE9_SCAN_COMPLETED_AT: '2026-10-09T12:00:05Z',
  GITHUB_EVENT_NAME: 'push',
  GITHUB_WORKSPACE: '/home/runner/work/repo/repo',
  GITHUB_REPOSITORY: 'acme/widgets',
  GITHUB_REPOSITORY_ID: '123456',
  GITHUB_REF: 'refs/heads/main',
  GITHUB_SHA: SHA,
  GITHUB_RUN_ID: '987654321',
  GITHUB_RUN_ATTEMPT: '1',
  GITHUB_JOB: 'scan',
  ACTIONS_ID_TOKEN_REQUEST_URL: OIDC_URL,
  ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'runner-request-token',
});

type Call = { url: string; init?: RequestInit };
const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });

/** Fake I/O. `ingest` answers each upload attempt in turn; the OIDC request
 *  always succeeds unless `oidc` says otherwise. */
function fakeDeps(
  ingest: Array<Response | Error>,
  opts: { head?: string; result?: string; oidc?: Response } = {}
) {
  const calls: Call[] = [];
  const sleeps: number[] = [];
  let i = 0;
  const deps: Deps = {
    fetch: async (url, init) => {
      calls.push({ url, init });
      if (url.startsWith('https://token.actions.example/')) {
        return opts.oidc ?? json(200, { value: TOKEN });
      }
      const next = ingest[i++];
      if (!next) throw new Error('unexpected upload attempt');
      if (next instanceof Error) throw next;
      return next;
    },
    sleep: async (ms) => {
      sleeps.push(ms);
    },
    gitHead: () => opts.head ?? SHA,
    readFile: () => opts.result ?? RESULT,
  };
  const uploads = () => calls.filter((c) => c.url.endsWith(upload.INGEST_PATH));
  return { deps, calls, sleeps, uploads };
}

describe('upload.js: when it sends nothing', () => {
  it('no key: no network at all', async () => {
    const f = fakeDeps([]);
    const r = await upload.run({ ...baseEnv(), NODE9_UPLOAD_KEY: '' }, f.deps);
    expect(r.uploaded).toBe(false);
    expect(f.calls).toHaveLength(0);
  });

  it('a pull_request run never uploads, even with a key', async () => {
    const f = fakeDeps([]);
    const r = await upload.run({ ...baseEnv(), GITHUB_EVENT_NAME: 'pull_request' }, f.deps);
    expect(r.uploaded).toBe(false);
    expect(f.calls).toHaveLength(0);
  });

  it('a tag push is not reported: it can never be the trusted branch', async () => {
    const f = fakeDeps([]);
    const r = await upload.run(
      { ...baseEnv(), GITHUB_REF: 'refs/tags/v1.0.0', GITHUB_REF_TYPE: 'tag' },
      f.deps
    );
    expect(r.uploaded).toBe(false);
    expect(f.calls).toHaveLength(0);
  });

  it('a value that is not a node9 key is not sent, and is not echoed', async () => {
    const f = fakeDeps([]);
    const r = await upload.run({ ...baseEnv(), NODE9_UPLOAD_KEY: 'ghp_notanode9key' }, f.deps);
    expect(f.calls).toHaveLength(0);
    expect(r.line).not.toContain('ghp_notanode9key');
  });

  it.each([
    'https://evil.example',
    'http://api.node9.ai',
    'https://api.node9.ai.evil.example',
    'https://api.node9.ai@evil.example',
    'https://api.node9.ai/other',
  ])('refuses the API address %s', async (url) => {
    const f = fakeDeps([]);
    const r = await upload.run({ ...baseEnv(), NODE9_API_URL: url }, f.deps);
    expect(r.uploaded).toBe(false);
    expect(f.calls).toHaveLength(0);
  });

  it('accepts only the two node9 origins, with or without a trailing slash', () => {
    expect(upload.apiOrigin(undefined)).toBe('https://api.node9.ai');
    expect(upload.apiOrigin('https://api.node9.ai/')).toBe('https://api.node9.ai');
    expect(upload.apiOrigin('https://dev-api.node9.ai')).toBe('https://dev-api.node9.ai');
  });

  it('a checkout at another commit is not labelled with the pushed commit', async () => {
    const f = fakeDeps([], { head: 'b'.repeat(40) });
    const r = await upload.run(baseEnv(), f.deps);
    expect(r.uploaded).toBe(false);
    expect(f.calls).toHaveLength(0);
  });

  it.each(['', 'not json', '{"findings":[]}'])(
    'a scan without a result (%j) is not sent',
    async (raw) => {
      const f = fakeDeps([], { result: raw });
      const r = await upload.run(baseEnv(), f.deps);
      expect(r.uploaded).toBe(false);
      expect(f.calls).toHaveLength(0);
    }
  );

  it('an unknown scanner version is not sent as a guess', async () => {
    const f = fakeDeps([]);
    const r = await upload.run({ ...baseEnv(), NODE9_SCANNER_VERSION: '' }, f.deps);
    expect(r.uploaded).toBe(false);
    expect(f.calls).toHaveLength(0);
  });

  it('a job without id-token: write says how to fix it', async () => {
    const f = fakeDeps([]);
    const env = baseEnv();
    delete env.ACTIONS_ID_TOKEN_REQUEST_URL;
    delete env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
    const r = await upload.run(env, f.deps);
    expect(r.uploaded).toBe(false);
    expect(r.line).toContain('id-token: write');
    expect(f.calls).toHaveLength(0);
  });
});

describe('upload.js: the upload', () => {
  it('sends the envelope the server expects, with both credentials, to the fixed path', async () => {
    const f = fakeDeps([json(201, { repositoryId: 'r', runId: 'x', duplicate: false })]);
    const r = await upload.run(baseEnv(), f.deps);
    expect(r.uploaded).toBe(true);

    const oidc = new URL(f.calls[0].url);
    expect(oidc.searchParams.get('audience')).toBe('node9');
    expect(oidc.searchParams.get('api-version')).toBe('2.0');
    const oidcHeaders = f.calls[0].init?.headers as Record<string, string>;
    expect(oidcHeaders.Authorization).toBe('Bearer runner-request-token');
    expect(f.calls[0].init?.signal).toBeInstanceOf(AbortSignal);

    const [u] = f.uploads();
    expect(u.url).toBe('https://api.node9.ai/api/v1/repository-scans/ingest');
    expect(u.init?.method).toBe('POST');
    expect(u.init?.redirect).toBe('error');
    const headers = u.init?.headers as Record<string, string>;
    expect(headers.Authorization).toBe(`Bearer ${KEY}`);
    expect(headers['X-GitHub-OIDC-Token']).toBe(TOKEN);

    const body = JSON.parse(String(u.init?.body));
    expect(body).toEqual({
      schemaVersion: 1,
      repository: { githubId: '123456', fullName: 'acme/widgets' },
      ref: 'refs/heads/main',
      commitSha: SHA,
      workflowRunId: '987654321',
      workflowRunAttempt: 1,
      workflowJobKey: 'scan',
      scannerVersion: '2.28.1',
      startedAt: '2026-10-09T12:00:00Z',
      completedAt: '2026-10-09T12:00:05Z',
      result: {
        findings: [{ check: 'CI-2', rule: 'CI-2.injectable-workflow', severity: 'high' }],
        inspected: ['.github/workflows/ci.yml'],
        incomplete: false,
      },
    });
    // The runner's local path and notes stay on the runner.
    expect(String(u.init?.body)).not.toContain('/home/runner');
  });

  it('the test deployment is reachable when asked for', async () => {
    const f = fakeDeps([json(201, { duplicate: false })]);
    await upload.run({ ...baseEnv(), NODE9_API_URL: 'https://dev-api.node9.ai' }, f.deps);
    expect(f.uploads()[0].url).toBe('https://dev-api.node9.ai/api/v1/repository-scans/ingest');
  });

  it('a server error is retried, and the retry succeeds', async () => {
    const f = fakeDeps([json(503, { message: 'down' }), json(201, { duplicate: false })]);
    const r = await upload.run(baseEnv(), f.deps);
    expect(r.uploaded).toBe(true);
    expect(f.uploads()).toHaveLength(2);
    expect(f.sleeps).toHaveLength(1);
    // The same body both times: the server recognises the retry.
    expect(f.uploads()[0].init?.body).toBe(f.uploads()[1].init?.body);
  });

  it('the network failing three times gives up after three attempts', async () => {
    const f = fakeDeps([new Error('ECONNRESET'), new Error('ECONNRESET'), new Error('timeout')]);
    const r = await upload.run(baseEnv(), f.deps);
    expect(r.uploaded).toBe(false);
    expect(f.uploads()).toHaveLength(3);
    expect(r.line).toContain('not affected');
  });

  it('a redirect is refused once, not retried', async () => {
    const redirect = new TypeError('fetch failed', { cause: new Error('unexpected redirect') });
    const f = fakeDeps([redirect]);
    const r = await upload.run(baseEnv(), f.deps);
    expect(r.uploaded).toBe(false);
    expect(f.uploads()).toHaveLength(1);
    expect(f.sleeps).toHaveLength(0);
  });

  it('a malformed OIDC request URL is a skip, not an exception', async () => {
    const f = fakeDeps([]);
    const r = await upload.run({ ...baseEnv(), ACTIONS_ID_TOKEN_REQUEST_URL: 'not a url' }, f.deps);
    expect(r.uploaded).toBe(false);
    expect(f.uploads()).toHaveLength(0);
  });

  it('a missing result file says so instead of blaming the scan', async () => {
    const f = fakeDeps([]);
    f.deps.readFile = () => {
      throw Object.assign(new Error('nope'), { code: 'ENOENT' });
    };
    const r = await upload.run(baseEnv(), f.deps);
    expect(r.line).toContain('ENOENT');
    const r2 = await upload.run({ ...baseEnv(), NODE9_RESULT: '' }, f.deps);
    expect(r2.line).toContain('no result file');
    expect(f.calls).toHaveLength(0);
  });

  it.each([400, 401, 403, 404, 409, 413, 429])('a %i refusal is not retried', async (status) => {
    const f = fakeDeps([json(status, { message: 'The run is not on the trusted branch.' })]);
    const r = await upload.run(baseEnv(), f.deps);
    expect(r.uploaded).toBe(false);
    expect(f.uploads()).toHaveLength(1);
    expect(r.line).toContain(String(status));
  });

  it('a refusal reads as the server applying its rules, not as a failed upload', async () => {
    const f = fakeDeps([json(403, { message: 'The run is not on the trusted branch.' })]);
    const r = await upload.run(baseEnv(), f.deps);
    expect(r.line).toMatch(/did not accept/);
    expect(r.line).not.toMatch(/failed/);
    expect(r.line).toContain('trusted branch');
  });

  it('three server errors: three attempts, two waits, then a failure line', async () => {
    const f = fakeDeps([json(503, {}), json(502, {}), json(500, { message: 'db' })]);
    const r = await upload.run(baseEnv(), f.deps);
    expect(r.uploaded).toBe(false);
    expect(f.uploads()).toHaveLength(3);
    expect(f.sleeps).toEqual([2000, 5000]);
    expect(r.line).toMatch(/failed after 3 attempts: 500/);
    // Every attempt has its own timeout, and the OIDC request too.
    for (const c of f.calls) expect(c.init?.signal).toBeInstanceOf(AbortSignal);
    expect(new Set(f.uploads().map((c) => c.init?.signal)).size).toBe(3);
  });

  it('a thrown fetch error that repeats a credential is scrubbed', async () => {
    const leak = () => new TypeError(`Headers.append: "${TOKEN}" is invalid (${KEY})`);
    // Thrown errors are retried, so each of the three attempts throws it.
    const f = fakeDeps([leak(), leak(), leak()]);
    const r = await upload.run(baseEnv(), f.deps);
    expect(r.line).not.toContain(KEY);
    expect(r.line).not.toContain(TOKEN);
    expect(r.line).toContain('[redacted]');
  });

  it('a GitHub token that is not a JWT is never sent', async () => {
    const f = fakeDeps([], { oidc: json(200, { value: 'not a jwt\r\nX: y' }) });
    const r = await upload.run(baseEnv(), f.deps);
    expect(r.uploaded).toBe(false);
    expect(f.uploads()).toHaveLength(0);
    expect(r.line).not.toContain('not a jwt');
  });

  it('a second attempt of a run is sent as attempt 2', async () => {
    const f = fakeDeps([json(201, { duplicate: false })]);
    await upload.run({ ...baseEnv(), GITHUB_RUN_ATTEMPT: '2' }, f.deps);
    expect(JSON.parse(String(f.uploads()[0].init?.body)).workflowRunAttempt).toBe(2);
    const g = fakeDeps([]);
    const r = await upload.run({ ...baseEnv(), GITHUB_RUN_ATTEMPT: '' }, g.deps);
    expect(r.uploaded).toBe(false);
    expect(g.uploads()).toHaveLength(0);
  });

  it('never prints the key or the token, even when the server echoes them', async () => {
    const f = fakeDeps([json(401, { message: `bad key ${KEY}\nand token ${TOKEN}` })]);
    const r = await upload.run(baseEnv(), f.deps);
    expect(r.line).not.toContain(KEY);
    expect(r.line).not.toContain(TOKEN);
    expect(r.line).not.toContain('\n');
  });

  it('GitHub refusing the OIDC request means no upload', async () => {
    const f = fakeDeps([], { oidc: json(403, {}) });
    const r = await upload.run(baseEnv(), f.deps);
    expect(r.uploaded).toBe(false);
    expect(f.uploads()).toHaveLength(0);
  });

  it('as a process it always exits 0, even when it cannot upload', () => {
    const r = spawnSync(process.execPath, [path.join(ROOT, 'upload.js')], {
      encoding: 'utf8',
      env: { PATH: process.env.PATH, NODE9_UPLOAD_KEY: 'n9r_short', GITHUB_EVENT_NAME: 'push' },
    });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('node9 upload skipped');
  });
});

describe('action.yml: the upload step', () => {
  const action = parse(fs.readFileSync(path.join(ROOT, 'action.yml'), 'utf8')) as {
    inputs: Record<string, { default?: string }>;
    runs: {
      steps: Array<{ name: string; if?: string; env?: Record<string, string>; run?: string }>;
    };
  };
  const steps = action.runs.steps;
  const at = (name: string) => steps.findIndex((s) => s.name === name);

  it('is opt-in: the key defaults to empty and the API to production', () => {
    expect(action.inputs['node9-upload-key'].default).toBe('');
    expect(action.inputs['node9-api-url'].default).toBe('https://api.node9.ai');
  });

  it('runs on push with a key only, before the gate', () => {
    const i = at('Send the scan to node9');
    expect(i).toBeGreaterThan(at('Run node9 agent-security scan'));
    expect(i).toBeLessThan(at('Comment + gate'));
    const cond = steps[i].if ?? '';
    expect(cond).toContain("github.event_name == 'push'");
    expect(cond).toContain("inputs.node9-upload-key != ''");
    expect(steps[i].run).toContain('|| true');
  });

  it('the key reaches the upload step and no other', () => {
    const holders = steps.filter((s) => JSON.stringify(s).includes('inputs.node9-upload-key }}'));
    expect(holders.map((s) => s.name)).toEqual(['Send the scan to node9']);
  });

  it('only an upload run asks npm for the exact version; pull requests are unchanged', () => {
    const scan = steps[at('Run node9 agent-security scan')];
    expect(scan.env?.NODE9_WILL_UPLOAD).toBe(
      "${{ github.event_name == 'push' && inputs.node9-upload-key != '' }}"
    );
    expect(scan.run).toMatch(
      /if \[ "\$NODE9_WILL_UPLOAD" = "true" \]; then\s+VERSION="\$\(timeout 30 npm view/
    );
  });

  it('no step interpolates an expression into its shell text; values arrive through env', () => {
    for (const s of steps) if (s.run) expect(s.run, s.name).not.toContain('${{');
  });

  it('the scan step resolves an exact version: the highest match, bounded, never junk', () => {
    const scan = steps[at('Run node9 agent-security scan')].run ?? '';
    expect(scan).toMatch(/timeout 30 npm view .* --fetch-retries=1/);
    const script = /node -e '([^']+)'/.exec(scan)?.[1];
    expect(script).toBeTruthy();
    const pick = (stdin: string) =>
      spawnSync(process.execPath, ['-e', script!], { input: stdin, encoding: 'utf8' }).stdout;
    expect(pick('"2.28.1"')).toBe('2.28.1');
    // npm lists range matches in publish order, not version order.
    expect(pick('["2.28.0","2.27.1"]')).toBe('2.28.0');
    expect(pick('["2.9.0","2.10.0"]')).toBe('2.10.0');
    expect(pick('')).toBe('');
    expect(pick('{"error":{"code":"E404"}}')).toBe('');
    expect(pick('"2.28.1; rm -rf /"')).toBe('');
    expect(pick('["2.28.1; rm -rf /"]')).toBe('');
  });
});
