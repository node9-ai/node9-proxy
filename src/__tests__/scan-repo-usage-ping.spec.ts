// The scan-repo usage ping (fw#388): what it sends, when it stays silent, and that
// a slow or dead endpoint can never hold a scan up.

import { describe, it, expect, vi, beforeAll, afterAll, afterEach } from 'vitest';
import fs from 'fs';
import http from 'http';
import os from 'os';
import path from 'path';
import type { AddressInfo } from 'net';
import { parse } from 'yaml';
import { spawnSync } from 'child_process';

const MACHINE = '3f2a8c1e-4b5d-4e6f-8a9b-0c1d2e3f4a5b';
const getMachineId = vi.fn(() => MACHINE);
vi.mock('../machine-id', () => ({ getMachineId: () => getMachineId() }));

import {
  buildScanRepoPing,
  sendScanRepoPing,
  telemetryDisabled,
  usageSource,
  type ScanRepoPing,
} from '../ci-check/usage-ping';
import { scanRepo } from '../ci-check';

// A repository with a real finding, so the payload test has something to leak.
const RISKY_WORKFLOW = `name: triage
on:
  issue_comment:
    types: [created]
permissions:
  contents: write
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: "Answer this comment: \${{ github.event.comment.body }}"
          anthropic_api_key: \${{ secrets.ANTHROPIC_API_KEY }}
`;

let repo = '';
beforeAll(() => {
  repo = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-usage-ping-secretname-'));
  fs.mkdirSync(path.join(repo, '.github', 'workflows'), { recursive: true });
  fs.writeFileSync(path.join(repo, '.github', 'workflows', 'triage-bot.yml'), RISKY_WORKFLOW);
  fs.writeFileSync(
    path.join(repo, '.mcp.json'),
    JSON.stringify({ mcpServers: { lookup: { command: 'npx', args: ['-y', '@acme/lookup-mcp'] } } })
  );
});
afterAll(() => {
  if (repo) fs.rmSync(repo, { recursive: true, force: true });
});
afterEach(() => getMachineId.mockClear());

describe('usageSource', () => {
  it('is cli on a plain terminal', () => {
    expect(usageSource({})).toBe('cli');
  });
  it('is ci when CI or GITHUB_ACTIONS is set', () => {
    expect(usageSource({ CI: 'true' })).toBe('ci');
    expect(usageSource({ CI: '1' })).toBe('ci');
    expect(usageSource({ GITHUB_ACTIONS: 'true' })).toBe('ci');
  });
  it('is action when our action.yml says so, even inside CI', () => {
    expect(usageSource({ NODE9_USAGE_SOURCE: 'action', CI: 'true' })).toBe('action');
  });
  it('ignores a falsy CI value', () => {
    expect(usageSource({ CI: 'false' })).toBe('cli');
  });
});

describe('telemetryDisabled', () => {
  it('is on by default', () => {
    expect(telemetryDisabled({})).toBe(false);
  });
  it.each([
    ['NODE9_NO_TELEMETRY', '1'],
    ['NODE9_NO_TELEMETRY', 'true'],
    ['DO_NOT_TRACK', '1'],
    ['NODE9_TESTING', '1'],
  ])('%s=%s turns it off', (k, v) => {
    expect(telemetryDisabled({ [k]: v })).toBe(true);
  });
  it('NODE9_NO_TELEMETRY=0 does not turn it off', () => {
    expect(telemetryDisabled({ NODE9_NO_TELEMETRY: '0' })).toBe(false);
  });
});

describe('buildScanRepoPing', () => {
  it('carries no target, path, file name or finding', async () => {
    const res = await scanRepo(repo);
    expect(res.findings.length).toBeGreaterThan(0);
    expect(res.worst).not.toBeNull();
    const ping = buildScanRepoPing(res, repo, {});
    const wire = JSON.stringify(ping);

    expect(wire).not.toContain('secretname');
    expect(wire).not.toContain(os.tmpdir());
    expect(wire).not.toContain('triage');
    expect(wire).not.toContain('lookup');
    for (const f of res.findings) {
      expect(wire).not.toContain(f.file);
    }
    expect(Object.keys(ping).sort()).toEqual(
      [
        'event',
        'incomplete',
        'machine_id',
        'node9_version',
        'os',
        'source',
        'target_kind',
        'worst',
      ].sort()
    );
    expect(ping).toMatchObject({
      event: 'scan_repo',
      source: 'cli',
      target_kind: 'local',
      worst: res.worst,
      machine_id: MACHINE,
    });
  });

  it('sends a GitHub target as github and never the owner or name', async () => {
    const res = await scanRepo(repo);
    const ping = buildScanRepoPing(res, 'acme-corp/very-private-thing', {});
    expect(ping.target_kind).toBe('github');
    expect(JSON.stringify(ping)).not.toMatch(/acme|private-thing/);
  });

  it('maps a clean result to none', async () => {
    const res = { ...(await scanRepo(repo)), worst: null };
    expect(buildScanRepoPing(res, repo, {}).worst).toBe('none');
  });

  it('action: a hashed repository id, and no machine id ever read or created', async () => {
    const res = await scanRepo(repo);
    const ping = buildScanRepoPing(res, repo, {
      NODE9_USAGE_SOURCE: 'action',
      GITHUB_REPOSITORY_ID: '123456789',
      GITHUB_REPOSITORY: 'acme-corp/very-private-thing',
    });
    expect(ping.source).toBe('action');
    expect(ping.repo_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(ping)).not.toContain('123456789');
    expect(JSON.stringify(ping)).not.toMatch(/acme|private-thing/);
    expect(ping.machine_id).toBeUndefined();
    expect(getMachineId).not.toHaveBeenCalled();
  });

  // Review finding: a fresh CI runner minted a new machine id per run and inflated the
  // unique-machines count. CI now counts repositories, like the Action.
  it('ci: a hashed repository id, and no machine id ever read or created', async () => {
    const res = await scanRepo(repo);
    const ping = buildScanRepoPing(res, repo, { CI: 'true', GITHUB_REPOSITORY_ID: '987' });
    expect(ping.source).toBe('ci');
    expect(ping.repo_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(ping.machine_id).toBeUndefined();
    const elsewhere = buildScanRepoPing(res, repo, { CI: 'true' });
    expect(elsewhere.repo_hash).toBeUndefined();
    expect(elsewhere.machine_id).toBeUndefined();
    expect(getMachineId).not.toHaveBeenCalled();
  });

  it('action: no hash when the repository id is missing or not numeric', async () => {
    const res = await scanRepo(repo);
    for (const id of [undefined, '', 'acme/x', '12a']) {
      const ping = buildScanRepoPing(res, repo, {
        NODE9_USAGE_SOURCE: 'action',
        GITHUB_REPOSITORY_ID: id,
      });
      expect(ping.repo_hash).toBeUndefined();
    }
  });
});

describe('sendScanRepoPing', () => {
  const PING: ScanRepoPing = {
    event: 'scan_repo',
    source: 'cli',
    node9_version: '2.36.0',
    os: 'linux',
    target_kind: 'local',
    worst: 'high',
    incomplete: false,
    machine_id: MACHINE,
  };

  function listen(handler: http.RequestListener): Promise<http.Server> {
    return new Promise((resolve) => {
      const server = http.createServer(handler);
      server.listen(0, '127.0.0.1', () => resolve(server));
    });
  }
  const portOf = (s: http.Server) => (s.address() as AddressInfo).port;

  it('posts the payload as JSON to /api/v1/telemetry', async () => {
    let got: { method?: string; url?: string; body: string } = { body: '' };
    const server = await listen((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        got = { method: req.method, url: req.url, body };
        res.end('{"ok":true}');
      });
    });
    try {
      await sendScanRepoPing(PING, 1500, {
        hostname: '127.0.0.1',
        port: portOf(server),
        protocol: 'http',
      });
      expect(got.method).toBe('POST');
      expect(got.url).toBe('/api/v1/telemetry');
      expect(JSON.parse(got.body)).toEqual(PING);
    } finally {
      server.close();
    }
  });

  it('gives up after the timeout when the server never answers', async () => {
    const server = await listen(() => {
      /* never respond */
    });
    try {
      const started = Date.now();
      await sendScanRepoPing(PING, 300, {
        hostname: '127.0.0.1',
        port: portOf(server),
        protocol: 'http',
      });
      expect(Date.now() - started).toBeLessThan(1500);
    } finally {
      server.closeAllConnections();
      server.close();
    }
  });

  it('resolves at once, without throwing, when nothing listens', async () => {
    const server = await listen(() => undefined);
    const port = portOf(server);
    await new Promise((r) => server.close(r));
    const started = Date.now();
    await expect(
      sendScanRepoPing(PING, 1500, { hostname: '127.0.0.1', port, protocol: 'http' })
    ).resolves.toBeUndefined();
    expect(Date.now() - started).toBeLessThan(1000);
  });
});

describe('action.yml and our own workflow', () => {
  const ROOT = path.resolve(__dirname, '../..');
  const action = parse(fs.readFileSync(path.join(ROOT, 'action.yml'), 'utf8')) as {
    inputs: Record<string, { default?: string }>;
    runs: { steps: Array<{ name: string; env?: Record<string, string> }> };
  };

  it('has a telemetry input that is on by default', () => {
    expect(action.inputs.telemetry.default).toBe('true');
  });

  const scanStep = () =>
    action.runs.steps.find((s) => s.name === 'Run node9 agent-security scan') as {
      env?: Record<string, string>;
      run?: string;
    };

  it('marks the scan as the Action and passes the input to the script', () => {
    expect(scanStep().env?.NODE9_USAGE_SOURCE).toBe('action');
    expect(scanStep().env?.NODE9_TELEMETRY_INPUT).toBe('${{ inputs.telemetry }}');
  });

  // Review finding: a step-level NODE9_NO_TELEMETRY: '' overrode the caller's job env,
  // so a user who opted out the documented way was still counted.
  it('never sets NODE9_NO_TELEMETRY in the step env, so a job-level opt-out survives', () => {
    expect(scanStep().env).not.toHaveProperty('NODE9_NO_TELEMETRY');
    expect(scanStep().env).not.toHaveProperty('DO_NOT_TRACK');
  });

  it('the script turns the count off for telemetry: false, in any case', () => {
    const line = scanStep()
      .run!.split('\n')
      .find((l) => l.includes('NODE9_TELEMETRY_INPUT'))!;
    const decide = (input: string, jobEnv: Record<string, string> = {}) =>
      spawnSync('bash', ['-c', `set -euo pipefail\n${line}\necho "[\${NODE9_NO_TELEMETRY:-}]"`], {
        encoding: 'utf8',
        env: { PATH: process.env.PATH, NODE9_TELEMETRY_INPUT: input, ...jobEnv },
      }).stdout.trim();
    expect(decide('false')).toBe('[1]');
    expect(decide('False')).toBe('[1]');
    expect(decide('true')).toBe('[]');
    expect(decide('true', { NODE9_NO_TELEMETRY: '1' })).toBe('[1]');
  });

  it('our dogfood workflow never counts itself', () => {
    const wf = parse(
      fs.readFileSync(path.join(ROOT, '.github/workflows/agent-security.yml'), 'utf8')
    ) as {
      jobs: Record<string, { steps: Array<{ uses?: string; with?: Record<string, unknown> }> }>;
    };
    const uses = Object.values(wf.jobs).flatMap((j) => j.steps.filter((s) => s.uses === './'));
    expect(uses.length).toBeGreaterThan(0);
    for (const step of uses) expect(step.with?.telemetry).toBe(false);
  });
});
