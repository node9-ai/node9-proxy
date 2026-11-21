// A posture fix line may only name a step that changes the row on the machine
// that reads it (founder's machine, 2026-11-21, governed by the workspace
// policy: every row offered a local command that the machine ignores, two rows
// advised turning on what was on, one named a command that only reports).
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

const state = {
  source: 'local' as 'workspace' | 'local',
  mode: 'audit',
  applied: [] as string[],
  egress: { enabled: false, mode: 'off' },
  autostart: 'disabled' as 'enabled' | 'disabled' | 'absent',
  dlp: new Set<string>(),
};

vi.mock('../../config', async () => {
  const actual = await vi.importActual<typeof import('../../config')>('../../config');
  return {
    ...actual,
    getConfig: () => ({
      ...actual.DEFAULT_CONFIG,
      policySource: state.source,
      settings: { ...actual.DEFAULT_CONFIG.settings, mode: state.mode },
      policy: {
        ...actual.DEFAULT_CONFIG.policy,
        appliedShields: state.applied,
        egress: { ...actual.DEFAULT_CONFIG.policy.egress, ...state.egress },
      },
    }),
  };
});
vi.mock('../../dlp', async () => {
  const actual = await vi.importActual<typeof import('../../dlp')>('../../dlp');
  return {
    ...actual,
    scanFilePath: (p: string) => (state.dlp.has(p) ? { severity: 'block' } : null),
  };
});
vi.mock('../../daemon/service', async () => {
  const actual =
    await vi.importActual<typeof import('../../daemon/service')>('../../daemon/service');
  return { ...actual, autostartState: () => state.autostart };
});
vi.mock('../../agent-wiring', async () => {
  const actual = await vi.importActual<typeof import('../../agent-wiring')>('../../agent-wiring');
  return {
    ...actual,
    getAgentWiring: () => [{ id: 'claude', label: 'Claude Code', isProtected: true }],
  };
});

import { FAKE_GH_TOKEN as FAKE_TOKEN } from '../../__tests__/helpers/github-token';
import { remedy } from '../remedy';
import { annotateCoverage } from '../enforcement';
import { checkCoverage } from '../coverage';
import { checkCost } from '../governance';
import { checkSecrets, MOVE_SECRET_LEAD } from '../secrets';
import { checkSupplyChain } from '../supply-chain';
import { evaluateEgressConfig } from '../egress';
import { buildNetworkFix } from '../inbound';
import { lighterPath } from '../containment';
import { deriveHeadline } from '../headline';
import { renderPosture } from '../render';
import type { Finding, PostureResult } from '../types';

/** A step this machine ignores when the workspace policy governs it. */
const LOCAL_STEP =
  /node9 (jail add|egress (watch|lock|strict)|shield enable)|config\.json|config file/;
const DASHBOARD = /dashboard/;

let home: string;

function write(rel: string, text: string): string {
  const file = path.join(home, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
  return file;
}

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-fix-lines-'));
  state.source = 'local';
  state.mode = 'audit';
  state.applied = [];
  state.egress = { enabled: false, mode: 'off' };
  state.autostart = 'disabled';
  state.dlp = new Set();
});

afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

describe('remedy: where a setting is changed on this machine', () => {
  const steps = (source: 'workspace' | 'local') => [
    remedy.mode(source),
    remedy.jailAdd(source, 'each file above'),
    remedy.egress(source),
    remedy.egressLockLine(source),
    remedy.shield(source, 'project-jail'),
    remedy.shieldLine(source, 'postgres'),
    remedy.checkWhere(source, 'loading.skill-tamper'),
    remedy.checkByTitle(source, 'Internal address', 'block', 'node9 egress strict on'),
    remedy.budget(source),
  ];

  it('names the dashboard, and no local command or file, under a workspace policy', () => {
    for (const s of steps('workspace')) {
      expect(s).not.toMatch(LOCAL_STEP);
      expect(s).toMatch(DASHBOARD);
    }
  });

  it('names the local command or config file on a local machine', () => {
    for (const s of steps('local')) {
      expect(s).toMatch(LOCAL_STEP);
      expect(s).not.toMatch(DASHBOARD);
    }
  });
});

describe('workspace-governed machine: no row offers a local step', () => {
  beforeEach(() => {
    state.source = 'workspace';
    state.applied = ['project-jail'];
  });

  function jailRow(paths: string[], lead?: string): Finding {
    return {
      category: 'Secrets',
      severity: 'high',
      title: 't',
      detail: paths.map((p) => path.basename(p)),
      fix: 'placeholder',
      owner: 'node9',
      coverageProbe: { kind: 'fileRead', paths, jailFix: true, lead },
    };
  }

  it('credential rows point at the dashboard for the jail and for the mode', async () => {
    const known = path.join(home, '.ssh', 'id_rsa');
    const unknown = path.join(home, '.netrc');
    state.dlp = new Set([known]);
    for (const paths of [[unknown], [known, unknown], [known]]) {
      const f = jailRow(paths);
      await annotateCoverage([f], { home, cwd: home });
      expect(f.fix).not.toBe('placeholder');
      expect(f.fix).not.toMatch(LOCAL_STEP);
      expect(f.fix).toMatch(DASHBOARD);
    }
  });

  it('the same rows keep the local commands on a local machine', async () => {
    state.source = 'local';
    const f = jailRow([path.join(home, '.netrc')]);
    await annotateCoverage([f], { home, cwd: home });
    expect(f.fix).toContain('node9 jail add');
  });

  it('egress, mode, cost and the headline follow the same rule', () => {
    const fixes = [
      evaluateEgressConfig({ enabled: false, mode: 'off', policySource: 'workspace' }).fix,
      ...checkCoverage({ home, cwd: home })
        .filter((f) => /mode/.test(f.title))
        .map((f) => f.fix),
      ...checkCost({ home, cwd: home }).map((f) => f.fix),
      deriveHeadline(
        [{ category: 'Coverage', severity: 'high', title: 'audit', detail: [] }],
        'workspace'
      )?.action,
    ];
    expect(fixes.length).toBeGreaterThanOrEqual(4);
    for (const fix of fixes) {
      expect(fix).toBeTruthy();
      expect(fix).not.toMatch(LOCAL_STEP);
      expect(fix).toMatch(DASHBOARD);
    }
  });

  it('the report says once that changes are made on the dashboard', () => {
    const result: PostureResult = {
      agent: 'agent on this host',
      findings: [
        { category: 'Egress', severity: 'high', title: 'open', detail: [], owner: 'node9' },
      ],
      passedCategories: [],
      erroredCategories: [],
      headline: null,
      score: 50,
      tier: 'at-risk',
      checksRun: 17,
      policySource: 'workspace',
    };
    const governed = renderPosture(result);
    expect(governed).toMatch(/workspace policy/);
    expect(governed).not.toMatch(/run the command/);
    const local = renderPosture({ ...result, policySource: 'local' });
    expect(local).toMatch(/run the command/);
    expect(local).not.toMatch(/workspace policy/);
  });
});

describe('nothing is advised that is already on', () => {
  it('Isolation lists only the steps not taken, and promises no points', () => {
    const none = lighterPath({ jailOn: false, egressBlocking: false, source: 'local' });
    expect(none).toContain('node9 shield enable project-jail');
    expect(none).toContain('node9 egress lock');

    const jailOn = lighterPath({ jailOn: true, egressBlocking: false, source: 'local' });
    expect(jailOn).not.toContain('shield enable project-jail');
    expect(jailOn).toContain('node9 egress lock');

    const both = lighterPath({ jailOn: true, egressBlocking: true, source: 'local' });
    expect(both).not.toMatch(/shield enable|node9 egress|•/);
    for (const text of [none, jailOn, both]) expect(text).not.toMatch(/\+\d/);
  });

  it('Network exposure drops a shield that is on, and the weight when all are', () => {
    const labels = ['PostgreSQL on :5432', 'Redis on :6379'];
    const allOn = buildNetworkFix(labels, { applied: ['postgres', 'redis'] });
    expect(allOn.reduces).toBe(false); // no weight, no hardening tier: the port is the user's
    expect(allOn.fix).not.toMatch(/shield enable/);
    expect(allOn.fix).toMatch(/listen_addresses/);

    const oneOn = buildNetworkFix(labels, { applied: ['postgres'] });
    expect(oneOn.reduces).toBe(true);
    expect(oneOn.fix).toContain('node9 shield enable redis');
    expect(oneOn.fix).not.toContain('node9 shield enable postgres');

    const noneOn = buildNetworkFix(labels);
    expect(noneOn.fix).toContain('node9 shield enable postgres');
    expect(noneOn.fix).toContain('node9 shield enable redis');
  });
});

describe('plaintext secrets: the fix is to move the secret', () => {
  it('leads with moving the secret; the credential-files row does not', async () => {
    write(
      '.claude.json',
      JSON.stringify({ mcpServers: { x: { env: { GITHUB_TOKEN: FAKE_TOKEN } } } })
    );
    write('.ssh/id_rsa', 'key');
    const findings = checkSecrets({ home, cwd: home, env: {} });
    const plaintext = findings.find((f) => /plaintext/.test(f.title));
    const creds = findings.find((f) => /credential file/.test(f.title));
    expect(plaintext).toBeDefined();
    expect(creds).toBeDefined();
    expect(plaintext!.fix!.startsWith(MOVE_SECRET_LEAD)).toBe(true);
    expect(creds!.fix).not.toContain(MOVE_SECRET_LEAD);

    // The lead survives the rewrite that fits the jail step to the state.
    state.applied = ['project-jail'];
    await annotateCoverage(findings, { home, cwd: home });
    expect(plaintext!.fix!.startsWith(MOVE_SECRET_LEAD)).toBe(true);
    expect(plaintext!.fix).toContain('node9 jail add');
    expect(creds!.fix).not.toContain(MOVE_SECRET_LEAD);
  });
});

describe('daemon autostart', () => {
  it('names the command that installs it, not the one that reports it', () => {
    const row = checkCoverage({ home, cwd: home }).find((f) => /reboot/.test(f.title));
    expect(row).toBeDefined();
    expect(row!.fix).toContain('node9 daemon install');
    expect(row!.fix).not.toContain('node9 doctor');
  });
});

describe('MCP servers outside node9', () => {
  // The entry the ChatGPT desktop app writes into Codex's config and rewrites
  // on launch. `node9 init` refuses to wrap it (setup.ts).
  const APP_MANAGED = [
    '[mcp_servers.node_repl]',
    'command = "/usr/lib/chatgpt/resources/cua_node/bin/node_repl"',
    'args = []',
    '',
    '[mcp_servers.node_repl.env]',
    'NODE_REPL_NODE_PATH = "/usr/lib/chatgpt/resources/cua_node/bin/node"',
    '',
  ].join('\n');
  const OWN = ['[mcp_servers.mine]', 'command = "node"', 'args = ["server.js"]', ''].join('\n');
  const outside = () =>
    checkSupplyChain({ home, cwd: home }).find((f) => /run outside node9/.test(f.title));

  it('does not count a server the agent app manages', () => {
    write('.codex/config.toml', APP_MANAGED);
    expect(outside()).toBeUndefined();
  });

  it("still counts the user's own server, and names the command that wraps it", () => {
    write('.codex/config.toml', APP_MANAGED + OWN);
    const row = outside();
    expect(row).toBeDefined();
    expect(row!.detail.join(' ')).toContain('mine');
    expect(row!.detail.join(' ')).not.toContain('node_repl');
    expect(row!.title.startsWith('1 of 1 ')).toBe(true);
    expect(row!.fix).toContain('node9 init');
  });
});

describe('render: sections', () => {
  const base: PostureResult = {
    agent: 'agent on this host',
    findings: [],
    passedCategories: [],
    erroredCategories: [],
    headline: null,
    score: 80,
    tier: 'good',
    checksRun: 17,
  };

  it('a row with a score weight renders in the hardening tier, whoever owns it', () => {
    const out = renderPosture({
      ...base,
      findings: [
        { category: 'Egress', severity: 'high', title: 'egress row', detail: [], owner: 'node9' },
        {
          category: 'Cost',
          severity: 'advisory',
          title: 'cost row',
          detail: [],
          owner: 'node9',
          node9Reduces: true,
          scoreWeight: 4,
        },
      ],
    });
    const tier = out.indexOf('AVAILABLE');
    expect(tier).toBeGreaterThan(-1);
    expect(out.indexOf('egress row')).toBeLessThan(tier);
    expect(out.indexOf('cost row')).toBeGreaterThan(tier);
  });

  it('the last section is not called OS-level: a skill to update is not', () => {
    const out = renderPosture({
      ...base,
      findings: [
        { category: 'Instruction files', severity: 'medium', title: 'x', detail: [], owner: 'os' },
      ],
    });
    expect(out).toMatch(/YOUR PART/);
    expect(out).not.toMatch(/OS-level/);
  });
});
