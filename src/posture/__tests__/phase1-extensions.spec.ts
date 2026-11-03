// node9Firewall#320 phase 1: the posture extension beyond the three new
// checks. Plugins and the package check under Supply chain (ASI04), the
// daemon after a reboot under Coverage (ASI10), the OWASP tag on every finding
// and on the wire, and the audit-mode fix text. Synthetic fixtures only.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

let checks: Record<string, string> = {};
let autostart: 'enabled' | 'disabled' | 'absent' | 'unsupported' = 'enabled';
let mode = 'standard';

vi.mock('../../config', async () => {
  const actual = await vi.importActual<typeof import('../../config')>('../../config');
  return {
    ...actual,
    getConfig: () => ({
      ...actual.DEFAULT_CONFIG,
      settings: { ...actual.DEFAULT_CONFIG.settings, mode },
      policy: { ...actual.DEFAULT_CONFIG.policy, checks: { ...checks } },
    }),
  };
});
vi.mock('../../daemon/service', async () => {
  const actual =
    await vi.importActual<typeof import('../../daemon/service')>('../../daemon/service');
  return { ...actual, autostartState: () => autostart };
});
vi.mock('../../agent-wiring', async () => {
  const actual = await vi.importActual<typeof import('../../agent-wiring')>('../../agent-wiring');
  return {
    ...actual,
    getAgentWiring: () => [{ id: 'claude', label: 'Claude Code', isProtected: true }],
  };
});

import { pluginPinState, checkSupplyChain } from '../supply-chain';
import { getRootKey } from '../../skill-pin';
import { checkCoverage } from '../coverage';
import { auditModeFix } from '../enforcement';
import { buildShipBody } from '../ship';
import { scorePosture } from '../score';
import type { CheckContext, Finding, PostureResult } from '../types';

let home: string;
let prevHome: string | undefined;

const ctx = (): CheckContext => ({ home, cwd: home });

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-phase1-'));
  prevHome = process.env.HOME;
  process.env.HOME = home; // the pin files live under the real HOME
  checks = {};
  autostart = 'enabled';
  mode = 'standard';
});

afterEach(() => {
  process.env.HOME = prevHome;
  fs.rmSync(home, { recursive: true, force: true });
});

function plugin(name: string): void {
  fs.mkdirSync(path.join(home, '.claude', 'plugins', 'marketplaces', 'm', 'plugins', name), {
    recursive: true,
  });
}

describe('Supply chain: plugins and the package check', () => {
  it('reads the pins from the same home as the plugin roots', () => {
    plugin('alpha');
    const root = pluginPinState(home).roots[0];
    // A pin in this home, while the process HOME points elsewhere.
    process.env.HOME = os.tmpdir();
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    fs.writeFileSync(
      path.join(home, '.node9', 'skill-pins.json'),
      JSON.stringify({
        roots: {
          [getRootKey(root)]: { rootPath: root, contentHash: 'h', exists: true, fileCount: 0 },
        },
      })
    );
    expect(pluginPinState(home).unpinned).toEqual([]);
  });

  it('lists installed plugin roots and which have no pin', () => {
    plugin('alpha');
    plugin('beta');
    const { roots, unpinned } = pluginPinState(home);
    expect(roots.map((r) => path.basename(r)).sort()).toEqual(['alpha', 'beta']);
    expect(unpinned).toEqual(roots);
  });

  it('with loading.skill-tamper off, installed plugins load unverified', () => {
    plugin('alpha');
    checks = { 'loading.skill-tamper': 'off' };
    const f = checkSupplyChain(ctx()).find((x) => x.title.includes('unverified'))!;
    expect(f).toBeDefined();
    expect(f.severity).toBe('advisory');
    expect(f.owner).toBe('node9');
    expect(f.detail[0].replace(/\\/g, '/')).toMatch(/^~\/\.claude\/plugins\//);
    expect(f.fix).toContain('loading.skill-tamper');
  });

  it('with the check on and no pin yet, says the next load pins it', () => {
    plugin('alpha');
    checks = { 'loading.skill-tamper': 'block' };
    const f = checkSupplyChain(ctx()).find((x) => x.title.includes('no pin yet'))!;
    expect(f).toBeDefined();
    expect(f.severity).toBe('advisory');
    expect(f.fix).toContain('node9 skill pin list');
  });

  it('reports the package check off', () => {
    checks = { 'loading.malicious-package': 'off' };
    const f = checkSupplyChain(ctx()).find((x) => x.title.includes('malicious-package index'))!;
    expect(f).toBeDefined();
    expect(f.owner).toBe('node9');
  });

  it('is quiet with no plugins and the defaults', () => {
    expect(checkSupplyChain(ctx()).filter((f) => /plugin|package/.test(f.title))).toEqual([]);
  });
});

describe('Coverage: the daemon after a reboot', () => {
  it('reports a missing or disabled autostart entry as a node9 finding', () => {
    autostart = 'absent';
    const f = checkCoverage(ctx()).find((x) => x.title.includes('reboot'))!;
    expect(f).toBeDefined();
    expect(f.severity).toBe('medium');
    expect(f.why).toContain('No autostart entry');
    expect(f.fix).toContain('node9 doctor');
    autostart = 'disabled';
    expect(checkCoverage(ctx()).find((x) => x.title.includes('reboot'))!.why).toContain('disabled');
  });

  it('says nothing when autostart is on or the platform has none', () => {
    for (const s of ['enabled', 'unsupported'] as const) {
      autostart = s;
      expect(checkCoverage(ctx()).find((x) => x.title.includes('reboot'))).toBeUndefined();
    }
  });
});

describe('the audit-mode fix text', () => {
  it('names the level and the setting, with no path', () => {
    const text = auditModeFix('observe', 'node9 already stops this');
    expect(text).toContain('audit mode');
    expect(text).toContain('node9 already stops this');
    expect(text).toContain('set mode to `standard`');
    expect(text).not.toMatch(/\/home\//);
  });
});

describe('the OWASP tag', () => {
  const finding = (category: string): Finding => ({
    category,
    severity: 'high',
    title: 't',
    detail: ['/home/u/.ssh/id_rsa'],
    owasp: 'ASI03',
  });

  it('ships the risk id and still never the detail', () => {
    const result: PostureResult = {
      agent: 'a',
      findings: [finding('Secrets')],
      passedCategories: [],
      erroredCategories: [],
      headline: null,
      score: 50,
      tier: 'at-risk',
      checksRun: 1,
    };
    const body = buildShipBody(result);
    expect(body.findings[0].owasp).toBe('ASI03');
    expect(JSON.stringify(body)).not.toContain('id_rsa');
  });

  it('does not change the score', () => {
    const a = scorePosture([finding('Secrets')], 10);
    const b = scorePosture([{ ...finding('Secrets'), owasp: undefined }], 10);
    expect(a).toEqual(b);
  });
});
