// node9Firewall#376 item 6, phase 4, check D: the package check for the MCP
// servers on a machine, its findings on the add-ons report, and the verdict
// for a server whose package is on the malicious-package list.
import { describe, it, expect, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { NameCheck } from '../../supply-chain/check';
import { indexKey, shardOf, writeMeta, writeShard } from '../../supply-chain/osv-index';
import { collectAddons } from '../collect';
import { AddonSessionGate } from '../gateway-gate';
import { mcpPackageFromCommand } from '../identity';
import { knownMalicious } from '../malicious-local';
import { refreshPackageStanding, standingFindings } from '../package-standing';
import { maliciousVerdict, type AddonPolicy } from '../policy';
import { addonVerdictForHookCall } from '../resolve';
import {
  MALICIOUS_RULE,
  maliciousAdvisories,
  readStanding,
  standingPath,
  writeStanding,
} from '../standing-file';

const homes: string[] = [];
function home(): string {
  const h = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-standing-'));
  fs.mkdirSync(path.join(h, '.node9'), { recursive: true });
  homes.push(h);
  return h;
}
afterEach(() => {
  for (const h of homes.splice(0)) fs.rmSync(h, { recursive: true, force: true });
  vi.unstubAllEnvs();
});

const NOW = Date.parse('2026-11-27T10:00:00Z');
const clean = (over: Partial<NameCheck> = {}): NameCheck => ({
  findings: [],
  misses: [],
  registryAsked: true,
  ...over,
});
const finding = (kind: string, advisories?: string[]) =>
  ({
    pkg: { ecosystem: 'npm', manager: 'npx', name: 'x', raw: 'x' },
    kind,
    detail: 'd',
    ...(advisories ? { advisories } : {}),
  }) as NameCheck['findings'][number];

describe('mcpPackageFromCommand', () => {
  it('names the package the launch command runs, with the version only when pinned', () => {
    expect(mcpPackageFromCommand('npx', ['-y', '@acme/db-mcp@1.4.2', '--port', '1'])).toEqual({
      ecosystem: 'npm',
      name: '@acme/db-mcp',
      version: '1.4.2',
    });
    expect(mcpPackageFromCommand('npx', ['-y', '@acme/db-mcp'])).toEqual({
      ecosystem: 'npm',
      name: '@acme/db-mcp',
    });
    // A tag is not a version the check can look up.
    expect(mcpPackageFromCommand('npx', ['@acme/db-mcp@latest'])?.version).toBeUndefined();
    expect(mcpPackageFromCommand('uvx', ['mcp-server-fetch==2025.1.17'])).toEqual({
      ecosystem: 'PyPI',
      name: 'mcp-server-fetch',
      version: '2025.1.17',
    });
  });

  it('is null for a server that is no registry package', () => {
    expect(mcpPackageFromCommand('docker', ['run', '-i', 'ghcr.io/acme/mcp:1'])).toBeNull();
    expect(mcpPackageFromCommand('/usr/local/bin/my-server', [])).toBeNull();
    expect(mcpPackageFromCommand('node', ['./server.js'])).toBeNull();
  });
});

describe('standingFindings', () => {
  it('maps what the package check found to the rules the row shows', () => {
    expect(standingFindings(clean({ findings: [finding('malicious', ['MAL-1'])] }), NOW)).toEqual([
      { rule: MALICIOUS_RULE, severity: 'critical', advisories: ['MAL-1'] },
    ]);
    expect(
      standingFindings(clean({ findings: [finding('malicious-unpinned', ['MAL-2'])] }), NOW)
    ).toEqual([{ rule: 'mcp.package-malicious-record', severity: 'high', advisories: ['MAL-2'] }]);
    expect(
      standingFindings(
        clean({ findings: [finding('lookalike'), finding('absent'), finding('placeholder')] }),
        NOW
      ).map((f) => [f.rule, f.severity])
    ).toEqual([
      ['mcp.package-lookalike', 'high'],
      ['mcp.package-absent', 'high'],
      ['mcp.package-removed', 'high'],
    ]);
  });

  it('calls a package new only inside the window, and only when nothing worse was found', () => {
    const day = 24 * 60 * 60 * 1000;
    expect(standingFindings(clean({ createdAtMs: NOW - 2 * day }), NOW)).toEqual([
      { rule: 'mcp.package-new', severity: 'medium' },
    ]);
    expect(standingFindings(clean({ createdAtMs: NOW - 30 * day }), NOW)).toEqual([]);
    expect(
      standingFindings(
        clean({ createdAtMs: NOW - 2 * day, findings: [finding('lookalike')] }),
        NOW
      ).map((f) => f.rule)
    ).toEqual(['mcp.package-lookalike']);
  });

  it('ignores the signals that describe one install at one moment', () => {
    expect(
      standingFindings(
        clean({
          findings: [finding('install-script'), finding('provenance-drop'), finding('new')],
        }),
        NOW
      )
    ).toEqual([]);
  });
});

describe('refreshPackageStanding', () => {
  const target = (version?: string) => ({
    identity: 'npm:@acme/db-mcp',
    pkg: { ecosystem: 'npm' as const, name: '@acme/db-mcp', ...(version ? { version } : {}) },
  });

  it('stores the result and does not ask again while it is fresh', async () => {
    const h = home();
    const asked: unknown[] = [];
    const check = vi.fn(async (requests: unknown) => {
      asked.push(requests);
      return [clean({ findings: [finding('malicious', ['MAL-1'])] })];
    });
    await refreshPackageStanding([target('1.0.0')], h, { check, now: NOW });
    expect(check).toHaveBeenCalledTimes(1);
    // What the check is asked is the package, never a path or an argument.
    expect(asked[0]).toEqual([
      expect.objectContaining({ ecosystem: 'npm', name: '@acme/db-mcp', version: '1.0.0' }),
    ]);
    expect(maliciousAdvisories('npm:@acme/db-mcp', h)).toEqual(['MAL-1']);
    await refreshPackageStanding([target('1.0.0')], h, { check, now: NOW + 60 * 60 * 1000 });
    expect(check).toHaveBeenCalledTimes(1);
    // Past the window, and when the pinned version changes, it is asked again.
    await refreshPackageStanding([target('1.0.0')], h, { check, now: NOW + 7 * 60 * 60 * 1000 });
    expect(check).toHaveBeenCalledTimes(2);
    await refreshPackageStanding([target('2.0.0')], h, {
      check,
      now: NOW + 7 * 60 * 60 * 1000 + 1,
    });
    expect(check).toHaveBeenCalledTimes(3);
  });

  it('a registry that did not answer is not "checked", and is asked again sooner', async () => {
    const h = home();
    const check = vi.fn(async () => [clean({ registryAsked: false, misses: ['offline'] })]);
    const file = await refreshPackageStanding([target()], h, { check, now: NOW });
    expect(file.entries['npm:@acme/db-mcp']).toMatchObject({ findings: [], registry: false });
    await refreshPackageStanding([target()], h, { check, now: NOW + 10 * 60 * 1000 });
    expect(check).toHaveBeenCalledTimes(1);
    await refreshPackageStanding([target()], h, { check, now: NOW + 31 * 60 * 1000 });
    expect(check).toHaveBeenCalledTimes(2);
  });

  it('forgets a server that is no longer configured', async () => {
    const h = home();
    const check = vi.fn(async () => [clean()]);
    await refreshPackageStanding([target()], h, { check, now: NOW });
    expect(Object.keys(readStanding(h).entries)).toEqual(['npm:@acme/db-mcp']);
    await refreshPackageStanding([], h, { check, now: NOW + 1 });
    expect(readStanding(h).entries).toEqual({});
  });

  it('keeps a malicious verdict when a later check fails as a whole', async () => {
    const h = home();
    await refreshPackageStanding([target()], h, {
      check: async () => [clean({ findings: [finding('malicious', ['MAL-1'])] })],
      now: NOW,
    });
    await refreshPackageStanding([target()], h, {
      check: async () => {
        throw new Error('registry down');
      },
      now: NOW + 7 * 60 * 60 * 1000,
    });
    expect(maliciousAdvisories('npm:@acme/db-mcp', h)).toEqual(['MAL-1']);
  });
});

describe('the standing file', () => {
  it('reads nothing from a missing, oversized or malformed file, and drops a bad entry only', () => {
    const h = home();
    expect(readStanding(h).entries).toEqual({});
    fs.writeFileSync(standingPath(h), '{not json');
    expect(readStanding(h).entries).toEqual({});
    fs.writeFileSync(
      standingPath(h),
      JSON.stringify({
        v: 1,
        entries: {
          'npm:good': {
            findings: [
              { rule: MALICIOUS_RULE, severity: 'critical', advisories: ['MAL-1', 'bad id!'] },
              { rule: 'has spaces', severity: 'high' },
              { rule: 'mcp.package-new', severity: 'huge' },
            ],
            registry: true,
            checkedAt: '2026-11-27T10:00:00.000Z',
          },
          'npm:bad': { findings: 'nope' },
        },
      })
    );
    expect(readStanding(h).entries).toEqual({
      'npm:good': {
        findings: [{ rule: MALICIOUS_RULE, severity: 'critical', advisories: ['MAL-1'] }],
        registry: true,
        checkedAt: '2026-11-27T10:00:00.000Z',
      },
    });
    expect(maliciousAdvisories('npm:good', h)).toEqual(['MAL-1']);
    expect(maliciousAdvisories('npm:bad', h)).toBeNull();
  });
});

describe('the add-ons report', () => {
  function configured(h: string): void {
    fs.writeFileSync(
      path.join(h, '.claude.json'),
      JSON.stringify({
        mcpServers: {
          bad: { command: 'npx', args: ['-y', '@acme/db-mcp'] },
          fine: { command: 'npx', args: ['-y', '@acme/ok-mcp'] },
          unreached: { command: 'uvx', args: ['mcp-server-fetch'] },
          image: { command: 'docker', args: ['run', '-i', 'ghcr.io/acme/mcp'] },
        },
      })
    );
  }
  const at = '2026-11-27T10:00:00.000Z';

  it('carries rule ids and severities per server, and tells "not checked" from "nothing found"', () => {
    const h = home();
    configured(h);
    writeStanding(
      {
        v: 1,
        entries: {
          'npm:@acme/db-mcp': {
            findings: [{ rule: MALICIOUS_RULE, severity: 'critical', advisories: ['MAL-1'] }],
            registry: true,
            checkedAt: at,
          },
          'npm:@acme/ok-mcp': { findings: [], registry: true, checkedAt: at },
          // Only the local index was read: no finding is not a clean bill.
          'pypi:mcp-server-fetch': { findings: [], registry: false, checkedAt: at },
        },
      },
      h
    );
    const byName = Object.fromEntries(collectAddons(h, {}).mcp.map((m) => [m.name, m]));
    expect(byName.bad.findings).toEqual([{ rule: MALICIOUS_RULE, severity: 'critical' }]);
    expect(byName.fine.findings).toEqual([]);
    expect(byName.unreached.findings).toBeUndefined();
    expect(byName.image.findings).toBeUndefined();
    // Advisory ids stay on the machine.
    expect(JSON.stringify(byName)).not.toContain('MAL-1');
  });

  it('has no findings field before any check ran (as an older proxy sends)', () => {
    const h = home();
    configured(h);
    for (const m of collectAddons(h, {}).mcp) expect(m.findings).toBeUndefined();
  });
});

describe('a server whose package is on the malicious list, at the hook', () => {
  function withMalicious(): string {
    const h = home();
    fs.writeFileSync(
      path.join(h, '.claude.json'),
      JSON.stringify({ mcpServers: { db: { command: 'npx', args: ['-y', '@acme/db-mcp'] } } })
    );
    writeStanding(
      {
        v: 1,
        entries: {
          'npm:@acme/db-mcp': {
            findings: [{ rule: MALICIOUS_RULE, severity: 'critical', advisories: ['MAL-1'] }],
            registry: true,
            checkedAt: '2026-11-27T10:00:00.000Z',
          },
        },
      },
      h
    );
    return h;
  }
  const call = { toolName: 'mcp__db__query', toolInput: {}, mcpServer: 'db', agent: 'Claude Code' };

  it('is stopped with no approved list at all, and names the advisory', async () => {
    const v = await addonVerdictForHookCall(undefined, call, withMalicious(), 'block');
    expect(v.action).toBe('block');
    expect(v).toMatchObject({ ruleName: 'addon:mcp-malicious:npm:@acme/db-mcp' });
    expect(v.action !== 'allow' && v.reason).toContain('MAL-1');
  });

  it('asks a person under the review setting, and does nothing when the package check is off', async () => {
    const h = withMalicious();
    expect((await addonVerdictForHookCall(undefined, call, h, 'review')).action).toBe('review');
    expect((await addonVerdictForHookCall(undefined, call, h, undefined)).action).toBe('allow');
  });

  it('is stopped even when the workspace approved the server', async () => {
    const approved: AddonPolicy = {
      unapproved: 'block',
      mcp: { 'npm:@acme/db-mcp': 'approved' },
      skills: {},
      plugins: {},
    };
    expect((await addonVerdictForHookCall(approved, call, withMalicious(), 'block')).action).toBe(
      'block'
    );
  });

  it('reads no agent config when nothing malicious is stored (the hook runs on every MCP call)', async () => {
    const h = home();
    // A config that would throw if it were parsed as JSON and reported.
    fs.writeFileSync(path.join(h, '.claude.json'), '{ this is not json');
    const read = vi.spyOn(fs, 'readFileSync');
    const before = read.mock.calls.length;
    expect((await addonVerdictForHookCall(undefined, call, h, 'block')).action).toBe('allow');
    const paths = read.mock.calls.slice(before).map((c) => String(c[0]));
    read.mockRestore();
    expect(paths.some((p) => p.endsWith('.claude.json'))).toBe(false);
  });

  it('leaves another server alone', async () => {
    const h = withMalicious();
    fs.writeFileSync(
      path.join(h, '.claude.json'),
      JSON.stringify({ mcpServers: { db: { command: 'npx', args: ['-y', '@acme/ok-mcp'] } } })
    );
    expect((await addonVerdictForHookCall(undefined, call, h, 'block')).action).toBe('allow');
  });
});

describe('a server whose package is on the malicious list, at the gateway', () => {
  it('the stricter of the list and the package verdict holds, and one approval covers a review', () => {
    const gate = new AddonSessionGate('npm:@acme/db-mcp');
    const approved: AddonPolicy = {
      unapproved: 'block',
      mcp: { 'npm:@acme/db-mcp': 'approved' },
      skills: {},
      plugins: {},
    };
    expect(gate.verdict(approved).action).toBe('allow');
    const block = maliciousVerdict('npm:@acme/db-mcp', ['MAL-1'], 'block');
    expect(gate.verdict(approved, block).action).toBe('block');
    const review = maliciousVerdict('npm:@acme/db-mcp', ['MAL-1'], 'review');
    const v = gate.verdict(approved, review);
    expect(v.action).toBe('review');
    gate.record(v, true);
    expect(gate.verdict(approved, review).action).toBe('allow');
    // A block is never approved away.
    expect(gate.verdict(approved, block).action).toBe('block');
  });

  describe('knownMalicious: what this machine can tell without the network', () => {
    function indexed(entry: object): string {
      const h = home();
      // os.homedir() reads USERPROFILE on Windows, HOME elsewhere: set both.
      vi.stubEnv('HOME', h);
      vi.stubEnv('USERPROFILE', h);
      const key = indexKey('npm', '@acme/db-mcp');
      writeShard('npm', shardOf(key), { [key]: [{ id: 'MAL-9', ...entry }] });
      writeMeta('npm', {
        syncedAt: new Date().toISOString(),
        lastModifiedMs: Date.now(),
        records: 1,
        mode: 'full',
      });
      return h;
    }
    const pkg = (version?: string) => ({
      ecosystem: 'npm' as const,
      name: '@acme/db-mcp',
      ...(version ? { version } : {}),
    });

    it('a record for every version covers a launch that pins none', () => {
      const h = indexed({ all: true });
      expect(knownMalicious('npm:@acme/db-mcp', pkg(), h)).toEqual(['MAL-9']);
    });

    it('a record for some versions covers only a launch pinned to one of them', () => {
      const h = indexed({ versions: ['1.0.1'] });
      expect(knownMalicious('npm:@acme/db-mcp', pkg('1.0.1'), h)).toEqual(['MAL-9']);
      expect(knownMalicious('npm:@acme/db-mcp', pkg('1.0.0'), h)).toBeNull();
      // Unpinned: the index alone cannot tell which version runs.
      expect(knownMalicious('npm:@acme/db-mcp', pkg(), h)).toBeNull();
    });

    it("the daemon's stored verdict is enough on its own", () => {
      const h = home();
      vi.stubEnv('HOME', h);
      vi.stubEnv('USERPROFILE', h);
      writeStanding(
        {
          v: 1,
          entries: {
            'npm:@acme/db-mcp': {
              findings: [{ rule: MALICIOUS_RULE, severity: 'critical', advisories: ['MAL-1'] }],
              registry: true,
              checkedAt: '2026-11-27T10:00:00.000Z',
            },
          },
        },
        h
      );
      expect(knownMalicious('npm:@acme/db-mcp', pkg(), h)).toEqual(['MAL-1']);
      expect(knownMalicious('npm:@acme/other', null, h)).toBeNull();
    });
  });
});
