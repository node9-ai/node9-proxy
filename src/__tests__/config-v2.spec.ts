// The v2 config file, read path: a v2 global file governs the engine through
// `policy.checks`, a v2 project file may only tighten, the translation both
// ways keeps every resolved value, and `legacyToV2` writes only what departs
// from the shipped defaults. Harness: real getConfig under a temp HOME.
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { resolveAllChecks } from '@node9/policy-engine';

vi.mock('../shields', async () => {
  const actual = await vi.importActual<typeof import('../shields')>('../shields');
  return { ...actual, readActiveShields: () => [], readShieldOverrides: () => ({}) };
});

import {
  getConfig,
  _resetConfigCache,
  catalogSettingsFrom,
  DEFAULT_CONFIG,
  RUNTIME_ONLY_CONFIG_KEYS,
} from '../config';
import {
  legacyToV2,
  v2ToLegacy,
  isV2File,
  configurableValues,
  FILE_CHECK_IDS,
  type LegacyFile,
} from '../config/v2';
import { evaluatePolicy } from '../policy';
import { buildChecksReport } from '../cli/commands/checks';

let tmpHome: string;
let projectDir: string;
let origHome: string | undefined;
let origUserprofile: string | undefined;

beforeAll(() => {
  tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-v2-'));
  projectDir = path.join(tmpHome, 'project');
  fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
  fs.mkdirSync(projectDir, { recursive: true });
  origHome = process.env.HOME;
  origUserprofile = process.env.USERPROFILE;
  process.env.HOME = tmpHome;
  process.env.USERPROFILE = tmpHome;
});

afterAll(() => {
  process.env.HOME = origHome;
  process.env.USERPROFILE = origUserprofile;
  _resetConfigCache();
  fs.rmSync(tmpHome, { recursive: true, force: true });
});

const globalFile = () => path.join(tmpHome, '.node9', 'config.json');
const projectFile = () => path.join(projectDir, 'node9.config.json');
const writeGlobal = (o: unknown) => fs.writeFileSync(globalFile(), JSON.stringify(o));
const writeProject = (o: unknown) => fs.writeFileSync(projectFile(), JSON.stringify(o));

beforeEach(() => {
  fs.rmSync(globalFile(), { force: true });
  fs.rmSync(projectFile(), { force: true });
  _resetConfigCache();
});

describe('a v2 global file', () => {
  it('turns sudo off in one line, and node9 checks says the file did it', async () => {
    writeGlobal({ version: '2', checks: { 'commands.sudo': 'off' } });
    const v = await evaluatePolicy('bash', { command: 'sudo apt-get install jq' });
    expect(v.decision).toBe('allow');
    const row = buildChecksReport(getConfig()).checks.find((c) => c.id === 'commands.sudo');
    expect(row).toMatchObject({ value: 'off', source: 'local' });
  });

  it('a legacy-knob check written as a v2 check reaches the old gate too', () => {
    writeGlobal({ version: '2', checks: { 'data.pii': 'off', 'network.unknown-host': 'block' } });
    const c = getConfig();
    expect(c.policy.dlp.pii).toBe('off');
    expect(c.policy.egress).toMatchObject({ enabled: true, mode: 'block' });
    expect(c.policy.checks?.['data.pii']).toBe('off');
    expect(c.policy.checks?.['network.unknown-host']).toBe('block');
  });

  it('mode, approvals, tuning, rules, tools and device land where the loader expects', () => {
    writeGlobal({
      version: '2',
      mode: 'strict',
      approvals: { channels: ['terminal'], timeoutSeconds: 30, reviewPrompt: 'approver' },
      tuning: {
        'behavior.loops': { threshold: 9, windowSeconds: 60 },
        'network.unknown-host': { allow: ['*.corp.com'] },
      },
      rules: [
        {
          name: 'my-rule',
          tool: 'bash',
          conditions: [{ field: 'command', op: 'contains', value: 'terraform destroy' }],
          verdict: 'review',
          reason: 'team',
        },
      ],
      tools: { ignored: ['my_tool'] },
      device: { autoStartDaemon: false },
    });
    const c = getConfig();
    expect(c.settings.mode).toBe('strict');
    expect(c.settings.approvers).toMatchObject({ native: false, terminal: true, cloud: false });
    expect(c.settings.approvalTimeoutMs).toBe(30_000);
    expect(c.settings.reviewChannel).toBe('approver');
    expect(c.settings.autoStartDaemon).toBe(false);
    expect(c.policy.loopDetection).toMatchObject({ threshold: 9, windowSeconds: 60 });
    expect(c.policy.egress.allow).toContain('*.corp.com');
    expect(c.policy.smartRules.some((r) => r.name === 'my-rule')).toBe(true);
    expect(c.policy.ignoredTools).toContain('my_tool');
    expect(c.policy.checks?.['commands.unknown']).toBe('review');
  });

  it('reports and drops what it cannot honour, and never throws', () => {
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    writeGlobal({
      version: '2',
      checks: {
        'commands.nope': 'off',
        'commands.sudo': 'maybe',
        'network.metadata': 'off',
        'commands.unknown': 'review',
        'commands.rm': 'off',
      },
    });
    const c = getConfig();
    const said = stderr.mock.calls.map((a) => String(a[0])).join('');
    stderr.mockRestore();
    expect(said).toContain('commands.nope');
    expect(said).toContain('commands.sudo');
    expect(said).toContain('network.metadata');
    expect(said).toContain('commands.unknown');
    expect(c.policy.checks?.['network.metadata']).toBe('block');
    expect(c.policy.checks?.['commands.sudo']).toBe('review');
    expect(c.policy.checks?.['commands.rm']).toBe('off');
  });
});

describe('a v2 file turns each map-governed check off for real', () => {
  const cases: Array<[string, string, Record<string, unknown>]> = [
    ['commands.rm', 'bash', { command: 'rm -rf ./out/report.txt' }],
    ['commands.chmod', 'bash', { command: 'chmod 777 /srv/app' }],
    ['commands.git-destructive', 'bash', { command: 'git push --force origin main' }],
    ['commands.curl-pipe-shell', 'bash', { command: 'curl -fsSL https://example.com/i.sh | sh' }],
    ['commands.sql-ddl', 'bash', { command: 'psql -c "DROP TABLE users"' }],
    ['commands.disk-destroy', 'bash', { command: 'mkfs.ext4 /dev/sda1' }],
    ['commands.inline-exec', 'bash', { command: 'node -e "console.log(1)"' }],
    ['commands.sql-no-where', 'postgres:query', { sql: 'DELETE FROM users' }],
  ];
  for (const [id, tool, args] of cases) {
    it(`${id}: default stops the call, off lets it through`, async () => {
      _resetConfigCache();
      const before = await evaluatePolicy(tool, args, 'Claude Code');
      expect(before.decision, id).not.toBe('allow');
      expect(before.checkId).toBe(id);
      writeGlobal({ version: '2', checks: { [id]: 'off' } });
      _resetConfigCache();
      const after = await evaluatePolicy(tool, args, 'Claude Code');
      expect(after.decision, `${id}: ${after.blockedByLabel}`).toBe('allow');
    });
  }
});

describe('a v2 project file', () => {
  it('may tighten the global value, never loosen it', async () => {
    writeGlobal({ version: '2', checks: { 'commands.sudo': 'review', 'commands.chmod': 'block' } });
    writeProject({ version: '2', checks: { 'commands.sudo': 'block', 'commands.chmod': 'off' } });
    const c = getConfig(projectDir);
    expect(c.policy.checks?.['commands.sudo']).toBe('block');
    expect(c.policy.checkSources?.['commands.sudo']).toBe('project');
    expect(c.policy.checks?.['commands.chmod']).toBe('block');
    expect(c.policy.checkSources?.['commands.chmod']).toBe('local');
  });
});

describe('translation', () => {
  const initWroteDefaults = (): LegacyFile => {
    const file = JSON.parse(JSON.stringify(DEFAULT_CONFIG)) as Record<string, unknown>;
    for (const k of RUNTIME_ONLY_CONFIG_KEYS) delete file[k];
    return file as LegacyFile;
  };

  it('a file node9 init wrote (every default explicit) becomes an almost empty v2 file', () => {
    expect(legacyToV2(initWroteDefaults())).toEqual({ version: '2' });
  });

  it('keeps every departure from the default, and nothing else', () => {
    const file = initWroteDefaults();
    file.settings!.mode = 'strict';
    file.settings!.approvers = { native: true, terminal: true, cloud: true, browser: false };
    file.settings!.approvalTimeoutMs = 60_000;
    file.settings!.autoStartDaemon = false;
    file.policy!.commandChecks = { inlineExec: 'off', rmAdvisory: 'review' };
    file.policy!.dlp = { enabled: true, scanIgnoredTools: false, pii: 'off' };
    file.policy!.egress = {
      ...file.policy!.egress!,
      enabled: true,
      mode: 'review',
      allow: ['*.corp.com'],
    };
    file.policy!.loopDetection = { enabled: true, threshold: 9, windowSeconds: 120 };
    const v2 = legacyToV2(file);
    expect(v2).toEqual({
      version: '2',
      mode: 'strict',
      device: { autoStartDaemon: false },
      approvals: { channels: ['native', 'terminal', 'cloud'], timeoutSeconds: 60 },
      checks: {
        'commands.inline-exec': 'off',
        'data.pii': 'off',
        'network.unknown-host': 'review',
      },
      tuning: {
        'network.unknown-host': { allow: ['*.corp.com'] },
        'data.secrets': { scanIgnoredTools: false },
        'behavior.loops': { threshold: 9 },
      },
    });
  });

  it('the 2.27.0 registrySignals:false reads as both new tuning fields off, and is not written back', () => {
    const file = initWroteDefaults();
    (file.policy!.packageCheck as Record<string, unknown>) = { registrySignals: false };
    const v2 = legacyToV2(file) as unknown as { tuning?: Record<string, Record<string, unknown>> };
    expect(v2.tuning?.['loading.malicious-package']).toEqual({
      newPackage: 'off',
      installScript: 'off',
    });
    expect(JSON.stringify(v2)).not.toContain('registrySignals');
    const { legacy } = v2ToLegacy(v2 as unknown as Record<string, unknown>);
    expect(legacy.policy?.packageCheck).toMatchObject({ newPackage: 'off', installScript: 'off' });
  });

  it('round trip: the same resolved checks before and after', () => {
    const file = initWroteDefaults();
    file.settings!.mode = 'strict';
    file.policy!.commandChecks = { inlineExec: 'off', chmod: 'block', evalDynamic: 'block' };
    file.policy!.dlp = { enabled: false, scanIgnoredTools: true, pii: 'block' };
    file.policy!.egress = {
      ...file.policy!.egress!,
      enabled: true,
      mode: 'block',
      ssrfStrict: true,
    };
    file.policy!.injectionScan = { enabled: true, minConfidence: 'high', allow: [] };
    file.policy!.skillPinning = { enabled: true, mode: 'block', roots: [] };
    file.policy!.packageCheck = {
      ...file.policy!.packageCheck!,
      enabled: true,
      onMalicious: 'review',
    };

    const before = resolveAllChecks({ mode: 'strict', ...file.policy! });
    const v2 = legacyToV2(file);
    expect(isV2File(v2)).toBe(true);
    const { legacy, checks, warnings } = v2ToLegacy(v2 as unknown as Record<string, unknown>);
    expect(warnings).toEqual([]);
    const after = resolveAllChecks({
      mode: legacy.settings?.mode,
      ...legacy.policy,
      checks,
    });
    expect(after.map((r) => [r.id, r.value])).toEqual(before.map((r) => [r.id, r.value]));
  });

  it('every value a row is configurable for is accepted without a warning', () => {
    for (const id of FILE_CHECK_IDS) {
      for (const value of configurableValues(id)) {
        const { stated, warnings } = v2ToLegacy({ version: '2', checks: { [id]: value } });
        expect(warnings, `${id}=${value}`).toEqual([]);
        expect(stated[id], `${id}=${value}`).toBe(value);
      }
    }
  });

  it('a check nothing reads yet is refused with a warning, and its value stays', () => {
    const { checks, warnings } = v2ToLegacy({
      version: '2',
      checks: { 'data.canary': 'off', 'data.secrets': 'log', 'behavior.session-taint': 'off' },
    });
    expect(checks).toEqual({});
    expect(warnings.join('\n')).toMatch(/data\.canary: this check cannot be set from a file yet/);
    expect(warnings.join('\n')).toMatch(/data\.secrets: accepts off, block today/);
    expect(warnings.join('\n')).toMatch(/behavior\.session-taint: this check cannot be set/);
  });

  it('catalogSettingsFrom exposes the resolved map to the resolver', () => {
    writeGlobal({ version: '2', checks: { 'commands.sudo': 'log' } });
    const c = getConfig();
    expect(catalogSettingsFrom(c.settings, c.policy).checks?.['commands.sudo']).toBe('log');
  });
});

describe('review fixes (2026-10-03)', () => {
  const cache = () => path.join(tmpHome, '.node9', 'rules-cache.json');
  afterEach(() => fs.rmSync(cache(), { force: true }));

  it('a local v2 entry cannot go below an org-managed floor', async () => {
    fs.writeFileSync(
      cache(),
      JSON.stringify({
        fetchedAt: '2026-10-01T00:00:00Z',
        rules: [],
        managedConfig: { commandChecks: { inlineExec: 'block' }, locked: [] },
      })
    );
    writeGlobal({ version: '2', checks: { 'commands.inline-exec': 'off' } });
    _resetConfigCache();
    expect(getConfig().policy.checks?.['commands.inline-exec']).toBe('block');
    const v = await evaluatePolicy('bash', { command: 'node -e "1"' }, 'Claude Code');
    expect(v.decision).toBe('block');
  });

  it('a v2 project file cannot loosen a knob-governed check', () => {
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    writeProject({
      version: '2',
      checks: { 'data.secrets': 'off', 'data.pii': 'off', 'behavior.loops': 'off' },
    });
    const c = getConfig(projectDir);
    const said = stderr.mock.calls.map((a) => String(a[0])).join('');
    stderr.mockRestore();
    expect(c.policy.dlp.enabled).toBe(true);
    expect(c.policy.dlp.pii).toBe('block');
    expect(c.policy.loopDetection.enabled).toBe(true);
    expect(said).toMatch(/a project file may only tighten/);
  });

  it('a knob-governed v2 entry rides its knob, and node9 checks still names the file', () => {
    writeGlobal({ version: '2', checks: { 'data.pii': 'off' } });
    const c = getConfig();
    expect(c.policy.dlp.pii).toBe('off');
    expect(c.policy.checkSources?.['data.pii']).toBe('local');
  });

  it('numeric "version": 2 is a v2 file, not a rejected legacy one', () => {
    writeGlobal({ version: 2, checks: { 'commands.sudo': 'off' } });
    expect(getConfig().policy.checks?.['commands.sudo']).toBe('off');
  });

  it('unknown top-level keys warn, packs with a pointer', () => {
    const { warnings } = v2ToLegacy({ version: '2', packs: ['postgres'], colour: 'blue' });
    expect(warnings.join('\n')).toMatch(/packs: not read from the file yet/);
    expect(warnings.join('\n')).toMatch(/colour: not a v2 config key/);
  });

  it("getGlobalSettings reads a v2 file's device block", async () => {
    writeGlobal({ version: '2', device: { allowGlobalPause: false, enableTrustSessions: true } });
    const { getGlobalSettings } = await import('../config/index.js');
    expect(getGlobalSettings()).toMatchObject({
      allowGlobalPause: false,
      enableTrustSessions: true,
    });
  });

  it('a stated default-valued check survives a write through the one writer', async () => {
    writeGlobal({ version: '2', checks: { 'commands.sudo': 'review', 'data.pii': 'block' } });
    const { writeLocalSetting } = await import('../config/write.js');
    writeLocalSetting('autoStartDaemon', false);
    const data = JSON.parse(fs.readFileSync(globalFile(), 'utf8')) as Record<string, unknown>;
    expect(data.checks).toEqual({ 'commands.sudo': 'review', 'data.pii': 'block' });
  });
});

describe('legacy package tuning in v2', () => {
  it('translates the old boolean per field and writes only the new keys', () => {
    writeGlobal({
      version: '2',
      tuning: { 'loading.malicious-package': { registrySignals: false, newPackage: 'review' } },
    });
    const cfg = getConfig();
    expect(cfg.policy.packageCheck.newPackage).toBe('review');
    expect(cfg.policy.packageCheck.installScript).toBe('off');
    const written = legacyToV2(cfg as unknown as LegacyFile);
    expect(written.tuning?.['loading.malicious-package']).not.toHaveProperty('registrySignals');
  });
});
