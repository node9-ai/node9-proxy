// src/__tests__/config-patch.spec.ts
// Unit tests for patchConfig: smartRule and ignoredTool patching, dedup, atomic write.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { patchConfig } from '../config/patch.js';

let tmpDir: string;
let configPath: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-patch-test-'));
  configPath = path.join(tmpDir, 'config.json');
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe('patchConfig — ignoredTool', () => {
  it('creates config file if it does not exist', () => {
    patchConfig(configPath, { type: 'ignoredTool', toolName: 'Bash' });
    const data = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    expect(data.policy.ignoredTools).toContain('Bash');
  });

  it('appends to existing ignoredTools', () => {
    fs.writeFileSync(configPath, JSON.stringify({ policy: { ignoredTools: ['Read'] } }));
    patchConfig(configPath, { type: 'ignoredTool', toolName: 'Write' });
    const data = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    expect(data.policy.ignoredTools).toContain('Read');
    expect(data.policy.ignoredTools).toContain('Write');
  });

  it('does not duplicate an existing ignoredTool', () => {
    patchConfig(configPath, { type: 'ignoredTool', toolName: 'Bash' });
    patchConfig(configPath, { type: 'ignoredTool', toolName: 'Bash' });
    const data = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    expect(data.policy.ignoredTools.filter((t: string) => t === 'Bash')).toHaveLength(1);
  });
});

describe('patchConfig — smartRule', () => {
  const rule = {
    name: 'allow-read-src',
    tool: 'Read',
    conditions: [{ field: 'path', op: 'matchesGlob' as const, value: '/src/**' }],
    verdict: 'allow' as const,
    reason: 'Test rule',
  };

  it('creates config file with smartRule if it does not exist', () => {
    patchConfig(configPath, { type: 'smartRule', rule });
    const data = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    expect(data.policy.smartRules).toHaveLength(1);
    expect(data.policy.smartRules[0].name).toBe('allow-read-src');
  });

  it('appends to existing smartRules', () => {
    const existing = {
      name: 'existing-rule',
      tool: 'Write',
      conditions: [],
      verdict: 'deny' as const,
      reason: 'Existing',
    };
    fs.writeFileSync(configPath, JSON.stringify({ policy: { smartRules: [existing] } }));
    patchConfig(configPath, { type: 'smartRule', rule });
    const data = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    expect(data.policy.smartRules).toHaveLength(2);
  });

  it('does not duplicate a rule with the same name', () => {
    patchConfig(configPath, { type: 'smartRule', rule });
    patchConfig(configPath, { type: 'smartRule', rule });
    const data = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    expect(
      data.policy.smartRules.filter((r: { name: string }) => r.name === rule.name)
    ).toHaveLength(1);
  });

  it('preserves existing config keys outside of policy', () => {
    fs.writeFileSync(configPath, JSON.stringify({ version: 2, policy: {} }));
    patchConfig(configPath, { type: 'smartRule', rule });
    const data = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    expect(data.version).toBe(2);
  });
});

describe('patchConfig — error handling', () => {
  it('throws on corrupted config file', () => {
    fs.writeFileSync(configPath, 'NOT JSON {{{');
    expect(() => patchConfig(configPath, { type: 'ignoredTool', toolName: 'Bash' })).toThrow();
  });

  it.skipIf(process.platform === 'win32')('writes file with mode 0o600', () => {
    // Set process umask to 0 so the test is not sensitive to the environment umask.
    // Without this, a umask of 0o077 would mask 0o600 to 0o600 (same), but a umask
    // of 0o022 would also leave 0o600 intact — yet we want to verify the mode arg
    // is actually passed, not inferred from a lucky umask.
    const prevUmask = process.umask(0o000);
    try {
      patchConfig(configPath, { type: 'ignoredTool', toolName: 'Bash' });
      const stat = fs.statSync(configPath);
      expect(stat.mode & 0o777).toBe(0o600);
    } finally {
      process.umask(prevUmask);
    }
  });

  it('does not leave a .node9-tmp file after successful write', () => {
    patchConfig(configPath, { type: 'ignoredTool', toolName: 'Bash' });
    const tmpPath = configPath + '.node9-tmp';
    expect(fs.existsSync(tmpPath)).toBe(false);
  });

  it('cleans up .node9-tmp when renameSync fails', () => {
    // Simulate cross-device rename failure (EXDEV). writeFileSync succeeds and
    // creates the tmp file; renameSync throws. patchConfig must delete the tmp
    // file before re-throwing so it doesn't accumulate stale artifacts.
    const renameSpy = vi.spyOn(fs, 'renameSync').mockImplementationOnce(() => {
      throw Object.assign(new Error('EXDEV: cross-device link'), { code: 'EXDEV' });
    });
    try {
      expect(() => patchConfig(configPath, { type: 'ignoredTool', toolName: 'Bash' })).toThrow();
      expect(fs.existsSync(configPath + '.node9-tmp')).toBe(false);
    } finally {
      renameSpy.mockRestore();
    }
  });

  it('throws when writeFileSync fails (e.g. EACCES on a read-only directory)', () => {
    vi.spyOn(fs, 'writeFileSync').mockImplementationOnce(() => {
      throw Object.assign(new Error('EACCES: permission denied'), { code: 'EACCES' });
    });
    try {
      expect(() => patchConfig(configPath, { type: 'ignoredTool', toolName: 'Bash' })).toThrow(
        /EACCES/
      );
    } finally {
      vi.restoreAllMocks();
    }
  });
});
