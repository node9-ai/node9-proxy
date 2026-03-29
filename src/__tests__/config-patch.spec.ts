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

  it('creates parent directories if they do not exist', () => {
    // patchConfig should call mkdirSync({ recursive: true }) before writing.
    // This covers the production path where ~/.node9/ doesn't exist on first run.
    const nestedPath = path.join(tmpDir, 'nested', 'deep', 'config.json');
    patchConfig(nestedPath, { type: 'ignoredTool', toolName: 'Bash' });
    const data = JSON.parse(fs.readFileSync(nestedPath, 'utf8'));
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

describe('patchConfig — sequential writes', () => {
  it('two back-to-back patches both take effect (no write is lost)', () => {
    patchConfig(configPath, { type: 'ignoredTool', toolName: 'Bash' });
    patchConfig(configPath, { type: 'ignoredTool', toolName: 'Read' });
    const data = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    expect(data.policy.ignoredTools).toContain('Bash');
    expect(data.policy.ignoredTools).toContain('Read');
  });

  it('second smartRule patch is appended, not overwritten', () => {
    const rule1 = {
      name: 'rule-one',
      tool: 'Read',
      conditions: [{ field: 'path', op: 'matchesGlob' as const, value: '/src/**' }],
      verdict: 'allow' as const,
    };
    const rule2 = {
      name: 'rule-two',
      tool: 'Write',
      conditions: [{ field: 'path', op: 'matchesGlob' as const, value: '/tmp/**' }],
      verdict: 'allow' as const,
    };
    patchConfig(configPath, { type: 'smartRule', rule: rule1 });
    patchConfig(configPath, { type: 'smartRule', rule: rule2 });
    const data = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    expect(data.policy.smartRules).toHaveLength(2);
    expect(data.policy.smartRules.map((r: { name: string }) => r.name)).toContain('rule-one');
    expect(data.policy.smartRules.map((r: { name: string }) => r.name)).toContain('rule-two');
  });
});

describe('patchConfig — error handling', () => {
  afterEach(() => {
    // Belt-and-suspenders: restore any lingering spies even if a test's
    // own finally block was skipped by an unexpected framework error.
    vi.restoreAllMocks();
  });
  it('throws on corrupted config file and does not clobber it', () => {
    const badContent = 'NOT JSON {{{';
    fs.writeFileSync(configPath, badContent);
    expect(() => patchConfig(configPath, { type: 'ignoredTool', toolName: 'Bash' })).toThrow();
    // Corrupted file must not be truncated or overwritten by the failing call
    expect(fs.readFileSync(configPath, 'utf8')).toBe(badContent);
    // Parse failure happens before any write — no .node9-tmp orphan should be left
    expect(fs.existsSync(configPath + '.node9-tmp')).toBe(false);
  });

  it('passes mode 0o600 to writeFileSync (spy-based, all platforms)', () => {
    // Checks that patchConfig explicitly requests 0o600 regardless of umask.
    // This is a faster, platform-safe complement to the umask-based test below —
    // it verifies the intent (the argument) without touching process.umask.
    const writeSpy = vi.spyOn(fs, 'writeFileSync');
    try {
      patchConfig(configPath, { type: 'ignoredTool', toolName: 'Bash' });
      const tmpCall = writeSpy.mock.calls.find(([p]) => String(p).endsWith('.node9-tmp'));
      expect(tmpCall).toBeDefined();
      if (!tmpCall) return; // TypeScript narrowing — never reached; expect above throws first
      const opts = tmpCall[2];
      // Guard against a string encoding arg — if the call signature changes to pass
      // e.g. 'utf8', opts would be a string and mode would be undefined, silently
      // letting the test pass. The typeof check makes that failure explicit.
      if (typeof opts !== 'object' || opts === null)
        throw new Error(`Expected options object, got ${typeof opts}`);
      expect((opts as { mode?: number }).mode).toBe(0o600);
    } finally {
      writeSpy.mockRestore();
    }
  });

  it.skipIf(process.platform === 'win32')('writes file with mode 0o600', () => {
    // Set process umask to 0 so the test is not sensitive to the environment umask.
    // Without this, a umask of 0o077 would mask 0o600 to 0o600 (same), but a umask
    // of 0o022 would also leave 0o600 intact — yet we want to verify the mode arg
    // is actually passed, not inferred from a lucky umask.
    //
    // NOTE: process.umask() is process-global and affects all threads sharing the
    // same OS process. Vitest's default --pool=threads runs each test FILE in its
    // own worker_threads worker, but worker threads share the host process umask.
    // Tests within a single file run serially, so the try/finally restore is safe
    // against other tests in this file. The risk window (µs duration of patchConfig)
    // is tiny, but if strict isolation is ever required, run with --pool=forks or
    // move this test to a dedicated file so no other file shares the same worker.
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
    // writeFileSync is the call that CREATES the tmp file. If it throws, the tmp
    // file was never created — nothing to clean up. Assert both the error and the
    // absence of the tmp file to confirm no partial artifact was left.
    const writeSpy = vi.spyOn(fs, 'writeFileSync').mockImplementationOnce(() => {
      throw Object.assign(new Error('EACCES: permission denied'), { code: 'EACCES' });
    });
    try {
      expect(() => patchConfig(configPath, { type: 'ignoredTool', toolName: 'Bash' })).toThrow(
        /EACCES/
      );
      expect(fs.existsSync(configPath + '.node9-tmp')).toBe(false);
    } finally {
      writeSpy.mockRestore();
    }
  });

  it('cleans up .node9-tmp when writeFileSync writes partial content then throws (ENOSPC)', () => {
    // Simulate a disk-full scenario: writeFileSync creates the tmp file (partial
    // content written) and then throws. patchConfig must unlink the partial tmp
    // before re-throwing so no stale artifact remains.
    const tmpPath = configPath + '.node9-tmp';
    const realWriteFileSync = fs.writeFileSync.bind(fs); // capture before spy
    const writeSpy = vi
      .spyOn(fs, 'writeFileSync')
      .mockImplementationOnce((p: fs.PathOrFileDescriptor) => {
        // Write partial content to simulate bytes-written-then-failed
        realWriteFileSync(String(p), 'partial{');
        throw Object.assign(new Error('ENOSPC: no space left on device'), { code: 'ENOSPC' });
      });
    try {
      expect(() => patchConfig(configPath, { type: 'ignoredTool', toolName: 'Bash' })).toThrow(
        /ENOSPC/
      );
      expect(fs.existsSync(tmpPath)).toBe(false);
    } finally {
      writeSpy.mockRestore();
    }
  });
});
