import { describe, it, expect, vi, beforeEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

// Typed alias for fs.realpathSync.native — avoids repeated `unknown` casts and
// matches the same alias used in dlp.test.ts for consistency.
type RealpathWithNative = typeof fs.realpathSync & { native: (p: unknown) => string };

// ── Mock child_process BEFORE importing undo (hoisted by vitest) ─────────────
vi.mock('child_process', () => ({
  spawnSync: vi.fn(),
  spawn: vi.fn().mockReturnValue({ unref: vi.fn() }),
}));

// ── Mock net to prevent test snapshots from leaking to the live daemon ────────
vi.mock('net', () => ({
  default: { createConnection: vi.fn().mockReturnValue({ on: vi.fn(), end: vi.fn() }) },
  createConnection: vi.fn().mockReturnValue({ on: vi.fn(), end: vi.fn() }),
}));

import { spawnSync, spawn } from 'child_process';
import {
  createShadowSnapshot,
  getLatestSnapshot,
  getSnapshotHistory,
  computeUndoDiff,
  applyUndo,
  getShadowRepoDir,
} from '../undo.js';

// ── Filesystem mocks (module-level — NOT restored between tests) ──────────────
vi.spyOn(fs, 'existsSync').mockReturnValue(false);
vi.spyOn(fs, 'readFileSync').mockReturnValue('');
const writeSpy = vi.spyOn(fs, 'writeFileSync').mockImplementation(() => undefined);
vi.spyOn(fs, 'mkdirSync').mockImplementation(() => undefined);
vi.spyOn(fs, 'unlinkSync').mockImplementation(() => undefined);
// Mock BOTH realpathSync and realpathSync.native — production code calls .native
// for symlink-escape prevention. Mocking only the base function would leave
// the security path untested.
vi.spyOn(fs, 'realpathSync').mockImplementation((p) => String(p));
(fs.realpathSync as RealpathWithNative).native = vi
  .fn()
  .mockImplementation((p: unknown) => String(p));
vi.spyOn(fs, 'readdirSync').mockReturnValue([]);
vi.spyOn(fs, 'statSync').mockReturnValue({ mtimeMs: 0 } as ReturnType<typeof fs.statSync>);
vi.spyOn(fs, 'rmSync').mockImplementation(() => undefined);
vi.spyOn(os, 'homedir').mockReturnValue('/mock/home');
vi.spyOn(process, 'cwd').mockReturnValue('/mock/project');

// undo.ts computes SNAPSHOT_STACK_PATH at module-load time (before our spy is
// active), so it uses the real homedir. Match by filename suffix instead.
const byStackPath = ([p]: Parameters<typeof fs.writeFileSync>) =>
  String(p).endsWith('snapshots.json');
const byLatestPath = ([p]: Parameters<typeof fs.writeFileSync>) =>
  String(p).endsWith('undo_latest.txt');
const byExcludePath = ([p]: Parameters<typeof fs.writeFileSync>) => String(p).endsWith('exclude');

const mockSpawn = vi.mocked(spawnSync);

// ── Test helpers ──────────────────────────────────────────────────────────────

/** Constructs a typed spawnSync return value, reducing cast boilerplate. */
function spawnResult(stdout = '', status = 0): ReturnType<typeof spawnSync> {
  return {
    status,
    stdout: Buffer.from(stdout),
    stderr: Buffer.from(''),
  } as ReturnType<typeof spawnSync>;
}

/**
 * Mocks spawnSync so all git operations succeed. Handles rev-parse --git-dir
 * (shadow repo health check), config, add, write-tree, commit-tree, diff, and ls-tree.
 * Uses `--git-dir` to distinguish the health-check rev-parse from other
 * rev-parse variants (e.g. rev-parse HEAD) so those don't collapse.
 */
function mockGitSuccess(
  treeHash = 'abc123tree',
  commitHash = 'def456commit',
  opts: { diffFiles?: string; diffContent?: string; lsTreeFiles?: string } = {}
) {
  mockSpawn.mockImplementation((_cmd, args) => {
    const a = (args ?? []) as string[];
    // Only match the shadow-repo health-check: `git rev-parse --git-dir`
    if (a.includes('rev-parse') && a.includes('--git-dir')) return spawnResult('/shadow\n');
    if (a.includes('config') || a.includes('init')) return spawnResult();
    if (a.includes('add')) return spawnResult();
    if (a.includes('write-tree')) return spawnResult(treeHash + '\n');
    if (a.includes('commit-tree')) return spawnResult(commitHash + '\n');
    // diff --name-only → file list
    if (a.includes('diff') && a.includes('--name-only')) return spawnResult(opts.diffFiles ?? '');
    // diff (without --name-only) → unified diff content
    if (a.includes('diff')) return spawnResult(opts.diffContent ?? '');
    // ls-tree → file list for first snapshot
    if (a.includes('ls-tree')) return spawnResult(opts.lsTreeFiles ?? '');
    return spawnResult();
  });
}

/**
 * Sets up fs mocks to simulate a healthy shadow repo for cwd=/mock/project.
 */
function withShadowRepo(includeStackFile = false) {
  // readdirSync → [] simulates no orphaned index_* files in the shadow dir.
  // The shadow repo existence check uses `git rev-parse --git-dir` (spawnSync),
  // NOT readdirSync, so this empty return is correct and doesn't affect init logic.
  vi.mocked(fs.readdirSync).mockReturnValue([]);
  vi.mocked(fs.existsSync).mockImplementation((p) => {
    const s = String(p);
    if (includeStackFile && s.endsWith('snapshots.json')) return true;
    return false;
  });
  vi.mocked(fs.readFileSync).mockImplementation((p) => {
    const s = String(p);
    // normalizeCwdForHash('/mock/project') = '/mock/project' (realpathSync mock is identity)
    if (s.endsWith('project-path.txt')) return '/mock/project';
    if (s.endsWith('snapshots.json') && includeStackFile) return '[]';
    return '';
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(fs.existsSync).mockReturnValue(false);
  vi.mocked(fs.readFileSync).mockReturnValue('');
  vi.mocked(fs.writeFileSync).mockImplementation(() => undefined);
  vi.mocked(fs.mkdirSync).mockImplementation(() => undefined);
  vi.mocked(fs.unlinkSync).mockImplementation(() => undefined);
  vi.mocked(fs.realpathSync).mockImplementation((p) => String(p));
  vi.mocked((fs.realpathSync as RealpathWithNative).native).mockImplementation((p: unknown) =>
    String(p)
  );
  vi.mocked(fs.readdirSync).mockReturnValue([]);
  vi.mocked(fs.statSync).mockReturnValue({ mtimeMs: 0 } as ReturnType<typeof fs.statSync>);
  vi.mocked(fs.rmSync).mockImplementation(() => undefined);
});

// ── getSnapshotHistory ────────────────────────────────────────────────────────

describe('getSnapshotHistory', () => {
  it('returns empty array when snapshots.json does not exist', () => {
    vi.mocked(fs.existsSync).mockReturnValue(false);
    expect(getSnapshotHistory()).toEqual([]);
  });

  it('returns parsed array when file exists', () => {
    const entries = [
      { hash: 'abc', tool: 'edit', argsSummary: 'src/app.ts', cwd: '/proj', timestamp: 1000 },
    ];
    vi.mocked(fs.existsSync).mockImplementation((p) => String(p).endsWith('snapshots.json'));
    vi.mocked(fs.readFileSync).mockImplementation((p) => {
      if (String(p).endsWith('snapshots.json')) return JSON.stringify(entries);
      throw new Error('not found');
    });
    expect(getSnapshotHistory()).toEqual(entries);
  });

  it('returns empty array when file is malformed JSON', () => {
    vi.mocked(fs.existsSync).mockImplementation((p) => String(p).endsWith('snapshots.json'));
    vi.mocked(fs.readFileSync).mockImplementation(() => 'not-json');
    expect(getSnapshotHistory()).toEqual([]);
  });
});

// ── getLatestSnapshot ─────────────────────────────────────────────────────────

describe('getLatestSnapshot', () => {
  it('returns null when stack is empty', () => {
    vi.mocked(fs.existsSync).mockReturnValue(false);
    expect(getLatestSnapshot()).toBeNull();
  });

  it('returns the last entry in the stack', () => {
    const entries = [
      { hash: 'first', tool: 'write', argsSummary: 'a.ts', cwd: '/p', timestamp: 1000 },
      { hash: 'second', tool: 'edit', argsSummary: 'b.ts', cwd: '/p', timestamp: 2000 },
    ];
    vi.mocked(fs.existsSync).mockImplementation((p) => String(p).endsWith('snapshots.json'));
    vi.mocked(fs.readFileSync).mockImplementation((p) => {
      if (String(p).endsWith('snapshots.json')) return JSON.stringify(entries);
      return '';
    });
    expect(getLatestSnapshot()?.hash).toBe('second');
  });
});

// ── getShadowRepoDir ──────────────────────────────────────────────────────────

describe('getShadowRepoDir', () => {
  it('returns a path under ~/.node9/snapshots/', () => {
    const dir = getShadowRepoDir('/mock/project');
    expect(dir).toContain(path.join('mock', 'home', '.node9', 'snapshots'));
  });

  it('returns the same dir for the same cwd', () => {
    expect(getShadowRepoDir('/mock/project')).toBe(getShadowRepoDir('/mock/project'));
  });

  it('returns different dirs for different cwds', () => {
    expect(getShadowRepoDir('/mock/project')).not.toBe(getShadowRepoDir('/mock/other'));
  });

  it('uses a 16-char hex hash', () => {
    const dir = getShadowRepoDir('/mock/project');
    const hash = path.basename(dir);
    expect(hash).toMatch(/^[0-9a-f]{16}$/);
  });
});

// ── createShadowSnapshot ──────────────────────────────────────────────────────

describe('createShadowSnapshot', () => {
  it('works for non-git directories (no .git required)', async () => {
    withShadowRepo(true);
    mockGitSuccess('tree111', 'commit222');

    const result = await createShadowSnapshot('edit', { file_path: 'src/app.ts' });
    expect(result).toBe('commit222');
  });

  it('returns null when shadow repo init fails (git not available)', async () => {
    vi.mocked(fs.readdirSync).mockReturnValue([]);
    mockSpawn.mockReturnValue({
      status: 1,
      stdout: Buffer.from(''),
      stderr: Buffer.from('error'),
    } as ReturnType<typeof spawnSync>);

    const result = await createShadowSnapshot('edit', { file_path: 'src/app.ts' });
    expect(result).toBeNull();
  });

  it('returns null when git write-tree fails', async () => {
    withShadowRepo(false);
    mockSpawn.mockImplementation((_cmd, args) => {
      const a = (args ?? []) as string[];
      if (a.includes('rev-parse') && a.includes('--git-dir'))
        return {
          status: 0,
          stdout: Buffer.from('/shadow\n'),
          stderr: Buffer.from(''),
        } as ReturnType<typeof spawnSync>;
      return {
        status: 1,
        stdout: Buffer.from(''),
        stderr: Buffer.from(''),
      } as ReturnType<typeof spawnSync>;
    });
    const result = await createShadowSnapshot('edit', {});
    expect(result).toBeNull();
  });

  it('returns commit hash and writes stack on success', async () => {
    withShadowRepo(true);
    mockGitSuccess('tree111', 'commit222');

    const result = await createShadowSnapshot('edit', { file_path: 'src/main.ts' });

    expect(result).toBe('commit222');
    const writeCall = writeSpy.mock.calls.find(byStackPath);
    expect(writeCall).toBeDefined();
    const written = JSON.parse(String(writeCall![1]));
    expect(written).toHaveLength(1);
    expect(written[0].hash).toBe('commit222');
    expect(written[0].tool).toBe('edit');
    expect(written[0].argsSummary).toBe('src/main.ts');
  });

  it('also writes backward-compat undo_latest.txt', async () => {
    withShadowRepo(true);
    mockGitSuccess('tree111', 'commit333');

    await createShadowSnapshot('write', { file_path: 'x.ts' });

    const latestWrite = writeSpy.mock.calls.find(byLatestPath);
    expect(latestWrite).toBeDefined();
    expect(String(latestWrite![1])).toBe('commit333');
  });

  it('caps at MAX_SNAPSHOTS (10) per project, evicting oldest entry for that cwd', async () => {
    withShadowRepo(true);
    // 10 existing entries all for /mock/project (same cwd as process.cwd mock)
    const existing = Array.from({ length: 10 }, (_, i) => ({
      hash: `hash${i}`,
      tool: 'edit',
      argsSummary: `file${i}.ts`,
      cwd: '/mock/project',
      timestamp: i * 1000,
    }));
    vi.mocked(fs.readFileSync).mockImplementation((p) => {
      const s = String(p);
      if (s.endsWith('project-path.txt')) return '/mock/project';
      if (s.endsWith('snapshots.json')) return JSON.stringify(existing);
      return '';
    });
    vi.mocked(fs.existsSync).mockImplementation((p) => String(p).endsWith('snapshots.json'));
    mockGitSuccess('treeX', 'commitX');

    await createShadowSnapshot('edit', { file_path: 'new.ts' });

    const writeCall = writeSpy.mock.calls.find(byStackPath);
    const written = JSON.parse(String(writeCall![1]));
    expect(written).toHaveLength(10);
    expect(written[0].hash).toBe('hash1'); // oldest of /mock/project dropped
    expect(written[9].hash).toBe('commitX'); // newest added
  });

  it('per-project cap does not evict entries from other projects', async () => {
    withShadowRepo(true);
    // 10 entries for /other/project + 1 existing for /mock/project
    const existing = [
      ...Array.from({ length: 10 }, (_, i) => ({
        hash: `other${i}`,
        tool: 'edit',
        argsSummary: `file${i}.ts`,
        cwd: '/other/project',
        timestamp: i * 1000,
      })),
      {
        hash: 'mine0',
        tool: 'edit',
        argsSummary: 'mine.ts',
        cwd: '/mock/project',
        timestamp: 9000,
      },
    ];
    vi.mocked(fs.readFileSync).mockImplementation((p) => {
      const s = String(p);
      if (s.endsWith('project-path.txt')) return '/mock/project';
      if (s.endsWith('snapshots.json')) return JSON.stringify(existing);
      return '';
    });
    vi.mocked(fs.existsSync).mockImplementation((p) => String(p).endsWith('snapshots.json'));
    mockGitSuccess('treeY', 'commitY');

    await createShadowSnapshot('edit', { file_path: 'new.ts' });

    const writeCall = writeSpy.mock.calls.find(byStackPath);
    const written = JSON.parse(String(writeCall![1]));
    // /other/project entries must be untouched (10 still present)
    const otherEntries = written.filter((e: { cwd: string }) => e.cwd === '/other/project');
    expect(otherEntries).toHaveLength(10);
    // /mock/project now has 2 entries (was 1, added 1 — under cap)
    const myEntries = written.filter((e: { cwd: string }) => e.cwd === '/mock/project');
    expect(myEntries).toHaveLength(2);
  });

  it('derives cwd from absolute file_path by finding project root (.git marker)', async () => {
    // Use platform-appropriate absolute paths: path.isAbsolute('/foo') is false on Windows
    // (Windows requires a drive letter like C:\foo), so hardcoded Unix paths cause the test
    // to skip findProjectRoot and fall back to process.cwd() on the Windows CI runner.
    const projectRoot = process.platform === 'win32' ? 'C:\\abs\\myproj' : '/abs/myproj';
    const filePath = path.join(projectRoot, 'src', 'foo.ts');
    const gitDir = path.join(projectRoot, '.git');

    // Shadow repo must validate as healthy for the derived cwd (projectRoot)
    vi.mocked(fs.readdirSync).mockReturnValue([]);
    vi.mocked(fs.existsSync).mockImplementation((p) => {
      const s = String(p);
      if (s === gitDir) return true; // project root marker
      if (s.endsWith('snapshots.json')) return false;
      return false;
    });
    vi.mocked(fs.readFileSync).mockImplementation((p) => {
      const s = String(p);
      // Shadow repo project-path.txt must match the derived cwd
      if (s.endsWith('project-path.txt')) return projectRoot;
      return '';
    });
    mockGitSuccess('treeR', 'commitR');

    await createShadowSnapshot('edit', { file_path: filePath });

    const writeCall = writeSpy.mock.calls.find(byStackPath);
    const written = JSON.parse(String(writeCall![1]));
    // Snapshot must be keyed to the project root, not process.cwd()
    expect(written[0].cwd).toBe(projectRoot);
  });

  it('falls back to process.cwd() when file_path is relative', async () => {
    withShadowRepo(true);
    mockGitSuccess('treeF', 'commitF');

    await createShadowSnapshot('edit', { file_path: 'src/relative.ts' });

    const writeCall = writeSpy.mock.calls.find(byStackPath);
    const written = JSON.parse(String(writeCall![1]));
    expect(written[0].cwd).toBe('/mock/project');
  });

  it('falls back to process.cwd() when args have no file_path', async () => {
    withShadowRepo(true);
    mockGitSuccess('treeG', 'commitG');

    await createShadowSnapshot('bash', { command: 'npm test' });

    const writeCall = writeSpy.mock.calls.find(byStackPath);
    const written = JSON.parse(String(writeCall![1]));
    expect(written[0].cwd).toBe('/mock/project');
  });

  it('extracts argsSummary from command field when no file_path', async () => {
    withShadowRepo(true);
    mockGitSuccess('treeA', 'commitA');

    await createShadowSnapshot('bash', { command: 'npm run build --production' });

    const writeCall = writeSpy.mock.calls.find(byStackPath);
    const written = JSON.parse(String(writeCall![1]));
    expect(written[0].argsSummary).toBe('npm run build --production');
  });

  it('extracts argsSummary from sql field', async () => {
    withShadowRepo(true);
    mockGitSuccess('treeB', 'commitB');

    await createShadowSnapshot('query', { sql: 'SELECT * FROM users' });

    const writeCall = writeSpy.mock.calls.find(byStackPath);
    const written = JSON.parse(String(writeCall![1]));
    expect(written[0].argsSummary).toBe('SELECT * FROM users');
  });

  it('uses GIT_DIR (shadow) and GIT_WORK_TREE for all git operations', async () => {
    withShadowRepo(true);
    mockGitSuccess('treeX', 'commitX');

    await createShadowSnapshot('edit', { file_path: 'src/app.ts' });

    // Find the git add call and verify shadow env
    const addCall = mockSpawn.mock.calls.find(([, args]) => (args as string[]).includes('add'));
    expect(addCall).toBeDefined();
    const addEnv = addCall![2]?.env as Record<string, string>;
    expect(addEnv?.GIT_DIR).toContain(path.join('.node9', 'snapshots'));
    expect(addEnv?.GIT_WORK_TREE).toBe('/mock/project');
    // Index file must be inside shadow dir — never in the user's .git
    expect(addEnv?.GIT_INDEX_FILE).toContain(path.join('.node9', 'snapshots'));
    expect(addEnv?.GIT_INDEX_FILE).not.toMatch(/[/\\]\.git[/\\]/);
  });

  it('cleans up the per-invocation index file after snapshot (finally block)', async () => {
    withShadowRepo(true);
    mockGitSuccess('treeX', 'commitX');

    await createShadowSnapshot('edit', {});

    // unlinkSync should be called for the index file (inside shadow dir)
    const unlinkCalls = vi.mocked(fs.unlinkSync).mock.calls.map(([p]) => String(p));
    expect(unlinkCalls.some((p) => p.includes('index_'))).toBe(true);
  });

  it('cleans up index file even when write-tree fails (finally block on error path)', async () => {
    withShadowRepo(false);
    mockSpawn.mockImplementation((_cmd, args) => {
      const a = (args ?? []) as string[];
      if (a.includes('rev-parse') && a.includes('--git-dir')) return spawnResult('/shadow\n');
      if (a.includes('write-tree')) return spawnResult('', 1); // simulate failure
      return spawnResult();
    });

    const result = await createShadowSnapshot('edit', {});
    expect(result).toBeNull(); // snapshot failed

    // Index file must still be cleaned up — the finally block must fire on failure
    const unlinkCalls = vi.mocked(fs.unlinkSync).mock.calls.map(([p]) => String(p));
    expect(unlinkCalls.some((p) => p.includes('index_'))).toBe(true);
  });

  it('calls unref() on the git gc background process', async () => {
    // GC fires when stack.length % 5 === 0 (checked before MAX_SNAPSHOTS eviction).
    // 4 existing + 1 new = 5 → 5 % 5 === 0 → GC fires.
    withShadowRepo(true);
    const existing = Array.from({ length: 4 }, (_, i) => ({
      hash: `hash${i}`,
      tool: 'edit',
      argsSummary: `f${i}.ts`,
      cwd: '/p',
      timestamp: i * 1000,
    }));
    vi.mocked(fs.readFileSync).mockImplementation((p) => {
      const s = String(p);
      if (s.endsWith('project-path.txt')) return '/mock/project';
      if (s.endsWith('snapshots.json')) return JSON.stringify(existing);
      return '';
    });
    vi.mocked(fs.existsSync).mockImplementation((p) => String(p).endsWith('snapshots.json'));
    mockGitSuccess('treeGC', 'commitGC');

    await createShadowSnapshot('edit', {});

    // spawn (not spawnSync) should have been called for gc --auto
    const mockSpawnFn = vi.mocked(spawn);
    expect(mockSpawnFn).toHaveBeenCalled();
    const gcCall = mockSpawnFn.mock.calls.find(([, args]) => (args as string[]).includes('gc'));
    expect(gcCall).toBeDefined();
    // unref() must be called so gc doesn't block Node.js exit
    const returnVal = mockSpawnFn.mock.results.find(
      (r) => r.type === 'return' && r.value?.unref
    )?.value;
    expect(returnVal?.unref).toHaveBeenCalled();
  });

  it('captures files and diff from previous snapshot for the same cwd', async () => {
    withShadowRepo(true);
    const existing = [
      {
        hash: 'prevhash',
        tool: 'edit',
        argsSummary: 'old.ts',
        cwd: '/mock/project',
        timestamp: 1000,
      },
    ];
    vi.mocked(fs.readFileSync).mockImplementation((p) => {
      const s = String(p);
      if (s.endsWith('project-path.txt')) return '/mock/project';
      if (s.endsWith('snapshots.json')) return JSON.stringify(existing);
      return '';
    });
    vi.mocked(fs.existsSync).mockImplementation((p) => String(p).endsWith('snapshots.json'));
    mockGitSuccess('treeD', 'commitD', {
      diffFiles: 'src/auth.ts\nsrc/utils.ts\n',
      diffContent: '-old\n+new\n',
    });

    await createShadowSnapshot('edit', { file_path: 'src/auth.ts' });

    const writeCall = writeSpy.mock.calls.find(byStackPath);
    const written = JSON.parse(String(writeCall![1]));
    const entry = written[written.length - 1];
    expect(entry.files).toEqual(['src/auth.ts', 'src/utils.ts']);
    expect(entry.diff).toBe('-old\n+new\n');
  });

  it('uses ls-tree for files on first snapshot (no previous entry for cwd)', async () => {
    withShadowRepo(true);
    mockGitSuccess('treeF', 'commitF', { lsTreeFiles: 'src/index.ts\npackage.json\n' });

    await createShadowSnapshot('write', { file_path: 'src/index.ts' });

    const writeCall = writeSpy.mock.calls.find(byStackPath);
    const written = JSON.parse(String(writeCall![1]));
    expect(written[0].files).toEqual(['src/index.ts', 'package.json']);
    expect(written[0].diff).toBeNull();
  });

  it('does not use a previous snapshot from a different cwd for diff', async () => {
    withShadowRepo(true);
    // Previous snapshot is from a DIFFERENT project
    const existing = [
      {
        hash: 'otherhash',
        tool: 'edit',
        argsSummary: 'file.ts',
        cwd: '/other/project',
        timestamp: 1000,
      },
    ];
    vi.mocked(fs.readFileSync).mockImplementation((p) => {
      const s = String(p);
      if (s.endsWith('project-path.txt')) return '/mock/project';
      if (s.endsWith('snapshots.json')) return JSON.stringify(existing);
      return '';
    });
    vi.mocked(fs.existsSync).mockImplementation((p) => String(p).endsWith('snapshots.json'));
    mockGitSuccess('treeN', 'commitN', { lsTreeFiles: 'src/app.ts\n' });

    await createShadowSnapshot('write', { file_path: 'src/app.ts' });

    const writeCall = writeSpy.mock.calls.find(byStackPath);
    const written = JSON.parse(String(writeCall![1]));
    const entry = written[written.length - 1];
    // Should use ls-tree (first snapshot path), not diff against other project
    expect(entry.files).toEqual(['src/app.ts']);
    expect(entry.diff).toBeNull();
  });

  it('buildArgsSummary falls back to empty string when no recognisable field', async () => {
    withShadowRepo(true);
    mockGitSuccess('treeZ', 'commitZ');

    await createShadowSnapshot('unknown', { unrecognised: 'value' });

    const writeCall = writeSpy.mock.calls.find(byStackPath);
    const written = JSON.parse(String(writeCall![1]));
    // Should be empty string, NOT 'unknown' (the tool name)
    expect(written[0].argsSummary).toBe('');
  });

  it('uses a unique GIT_INDEX_FILE per concurrent invocation', async () => {
    withShadowRepo(true);
    mockGitSuccess('treeA', 'commitA');

    // Run two snapshots back-to-back (synchronous mock — simulates concurrent PIDs
    // by checking the index file names are pid_timestamp scoped)
    const [r1, r2] = await Promise.all([
      createShadowSnapshot('edit', { file_path: 'a.ts' }),
      createShadowSnapshot('edit', { file_path: 'b.ts' }),
    ]);

    expect(r1).not.toBeNull();
    expect(r2).not.toBeNull();

    // Collect all GIT_INDEX_FILE values used across all git-add calls
    const indexFiles = mockSpawn.mock.calls
      .filter(([, args]) => (args as string[]).includes('add'))
      .map(([, , opts]) => (opts?.env as Record<string, string>)?.GIT_INDEX_FILE)
      .filter(Boolean);

    // All index files must be inside the shadow dir, never in user's .git
    for (const f of indexFiles) {
      expect(f).toContain(path.join('.node9', 'snapshots'));
      expect(f).not.toMatch(/[/\\]\.git[/\\]/);
    }
  });
});

// ── ensureShadowRepo (via createShadowSnapshot) ───────────────────────────────

describe('ensureShadowRepo', () => {
  it('initializes shadow repo when it does not exist (rev-parse fails)', async () => {
    vi.mocked(fs.readdirSync).mockReturnValue([]);
    vi.mocked(fs.readFileSync).mockImplementation((p) =>
      String(p).endsWith('snapshots.json') ? '[]' : ''
    );
    vi.mocked(fs.existsSync).mockImplementation((p) => String(p).endsWith('snapshots.json'));

    mockSpawn.mockImplementation((_cmd, args) => {
      const a = (args ?? []) as string[];
      if (a.includes('rev-parse') && a.includes('--git-dir'))
        return {
          status: 1,
          stdout: Buffer.from(''),
          stderr: Buffer.from(''),
        } as ReturnType<typeof spawnSync>;
      // init, config, add, write-tree, commit-tree all succeed
      if (a.includes('write-tree'))
        return {
          status: 0,
          stdout: Buffer.from('tree123\n'),
          stderr: Buffer.from(''),
        } as ReturnType<typeof spawnSync>;
      if (a.includes('commit-tree'))
        return {
          status: 0,
          stdout: Buffer.from('commit123\n'),
          stderr: Buffer.from(''),
        } as ReturnType<typeof spawnSync>;
      return {
        status: 0,
        stdout: Buffer.from(''),
        stderr: Buffer.from(''),
      } as ReturnType<typeof spawnSync>;
    });

    const result = await createShadowSnapshot('edit', {});
    expect(result).toBe('commit123');

    const initCall = mockSpawn.mock.calls.find(([, args]) => (args as string[]).includes('init'));
    expect(initCall).toBeDefined();
    expect(initCall![1] as string[]).toContain('--bare');
  });

  it('skips init when shadow repo is healthy and path matches', async () => {
    withShadowRepo(true);
    mockGitSuccess('tree1', 'commit1');

    await createShadowSnapshot('edit', {});

    const initCall = mockSpawn.mock.calls.find(([, args]) => (args as string[]).includes('init'));
    expect(initCall).toBeUndefined();
  });

  it('reinitializes when project-path.txt does not match (collision/rename)', async () => {
    vi.mocked(fs.readdirSync).mockReturnValue([]);
    vi.mocked(fs.existsSync).mockImplementation((p) => String(p).endsWith('snapshots.json'));
    vi.mocked(fs.readFileSync).mockImplementation((p) => {
      const s = String(p);
      // Simulate stored path being different (collision/rename)
      if (s.endsWith('project-path.txt')) return '/some/other/project';
      if (s.endsWith('snapshots.json')) return '[]';
      return '';
    });

    mockSpawn.mockImplementation((_cmd, args) => {
      const a = (args ?? []) as string[];
      if (a.includes('rev-parse') && a.includes('--git-dir'))
        return {
          status: 0,
          stdout: Buffer.from('/shadow\n'),
          stderr: Buffer.from(''),
        } as ReturnType<typeof spawnSync>;
      if (a.includes('write-tree'))
        return {
          status: 0,
          stdout: Buffer.from('treeX\n'),
          stderr: Buffer.from(''),
        } as ReturnType<typeof spawnSync>;
      if (a.includes('commit-tree'))
        return {
          status: 0,
          stdout: Buffer.from('commitX\n'),
          stderr: Buffer.from(''),
        } as ReturnType<typeof spawnSync>;
      return {
        status: 0,
        stdout: Buffer.from(''),
        stderr: Buffer.from(''),
      } as ReturnType<typeof spawnSync>;
    });

    await createShadowSnapshot('edit', {});

    // rmSync should have been called to blow away the mismatched shadow dir
    expect(vi.mocked(fs.rmSync)).toHaveBeenCalled();
    // And init should have been called to reinitialize
    const initCall = mockSpawn.mock.calls.find(([, args]) => (args as string[]).includes('init'));
    expect(initCall).toBeDefined();
  });

  it('sets core.untrackedCache and core.fsmonitor on init', async () => {
    vi.mocked(fs.readdirSync).mockReturnValue([]);
    vi.mocked(fs.readFileSync).mockImplementation((p) =>
      String(p).endsWith('snapshots.json') ? '[]' : ''
    );
    vi.mocked(fs.existsSync).mockImplementation((p) => String(p).endsWith('snapshots.json'));

    mockSpawn.mockImplementation((_cmd, args) => {
      const a = (args ?? []) as string[];
      if (a.includes('rev-parse') && a.includes('--git-dir'))
        return { status: 1, stdout: Buffer.from(''), stderr: Buffer.from('') } as ReturnType<
          typeof spawnSync
        >;
      if (a.includes('write-tree'))
        return {
          status: 0,
          stdout: Buffer.from('tree\n'),
          stderr: Buffer.from(''),
        } as ReturnType<typeof spawnSync>;
      if (a.includes('commit-tree'))
        return {
          status: 0,
          stdout: Buffer.from('commit\n'),
          stderr: Buffer.from(''),
        } as ReturnType<typeof spawnSync>;
      return { status: 0, stdout: Buffer.from(''), stderr: Buffer.from('') } as ReturnType<
        typeof spawnSync
      >;
    });

    await createShadowSnapshot('edit', {});

    const configCalls = mockSpawn.mock.calls.filter(([, args]) =>
      (args as string[]).includes('config')
    );
    const allConfigArgs = configCalls.flatMap(([, a]) => a as string[]);
    expect(allConfigArgs).toContain('core.untrackedCache');
    expect(allConfigArgs).toContain('core.fsmonitor');
  });
});

// ── writeShadowExcludes (via createShadowSnapshot) ────────────────────────────

describe('writeShadowExcludes', () => {
  it('always writes .git and .node9 into info/exclude', async () => {
    withShadowRepo(true);
    mockGitSuccess();

    await createShadowSnapshot('edit', {}, ['node_modules', 'dist']);

    const excludeWrite = writeSpy.mock.calls.find(byExcludePath);
    expect(excludeWrite).toBeDefined();
    const content = String(excludeWrite![1]);
    expect(content).toContain('.git');
    expect(content).toContain('.node9');
    expect(content).toContain('node_modules');
    expect(content).toContain('dist');
  });

  it('excludes .git and .node9 even when ignorePaths is empty', async () => {
    withShadowRepo(true);
    mockGitSuccess();

    await createShadowSnapshot('edit', {});

    const excludeWrite = writeSpy.mock.calls.find(byExcludePath);
    expect(excludeWrite).toBeDefined();
    const content = String(excludeWrite![1]);
    expect(content).toContain('.git');
    expect(content).toContain('.node9');
  });
});

// ── computeUndoDiff ───────────────────────────────────────────────────────────

describe('computeUndoDiff', () => {
  it('returns null when git diff --stat is empty (no changes)', () => {
    vi.mocked(fs.readdirSync).mockReturnValue([]);
    mockSpawn.mockReturnValue({
      status: 0,
      stdout: Buffer.from(''),
      stderr: Buffer.from(''),
    } as ReturnType<typeof spawnSync>);
    expect(computeUndoDiff('abc123', '/mock/project')).toBeNull();
  });

  it('returns null when git diff fails', () => {
    vi.mocked(fs.readdirSync).mockReturnValue([]);
    mockSpawn.mockReturnValue({
      status: 1,
      stdout: Buffer.from(''),
      stderr: Buffer.from('error'),
    } as ReturnType<typeof spawnSync>);
    expect(computeUndoDiff('abc123', '/mock/project')).toBeNull();
  });

  it('strips git header lines (diff --git, index) from output', () => {
    vi.mocked(fs.readdirSync).mockReturnValue([]);
    mockSpawn
      .mockReturnValueOnce({
        // rev-parse (buildGitEnv)
        status: 0,
        stdout: Buffer.from('/shadow\n'),
        stderr: Buffer.from(''),
      } as ReturnType<typeof spawnSync>)
      .mockReturnValueOnce({
        // diff --stat
        status: 0,
        stdout: Buffer.from('1 file changed'),
        stderr: Buffer.from(''),
      } as ReturnType<typeof spawnSync>)
      .mockReturnValueOnce({
        // diff
        status: 0,
        stdout: Buffer.from(
          'diff --git a/foo.ts b/foo.ts\nindex abc..def 100644\n--- a/foo.ts\n+++ b/foo.ts\n@@ -1,3 +1,3 @@\n-old\n+new\n'
        ),
        stderr: Buffer.from(''),
      } as ReturnType<typeof spawnSync>);

    const result = computeUndoDiff('abc123', '/mock/project');
    expect(result).not.toContain('diff --git');
    expect(result).not.toContain('index abc');
    expect(result).toContain('--- a/foo.ts');
    expect(result).toContain('+++ b/foo.ts');
    expect(result).toContain('-old');
    expect(result).toContain('+new');
  });

  it('returns null when diff output is empty after stripping headers', () => {
    vi.mocked(fs.readdirSync).mockReturnValue([]);
    mockSpawn
      .mockReturnValueOnce({
        // rev-parse
        status: 0,
        stdout: Buffer.from('/shadow\n'),
        stderr: Buffer.from(''),
      } as ReturnType<typeof spawnSync>)
      .mockReturnValueOnce({
        // diff --stat
        status: 0,
        stdout: Buffer.from('1 file changed'),
        stderr: Buffer.from(''),
      } as ReturnType<typeof spawnSync>)
      .mockReturnValueOnce({
        // diff
        status: 0,
        stdout: Buffer.from(
          'diff --git a/foo.ts b/foo.ts\nindex abc..def 100644\nBinary files differ\n'
        ),
        stderr: Buffer.from(''),
      } as ReturnType<typeof spawnSync>);

    expect(computeUndoDiff('abc123', '/mock/project')).toBeNull();
  });

  it('falls back to ambient git (no GIT_DIR) for old hashes when shadow repo is absent', () => {
    vi.mocked(fs.readdirSync).mockReturnValue([]);
    mockSpawn
      .mockReturnValueOnce({
        // rev-parse fails → shadow absent → legacy env
        status: 1,
        stdout: Buffer.from(''),
        stderr: Buffer.from(''),
      } as ReturnType<typeof spawnSync>)
      .mockReturnValueOnce({
        // diff --stat (legacy)
        status: 0,
        stdout: Buffer.from('2 files changed'),
        stderr: Buffer.from(''),
      } as ReturnType<typeof spawnSync>)
      .mockReturnValueOnce({
        // diff (legacy)
        status: 0,
        stdout: Buffer.from('--- a/foo.ts\n+++ b/foo.ts\n-old\n+new\n'),
        stderr: Buffer.from(''),
      } as ReturnType<typeof spawnSync>);

    const result = computeUndoDiff('abc123', '/mock/project');
    expect(result).not.toBeNull();

    // Verify no GIT_DIR in the diff call's env (legacy path)
    const diffCall = mockSpawn.mock.calls[2];
    expect((diffCall?.[2]?.env as Record<string, string>)?.GIT_DIR).toBeUndefined();
  });
});

// ── applyUndo ─────────────────────────────────────────────────────────────────

describe('applyUndo', () => {
  it('returns false when git restore fails', () => {
    vi.mocked(fs.readdirSync).mockReturnValue([]);
    mockSpawn.mockReturnValue({
      status: 1,
      stdout: Buffer.from(''),
      stderr: Buffer.from(''),
    } as ReturnType<typeof spawnSync>);
    expect(applyUndo('abc123', '/mock/project')).toBe(false);
  });

  it('returns true when restore succeeds and file lists match', () => {
    vi.mocked(fs.readdirSync).mockReturnValue([]);
    mockSpawn.mockImplementation((_cmd, args) => {
      const a = (args ?? []) as string[];
      if (a.includes('rev-parse') && a.includes('--git-dir'))
        return {
          status: 0,
          stdout: Buffer.from('/shadow\n'),
          stderr: Buffer.from(''),
        } as ReturnType<typeof spawnSync>;
      if (a.includes('restore'))
        return { status: 0, stdout: Buffer.from(''), stderr: Buffer.from('') } as ReturnType<
          typeof spawnSync
        >;
      if (a.includes('ls-tree'))
        return {
          status: 0,
          stdout: Buffer.from('src/app.ts\n'),
          stderr: Buffer.from(''),
        } as ReturnType<typeof spawnSync>;
      if (a.includes('--others'))
        return { status: 0, stdout: Buffer.from(''), stderr: Buffer.from('') } as ReturnType<
          typeof spawnSync
        >;
      // ls-files (tracked)
      return {
        status: 0,
        stdout: Buffer.from('src/app.ts\n'),
        stderr: Buffer.from(''),
      } as ReturnType<typeof spawnSync>;
    });
    expect(applyUndo('abc123', '/mock/project')).toBe(true);
  });

  it('deletes files that exist in working tree but not in snapshot', () => {
    vi.mocked(fs.existsSync).mockImplementation((p) => String(p).includes('extra.ts'));
    vi.mocked(fs.readdirSync).mockReturnValue([]);
    mockSpawn.mockImplementation((_cmd, args) => {
      const a = (args ?? []) as string[];
      if (a.includes('rev-parse') && a.includes('--git-dir'))
        return {
          status: 0,
          stdout: Buffer.from('/shadow\n'),
          stderr: Buffer.from(''),
        } as ReturnType<typeof spawnSync>;
      if (a.includes('restore'))
        return { status: 0, stdout: Buffer.from(''), stderr: Buffer.from('') } as ReturnType<
          typeof spawnSync
        >;
      if (a.includes('ls-tree'))
        return {
          status: 0,
          stdout: Buffer.from('src/app.ts\n'),
          stderr: Buffer.from(''),
        } as ReturnType<typeof spawnSync>;
      if (a.includes('--others'))
        return {
          status: 0,
          stdout: Buffer.from('extra.ts\n'),
          stderr: Buffer.from(''),
        } as ReturnType<typeof spawnSync>;
      return {
        status: 0,
        stdout: Buffer.from('src/app.ts\n'),
        stderr: Buffer.from(''),
      } as ReturnType<typeof spawnSync>;
    });

    applyUndo('abc123', '/mock/project');

    const deleted = vi.mocked(fs.unlinkSync).mock.calls.map(([p]) => String(p));
    expect(deleted.some((p) => p.includes('extra.ts'))).toBe(true);
  });

  it('uses shadow GIT_DIR for restore and ls-tree', () => {
    vi.mocked(fs.readdirSync).mockReturnValue([]);
    mockSpawn.mockImplementation((_cmd, args) => {
      const a = (args ?? []) as string[];
      if (a.includes('rev-parse') && a.includes('--git-dir'))
        return {
          status: 0,
          stdout: Buffer.from('/shadow\n'),
          stderr: Buffer.from(''),
        } as ReturnType<typeof spawnSync>;
      return { status: 0, stdout: Buffer.from(''), stderr: Buffer.from('') } as ReturnType<
        typeof spawnSync
      >;
    });

    applyUndo('abc123', '/mock/project');

    const restoreCall = mockSpawn.mock.calls.find(([, args]) =>
      (args as string[]).includes('restore')
    );
    expect(restoreCall).toBeDefined();
    const restoreEnv = restoreCall![2]?.env as Record<string, string>;
    expect(restoreEnv?.GIT_DIR).toContain(path.join('.node9', 'snapshots'));
    expect(restoreEnv?.GIT_WORK_TREE).toBe('/mock/project');
  });

  it('returns false when ls-tree exits non-zero (prevents empty-set mass delete)', () => {
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    vi.mocked(fs.readdirSync).mockReturnValue([]);
    mockSpawn.mockImplementation((_cmd, args) => {
      const a = (args ?? []) as string[];
      if (a.includes('rev-parse') && a.includes('--git-dir')) return spawnResult('/shadow\n', 0);
      if (a.includes('restore')) return spawnResult('', 0);
      if (a.includes('ls-tree')) return spawnResult('', 1); // ls-tree fails
      return spawnResult('', 0);
    });
    // Must return false rather than deleting every file in the working tree
    expect(applyUndo('abc123', '/mock/project')).toBe(false);
    expect(vi.mocked(fs.unlinkSync)).not.toHaveBeenCalled();
    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('ls-tree failed'));
    stderrSpy.mockRestore();
  });

  it('returns false when ls-tree exits 0 with empty stdout (mass-delete footgun)', () => {
    // ls-tree status 0 + empty stdout → snapshotFiles would be empty set →
    // every tracked file would be deleted. The empty-set guard catches this case.
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    vi.mocked(fs.readdirSync).mockReturnValue([]);
    vi.mocked(fs.existsSync).mockReturnValue(true);
    mockSpawn.mockImplementation((_cmd, args) => {
      const a = (args ?? []) as string[];
      if (a.includes('rev-parse') && a.includes('--git-dir')) return spawnResult('/shadow\n', 0);
      if (a.includes('restore')) return spawnResult('', 0);
      if (a.includes('ls-tree')) return spawnResult('', 0); // exits 0 but no files
      if (a.includes('--others')) return spawnResult('', 0);
      return spawnResult('src/app.ts\n', 0); // one tracked file that would be mass-deleted
    });
    expect(applyUndo('abc123', '/mock/project')).toBe(false);
    expect(vi.mocked(fs.unlinkSync)).not.toHaveBeenCalled();
    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('no files'));
    stderrSpy.mockRestore();
  });
});
