import { describe, it, expect, vi, beforeEach } from 'vitest';
import fs from 'fs';
import os from 'os';

// ── Mock child_process BEFORE importing undo (hoisted by vitest) ─────────────
vi.mock('child_process', () => ({ spawnSync: vi.fn() }));

import { spawnSync } from 'child_process';
import {
  createShadowSnapshot,
  getLatestSnapshot,
  getSnapshotHistory,
  computeUndoDiff,
  applyUndo,
} from '../undo.js';

// ── Filesystem mocks (module-level — NOT restored between tests) ──────────────
vi.spyOn(fs, 'existsSync').mockReturnValue(false);
vi.spyOn(fs, 'readFileSync').mockReturnValue('');
const writeSpy = vi.spyOn(fs, 'writeFileSync').mockImplementation(() => undefined);
vi.spyOn(fs, 'mkdirSync').mockImplementation(() => undefined);
vi.spyOn(fs, 'unlinkSync').mockImplementation(() => undefined);
vi.spyOn(os, 'homedir').mockReturnValue('/mock/home');
vi.spyOn(process, 'cwd').mockReturnValue('/mock/project');

// undo.ts computes SNAPSHOT_STACK_PATH at module-load time (before our spy is
// active), so it uses the real homedir. Match by filename suffix instead.
const byStackPath = ([p]: Parameters<typeof fs.writeFileSync>) =>
  String(p).endsWith('snapshots.json');
const byLatestPath = ([p]: Parameters<typeof fs.writeFileSync>) =>
  String(p).endsWith('undo_latest.txt');

const mockSpawn = vi.mocked(spawnSync);

function mockGitSuccess(treeHash = 'abc123tree', commitHash = 'def456commit') {
  mockSpawn.mockImplementation((_cmd, args) => {
    const a = (args ?? []) as string[];
    if (a.includes('add'))
      return { status: 0, stdout: Buffer.from(''), stderr: Buffer.from('') } as ReturnType<
        typeof spawnSync
      >;
    if (a.includes('write-tree'))
      return {
        status: 0,
        stdout: Buffer.from(treeHash + '\n'),
        stderr: Buffer.from(''),
      } as ReturnType<typeof spawnSync>;
    if (a.includes('commit-tree'))
      return {
        status: 0,
        stdout: Buffer.from(commitHash + '\n'),
        stderr: Buffer.from(''),
      } as ReturnType<typeof spawnSync>;
    return { status: 0, stdout: Buffer.from(''), stderr: Buffer.from('') } as ReturnType<
      typeof spawnSync
    >;
  });
}

function withStack(entries: object[]) {
  vi.mocked(fs.existsSync).mockImplementation((p) => String(p).endsWith('snapshots.json'));
  vi.mocked(fs.readFileSync).mockImplementation((p) => {
    if (String(p).endsWith('snapshots.json')) return JSON.stringify(entries);
    throw new Error('not found');
  });
}

function withGitRepo(includeStackFile = false) {
  const gitDir = '/mock/project/.git';
  vi.mocked(fs.existsSync).mockImplementation((p) => {
    const s = String(p);
    if (s === gitDir) return true;
    if (includeStackFile && s.endsWith('snapshots.json')) return true;
    return false;
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  // Re-apply default mock implementations after clearAllMocks
  vi.mocked(fs.existsSync).mockReturnValue(false);
  vi.mocked(fs.readFileSync).mockReturnValue('');
  vi.mocked(fs.writeFileSync).mockImplementation(() => undefined);
  vi.mocked(fs.mkdirSync).mockImplementation(() => undefined);
  vi.mocked(fs.unlinkSync).mockImplementation(() => undefined);
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
    withStack(entries);
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
    withStack(entries);
    expect(getLatestSnapshot()?.hash).toBe('second');
  });
});

// ── createShadowSnapshot ──────────────────────────────────────────────────────

describe('createShadowSnapshot', () => {
  it('returns null when .git directory does not exist', async () => {
    vi.mocked(fs.existsSync).mockReturnValue(false);
    const result = await createShadowSnapshot('edit', { file_path: 'src/app.ts' });
    expect(result).toBeNull();
  });

  it('returns null when git write-tree fails', async () => {
    withGitRepo(false);
    mockSpawn.mockReturnValue({
      status: 1,
      stdout: Buffer.from(''),
      stderr: Buffer.from(''),
    } as ReturnType<typeof spawnSync>);
    const result = await createShadowSnapshot('edit', {});
    expect(result).toBeNull();
  });

  it('returns commit hash and writes stack on success', async () => {
    withGitRepo(true);
    vi.mocked(fs.readFileSync).mockImplementation((p) =>
      String(p).endsWith('snapshots.json') ? '[]' : ''
    );
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
    withGitRepo(true);
    vi.mocked(fs.readFileSync).mockImplementation((p) =>
      String(p).endsWith('snapshots.json') ? '[]' : ''
    );
    mockGitSuccess('tree111', 'commit333');

    await createShadowSnapshot('write', { file_path: 'x.ts' });

    const latestWrite = writeSpy.mock.calls.find(byLatestPath);
    expect(latestWrite).toBeDefined();
    expect(String(latestWrite![1])).toBe('commit333');
  });

  it('caps the stack at MAX_SNAPSHOTS (10)', async () => {
    withGitRepo(true);
    const existing = Array.from({ length: 10 }, (_, i) => ({
      hash: `hash${i}`,
      tool: 'edit',
      argsSummary: `file${i}.ts`,
      cwd: '/p',
      timestamp: i * 1000,
    }));
    vi.mocked(fs.readFileSync).mockImplementation((p) =>
      String(p).endsWith('snapshots.json') ? JSON.stringify(existing) : ''
    );
    mockGitSuccess('treeX', 'commitX');

    await createShadowSnapshot('edit', { file_path: 'new.ts' });

    const writeCall = writeSpy.mock.calls.find(byStackPath);
    const written = JSON.parse(String(writeCall![1]));
    expect(written).toHaveLength(10);
    expect(written[0].hash).toBe('hash1'); // oldest dropped
    expect(written[9].hash).toBe('commitX'); // newest added
  });

  it('extracts argsSummary from command field when no file_path', async () => {
    withGitRepo(true);
    vi.mocked(fs.readFileSync).mockImplementation((p) =>
      String(p).endsWith('snapshots.json') ? '[]' : ''
    );
    mockGitSuccess('treeA', 'commitA');

    await createShadowSnapshot('bash', { command: 'npm run build --production' });

    const writeCall = writeSpy.mock.calls.find(byStackPath);
    const written = JSON.parse(String(writeCall![1]));
    expect(written[0].argsSummary).toBe('npm run build --production');
  });

  it('extracts argsSummary from sql field', async () => {
    withGitRepo(true);
    vi.mocked(fs.readFileSync).mockImplementation((p) =>
      String(p).endsWith('snapshots.json') ? '[]' : ''
    );
    mockGitSuccess('treeB', 'commitB');

    await createShadowSnapshot('query', { sql: 'SELECT * FROM users' });

    const writeCall = writeSpy.mock.calls.find(byStackPath);
    const written = JSON.parse(String(writeCall![1]));
    expect(written[0].argsSummary).toBe('SELECT * FROM users');
  });
});

// ── computeUndoDiff ───────────────────────────────────────────────────────────

describe('computeUndoDiff', () => {
  it('returns null when git diff --stat is empty (no changes)', () => {
    mockSpawn.mockReturnValue({
      status: 0,
      stdout: Buffer.from(''),
      stderr: Buffer.from(''),
    } as ReturnType<typeof spawnSync>);
    expect(computeUndoDiff('abc123', '/mock/project')).toBeNull();
  });

  it('returns null when git diff fails', () => {
    mockSpawn.mockReturnValue({
      status: 1,
      stdout: Buffer.from(''),
      stderr: Buffer.from('error'),
    } as ReturnType<typeof spawnSync>);
    expect(computeUndoDiff('abc123', '/mock/project')).toBeNull();
  });

  it('strips git header lines (diff --git, index) from output', () => {
    mockSpawn
      .mockReturnValueOnce({
        status: 0,
        stdout: Buffer.from('1 file changed'),
        stderr: Buffer.from(''),
      } as ReturnType<typeof spawnSync>)
      .mockReturnValueOnce({
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
    mockSpawn
      .mockReturnValueOnce({
        status: 0,
        stdout: Buffer.from('1 file changed'),
        stderr: Buffer.from(''),
      } as ReturnType<typeof spawnSync>)
      .mockReturnValueOnce({
        status: 0,
        stdout: Buffer.from(
          'diff --git a/foo.ts b/foo.ts\nindex abc..def 100644\nBinary files differ\n'
        ),
        stderr: Buffer.from(''),
      } as ReturnType<typeof spawnSync>);

    const result = computeUndoDiff('abc123', '/mock/project');
    expect(result).toBeNull();
  });
});

// ── applyUndo ─────────────────────────────────────────────────────────────────

describe('applyUndo', () => {
  it('returns false when git restore fails', () => {
    mockSpawn.mockReturnValue({
      status: 1,
      stdout: Buffer.from(''),
      stderr: Buffer.from(''),
    } as ReturnType<typeof spawnSync>);
    expect(applyUndo('abc123', '/mock/project')).toBe(false);
  });

  it('returns true when restore succeeds and file lists match', () => {
    mockSpawn.mockImplementation((_cmd, args) => {
      const a = (args ?? []) as string[];
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
    mockSpawn.mockImplementation((_cmd, args) => {
      const a = (args ?? []) as string[];
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
});
