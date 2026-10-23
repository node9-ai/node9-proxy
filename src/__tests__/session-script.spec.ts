// src/__tests__/session-script.spec.ts
// fw#372 A3: a script the session wrote and then runs is judged from its
// content. The helper is tested with injected daemon and file readers; the
// gate test runs authorizeHeadless with the daemon client mocked, so the
// real orchestrator path (file policy and engine, stricter verdict wins) is
// exercised on a file written into a temp project.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

const mockCheckWritten = vi.fn(async (_paths: readonly string[]) => ({ written: [] as string[] }));
const mockNotifyWritten = vi.fn(async (_paths: readonly string[]) => {});

vi.mock('../auth/daemon.js', async (orig) => ({
  ...(await orig<typeof import('../auth/daemon.js')>()),
  isDaemonRunning: () => false,
  notifyActivitySocket: vi.fn(async () => true),
  checkSessionTaint: vi.fn(async () => ({ tainted: false })),
  checkSessionExposure: vi.fn(async () => ({ exposed: false })),
  checkTaint: vi.fn(async () => ({ tainted: false })),
  checkWritten: (paths: readonly string[]) => mockCheckWritten(paths),
  notifyWritten: (paths: readonly string[]) => mockNotifyWritten(paths),
  getInternalToken: () => null,
}));

import { authorizeHeadless, _resetConfigCache } from '../core.js';
import { resolveSessionScript, sessionWriteTargets } from '../auth/session-script.js';
import { prepareFileAccesses } from '../policy/file-access.js';

const LAYERS = { trusted: { bash: 'command' } };
// Every expected path is built the way the code builds it, so the helper rows
// hold on Windows too (path.resolve('/proj') is D:\proj there).
const PROJ = path.resolve('/proj');
const inProj = (...parts: string[]) => path.join(PROJ, ...parts);

describe('resolveSessionScript (helper)', () => {
  const deps = (written: string[], files: Record<string, string>) => ({
    checkWritten: async () => ({ written }),
    readScript: (p: string) => files[p] ?? null,
  });

  it('names the script, resolved against cwd, and prepares its content as a command', async () => {
    const r = await resolveSessionScript(
      'Bash',
      { command: 'bash scripts/run.sh' },
      PROJ,
      LAYERS,
      deps([inProj('scripts', 'run.sh')], { [inProj('scripts', 'run.sh')]: 'echo hi\n' })
    );
    expect(r?.path).toBe('scripts/run.sh');
    expect(r?.resolved).toBe(inProj('scripts', 'run.sh'));
    expect(r?.args.command).toBe('echo hi\n');
  });

  it('nothing when the session did not write it, when the file is unreadable, or for a non-shell tool', async () => {
    const d = deps([], {});
    expect(
      await resolveSessionScript('Bash', { command: 'bash run.sh' }, PROJ, LAYERS, d)
    ).toBeNull();
    expect(
      await resolveSessionScript(
        'Bash',
        { command: 'bash run.sh' },
        PROJ,
        LAYERS,
        deps([inProj('run.sh')], {})
      )
    ).toBeNull();
    expect(await resolveSessionScript('Read', { file_path: 'run.sh' }, PROJ, LAYERS, d)).toBeNull();
  });

  it('a daemon failure or a reader throw fails open', async () => {
    const r = await resolveSessionScript('Bash', { command: 'bash run.sh' }, PROJ, LAYERS, {
      checkWritten: async () => {
        throw new Error('down');
      },
      readScript: () => null,
    });
    expect(r).toBeNull();
  });
});

describe('sessionWriteTargets (helper)', () => {
  it('a file tool names its path; a shell command its write targets; reads are not writes', () => {
    expect(
      sessionWriteTargets('Write', { file_path: 'x.sh', content: '' }, undefined, PROJ)
    ).toEqual([inProj('x.sh')]);
    expect(sessionWriteTargets('Read', { file_path: 'x.sh' }, undefined, PROJ)).toEqual([]);
    // The shell half reads the file policy's accesses, which are POSIX-only.
    if (process.platform === 'win32') return;
    const fa = prepareFileAccesses(
      'Bash',
      { command: 'echo a > out.sh && cat in.txt' },
      PROJ,
      LAYERS,
      '/home/u'
    );
    expect(
      sessionWriteTargets('Bash', { command: 'echo a > out.sh && cat in.txt' }, fa, PROJ)
    ).toEqual([inProj('out.sh')]);
  });
});

describe('the gate judges a script the session wrote from its content', () => {
  let home: string;
  let proj: string;
  let origHome: string | undefined;
  const META = { agent: 'Claude Code', sessionId: 'script-session' };
  const bash = (command: string) => authorizeHeadless('Bash', { command }, META, { cwd: proj });

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-session-script-'));
    proj = path.join(home, 'proj');
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    fs.mkdirSync(proj, { recursive: true });
    origHome = process.env.HOME;
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    fs.writeFileSync(
      path.join(home, '.node9', 'config.json'),
      JSON.stringify({
        settings: {
          mode: 'standard',
          approvalTimeoutMs: 50,
          approvers: { native: false, browser: false, cloud: false, terminal: false },
        },
        policy: {},
      })
    );
    _resetConfigCache();
    mockCheckWritten.mockReset();
    mockCheckWritten.mockResolvedValue({ written: [] });
    mockNotifyWritten.mockClear();
  });

  afterEach(() => {
    if (origHome !== undefined) process.env.HOME = origHome;
    else delete process.env.HOME;
    fs.rmSync(home, { recursive: true, force: true });
    _resetConfigCache();
  });

  const written = (name: string, content: string) => {
    const p = path.join(proj, name);
    fs.writeFileSync(p, content);
    mockCheckWritten.mockResolvedValue({ written: [p] });
    return p;
  };

  it('a write records its target with the daemon', async () => {
    await authorizeHeadless('Write', { file_path: 'run.sh', content: 'echo hi\n' }, META, {
      cwd: proj,
    });
    expect(mockNotifyWritten).toHaveBeenCalledWith([path.join(proj, 'run.sh')]);
  });

  it('a harmless script runs; the same name not written by the session is not read at all', async () => {
    written('run.sh', 'echo building\nls -la\n');
    expect((await bash('bash run.sh')).approved).toBe(true);
    mockCheckWritten.mockResolvedValue({ written: [] });
    expect((await bash('bash run.sh')).approved).toBe(true);
  });

  // The file policy (files.system-dirs) is POSIX-only: prepareFileAccesses
  // returns no accesses on win32, so this row has nothing to see there.
  it.skipIf(process.platform === 'win32')(
    'a system-directory change inside the script is reviewed, naming the script',
    async () => {
      written('run.sh', '#!/bin/bash\nset -e\nrm /var/log/app.log\n');
      const held = await bash('bash run.sh');
      expect(held.approved).toBe(false);
      expect(held.blockedBy).toBe('timeout'); // reached the approver race
      // The inline-ask path hands the reason to the agent's own prompt.
      const asked = await authorizeHeadless('Bash', { command: 'bash run.sh' }, META, {
        cwd: proj,
        deferReview: true,
      });
      expect(asked.review).toBe(true);
      // The label names the check; the description says it came from the script.
      expect(asked.reason).toMatch(/system directory/);
      expect(asked.ruleDescription).toMatch(/In run\.sh, a script written this session/);
      expect(mockCheckWritten).toHaveBeenCalledWith([path.join(proj, 'run.sh')]);
    }
  );

  it('an engine block inside the script blocks the run, through ./ and through sh', async () => {
    written('clean.sh', 'rm -rf /\n');
    for (const cmd of ['./clean.sh', 'sh ./clean.sh', 'source clean.sh']) {
      const r = await bash(cmd);
      expect(r.approved, cmd).toBe(false);
      expect(r.blockedBy, cmd).toBe('local-config');
      expect(r.reason, cmd).toMatch(/In \.?\/?clean\.sh, a script written this session/);
    }
  });

  it.skipIf(process.platform === 'win32')(
    'the command itself is still judged first: a review on the command line stands',
    async () => {
      written('ok.sh', 'echo fine\n');
      const r = await bash('rm /var/log/app.log && bash ok.sh');
      expect(r.approved).toBe(false);
      expect(r.reason ?? '').not.toMatch(/written this session/);
    }
  );
});
