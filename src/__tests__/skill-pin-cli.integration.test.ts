/**
 * Integration tests for `node9 skill pin` CLI (list / update / reset).
 *
 * These spawn the real built CLI subprocess against dist/cli.js with an
 * isolated HOME directory. See src/__tests__/check.integration.test.ts for
 * the runner pattern this mirrors.
 *
 * Requires `npm run build` before running.
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

import { updatePin, getRootKey, hashSkillRoot } from '../skill-pin';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const cliExists = fs.existsSync(CLI);

// Skip the whole suite if dist/cli.js wasn't built — avoids confusing CI output.
const itBuilt = cliExists ? it : it.skip;

interface RunResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

function runCli(args: string[], env: Record<string, string> = {}, timeoutMs = 60000): RunResult {
  const baseEnv = { ...process.env };
  delete baseEnv.NODE9_API_KEY;
  delete baseEnv.NODE9_API_URL;
  const result = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: timeoutMs,
    cwd: os.tmpdir(),
    env: {
      ...baseEnv,
      NODE9_NO_AUTO_DAEMON: '1',
      NODE9_TESTING: '1',
      FORCE_COLOR: '0',
      ...env,
      ...(env.HOME != null ? { USERPROFILE: env.HOME } : {}),
    },
  });

  if (result.error) {
    console.error('[skill-pin CLI test] spawn error:', result.error);
  }
  return {
    status: result.status,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

beforeAll(() => {
  if (!cliExists) {
    console.warn(
      `[skill-pin CLI test] dist/cli.js not found at ${CLI} — run \`npm run build\` first. Tests will be skipped.`
    );
  }
});

describe('node9 skill pin list', () => {
  let tmpHome: string;
  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-skillpin-cli-'));
  });
  afterEach(() => {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  itBuilt('prints a friendly message when no pins exist', () => {
    const r = runCli(['skill', 'pin', 'list'], { HOME: tmpHome });
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/No skill roots are pinned/i);
  });

  itBuilt('lists a previously-written pin with rootPath, hash, fileCount', () => {
    // Seed the HOME pin file directly by running the module in-process with mocked HOME
    const origHome = process.env.HOME;
    const origUserprofile = process.env.USERPROFILE;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    try {
      const rootPath = '/tmp/project-alpha/.cursor/rules';
      updatePin(getRootKey(rootPath), rootPath, 'a'.repeat(64), true, 4);
    } finally {
      process.env.HOME = origHome;
      process.env.USERPROFILE = origUserprofile;
    }

    const r = runCli(['skill', 'pin', 'list'], { HOME: tmpHome });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('/tmp/project-alpha/.cursor/rules');
    expect(r.stdout).toContain('Files (4)');
    expect(r.stdout).toContain('a'.repeat(16)); // truncated hash display
  });

  itBuilt('reports a corrupt pin file and exits 1 with a remediation hint', () => {
    const node9Dir = path.join(tmpHome, '.node9');
    fs.mkdirSync(node9Dir, { recursive: true });
    fs.writeFileSync(path.join(node9Dir, 'skill-pins.json'), 'not json');
    const r = runCli(['skill', 'pin', 'list'], { HOME: tmpHome });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/corrupt/i);
    expect(r.stderr).toMatch(/skill pin reset/);
  });
});

describe('node9 skill pin update', () => {
  let tmpHome: string;
  let tmpSkills: string;
  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-skillpin-cli-'));
    tmpSkills = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-skillpin-root-'));
  });
  afterEach(() => {
    fs.rmSync(tmpHome, { recursive: true, force: true });
    fs.rmSync(tmpSkills, { recursive: true, force: true });
  });

  itBuilt('exits 1 with a helpful message when the rootKey is unknown', () => {
    const r = runCli(['skill', 'pin', 'update', 'deadbeefcafebabe', '--yes'], { HOME: tmpHome });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/No pin found/);
    expect(r.stderr).toMatch(/skill pin list/);
  });

  itBuilt('re-pins with --yes (non-interactive) and shows the diff summary', () => {
    // Seed a directory root and its pin
    fs.writeFileSync(path.join(tmpSkills, 'a.md'), 'original');
    fs.writeFileSync(path.join(tmpSkills, 'gone.md'), 'will-be-removed');

    const origHome = process.env.HOME;
    const origUserprofile = process.env.USERPROFILE;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    try {
      const before = hashSkillRoot(tmpSkills);
      updatePin(
        getRootKey(tmpSkills),
        tmpSkills,
        before.contentHash,
        before.exists,
        before.fileCount,
        before.fileManifest
      );
    } finally {
      process.env.HOME = origHome;
      process.env.USERPROFILE = origUserprofile;
    }

    // Mutate: modify one, remove one, add one
    fs.writeFileSync(path.join(tmpSkills, 'a.md'), 'tampered');
    fs.unlinkSync(path.join(tmpSkills, 'gone.md'));
    fs.writeFileSync(path.join(tmpSkills, 'added.md'), 'new');

    const rootKey = getRootKey(tmpSkills);
    const r = runCli(['skill', 'pin', 'update', rootKey, '--yes'], { HOME: tmpHome });
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/added/i);
    expect(r.stdout).toMatch(/removed/i);
    expect(r.stdout).toMatch(/modified/i);
    expect(r.stdout).toMatch(/re-?pinned/i);
  });
});

describe('node9 skill pin reset', () => {
  let tmpHome: string;
  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-skillpin-cli-'));
  });
  afterEach(() => {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  itBuilt('reports "nothing to clear" when no pins exist', () => {
    const r = runCli(['skill', 'pin', 'reset'], { HOME: tmpHome });
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/No pins to clear|Cleared 0/i);
  });

  itBuilt('clears pins and wipes the skill-sessions directory', () => {
    const origHome = process.env.HOME;
    const origUserprofile = process.env.USERPROFILE;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    try {
      updatePin(getRootKey('/p'), '/p', 'a'.repeat(64), true, 1);
    } finally {
      process.env.HOME = origHome;
      process.env.USERPROFILE = origUserprofile;
    }

    // Seed a stale session flag
    const sessionsDir = path.join(tmpHome, '.node9', 'skill-sessions');
    fs.mkdirSync(sessionsDir, { recursive: true });
    fs.writeFileSync(path.join(sessionsDir, 'sess-1.json'), '{"state":"verified"}');

    const r = runCli(['skill', 'pin', 'reset'], { HOME: tmpHome });
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/Cleared/);

    const pinsPath = path.join(tmpHome, '.node9', 'skill-pins.json');
    const pinsRaw = fs.readFileSync(pinsPath, 'utf-8');
    expect(JSON.parse(pinsRaw)).toEqual({ roots: {} });

    // Session flags should be wiped so the session isn't resurrected with stale state.
    expect(fs.existsSync(path.join(sessionsDir, 'sess-1.json'))).toBe(false);
  });
});
