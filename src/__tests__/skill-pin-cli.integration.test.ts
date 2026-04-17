/**
 * Integration tests for `node9 skill pin` CLI (list / update / reset).
 * Spawns dist/cli.js with an isolated HOME. Requires `npm run build` first.
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

import { updatePin, getRootKey } from '../skill-pin';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const cliExists = fs.existsSync(CLI);
const itBuilt = cliExists ? it : it.skip;

function runCli(
  args: string[],
  env: Record<string, string> = {}
): {
  status: number | null;
  stdout: string;
  stderr: string;
} {
  const baseEnv = { ...process.env };
  delete baseEnv.NODE9_API_KEY;
  delete baseEnv.NODE9_API_URL;
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: 60000,
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
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

function seedPin(tmpHome: string, rootKey: string, rootPath: string): void {
  const origHome = process.env.HOME;
  const origUP = process.env.USERPROFILE;
  process.env.HOME = tmpHome;
  process.env.USERPROFILE = tmpHome;
  try {
    updatePin(rootKey, rootPath, 'a'.repeat(64), true, 4);
  } finally {
    process.env.HOME = origHome;
    process.env.USERPROFILE = origUP;
  }
}

beforeAll(() => {
  if (!cliExists) {
    console.warn(`[skill-pin CLI test] dist/cli.js not found — run \`npm run build\`.`);
  }
});

describe('node9 skill pin', () => {
  let tmpHome: string;
  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-skillpin-cli-'));
  });
  afterEach(() => {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  itBuilt('list: friendly empty message when no pins exist', () => {
    const r = runCli(['skill', 'pin', 'list'], { HOME: tmpHome });
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/No skill roots are pinned/i);
  });

  itBuilt('list: shows rootPath, hash, fileCount for a seeded pin', () => {
    const rootPath = '/tmp/project-alpha/.cursor/rules';
    seedPin(tmpHome, getRootKey(rootPath), rootPath);
    const r = runCli(['skill', 'pin', 'list'], { HOME: tmpHome });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain(rootPath);
    expect(r.stdout).toContain('Files (4)');
    expect(r.stdout).toContain('a'.repeat(16));
  });

  itBuilt('list: corrupt pin file exits 1 with remediation hint', () => {
    const dir = path.join(tmpHome, '.node9');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'skill-pins.json'), 'not json');
    const r = runCli(['skill', 'pin', 'list'], { HOME: tmpHome });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/corrupt/i);
    expect(r.stderr).toMatch(/skill pin reset/);
  });

  itBuilt('update: unknown rootKey exits 1 with a helpful message', () => {
    const r = runCli(['skill', 'pin', 'update', 'deadbeefcafebabe'], { HOME: tmpHome });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/No pin found/);
  });

  itBuilt('update: removes a known pin so next session re-pins', () => {
    const rootPath = '/tmp/project-alpha/.cursor/rules';
    const key = getRootKey(rootPath);
    seedPin(tmpHome, key, rootPath);
    const r = runCli(['skill', 'pin', 'update', key], { HOME: tmpHome });
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/Pin removed/);
    const pins = JSON.parse(
      fs.readFileSync(path.join(tmpHome, '.node9', 'skill-pins.json'), 'utf-8')
    );
    expect(pins.roots[key]).toBeUndefined();
  });

  itBuilt('reset: clears pins AND wipes skill-sessions/', () => {
    seedPin(tmpHome, getRootKey('/p'), '/p');
    const sessionsDir = path.join(tmpHome, '.node9', 'skill-sessions');
    fs.mkdirSync(sessionsDir, { recursive: true });
    fs.writeFileSync(path.join(sessionsDir, 'sess-1.json'), '{"state":"verified"}');
    const r = runCli(['skill', 'pin', 'reset'], { HOME: tmpHome });
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/Cleared/);
    const pins = JSON.parse(
      fs.readFileSync(path.join(tmpHome, '.node9', 'skill-pins.json'), 'utf-8')
    );
    expect(pins).toEqual({ roots: {} });
    expect(fs.existsSync(path.join(sessionsDir, 'sess-1.json'))).toBe(false);
  });
});
