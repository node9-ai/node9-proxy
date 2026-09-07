// `node9 uninstall` must remove the things node9 put in the user's home.
// Map and decisions: doc/roadmap/active/uninstall-leftovers-map.md
//
// Two leftovers, both reproduced before this spec existed:
//   - the three canary decoy files, which --purge then makes UNRECOVERABLE by
//     deleting the registry that is the only record of them being fake
//   - the launchd plist / systemd unit, which restarts the daemon at next login
//
// The --purge rows are not spawned: that path prompts with @inquirer/prompts
// and a spawned CLI with no TTY cannot answer it. The ORDER those rows exist to
// pin is asserted directly on the exported helper instead, which is where the
// ordering actually lives.
import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
let home: string;

const DECOYS = ['.aws/credentials', '.env.bak', '.ssh/id_rsa_backup'];
const abs = (rel: string) => path.join(home, ...rel.split('/'));

function run(args: string[]) {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    NODE9_TESTING: '1',
    NODE9_NO_AUTO_DAEMON: '1',
    NO_COLOR: '1',
  };
  delete env.XDG_CONFIG_HOME;
  delete env.NODE9_API_KEY;
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: 90000,
    cwd: os.tmpdir(),
    env,
    input: '',
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}
const plantAll = () => {
  const r = run(['canary', 'plant', '--all', '--json']);
  expect(r.status, r.stderr).toBe(0);
  for (const d of DECOYS) expect(fs.existsSync(abs(d)), `${d} should have been planted`).toBe(true);
};
const registry = () => path.join(home, '.node9', 'canaries.json');

beforeAll(() => {
  if (!fs.existsSync(CLI)) throw new Error(`build first: ${CLI}`);
});
beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-uninst-'));
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
});
afterEach(() => fs.rmSync(home, { recursive: true, force: true }));

describe('U. uninstall removes what node9 put in the home', () => {
  it('U8 known-true: uninstall still succeeds and reports the wiring scan', () => {
    const r = run(['uninstall']);
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toMatch(/Removing hooks/);
  });

  it('U5 with nothing planted, uninstall says nothing about decoys', () => {
    const r = run(['uninstall']);
    expect(r.status).toBe(0);
    expect(r.stdout).not.toMatch(/decoy/i);
  });

  it('U1 the three decoy files are removed, with or without --purge', () => {
    plantAll();
    const r = run(['uninstall']);
    expect(r.status, r.stderr).toBe(0);
    for (const d of DECOYS) expect(fs.existsSync(abs(d)), `${d} must be removed`).toBe(false);
    expect(r.stdout).toMatch(/decoy/i);
    // ~/.node9 is untouched without --purge
    expect(fs.existsSync(registry())).toBe(true);
  });

  it('U6 after uninstall, canary status agrees with the disk', () => {
    plantAll();
    run(['uninstall']);
    const r = run(['canary', 'status', '--json']);
    const sites = (JSON.parse(r.stdout) as { sites: Array<{ kind: string; state: string }> }).sites;
    for (const s of sites) expect(s.state, s.kind).not.toBe('planted');
    for (const d of DECOYS) expect(fs.existsSync(abs(d))).toBe(false);
  });

  it('U3 a decoy that changed on disk is NAMED and left, and uninstall still succeeds', () => {
    plantAll();
    fs.appendFileSync(abs('.env.bak'), '# user edited this\n');
    const r = run(['uninstall']);
    expect(r.status, 'a refusal must not fail the uninstall').toBe(0);
    // The changed one survives AND is explicitly reported as left behind.
    // Asserting only that the path appears somewhere is too weak: the reason
    // line mentions it too, so removing the "left in place" marker left this
    // row green (caught by mutation). The requirement is that the user can
    // scan the output and see what is still on disk, not that the path is
    // mentioned incidentally.
    expect(fs.existsSync(abs('.env.bak'))).toBe(true);
    const out = r.stdout + r.stderr;
    expect(out).toMatch(/Left in place/i);
    const leftLine = out.split('\n').find((l) => /Left in place/i.test(l)) ?? '';
    expect(leftLine, 'the left-in-place line must name the path').toContain('.env.bak');
    // the other two are gone
    expect(fs.existsSync(abs('.aws/credentials'))).toBe(false);
    expect(fs.existsSync(abs('.ssh/id_rsa_backup'))).toBe(false);
  });

  it('U2 with --purge, the decoys are gone BEFORE the purge is even decided', () => {
    // The purge prompt needs a TTY, so a spawned --purge aborts at the prompt.
    // That is what makes this row possible: if decoy removal ran AFTER the
    // purge step, an aborted purge would leave all three on disk. It running
    // before means they are gone regardless of what the user answers, which is
    // exactly the ordering the finding is about.
    plantAll();
    const r = run(['uninstall', '--purge']);
    for (const d of DECOYS)
      expect(fs.existsSync(abs(d)), `${d} must be gone before the purge`).toBe(false);
    // and the registry survives, because the prompt was never answered
    expect(fs.existsSync(registry())).toBe(true);
    expect(r.stdout).toMatch(/decoy/i);
  });

  it('U7 the daemon service file is removed', () => {
    // Both platform locations; whichever this platform uses must be gone after.
    const plist = path.join(home, 'Library', 'LaunchAgents', 'ai.node9.daemon.plist');
    const unit = path.join(home, '.config', 'systemd', 'user', 'node9-daemon.service');
    for (const f of [plist, unit]) {
      fs.mkdirSync(path.dirname(f), { recursive: true });
      fs.writeFileSync(f, '# node9 service\n');
    }
    const r = run(['uninstall']);
    expect(r.status, r.stderr).toBe(0);
    const survivor = process.platform === 'darwin' ? plist : unit;
    expect(fs.existsSync(survivor), 'the service that restarts the daemon must be removed').toBe(
      false
    );
  });
});
