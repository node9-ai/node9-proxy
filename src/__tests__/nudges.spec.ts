// When `node9 report` suggests the dashboard (node9Firewall#390, design
// section 19): three local signals, once each, one per report, never when
// logged in, and no author address anywhere.
import { describe, it, expect } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawnSync } from 'child_process';
import {
  dashboardNudge,
  markNudgeShown,
  nudgesFilePath,
  readShownNudges,
  gitEnvFor,
  recentAuthorCount,
  teamProject,
  type NudgeKey,
} from '../apps/nudges';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'n9-nudges-'));
const none = new Set<NudgeKey>();
const signals = (o: Partial<Parameters<typeof dashboardNudge>[0]> = {}) => ({
  loggedIn: false,
  unanswered: 0,
  asked: 0,
  team: () => undefined,
  ...o,
});

describe('dashboardNudge', () => {
  it('each signal at its threshold, none below', () => {
    expect(dashboardNudge(signals({ unanswered: 2 }), none)).toBeNull();
    expect(dashboardNudge(signals({ unanswered: 3 }), none)?.key).toBe('dashboard-unanswered');
    expect(dashboardNudge(signals({ asked: 9 }), none)).toBeNull();
    expect(dashboardNudge(signals({ asked: 10 }), none)?.key).toBe('dashboard-questions');
    expect(dashboardNudge(signals({ team: () => 'shop' }), none)).toMatchObject({
      key: 'dashboard-team',
      line: expect.stringContaining('shop'),
    });
  });

  it('one per report, in order: unanswered, team, questions', () => {
    const all = signals({ unanswered: 5, asked: 40, team: () => 'shop' });
    expect(dashboardNudge(all, none)?.key).toBe('dashboard-unanswered');
    expect(dashboardNudge(all, new Set<NudgeKey>(['dashboard-unanswered']))?.key).toBe(
      'dashboard-team'
    );
    expect(
      dashboardNudge(all, new Set<NudgeKey>(['dashboard-unanswered', 'dashboard-team']))?.key
    ).toBe('dashboard-questions');
    expect(
      dashboardNudge(
        all,
        new Set<NudgeKey>(['dashboard-unanswered', 'dashboard-team', 'dashboard-questions'])
      )
    ).toBeNull();
  });

  it('never when logged in, and git is not even asked then', () => {
    let asked = false;
    const team = () => {
      asked = true;
      return 'shop';
    };
    expect(
      dashboardNudge(signals({ loggedIn: true, unanswered: 9, asked: 50, team }), none)
    ).toBeNull();
    expect(asked).toBe(false);
  });
});

describe('once each', () => {
  it('a shown nudge is recorded and not shown again', () => {
    const home = tmp();
    expect(readShownNudges(home).size).toBe(0);
    markNudgeShown('dashboard-questions', home);
    const shown = readShownNudges(home);
    expect([...shown]).toEqual(['dashboard-questions']);
    expect(dashboardNudge(signals({ asked: 40 }), shown)).toBeNull();
    expect(fs.statSync(nudgesFilePath(home)).mode & 0o777).toBe(0o600);
  });

  it('an unreadable file is none shown', () => {
    const home = tmp();
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    fs.writeFileSync(nudgesFilePath(home), '{oops');
    expect(readShownNudges(home).size).toBe(0);
  });
});

describe('the team signal', () => {
  const git = (dir: string, ...args: string[]) => {
    // Without the GIT_* variables a git hook sets, or git would write into
    // the repository being committed (this suite runs in the pre-commit hook).
    const r = spawnSync('git', ['-C', dir, ...args], { encoding: 'utf8', env: gitEnvFor() });
    expect(r.error).toBeUndefined();
    expect(r.status).toBe(0);
  };
  const commitAs = (dir: string, email: string, file: string) => {
    fs.writeFileSync(path.join(dir, file), file);
    git(dir, 'add', file);
    git(dir, '-c', `user.name=${email}`, '-c', `user.email=${email}`, 'commit', '-qm', file);
  };

  it('git runs without inherited GIT_* variables', () => {
    expect(gitEnvFor({ GIT_DIR: '/x/.git', GIT_INDEX_FILE: 'i', PATH: '/bin' })).toEqual({
      PATH: '/bin',
    });
  });

  it('counts authors of the last 30 days; a lone author or no repo is no team', () => {
    const solo = tmp();
    git(solo, 'init', '-q');
    commitAs(solo, 'one@example.com', 'a');
    commitAs(solo, 'one@example.com', 'b');
    const team = tmp();
    git(team, 'init', '-q');
    commitAs(team, 'one@example.com', 'a');
    commitAs(team, 'two@example.com', 'b');
    const notRepo = tmp();

    expect(recentAuthorCount(solo)).toBe(1);
    expect(recentAuthorCount(team)).toBe(2);
    expect(recentAuthorCount(notRepo)).toBe(0);
    expect(teamProject([notRepo, solo, team])).toBe(path.basename(team));
    expect(teamProject([notRepo, solo])).toBeUndefined();
  });

  it('looks at the five most recent projects only, and prints the name, no address', () => {
    const seen: string[] = [];
    const count = (d: string) => {
      seen.push(d);
      return d.endsWith('/p6') ? 3 : 1;
    };
    const dirs = ['/w/p1', '/w/p2', '/w/p3', '/w/p4', '/w/p5', '/w/p6'];
    expect(teamProject(dirs, count)).toBeUndefined();
    expect(seen).toEqual(dirs.slice(0, 5));
    const line = dashboardNudge(signals({ team: () => 'shop' }), none)!.line;
    expect(line).not.toMatch(/@/);
  });
});
