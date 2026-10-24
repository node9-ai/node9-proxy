// src/apps/nudges.ts
// When `node9 report` suggests the dashboard (node9Firewall#390, design
// section 19). Three moments, local signals only, once each, at most one per
// report, and only on a machine that is not logged in:
//   - nobody was there to answer: reviews that timed out in the period;
//   - a team: more than one author commits to a project the agent worked in;
//   - many questions: asked ten or more times in the period.
// ~/.node9/nudges.json records which were shown. git runs only here (never in
// the hook), with a timeout; author addresses are counted, never kept.
import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawnSync } from 'child_process';

export type NudgeKey = 'dashboard-unanswered' | 'dashboard-team' | 'dashboard-questions';

export const UNANSWERED_AT = 3;
export const QUESTIONS_AT = 10;
const TEAM_AUTHORS_AT = 2;
const TEAM_PROJECTS = 5;
const GIT_TIMEOUT_MS = 2000;

export function nudgesFilePath(home: string = os.homedir()): string {
  return path.join(home, '.node9', 'nudges.json');
}

/** The nudges already shown, by key. A missing or unreadable file is none. */
export function readShownNudges(home?: string): Set<NudgeKey> {
  try {
    const raw = JSON.parse(fs.readFileSync(nudgesFilePath(home), 'utf8')) as unknown;
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return new Set();
    return new Set(
      Object.keys(raw).filter((k): k is NudgeKey =>
        ['dashboard-unanswered', 'dashboard-team', 'dashboard-questions'].includes(k)
      )
    );
  } catch {
    return new Set();
  }
}

/** Record that a nudge was shown, so it is never shown again. */
export function markNudgeShown(key: NudgeKey, home?: string, now: Date = new Date()): void {
  const file = nudgesFilePath(home);
  let data: Record<string, string> = {};
  try {
    const raw = JSON.parse(fs.readFileSync(file, 'utf8')) as unknown;
    if (raw && typeof raw === 'object' && !Array.isArray(raw)) data = raw as Record<string, string>;
  } catch {
    /* missing or unreadable: start over; the worst case is one repeat */
  }
  data[key] = now.toISOString();
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(data, null, 2) + '\n', { mode: 0o600 });
  } catch {
    /* a report line is not worth failing the report for */
  }
}

/** The environment without inherited GIT_* variables: run from inside a git
 *  hook (GIT_DIR, GIT_INDEX_FILE set), `git -C dir` would read that
 *  repository instead of `dir`. */
export function gitEnvFor(env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  return Object.fromEntries(Object.entries(env).filter(([k]) => !k.startsWith('GIT_')));
}

/** How many people committed to `dir` in the last 30 days; 0 when it is not a
 *  repository, git is missing or slow. Addresses are counted, never returned. */
export function recentAuthorCount(dir: string): number {
  const r = spawnSync('git', ['-C', dir, 'log', '--since=30.days', '--format=%ae', '-n', '500'], {
    encoding: 'utf8',
    timeout: GIT_TIMEOUT_MS,
    stdio: ['ignore', 'pipe', 'ignore'],
    env: gitEnvFor(),
  });
  if (r.error || r.status !== 0 || typeof r.stdout !== 'string') return 0;
  return new Set(
    r.stdout
      .split('\n')
      .map((l) => l.trim().toLowerCase())
      .filter(Boolean)
  ).size;
}

/** The first recent project more than one person commits to, by name. */
export function teamProject(
  dirs: readonly string[],
  countAuthors: (dir: string) => number = recentAuthorCount
): string | undefined {
  for (const dir of dirs.slice(0, TEAM_PROJECTS)) {
    if (countAuthors(dir) >= TEAM_AUTHORS_AT) return path.basename(dir);
  }
  return undefined;
}

export interface NudgeSignals {
  loggedIn: boolean;
  /** Reviews in the period that timed out with no answer. */
  unanswered: number;
  /** Times node9 asked in the period. */
  asked: number;
  /** Looked up only when needed: a recent project with more than one author. */
  team: () => string | undefined;
}

/** The one dashboard line this report shows, if any, and its key. */
export function dashboardNudge(
  s: NudgeSignals,
  shown: ReadonlySet<NudgeKey>
): { key: NudgeKey; line: string } | null {
  if (s.loggedIn) return null;
  if (!shown.has('dashboard-unanswered') && s.unanswered >= UNANSWERED_AT)
    return {
      key: 'dashboard-unanswered',
      line: `${s.unanswered} questions waited with nobody to answer. With the dashboard they reach your phone or Slack: node9 login`,
    };
  if (!shown.has('dashboard-team')) {
    const project = s.team();
    if (project)
      return {
        key: 'dashboard-team',
        line: `Others commit to ${project} too. The dashboard gives the team one policy and one place to approve: node9 login`,
      };
  }
  if (!shown.has('dashboard-questions') && s.asked >= QUESTIONS_AT)
    return {
      key: 'dashboard-questions',
      line: `node9 asked ${s.asked} times this period. Approve from your phone and stop a question with one click: node9 login`,
    };
  return null;
}
