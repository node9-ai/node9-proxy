// The footer after a one-off `npx node9-ai posture`: point at a local install
// before the team sign-up. An installed node9 does not repeat the install line.
import { describe, it, expect } from 'vitest';
import { renderPosture, ranViaNpx } from '../render';
import type { PostureResult } from '../types';

const RESULT: PostureResult = {
  agent: 'agent on this host',
  findings: [],
  passedCategories: [],
  erroredCategories: [],
  headline: { risk: '', action: '' },
  score: 100,
  tier: 'good',
  checksRun: 1,
} as unknown as PostureResult;

// The row a machine without node9 gets: nothing is wired into any agent.
const NOT_WIRED: PostureResult = {
  ...RESULT,
  findings: [
    {
      category: 'Coverage',
      severity: 'critical',
      title: 'node9 is not in-path for any agent',
      detail: [],
      owner: 'node9',
    },
  ],
};

describe('posture footer', () => {
  it('adds the install step when posture ran through npx on a machine without node9', () => {
    const out = renderPosture(NOT_WIRED, { viaNpx: true });
    expect(out).toContain('npm install -g node9-ai');
    expect(out.indexOf('npm install -g node9-ai')).toBeLessThan(out.indexOf('auth/signup'));
  });

  it('leaves it out for an installed node9', () => {
    expect(renderPosture(RESULT)).not.toContain('npm install -g');
    expect(renderPosture(NOT_WIRED)).not.toContain('npm install -g');
  });

  // 2.66.2 told a machine with node9 wired in to install node9, because the
  // run came through npx.
  it('leaves it out when node9 is already wired in, even through npx', () => {
    expect(renderPosture(RESULT, { viaNpx: true })).not.toContain('npm install -g');
  });

  it('recognises npx from npm_command or the _npx cache path', () => {
    expect(ranViaNpx({ npm_command: 'exec' }, '/usr/bin/node9')).toBe(true);
    expect(ranViaNpx({}, '/home/u/.npm/_npx/abc/node_modules/.bin/node9')).toBe(true);
    expect(ranViaNpx({}, '/usr/local/bin/node9')).toBe(false);
  });
});
