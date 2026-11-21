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

describe('posture footer', () => {
  it('adds the install step when posture ran through npx', () => {
    const out = renderPosture(RESULT, { viaNpx: true });
    expect(out).toContain('npm install -g node9-ai');
    expect(out.indexOf('npm install -g node9-ai')).toBeLessThan(out.indexOf('auth/signup'));
  });

  it('leaves it out for an installed node9', () => {
    expect(renderPosture(RESULT)).not.toContain('npm install -g');
  });

  it('recognises npx from npm_command or the _npx cache path', () => {
    expect(ranViaNpx({ npm_command: 'exec' }, '/usr/bin/node9')).toBe(true);
    expect(ranViaNpx({}, '/home/u/.npm/_npx/abc/node_modules/.bin/node9')).toBe(true);
    expect(ranViaNpx({}, '/usr/local/bin/node9')).toBe(false);
  });
});
