// fw#304 review: the daemon names who resolved a card its background pass
// decided, and one list of human channels serves the daemon and the hook.
import { describe, it, expect } from 'vitest';
import {
  backgroundPassSource,
  DECISION_ROUTE_SOURCES,
  HUMAN_DECISION_SOURCES,
  REDIRECT_SOURCE,
} from '../auth/decision-sources';

describe('backgroundPassSource', () => {
  it.each([
    [{ blockedBy: 'team-policy' }, 'cloud'],
    [{ checkedBy: 'cloud' }, 'cloud'],
    [{ blockedBy: 'timeout' }, 'timeout'],
    [{ blockedBy: 'local-config' }, 'policy'],
    [{ checkedBy: 'local-policy' }, 'policy'],
    [{}, 'policy'],
  ] as const)('%j -> %s', (result, source) => {
    expect(backgroundPassSource(result)).toBe(source);
  });
});

describe('decision source lists', () => {
  it('the /decision route accepts every human channel and the redirect, nothing the daemon sets itself', () => {
    for (const s of HUMAN_DECISION_SOURCES) expect(DECISION_ROUTE_SOURCES.has(s)).toBe(true);
    expect(DECISION_ROUTE_SOURCES.has(REDIRECT_SOURCE)).toBe(true);
    for (const s of ['timeout', 'cloud', 'policy']) {
      expect(DECISION_ROUTE_SOURCES.has(s)).toBe(false);
      expect(HUMAN_DECISION_SOURCES.has(s)).toBe(false);
    }
  });
});
