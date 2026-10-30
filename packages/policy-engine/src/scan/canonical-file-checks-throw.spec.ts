// A throw inside the file checks: the gate fails closed with
// file-inspection-incomplete, and the history scan reports the same rule.
// Its own file because the mock replaces evaluateFileChecks for every
// importer, the gate included.
import { describe, it, expect, vi } from 'vitest';

vi.mock('../files/file-checks', () => ({
  evaluateFileChecks: () => {
    throw new Error('matcher refused the pattern');
  },
}));

import { extractCanonicalFindings } from './canonical';
import { evaluatePolicy } from '../policy';
import { DEFAULT_CONFIG } from '../../../../src/config';

describe('extractCanonicalFindings: the file checks throw', () => {
  const args = { file_path: '/home/u/proj/.husky/pre-commit', content: '' };

  it('reports file-inspection-incomplete, as the gate decides', async () => {
    const out = extractCanonicalFindings(
      { toolName: 'Write', args, timestamp: '2026-10-30T10:00:00Z' },
      {
        sessionId: 's',
        lineIndex: 0,
        project: 'p',
        agent: 'claude',
        rules: [],
        toolInspection: {},
        dlpEnabled: false,
        cwd: '/home/u/proj',
        homeDirs: ['/home/u'],
      }
    );
    const f = out.find((x) => x.type === 'file-access');
    expect(f?.ruleName).toBe('file-inspection-incomplete');
    expect(f?.verdict).toBe('review');

    const gate = await evaluatePolicy(DEFAULT_CONFIG, 'Write', args, {
      cwd: '/home/u/proj',
      homeDirs: ['/home/u'],
    });
    expect(gate.decision).toBe('review');
    expect(gate.ruleName).toBe(f?.ruleName);
  });
});
