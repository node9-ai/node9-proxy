import { describe, it, expect } from 'vitest';
import { summarizeBlast, truncateBlastPath, type BlastResult } from './index';

describe('truncateBlastPath', () => {
  it('keeps already-short paths unchanged (≤2 segments)', () => {
    expect(truncateBlastPath('.env')).toBe('.env');
    expect(truncateBlastPath('foo/bar')).toBe('foo/bar');
  });

  it('reduces a long absolute path to its last 2 segments', () => {
    expect(truncateBlastPath('/Users/alice/Code/payments-prod/.env.production')).toBe(
      'payments-prod/.env.production'
    );
  });

  it('reduces a long home-relative path to its last 2 segments', () => {
    expect(truncateBlastPath('~/.config/gcloud/credentials.db')).toBe('gcloud/credentials.db');
  });

  it('handles Windows-style backslash separators', () => {
    expect(truncateBlastPath('C:\\Users\\alice\\Code\\app\\.env')).toBe('app/.env');
  });

  it('returns an empty string for empty input (defensive)', () => {
    expect(truncateBlastPath('')).toBe('');
  });

  it('strips trailing separators before counting segments', () => {
    expect(truncateBlastPath('/foo/bar/')).toBe('foo/bar');
  });
});

describe('summarizeBlast', () => {
  const result: BlastResult = {
    reachable: [
      {
        full: '/home/alice/.ssh/id_rsa',
        label: '~/.ssh/id_rsa',
        description: 'RSA private key',
        score: 20,
      },
      {
        full: '/home/alice/.aws/credentials',
        label: '~/.aws/credentials',
        description: 'AWS keys',
        score: 20,
      },
      {
        full: '/home/alice/.docker/config.json',
        label: '~/.docker/config.json',
        description: 'Docker auth',
        score: 10,
      },
    ],
    envFindings: [
      { key: 'GITHUB_TOKEN', patternName: 'GitHub Token' },
      { key: 'AWS_SECRET_ACCESS_KEY', patternName: 'AWS Secret Key' },
    ],
    score: 50,
  };

  it('passes the score through verbatim from the input', () => {
    expect(summarizeBlast(result).score).toBe(50);
  });

  it('counts total exposures across reachable + env findings', () => {
    expect(summarizeBlast(result).exposureCount).toBe(5);
  });

  it('reports envExposureCount separately (no key names included)', () => {
    const s = summarizeBlast(result);
    expect(s.envExposureCount).toBe(2);
    // Critical: no env var keys in the summary
    expect(JSON.stringify(s)).not.toContain('GITHUB_TOKEN');
    expect(JSON.stringify(s)).not.toContain('AWS_SECRET_ACCESS_KEY');
  });

  it('sorts worstPaths by score descending', () => {
    const s = summarizeBlast(result);
    expect(s.worstPaths.map((p) => p.score)).toEqual([20, 20, 10]);
  });

  it('truncates worst-path labels to ≤2 segments (privacy)', () => {
    const s = summarizeBlast({
      ...result,
      reachable: [
        {
          full: '/Users/alice/Code/payments-prod/.env.production',
          label: '/Users/alice/Code/payments-prod/.env.production',
          description: 'Project secrets',
          score: 20,
        },
      ],
    });
    // Path is reduced — full home-dir layout NOT exfiltrated
    expect(s.worstPaths[0].path).toBe('payments-prod/.env.production');
    expect(JSON.stringify(s)).not.toContain('alice');
    expect(JSON.stringify(s)).not.toContain('/Users/');
  });

  it('caps the worstPaths list to topN (default 5)', () => {
    const many: BlastResult = {
      reachable: Array.from({ length: 20 }, (_, i) => ({
        full: `/p/finding-${i}`,
        label: `f${i}`,
        description: 'x',
        score: 10,
      })),
      envFindings: [],
      score: 0,
    };
    expect(summarizeBlast(many).worstPaths).toHaveLength(5);
  });

  it('respects a custom topN', () => {
    const many: BlastResult = {
      reachable: Array.from({ length: 20 }, (_, i) => ({
        full: `/p/finding-${i}`,
        label: `f${i}`,
        description: 'x',
        score: 10,
      })),
      envFindings: [],
      score: 0,
    };
    expect(summarizeBlast(many, { topN: 3 }).worstPaths).toHaveLength(3);
  });

  it('produces identical output for identical input (deterministic)', () => {
    expect(summarizeBlast(result)).toEqual(summarizeBlast(result));
  });

  it('tie-breaks equal scores alphabetically by label (stable order)', () => {
    // If the order varied across calls, the SaaS would see a "new"
    // snapshot every poll even when nothing changed.
    const tied: BlastResult = {
      reachable: [
        { full: '/x/zebra', label: 'zebra', description: '', score: 20 },
        { full: '/x/alpha', label: 'alpha', description: '', score: 20 },
        { full: '/x/mango', label: 'mango', description: '', score: 20 },
      ],
      envFindings: [],
      score: 40,
    };
    const labels = summarizeBlast(tied).worstPaths.map((p) => p.path);
    expect(labels).toEqual(['alpha', 'mango', 'zebra']);
  });

  it('returns 0 exposureCount for a clean machine', () => {
    expect(summarizeBlast({ reachable: [], envFindings: [], score: 100 }).exposureCount).toBe(0);
  });

  it('returns empty worstPaths when there are no reachable findings', () => {
    expect(summarizeBlast({ reachable: [], envFindings: [], score: 100 }).worstPaths).toEqual([]);
  });
});
