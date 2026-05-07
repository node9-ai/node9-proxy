/**
 * Symmetric staleness test for printFindingRow.
 *
 * The DLP credential-leak section dims findings older than STALE_AGE_DAYS
 * (30) so a wall of recent + ancient hits has clear visual hierarchy.
 * This test pins the same behavior on the row used for blocked / review
 * findings — i.e. agent badge and command preview both render dimmed
 * when the finding is stale, and keep their accent color when recent.
 *
 * We assert on raw ANSI escape sequences (`\x1b[36m` cyan, `\x1b[2m` dim)
 * because that's what the behavioral claim is about. A snapshot of the
 * stripped string would erase exactly the difference under test.
 */
import { describe, it, expect, vi, beforeEach, afterEach, beforeAll, afterAll } from 'vitest';
import chalk from 'chalk';
import { printFindingRow } from '../cli/commands/scan';
import type { FindingRef } from '../scan-summary';

const ESC_DIM = '\x1b[2m';
const ESC_CYAN = '\x1b[36m';
const ESC_GRAY = '\x1b[90m';

// Vitest disables color by default; force level 1 so we can assert on
// the ANSI escapes that encode the behavior under test.
let savedChalkLevel: typeof chalk.level;
beforeAll(() => {
  savedChalkLevel = chalk.level;
  chalk.level = 1;
});
afterAll(() => {
  chalk.level = savedChalkLevel;
});

let captured: string;
let logSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  captured = '';
  logSpy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
    captured += args.map((a) => (typeof a === 'string' ? a : String(a))).join(' ') + '\n';
  });
});

afterEach(() => {
  logSpy.mockRestore();
});

function finding(
  timestampISO: string,
  agent: 'claude' | 'gemini' | 'codex' = 'claude'
): FindingRef {
  return {
    timestamp: timestampISO,
    command: 'git push --force origin main',
    fullCommand: 'git push --force origin main',
    project: '~/repo',
    sessionId: 'sess123',
    agent,
    toolName: 'Bash',
  };
}

describe('printFindingRow staleness', () => {
  it('recent Claude finding renders agent badge in cyan and command in gray', () => {
    // 5 days ago — well within the 30-day window.
    const recent = new Date(Date.now() - 5 * 86_400_000).toISOString();
    printFindingRow(finding(recent), false, false, 70);
    expect(captured).toContain(ESC_CYAN);
    expect(captured).toContain(ESC_GRAY);
  });

  it('stale Claude finding renders without cyan or gray accents (dim instead)', () => {
    // 60 days ago — well past STALE_AGE_DAYS = 30.
    const stale = new Date(Date.now() - 60 * 86_400_000).toISOString();
    printFindingRow(finding(stale), false, false, 70);
    expect(captured).not.toContain(ESC_CYAN);
    expect(captured).not.toContain(ESC_GRAY);
    expect(captured).toContain(ESC_DIM);
  });

  it('finding right at the boundary (30 days + 1) is stale', () => {
    const just_stale = new Date(Date.now() - (30 * 86_400_000 + 1000)).toISOString();
    printFindingRow(finding(just_stale), false, false, 70);
    expect(captured).not.toContain(ESC_CYAN);
  });

  it('finding right inside the boundary (29 days) is recent', () => {
    const just_recent = new Date(Date.now() - 29 * 86_400_000).toISOString();
    printFindingRow(finding(just_recent), false, false, 70);
    expect(captured).toContain(ESC_CYAN);
  });
});
