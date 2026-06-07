// Golden-event corpus for `node9 scan` — Phase 1b of the report-correctness
// verification roadmap (doc/roadmap/report-correctness-verification.md).
//
// Each fixture under fixtures/golden-sessions/ pairs a JSONL session file with
// a sidecar .expected.json declaring the counts scan should produce. Adding a
// new fixture is two files; the test runner iterates the directory and asserts
// per-fixture in isolation so a failure points at the specific session.
//
// Isolation strategy: vi.spyOn(os, 'homedir') redirects to a temp dir per
// fixture, into which the JSONL is copied at the path Claude Code uses
// (`~/.claude/projects/<projDir>/<sessionId>.jsonl`). scanClaudeHistory then
// walks that temp tree and sees only the fixture under test — no contamination
// from the developer's real Claude history.
//
// Credential-shape values in fixtures are stored as placeholders
// (`__AWS_ACCESS_KEY__`, etc.) and assembled from split string parts at test
// time before being written into the temp tree. This keeps any contiguous
// matching-shape literal out of the committed repo — so external DLP scanners,
// node9 scan run over the checkout, and casual code review readers never see
// what looks like a real key. The assembled values still exercise the real
// DLP regex paths in scanClaudeHistory.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { scanClaudeHistory } from '../cli/commands/scan';

// Synthetic credential-shape values assembled at test time. Keep each value
// expressed as concatenation of small parts so no contiguous matching-shape
// substring exists in this file either. Adding a new placeholder:
//   1. Pick a marker like `__VENDOR_KEY__`.
//   2. Add its assembled value here.
//   3. Reference the marker in the fixture .jsonl.
const FIXTURE_PLACEHOLDERS: Record<string, string> = {
  // AWS Access Key ID — synthetic, no stopwords, matches the AWS DLP regex.
  __AWS_ACCESS_KEY__: 'AKIA' + 'QX7Z3BHDM7NPLKV5',
};

function expandFixturePlaceholders(text: string): string {
  let result = text;
  for (const [marker, value] of Object.entries(FIXTURE_PLACEHOLDERS)) {
    result = result.split(marker).join(value);
  }
  return result;
}

interface ExpectedDlpFinding {
  patternName: string;
  toolName: string;
}

interface Expected {
  description?: string;
  filesScanned: number;
  sessions: number;
  totalToolCalls: number;
  bashCalls: number;
  dlpFindingsCount: number;
  loopFindingsCount: number;
  dlpFindings?: ExpectedDlpFinding[];
}

const FIXTURES_DIR = path.join(__dirname, 'fixtures', 'golden-sessions');

function listFixtures(): string[] {
  return fs
    .readdirSync(FIXTURES_DIR)
    .filter((f) => f.endsWith('.jsonl'))
    .sort();
}

describe('node9 scan — golden corpus', () => {
  let tmpHome: string;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-golden-'));
    vi.spyOn(os, 'homedir').mockReturnValue(tmpHome);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  const fixtures = listFixtures();
  expect(fixtures.length).toBeGreaterThan(0);

  for (const fixture of fixtures) {
    const sessionId = fixture.replace(/\.jsonl$/, '');
    const expectedPath = path.join(FIXTURES_DIR, `${sessionId}.expected.json`);
    const expected: Expected = JSON.parse(fs.readFileSync(expectedPath, 'utf-8'));

    it(`${sessionId}: ${expected.description ?? ''}`.trim(), () => {
      const projectsDir = path.join(tmpHome, '.claude', 'projects', '-tmp-test');
      fs.mkdirSync(projectsDir, { recursive: true });
      const raw = fs.readFileSync(path.join(FIXTURES_DIR, fixture), 'utf-8');
      fs.writeFileSync(
        path.join(projectsDir, `${sessionId}.jsonl`),
        expandFixturePlaceholders(raw)
      );

      const result = scanClaudeHistory(null);

      expect(result.filesScanned).toBe(expected.filesScanned);
      expect(result.sessions).toBe(expected.sessions);
      expect(result.totalToolCalls).toBe(expected.totalToolCalls);
      expect(result.bashCalls).toBe(expected.bashCalls);
      expect(result.dlpFindings.length).toBe(expected.dlpFindingsCount);
      expect(result.loopFindings.length).toBe(expected.loopFindingsCount);

      if (expected.dlpFindings) {
        for (const exp of expected.dlpFindings) {
          const match = result.dlpFindings.find(
            (f) => f.patternName === exp.patternName && f.toolName === exp.toolName
          );
          expect(
            match,
            `expected DLP finding ${exp.patternName} on ${exp.toolName} not found in ${JSON.stringify(
              result.dlpFindings.map((f) => ({ patternName: f.patternName, toolName: f.toolName }))
            )}`
          ).toBeTruthy();
        }
      }
    });
  }
});
