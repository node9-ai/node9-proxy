// Phase 2b of the report-correctness verification roadmap
// (doc/roadmap/report-correctness-verification.md).
//
// Tripwire: the historical Report view in `node9 monitor` and the
// `node9 report` CLI must share the same audit aggregator. Today both
// import aggregateReportFromAudit from cli/aggregate/report-audit.ts.
// If a refactor introduces a parallel aggregator in monitor's data
// layer (`src/tui/dashboard/data.ts`), the two surfaces will silently
// diverge — same audit.log, different numbers.
//
// This test is a static check on the data module's source. It fires if
// the canonical import disappears OR if a similarly-named local function
// is introduced that could shadow it. Cheaper than behavioral equivalence
// testing, and the failure points squarely at the right file.

import { describe, expect, it } from 'vitest';
import fs from 'fs';
import path from 'path';

const DASHBOARD_DATA_PATH = path.join(__dirname, '..', 'tui', 'dashboard', 'data.ts');

describe('monitor/report aggregator sharing', () => {
  it('dashboard/data.ts imports the canonical aggregateReportFromAudit', () => {
    const source = fs.readFileSync(DASHBOARD_DATA_PATH, 'utf-8');
    expect(source).toMatch(
      /aggregateReportFromAudit[\s\S]*?from\s+['"]\.\.\/\.\.\/cli\/aggregate\/report-audit/
    );
  });

  it('dashboard/data.ts does not declare a parallel aggregator with a shadowing name', () => {
    const source = fs.readFileSync(DASHBOARD_DATA_PATH, 'utf-8');
    // A local `function aggregateReport...` or `const aggregateReport... =`
    // would silently shadow the import for callers in the same module.
    expect(source).not.toMatch(/function\s+aggregateReport[A-Za-z]*\b/);
    expect(source).not.toMatch(/\bconst\s+aggregateReport[A-Za-z]*\s*=/);
  });
});
