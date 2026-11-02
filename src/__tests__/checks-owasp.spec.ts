// `node9 checks` carries the OWASP risk of every row, so `node9 owasp` and a
// reader of `--json` get the risk from the same place as the catalog. Runs
// the real merged config under a temp HOME, like catalog-coverage.spec.ts.
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { ASI, CHECKS, isAsiId } from '@node9/policy-engine';
import { getConfig, _resetConfigCache } from '../config';
import { buildChecksReport, renderCheckDetail } from '../cli/commands/checks';

let tmpHome: string;
let origHome: string | undefined;
let origUserprofile: string | undefined;

beforeAll(() => {
  tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-checks-owasp-'));
  origHome = process.env.HOME;
  origUserprofile = process.env.USERPROFILE;
  process.env.HOME = tmpHome;
  process.env.USERPROFILE = tmpHome;
  fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
  _resetConfigCache();
});

afterAll(() => {
  process.env.HOME = origHome;
  process.env.USERPROFILE = origUserprofile;
  _resetConfigCache();
  fs.rmSync(tmpHome, { recursive: true, force: true });
});

describe('node9 checks carries the OWASP risk', () => {
  it('every row of the report names the risk its catalog entry names', () => {
    const report = buildChecksReport(getConfig());
    expect(report.checks.length).toBe(CHECKS.length);
    for (const row of report.checks) {
      expect(isAsiId(row.owasp), row.id).toBe(true);
      expect(row.owasp, row.id).toBe(CHECKS.find((c) => c.id === row.id)!.owasp);
    }
  });

  it('the detail view prints the risk id and its name', () => {
    const report = buildChecksReport(getConfig());
    const text = renderCheckDetail(report, 'data.credential-files');
    expect(text).toContain('ASI03');
    expect(text).toContain(ASI.ASI03);
    expect(renderCheckDetail(report, 'commands.node9-disarm')).toContain('ASI10 Rogue Agents');
  });
});
