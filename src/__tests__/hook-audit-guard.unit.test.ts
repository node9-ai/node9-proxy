// Phase 3a of the report-correctness verification roadmap
// (doc/roadmap/report-correctness-verification.md).
//
// Floor-count tripwire on the audit-guard catch blocks in hook code paths.
//
// CLAUDE.md rule: "Always write to hook-debug.log in catch blocks that guard
// audit trail. Silent failures in the log command create audit gaps."
//
// A truly semantic check ("every catch surrounding appendLocalAudit must write
// to hook-debug.log") requires source-level structural analysis. As a
// pragmatic MVP, we floor the count of `hook-debug.log` references in each
// hook code file. Removing a guard reduces the count and fails this test —
// the contributor has to bump the floor deliberately, which forces a code
// review that catches the regression.
//
// The floors were measured 2026-06-01. Bumping them up when adding new
// guards is welcome; lowering them requires justification.

import { describe, expect, it } from 'vitest';
import fs from 'fs';
import path from 'path';

const CHECK_TS = path.join(__dirname, '..', 'cli', 'commands', 'check.ts');
const LOG_TS = path.join(__dirname, '..', 'cli', 'commands', 'log.ts');

// Measured 2026-06-01 — see git blame on this constant when bumping.
const CHECK_TS_HOOK_DEBUG_FLOOR = 5;
const LOG_TS_HOOK_DEBUG_FLOOR = 1;

function countHookDebugReferences(filePath: string): number {
  const src = fs.readFileSync(filePath, 'utf-8');
  return (src.match(/hook-debug\.log/g) ?? []).length;
}

describe('hook code paths preserve audit-guard catches', () => {
  it(`check.ts retains ≥${CHECK_TS_HOOK_DEBUG_FLOOR} hook-debug.log audit guards`, () => {
    expect(countHookDebugReferences(CHECK_TS)).toBeGreaterThanOrEqual(CHECK_TS_HOOK_DEBUG_FLOOR);
  });

  it(`log.ts retains ≥${LOG_TS_HOOK_DEBUG_FLOOR} hook-debug.log audit guard`, () => {
    expect(countHookDebugReferences(LOG_TS)).toBeGreaterThanOrEqual(LOG_TS_HOOK_DEBUG_FLOOR);
  });

  it('check.ts has at least one catch block writing to hook-debug.log', () => {
    const src = fs.readFileSync(CHECK_TS, 'utf-8');
    // The audit-guard pattern: a `catch (err...)` block followed within ~500
    // characters by a hook-debug.log write. This proves at least one error
    // path on this file's surface logs to hook-debug.log.
    expect(src).toMatch(/catch\s*\([^)]*err[^)]*\)[\s\S]{0,500}hook-debug\.log/);
  });

  it('log.ts has at least one catch block writing to hook-debug.log', () => {
    const src = fs.readFileSync(LOG_TS, 'utf-8');
    expect(src).toMatch(/catch\s*\([^)]*err[^)]*\)[\s\S]{0,500}hook-debug\.log/);
  });
});
