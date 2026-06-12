// Regression test: SQL-DDL detection must be AST-aware — a DB CLI has to be a
// REAL command (analyzeShellCommand actions), not text inside a quoted grep
// pattern. The default regex rule (review-drop-truncate-shell) false-positived
// on `grep -riE "sql|mysql|drop table"` because cond1 read the grep
// alternation's `|` as a shell pipe (`|mysql`) and cond2 matched "drop table"
// text. Verified from ~/.node9/hook-debug.log 2026-06-12.

import { describe, it, expect } from 'vitest';
import { analyzeSqlDestructive } from './index';

describe('analyzeSqlDestructive — DB CLI must be a real command', () => {
  it('fires on psql -c "DROP TABLE …"', () => {
    const v = analyzeSqlDestructive('psql -c "DROP TABLE users"');
    expect(v?.verdict).toBe('review');
    expect(v?.ruleName).toBe('review-drop-truncate-shell');
  });

  it('fires on mysql -e "TRUNCATE TABLE …"', () => {
    expect(analyzeSqlDestructive('mysql -e "TRUNCATE TABLE sessions"')?.verdict).toBe('review');
  });

  it('fires on a real pipe into a DB CLI (cat dump.sql | psql … with DDL)', () => {
    expect(analyzeSqlDestructive('echo "DROP TABLE x" | psql mydb')?.verdict).toBe('review');
  });

  // ── The reported false positives: grep/echo of keywords → null ──
  it('does NOT fire on grep searching for DB keywords (the reported FP)', () => {
    const fp =
      'grep -riE "sql|postgres|mysql|drop table|database protocol|wire protocol" --include=*.go .';
    expect(analyzeSqlDestructive(fp)).toBeNull();
  });

  it('does NOT fire on echo of a DROP TABLE string (no DB CLI command)', () => {
    expect(analyzeSqlDestructive('echo "remember to DROP TABLE later"')).toBeNull();
  });

  it('does NOT fire when there is no DROP/TRUNCATE at all', () => {
    expect(analyzeSqlDestructive('psql -c "SELECT 1"')).toBeNull();
  });
});
