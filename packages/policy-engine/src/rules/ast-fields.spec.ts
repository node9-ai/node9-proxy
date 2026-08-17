// `ast.*` — smart-rule conditions reading AST-derived FACTS.
//
// This is what lets ONE implementation serve both worlds: the detector computes
// the fact, the rule asks about it. Before this, a protection needing structural
// analysis had to be written twice (a regex rule AND a code detector) and one of
// them silenced — the suppression layer that caused four rounds of regressions.
import { describe, it, expect } from 'vitest';
import { evaluateSmartConditions } from './index';
import type { SmartRule } from '../types';

const rule = (over: Partial<SmartRule>): SmartRule => ({
  tool: 'bash',
  verdict: 'review',
  conditions: [],
  ...over,
});

describe('ast.* condition fields', () => {
  it('matches on a structural fact a regex could not express', () => {
    const chmod = rule({
      conditions: [{ field: 'ast.chmodMode', op: 'exists' }],
    });
    // chmod really runs with a world-open MODE
    expect(evaluateSmartConditions({ command: 'chmod 777 /tmp/x' }, chmod)).toBe(true);
    // a SAFE mode on a path that merely contains "777" — the classic false
    // positive the raw-regex rule `chmod\s+(777|a\+rwx)` produces
    expect(evaluateSmartConditions({ command: 'chmod 644 ./777' }, chmod)).toBe(false);
    // "chmod 777" as a STRING inside code — no chmod runs
    expect(evaluateSmartConditions({ command: 'node -e "chmod 777 x"' }, chmod)).toBe(false);
  });

  it('supports regex operators over a fact value', () => {
    const ssh = rule({
      conditions: [{ field: 'ast.readsPaths', op: 'matches', value: '(^|/)\\.ssh/' }],
    });
    expect(evaluateSmartConditions({ command: 'cat ~/.ssh/id_rsa' }, ssh)).toBe(true);
    // the same text as an ARGUMENT to echo is not a read
    expect(evaluateSmartConditions({ command: 'echo "cat ~/.ssh/id_rsa"' }, ssh)).toBe(false);
  });

  it('supports the uncertainty net (yes|uncertain) that closes misparse bypasses', () => {
    const inline = rule({
      conditions: [{ field: 'ast.inlineExec', op: 'matches', value: '^(yes|uncertain)$' }],
    });
    expect(evaluateSmartConditions({ command: 'python3 -c "print(1)"' }, inline)).toBe(true);
    expect(evaluateSmartConditions({ command: 'perl -we "system(1)"' }, inline)).toBe(true);
    expect(evaluateSmartConditions({ command: 'bash -m -c "whoami"' }, inline)).toBe(true);
    // ordinary script runs must NOT match
    expect(evaluateSmartConditions({ command: 'python3 manage.py runserver' }, inline)).toBe(false);
    expect(evaluateSmartConditions({ command: 'perl -MData::Dumper script.pl' }, inline)).toBe(
      false
    );
  });

  it('conditionMode:"all" ANDs an ast fact with a raw field', () => {
    const r = rule({
      conditionMode: 'all',
      conditions: [
        { field: 'ast.chmodMode', op: 'exists' },
        { field: 'command', op: 'matches', value: '/srv' },
      ],
    });
    expect(evaluateSmartConditions({ command: 'chmod 777 /srv/app' }, r)).toBe(true);
    expect(evaluateSmartConditions({ command: 'chmod 777 /tmp/app' }, r)).toBe(false);
  });

  // Fail-closed: an ast.* condition must never make a rule match by accident on
  // a tool that carries no shell command.
  it('fails closed when the tool has no string command', () => {
    const r = rule({ conditions: [{ field: 'ast.inlineExec', op: 'exists' }] });
    expect(evaluateSmartConditions({ file_path: '/tmp/x' }, r)).toBe(false);
    expect(evaluateSmartConditions({ command: 123 }, r)).toBe(false);
    expect(evaluateSmartConditions({}, r)).toBe(false);
    expect(evaluateSmartConditions(null, r)).toBe(false);
  });

  it('an unknown ast.* key resolves to null rather than throwing', () => {
    const r = rule({ conditions: [{ field: 'ast.notARealFact', op: 'exists' }] });
    expect(evaluateSmartConditions({ command: 'ls' }, r)).toBe(false);
  });

  it('leaves non-ast fields untouched', () => {
    const r = rule({ conditions: [{ field: 'command', op: 'matches', value: '^ls' }] });
    expect(evaluateSmartConditions({ command: 'ls -la' }, r)).toBe(true);
  });
});
