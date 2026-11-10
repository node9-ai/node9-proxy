// Usage past the monthly budget (node9Firewall#427): which calls the status
// judges, the status from an untrusted body, and the notice once per level.
import { describe, it, expect } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  budgetNoticeLine,
  claimBudgetNotice,
  judgeSpendBudget,
  providerOfAgent,
  sanitizeSpendBudget,
} from '../auth/spend-budget';

const NOW = Date.parse('2026-11-16T12:00:00Z');
const status = {
  month: '2026-11',
  level: 100 as const,
  limitUSD: 150,
  coveredProviders: [] as string[],
};

describe('judgeSpendBudget', () => {
  it('judges this month at 75% or more, unless the check is off', () => {
    expect(judgeSpendBudget(status, 'block', 'Codex', NOW)).toEqual(status);
    expect(judgeSpendBudget({ ...status, level: 75 }, 'log', 'Codex', NOW)?.level).toBe(75);
    expect(judgeSpendBudget({ ...status, level: 0 }, 'block', 'Codex', NOW)).toBeNull();
    expect(judgeSpendBudget(status, 'off', 'Codex', NOW)).toBeNull();
    expect(judgeSpendBudget(undefined, 'block', 'Codex', NOW)).toBeNull();
  });
  it('a status of another month is stale', () => {
    expect(judgeSpendBudget({ ...status, month: '2026-10' }, 'block', 'Codex', NOW)).toBeNull();
  });
  it('an agent whose provider a plan covers is not judged; an unknown agent is', () => {
    const covered = { ...status, coveredProviders: ['OPENAI'] };
    expect(judgeSpendBudget(covered, 'block', 'Codex', NOW)).toBeNull();
    expect(judgeSpendBudget(covered, 'block', 'Claude Code', NOW)).not.toBeNull();
    expect(judgeSpendBudget(covered, 'block', 'GitHub Copilot', NOW)).not.toBeNull();
  });
  it('maps both name styles to a provider', () => {
    expect(providerOfAgent('Claude Code')).toBe('ANTHROPIC');
    expect(providerOfAgent('claude')).toBe('ANTHROPIC');
    expect(providerOfAgent('codex')).toBe('OPENAI');
    expect(providerOfAgent('Gemini CLI')).toBe('GOOGLE');
    expect(providerOfAgent('Antigravity')).toBeNull();
  });
});

describe('sanitizeSpendBudget', () => {
  it('keeps a valid status and drops unknown providers', () => {
    expect(
      sanitizeSpendBudget({ ...status, coveredProviders: ['OPENAI', 'EVIL', 'OPENAI'] })
    ).toEqual({
      ...status,
      coveredProviders: ['OPENAI'],
    });
  });
  it('refuses a malformed month, level or limit', () => {
    expect(sanitizeSpendBudget({ ...status, month: '2026-13' })).toBeUndefined();
    expect(sanitizeSpendBudget({ ...status, level: 99 })).toBeUndefined();
    expect(sanitizeSpendBudget({ ...status, limitUSD: -1 })).toBeUndefined();
    expect(sanitizeSpendBudget([status])).toBeUndefined();
    expect(sanitizeSpendBudget(null)).toBeUndefined();
  });
});

describe('the notice', () => {
  it('is claimed once per session for each month and level', () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-budget-'));
    try {
      expect(claimBudgetNotice('s1', '2026-11:75', home)).toBe(true);
      expect(claimBudgetNotice('s1', '2026-11:75', home)).toBe(false);
      expect(claimBudgetNotice('s1', '2026-11:90', home)).toBe(true);
      expect(claimBudgetNotice('s2', '2026-11:90', home)).toBe(true);
      expect(claimBudgetNotice('', '2026-11:90', home)).toBe(false);
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
  it('names the budget and how much is used', () => {
    expect(budgetNoticeLine({ ...status, level: 90 })).toContain('90% of this month');
    expect(budgetNoticeLine(status)).toContain('$150.00');
  });
});
