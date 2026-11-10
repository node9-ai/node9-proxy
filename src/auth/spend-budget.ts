// Usage past the monthly budget (node9Firewall#427). The server computes a
// person's month (usage no plan covers, against their budget) and sends the
// status in the managed config; this module decides whether a call is judged
// and keeps the user's notice to once per session and level.
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { Verdict } from '@node9/policy-engine';
import { atomicWriteSync } from '../utils/atomic-write';

export type SpendLevel = 0 | 75 | 90 | 100;

/** The managed status, as the sync body carries it. */
export interface SpendBudgetStatus {
  /** YYYY-MM, UTC. */
  month: string;
  level: SpendLevel;
  limitUSD: number;
  /** Providers the person's plans cover today: their agents add no usage
   *  beyond plans, so they are never stopped by the budget. */
  coveredProviders: string[];
}

const MONTH = /^\d{4}-(0[1-9]|1[0-2])$/;
const PROVIDERS = new Set(['ANTHROPIC', 'OPENAI', 'GOOGLE', 'OTHER']);

/** The status from an untrusted body or cache file, or undefined. */
export function sanitizeSpendBudget(raw: unknown): SpendBudgetStatus | undefined {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined;
  const r = raw as Record<string, unknown>;
  if (typeof r.month !== 'string' || !MONTH.test(r.month)) return undefined;
  if (r.level !== 0 && r.level !== 75 && r.level !== 90 && r.level !== 100) return undefined;
  if (typeof r.limitUSD !== 'number' || !Number.isFinite(r.limitUSD) || r.limitUSD < 0)
    return undefined;
  const covered = Array.isArray(r.coveredProviders)
    ? r.coveredProviders.filter((p): p is string => typeof p === 'string' && PROVIDERS.has(p))
    : [];
  return {
    month: r.month,
    level: r.level,
    limitUSD: Math.min(r.limitUSD, 1_000_000),
    coveredProviders: [...new Set(covered)],
  };
}

/** The provider an agent bills: the hook's names ("Claude Code", "Codex",
 *  "Gemini CLI") and the scan's short ones ("claude", "codex", "gemini"). */
export function providerOfAgent(agent: string | undefined): string | null {
  const a = (agent ?? '').toLowerCase();
  if (a === 'claude' || a === 'claude code') return 'ANTHROPIC';
  if (a === 'codex') return 'OPENAI';
  if (a === 'gemini' || a === 'gemini cli') return 'GOOGLE';
  return null;
}

/**
 * The status that applies to this call, or null: the check is on, the
 * status is this month's, it is at 75% or more, and the agent's provider is
 * not covered by a plan. A status of another month is stale (a new month
 * starts clean even before the device syncs).
 */
export function judgeSpendBudget(
  status: SpendBudgetStatus | undefined,
  value: Verdict | undefined,
  agent: string | undefined,
  now: number
): SpendBudgetStatus | null {
  if (!status || !value || value === 'off') return null;
  if (status.level < 75) return null;
  if (status.month !== new Date(now).toISOString().slice(0, 7)) return null;
  const provider = providerOfAgent(agent);
  if (provider && status.coveredProviders.includes(provider)) return null;
  return status;
}

/** The user's line for a status. */
export function budgetNoticeLine(status: SpendBudgetStatus): string {
  const limit = `$${status.limitUSD.toFixed(2)}`;
  return status.level === 100
    ? `💸 Node9: this month's budget of ${limit} for usage beyond plans is used up.`
    : `💸 Node9: ${status.level}% of this month's budget of ${limit} for usage beyond plans is used.`;
}

function noticeFile(sessionId: string, home: string): string {
  const id = crypto.createHash('sha256').update(sessionId).digest('hex').slice(0, 32);
  return path.join(home, '.node9', 'budget-notices', id);
}

/**
 * True once per session for each `key` (month and level): the flag file
 * holds the last key told. Best effort; a failure tells nothing.
 */
export function claimBudgetNotice(sessionId: string, key: string, home = os.homedir()): boolean {
  if (!sessionId) return false;
  const file = noticeFile(sessionId, home);
  try {
    if (fs.readFileSync(file, 'utf8') === key) return false;
  } catch {
    /* no flag yet */
  }
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    atomicWriteSync(file, key, { mode: 0o600 });
    return true;
  } catch {
    return false;
  }
}
