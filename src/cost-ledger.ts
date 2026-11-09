// src/cost-ledger.ts
// The spend ledger behind behavior.cost-budget (node9Firewall#427). The
// daemon's cost sync writes it every ten minutes from the agents' session
// files it already parses; the hook reads it, no daemon call, and so does a
// forecast under a HOME that carries one. Today's sessions only: a budget is
// about a runaway now, not history. The figure is up to one sync behind, and
// the check's words say so.
import fs from 'fs';
import os from 'os';
import path from 'path';

export interface CostLedger {
  /** When the ledger was written (ISO). Older than LEDGER_STALE_MS: not trusted. */
  asOf: string;
  /** The day the figures cover (YYYY-MM-DD, local). */
  day: string;
  sessions: Record<string, { usd: number; tokens: number }>;
  /** Every session of the day together. */
  dayUSD: number;
}

export interface LedgerEntry {
  date: string;
  runId?: string;
  costUSD: number;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
}

export const LEDGER_STALE_MS = 60 * 60 * 1000;

export function costLedgerFile(home = os.homedir()): string {
  return path.join(home, '.node9', 'cost', 'sessions.json');
}

export function localDay(now = new Date()): string {
  const y = now.getFullYear();
  const m = String(now.getMonth() + 1).padStart(2, '0');
  const d = String(now.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

/** Today's entries summed per session; entries without a session id count
 *  toward the day only. */
export function buildCostLedger(entries: LedgerEntry[], now = new Date()): CostLedger {
  const day = localDay(now);
  const sessions: CostLedger['sessions'] = {};
  let dayUSD = 0;
  for (const e of entries) {
    if (e.date !== day) continue;
    dayUSD += e.costUSD;
    if (!e.runId) continue;
    const cur = (sessions[e.runId] ??= { usd: 0, tokens: 0 });
    cur.usd += e.costUSD;
    cur.tokens += e.inputTokens + e.outputTokens + e.cacheReadTokens + e.cacheWriteTokens;
  }
  return { asOf: now.toISOString(), day, sessions, dayUSD };
}

/** Atomic write: the hook may read while the daemon writes. */
export function writeCostLedger(ledger: CostLedger, home = os.homedir()): void {
  const file = costLedgerFile(home);
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(ledger), { mode: 0o600 });
  fs.renameSync(tmp, file);
}

export function readCostLedger(home = os.homedir()): CostLedger | null {
  try {
    const parsed: unknown = JSON.parse(fs.readFileSync(costLedgerFile(home), 'utf-8'));
    if (!parsed || typeof parsed !== 'object') return null;
    const l = parsed as Partial<CostLedger>;
    if (typeof l.asOf !== 'string' || typeof l.day !== 'string') return null;
    if (!l.sessions || typeof l.sessions !== 'object') return null;
    return {
      asOf: l.asOf,
      day: l.day,
      sessions: l.sessions as CostLedger['sessions'],
      dayUSD: typeof l.dayUSD === 'number' ? l.dayUSD : 0,
    };
  } catch {
    return null;
  }
}

export interface BudgetVerdict {
  over: 'session' | 'day';
  spent: number;
  ceiling: number;
}

/**
 * Whether the session or the day is past its ceiling. `unknown` when the
 * figure cannot be trusted: no ledger, a stale one, another day, or a
 * session the ledger has not seen while only a session ceiling is set. The
 * day's ceiling is judged whenever the day's figure is fresh.
 */
export function judgeBudget(
  ledger: CostLedger | null,
  sessionId: string,
  budget: { sessionUSD?: number; dayUSD?: number },
  now: number
): BudgetVerdict | null | 'unknown' {
  if (budget.sessionUSD === undefined && budget.dayUSD === undefined) return null;
  if (!ledger) return 'unknown';
  const age = now - Date.parse(ledger.asOf);
  if (!Number.isFinite(age) || age > LEDGER_STALE_MS || age < -LEDGER_STALE_MS) return 'unknown';
  if (ledger.day !== localDay(new Date(now))) return 'unknown';
  if (budget.dayUSD !== undefined && ledger.dayUSD >= budget.dayUSD)
    return { over: 'day', spent: ledger.dayUSD, ceiling: budget.dayUSD };
  if (budget.sessionUSD !== undefined) {
    const s = sessionId ? ledger.sessions[sessionId] : undefined;
    if (!s) return budget.dayUSD === undefined ? 'unknown' : null;
    if (s.usd >= budget.sessionUSD)
      return { over: 'session', spent: s.usd, ceiling: budget.sessionUSD };
  }
  return null;
}
