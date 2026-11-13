// The forecast context: the live gate run without consequences.
//
// `forecastDecision` (forecast.ts) executes `_authorizeHeadlessCore` inside
// this context. Every module that would otherwise write a file, open a socket,
// call the daemon or the cloud consults `forecastRun()` first and routes into
// memory instead: audit rows go to the recorder, daemon queries are answered
// from the replayed session state, loop state lives in the state object. The
// core itself needs only a handful of edits (see
// docs/roadmap/active/scan-forecast-gate-code-design.md, section 3.3).
//
// AsyncLocalStorage, not a parameter: the side effects sit in callees two and
// three levels below the core (audit, daemon client, loop detector, exposure
// marker, pause and trust state), and threading a flag through every one of
// them would touch far more code than the behaviour deserves.

import { AsyncLocalStorage } from 'async_hooks';
import type { Config } from '../config';
import type { ForecastSessionState } from './forecast-state';

/** One audit row the live hook would have written. */
export interface ForecastRow {
  decision: 'allow' | 'deny';
  /** The audit tag (`dlp-block`, `smart-rule-block`, `local-policy`, ...). */
  checkedBy: string;
  ruleName?: string;
  checkId?: string;
  dlpPattern?: string;
  dlpSample?: string;
  piiPatterns?: string;
  canaryId?: string;
  canaryKind?: string;
  canaryPath?: string;
  canaryView?: string;
  loopCount?: number;
  exposure?: { kind: 'source' | 'logged'; destinations: number };
  /** The engine's `log` verdict: an allow that records the check. */
  logged?: boolean;
}

export interface ForecastRun {
  /** Rows in the order the gate produced them. */
  rows: ForecastRow[];
  /** Replayed session state; answers every daemon query. */
  session: ForecastSessionState;
  /** The configuration to judge under; `getConfig(cwd)` when absent. */
  config?: Config;
  /** Inputs the forecast could not reproduce (`package-registry`, ...). */
  unknown: Set<string>;
  /** The clock of the call being judged (a historical timestamp), for loop
   *  windows and taint expiry. Defaults to the wall clock. */
  now: number;
  /** The package check may query the advisory service and the registries, as
   *  the live hook does. Off for `scan` (a forecast over history stays on the
   *  machine); on for the server's benchmark replay (`forecast-cases
   *  --online-packages`), whose package cases need the lookup to agree with
   *  the hook. */
  onlinePackages?: boolean;
  /** The call is replayed from the start of its session: nothing was spent,
   *  so the cost ceiling judges nothing and the cost state is known (the
   *  benchmark replay, `forecast-cases`). Absent, the gate reads the machine's
   *  ledger and notes `cost-state` unknown when it has no fresh one. */
  freshSpend?: boolean;
}

const als = new AsyncLocalStorage<ForecastRun>();

/** The active forecast run, or undefined on the live path. */
export function forecastRun(): ForecastRun | undefined {
  return als.getStore();
}

export function runForecast<T>(run: ForecastRun, fn: () => Promise<T>): Promise<T> {
  return als.run(run, fn);
}

/** Record an input the forecast could not reproduce. No-op on the live path. */
export function noteForecastUnknown(what: string): void {
  forecastRun()?.unknown.add(what);
}
