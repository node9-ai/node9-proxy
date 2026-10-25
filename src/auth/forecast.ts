// The forecast entry: what the live gate would decide for a tool call, with no
// consequences. `node9 scan` judges every historical call through it, so the
// scan and the hook give one answer (fw#399, Part A of #320).
//
// The core (`_authorizeHeadlessCore`) runs unchanged inside the forecast
// context (forecast-context.ts): audit rows land in memory, daemon queries are
// answered from the replayed session state, nothing reaches a socket, a file,
// a popup or the cloud. The verdict reports what the gate decides at the
// caller's settings and says separately whether that decision is enforced:
// observe mode and a check set to `log` record and let the call through.

import { checkIdForRule, isRecordOnly, type Verdict } from '@node9/policy-engine';
import type { Config } from '../config';
import { getConfig } from '../config';
import { _authorizeHeadlessCore, type AuthResult } from './orchestrator';
import { runForecast, type ForecastRow, type ForecastRun } from './forecast-context';
import { ForecastSessionState } from './forecast-state';

export type ForecastDecision = 'allow' | 'log' | 'review' | 'block';

export type ForecastLayer =
  | 'file-protection'
  | 'taint-egress'
  | 'session-taint'
  | 'exposure'
  | 'canary'
  | 'ssrf'
  | 'dlp'
  | 'pii'
  | 'package'
  | 'app-permission'
  | 'loop'
  | 'policy'
  | 'persistent'
  | 'ignored'
  | 'none';

export interface ForecastVerdict {
  /** The gate's decision at the caller's settings, before any human. */
  decision: ForecastDecision;
  /** False when nothing stops the call: `allow`, `log`, or observe mode. */
  enforced: boolean;
  /** Why a review or block is not enforced: `settings.mode=observe`, or
   *  `checks.<id>=log` for a logged finding. */
  notEnforcedBecause?: string;
  checkId?: string;
  ruleName?: string;
  layer: ForecastLayer;
  label?: string;
  reason?: string;
  /** `settings.mode` the call was judged under. */
  mode: string;
  policySource: 'local' | 'workspace';
  /** The audit rows the live hook would have written, in order. */
  rows: ForecastRow[];
  /** Inputs the forecast could not reproduce; a verdict with entries here is
   *  still a verdict, with a caveat. */
  unknown: string[];
}

export interface ForecastMeta {
  agent?: string;
  mcpServer?: string;
  serverKey?: string;
  sessionId?: string;
  transcriptPath?: string;
}

export interface ForecastOptions {
  cwd?: string;
  /** The configuration to judge under; `getConfig(cwd)` when absent. A
   *  caller that judges many calls resolves it once per project. */
  config?: Config;
  /** Replayed session state. Absent: an empty state that reports
   *  `session-state` as unknown on the layers that need one. */
  session?: ForecastSessionState;
  /** The call's own clock (a historical timestamp). Default: now. */
  at?: number;
  sessionTaintGated?: boolean;
}

/** Audit tag → the layer that produced it. Tags are matched by prefix after
 *  the `observe-mode-` prefix and `-would-block` suffix are stripped. */
const LAYER_BY_TAG: ReadonlyArray<readonly [string, ForecastLayer]> = [
  ['file-protection', 'file-protection'],
  ['taint-egress', 'taint-egress'],
  ['dlp-canary', 'canary'],
  ['ssrf-destination', 'ssrf'],
  ['dlp', 'dlp'],
  ['pii', 'pii'],
  ['package', 'package'],
  ['app-permission', 'app-permission'],
  ['loop-detected', 'loop'],
  ['smart-rule', 'policy'],
  ['local-policy', 'policy'],
  ['persistent', 'persistent'],
  ['ignored', 'ignored'],
  ['trust', 'persistent'],
];

function layerOfTag(tag: string): ForecastLayer {
  const t = tag.replace(/^observe-mode-/, '').replace(/-would-block$/, '');
  for (const [prefix, layer] of LAYER_BY_TAG) if (t.startsWith(prefix)) return layer;
  return 'none';
}

/** Tags of an allow row that still records a finding (a check in `log`). */
const LOGGED_TAGS = new Set([
  'file-protection-log',
  'dlp-review-flagged',
  'package-review-flagged',
  'exposure-logged',
]);

function loggedRow(row: ForecastRow): boolean {
  if (row.decision !== 'allow') return false;
  if (LOGGED_TAGS.has(row.checkedBy)) return true;
  // The engine's `log` verdict lands as a `local-policy` allow that names the
  // rule; a plain allow names none.
  return row.checkedBy === 'local-policy' && !!row.ruleName;
}

/** The layer behind a soft review the core expresses only through its label. */
function layerOfReview(result: AuthResult, rows: ForecastRow[]): ForecastLayer {
  const label = `${result.blockedByLabel ?? ''} ${result.reason ?? ''}`;
  if (/taint service|was flagged by|flagged this session/i.test(label)) return 'session-taint';
  if (/outside content|exposure|after reading/i.test(label)) return 'exposure';
  if (/package check/i.test(label)) return 'package';
  if (/DLP/i.test(label)) return 'dlp';
  if (/file|path/i.test(label) && rows.some((r) => r.checkedBy.startsWith('file-protection')))
    return 'file-protection';
  if (/app permission/i.test(label)) return 'app-permission';
  return 'policy';
}

function modeOfCheck(config: Config, checkId: string | undefined): Verdict | undefined {
  if (!checkId) return undefined;
  return config.policy.checks?.[checkId];
}

export async function forecastDecision(
  toolName: string,
  args: unknown,
  meta?: ForecastMeta,
  opts: ForecastOptions = {}
): Promise<ForecastVerdict> {
  const config = opts.config ?? getConfig(opts.cwd);
  const session = opts.session ?? new ForecastSessionState(meta?.sessionId ?? '', { blind: true });
  const run: ForecastRun = {
    rows: [],
    session,
    config,
    unknown: new Set(),
    now: opts.at ?? Date.now(),
  };
  const result = await runForecast(run, () =>
    _authorizeHeadlessCore(toolName, args, meta, {
      cwd: opts.cwd,
      deferReview: true,
      ...(opts.sessionTaintGated !== undefined && { sessionTaintGated: opts.sessionTaintGated }),
    })
  );
  return toVerdict(toolName, result, run, config, session);
}

function toVerdict(
  toolName: string,
  result: AuthResult,
  run: ForecastRun,
  config: Config,
  session: ForecastSessionState
): ForecastVerdict {
  const rows = run.rows;
  const mode = config.settings.mode ?? 'standard';
  const recordOnly = isRecordOnly(mode);
  const denyRow = [...rows].reverse().find((r) => r.decision === 'deny');
  const logRow = rows.find(loggedRow);

  let decision: ForecastDecision;
  let layer: ForecastLayer;
  if (!result.approved && result.review) {
    decision = 'review';
    layer = denyRow ? layerOfTag(denyRow.checkedBy) : layerOfReview(result, rows);
  } else if (!result.approved) {
    decision = 'block';
    layer = denyRow ? layerOfTag(denyRow.checkedBy) : 'policy';
  } else if (logRow) {
    decision = 'log';
    layer = layerOfTag(logRow.checkedBy);
  } else {
    decision = 'allow';
    layer = 'none';
  }

  const decidingRow = decision === 'log' ? logRow : denyRow;
  const ruleName = result.ruleHit ?? decidingRow?.ruleName;
  const checkId = result.checkId ?? checkIdForRule(ruleName) ?? decidingRow?.checkId;

  const stops = decision === 'review' || decision === 'block';
  const enforced = stops && !recordOnly;
  let notEnforcedBecause: string | undefined;
  if (stops && recordOnly) notEnforcedBecause = `settings.mode=${mode}`;
  else if (decision === 'log') {
    const value = modeOfCheck(config, checkId);
    notEnforcedBecause = checkId
      ? `checks.${checkId}=${value ?? 'log'}`
      : `rule ${ruleName ?? 'unnamed'} records only`;
  }

  // State-dependent layers judged with a state nobody could feed: say so on
  // the calls they apply to (network, write, MCP), never on a plain read.
  if (session.blind && /^mcp__|^bash$|^write|^edit|^notebook/i.test(toolName))
    run.unknown.add('session-state');

  return {
    decision,
    enforced,
    ...(notEnforcedBecause && { notEnforcedBecause }),
    ...(checkId && { checkId }),
    ...(ruleName && { ruleName }),
    layer,
    ...(result.blockedByLabel && { label: result.blockedByLabel }),
    ...(result.reason && { reason: result.reason }),
    mode,
    policySource: config.policySource,
    rows,
    unknown: [...run.unknown].sort(),
  };
}
