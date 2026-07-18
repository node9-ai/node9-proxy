/**
 * The ONE place that turns a raw audit row into a human-readable outcome.
 *
 * WHY THIS EXISTS
 *
 * The audit log carries six spellings of three outcomes, written by seven
 * producers: the gate writes `allow`/`deny`, the PostToolUse hook writes
 * `allowed`, the daemon writes `auto-deny` and `mcp-discovered`, the DLP
 * scanner writes `dlp`, and two call sites write `block`. Every reader used to
 * hand-roll its own rule for collapsing that, and they disagreed:
 *
 *   • the MCP audit tool rendered everything that wasn't literally `block` or
 *     `review` as `[allow]` — so all 12,176 `deny` rows reported as ALLOWED
 *   • `node9 audit` used `startsWith('allow')`, correct for the main cases but
 *     showing `dlp` and `mcp-discovered` (findings, not verdicts) as DENY
 *   • `node9 sessions` had a third copy
 *
 * Two readers failing in OPPOSITE directions on the same file is what this
 * module removes. Vocabulary matches the dashboard's RequestStatus labels so
 * the CLI, the MCP tools and the web UI describe an event the same way.
 *
 * TWO RULES THAT MUST NOT BE RELAXED
 *
 * 1. An unrecognised decision NEVER classifies as `allow`. That is exactly the
 *    bug this replaces — a fall-through `else` that reported anything unknown
 *    as permitted. Reporting fails loud: unknown surfaces as `unknown` with the
 *    raw value preserved, so a new producer inventing an eighth spelling shows
 *    up in a test rather than silently as an allow in production.
 * 2. "Timed out" is not "Denied". 3,643 rows in one real log are refusals
 *    because nobody answered, not because a human refused. Those demand very
 *    different responses, and merging them hides approval fatigue.
 */

/** Coarse bucket — filtering and counting. `label` is presentation. */
export type AuditOutcome = 'allow' | 'deny' | 'observe' | 'info' | 'unknown';

export interface DecisionView {
  outcome: AuditOutcome;
  /** Dashboard vocabulary: Auto-allowed · Approved · Blocked · Denied · … */
  label: string;
  /** Exactly what the row stored, so nothing is hidden by the mapping. */
  raw: string;
}

/** checkedBy values meaning a HUMAN made the call (vs a rule firing). */
const HUMAN_SOURCES = new Set(['daemon', 'cloud', 'local-decision', 'inline-review-approved']);

const TIMEOUT_SOURCES = new Set(['timeout']);

const has = (s: string, needle: string) => s.includes(needle);

/** The subset of an audit row this needs. Anything row-shaped satisfies it. */
export interface AuditRowLike {
  decision?: unknown;
  checkedBy?: unknown;
  /** The gate writes `checkedBy`; the PostToolUse hook writes `source`. */
  source?: unknown;
}

/**
 * Classify one audit row. PASS THE ROW.
 *
 * The attribution field is NOT uniform: the gate writes `checkedBy`, while the
 * PostToolUse hook and the daemon write `source`. In one real log that is
 * 37,576 rows with `source` and no `checkedBy`.
 *
 * An earlier signature took `(decision, checkedBy)` and left each caller to
 * decide where the second argument came from — five callers made three
 * different choices, so a human approving an action displayed as "Auto-allowed"
 * and a human REFUSING one displayed as "Blocked". That is the same
 * reader-drift this module exists to prevent, just moved one level up into the
 * call sites. Taking the row removes the choice.
 *
 * The two-argument form is kept for callers that genuinely hold only the pair
 * (and for tests), but prefer the row form.
 */
export function classifyDecision(row: AuditRowLike): DecisionView;
export function classifyDecision(decision: unknown, checkedBy?: unknown): DecisionView;
export function classifyDecision(a: unknown, b?: unknown): DecisionView {
  // A row-shaped first argument carries its own attribution field; anything
  // else is the legacy (decision, checkedBy) pair.
  const isRow =
    !!a && typeof a === 'object' && ('decision' in a || 'checkedBy' in a || 'source' in a);
  const decision = isRow ? (a as AuditRowLike).decision : a;
  const attribution = isRow ? ((a as AuditRowLike).checkedBy ?? (a as AuditRowLike).source) : b;

  const raw = typeof decision === 'string' ? decision : String(decision ?? '');
  const src = typeof attribution === 'string' ? attribution.toLowerCase() : '';
  const d = raw.toLowerCase();

  // Shadow mode first: the row's own decision is unreliable here (one observe
  // path writes `allow`, another writes `deny` for the same concept), and
  // either way the action was NOT stopped — but node9 would have stopped it.
  // Counting these as plain allows is what makes shadow mode invisible.
  if (src && has(src, 'observe-mode')) {
    return { outcome: 'observe', label: 'Would block', raw };
  }

  // Not decisions at all — a detection finding and an inventory event. Bucketing
  // them as refusals (the CLI's old behaviour) invents denials that never were.
  if (d === 'dlp') return { outcome: 'info', label: 'Finding', raw };
  if (d === 'mcp-discovered') return { outcome: 'info', label: 'Info', raw };

  if (d === 'allow' || d === 'allowed') {
    // The PostToolUse hook records that a tool RAN. It isn't a verdict — the
    // gate already decided, earlier, in its own row.
    if (src === 'post-hook') return { outcome: 'allow', label: 'Ran', raw };
    if (HUMAN_SOURCES.has(src)) {
      return { outcome: 'allow', label: 'Approved', raw };
    }
    return { outcome: 'allow', label: 'Auto-allowed', raw };
  }

  if (d === 'deny' || d === 'auto-deny' || d === 'block') {
    if (TIMEOUT_SOURCES.has(src)) {
      return { outcome: 'deny', label: 'Timed out', raw };
    }
    if (HUMAN_SOURCES.has(src)) {
      return { outcome: 'deny', label: 'Denied', raw };
    }
    return { outcome: 'deny', label: 'Blocked', raw };
  }

  if (d === 'review' || d === 'pending') {
    return { outcome: 'info', label: 'Pending', raw };
  }

  // Never `allow`. See rule 1 in the header.
  return { outcome: 'unknown', label: raw ? `? ${raw}` : '? (none)', raw };
}

/** Fixed-width tag for aligned CLI / MCP output. */
export function decisionTag(view: DecisionView): string {
  return `[${view.label}]`.padEnd(14);
}
