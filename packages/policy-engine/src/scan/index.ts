// @node9/policy-engine — scan summarizer.
//
// Single source of truth for "what did we extract from each Claude Code
// session JSONL while watching it forward-only?". Used by:
//   - node9-proxy daemon (forward-only watermark scanner pushes summary
//     to the SaaS on each policy-sync tick)
//   - node9 SaaS /report aggregation (workspace-wide rollup)
//
// Pure functions. No I/O, no fs. The host code reads JSONL deltas, runs
// extractors, and passes findings in. The engine only summarizes + sanitizes.
//
// Privacy invariant: the summary contains COUNTS and pattern names ONLY.
// Never raw prompt text, never tool args, never file paths. Safe to send
// over the wire and persist on the SaaS side.

/**
 * One finding extracted from a JSONL delta scan. The host produces these
 * per-line; the engine aggregates them into a summary. `lineIndex` is local
 * to the JSONL file and not exfiltrated outside this struct — only the
 * count of findings matters at the workspace level.
 */
export interface ScanFinding {
  /** sessionId from the Claude Code JSONL line, used to bucket findings. */
  sessionId: string;
  /**
   * What kind of finding. New extractors should add their own type here
   * rather than overloading existing ones.
   */
  type:
    | 'dlp'
    | 'pii'
    | 'sensitive-file-read'
    | 'privilege-escalation'
    | 'network-exfil'
    | 'pipe-to-shell'
    | 'eval-of-remote'
    | 'destructive-op'
    | 'loop'
    | 'long-output-redacted';
  /** DLP / PII pattern that matched, e.g. "GitHub Token" or "Email". */
  patternName?: string;
  /** Local line index within the source JSONL — never exfiltrated. */
  lineIndex: number;
}

/**
 * Per-signal counts. Adding a new signal extractor means adding a new key
 * here; the FE will render it from this dict without code changes once
 * the chart is wired up.
 */
export interface ScanSignals {
  dlpFindings: number;
  piiFindings: number;
  sensitiveFileReads: number;
  privilegeEscalation: number;
  networkExfil: number;
  pipeToShell: number;
  evalOfRemote: number;
  destructiveOps: number;
  loops: number;
  longOutputRedactions: number;
}

/**
 * Compact, network-safe summary of a scan delta. This is the shape the
 * proxy sends to the SaaS on every policy-sync tick. The SaaS persists it
 * per-machine (1:1 with apiKey) and aggregates across the workspace for
 * the dashboard's Recent Exposure card.
 *
 * `score` follows the same 0-100 scale as blast: higher is cleaner. We
 * deduct per finding type based on severity weights (see `computeScanScore`
 * below), capped so a noisy session doesn't bottom out the score on its own.
 */
export interface ScanSummary {
  /** Number of distinct sessionIds touched by this scan delta. */
  totalSessions: number;
  /** Total tool-call lines parsed across all deltas. */
  totalToolCalls: number;
  /** Per-signal counts. */
  signals: ScanSignals;
  /**
   * Top DLP/PII pattern names by count, descending. Truncated to topN to
   * keep payload small. Only pattern *names*; samples never surface here.
   */
  topPatterns: Array<{ patternName: string; count: number }>;
  /** 0-100 cleanliness score. */
  score: number;
}

/** Default empty signals object — used as the seed for accumulation. */
function emptySignals(): ScanSignals {
  return {
    dlpFindings: 0,
    piiFindings: 0,
    sensitiveFileReads: 0,
    privilegeEscalation: 0,
    networkExfil: 0,
    pipeToShell: 0,
    evalOfRemote: 0,
    destructiveOps: 0,
    loops: 0,
    longOutputRedactions: 0,
  };
}

/**
 * Map a finding type to the signals key it increments. Centralised so a
 * new finding type only needs one addition (ScanFinding type literal +
 * one row here).
 */
const FINDING_TO_SIGNAL: Record<ScanFinding['type'], keyof ScanSignals> = {
  dlp: 'dlpFindings',
  pii: 'piiFindings',
  'sensitive-file-read': 'sensitiveFileReads',
  'privilege-escalation': 'privilegeEscalation',
  'network-exfil': 'networkExfil',
  'pipe-to-shell': 'pipeToShell',
  'eval-of-remote': 'evalOfRemote',
  'destructive-op': 'destructiveOps',
  loop: 'loops',
  'long-output-redacted': 'longOutputRedactions',
};

/**
 * Per-finding-type score deduction. Tuned so:
 *   - One credential leak (-30) drops the score from 100 to 70 — at-risk
 *     territory, demands attention.
 *   - One destructive op (-15) is a yellow flag.
 *   - One loop (-3) is mild noise; many loops still add up.
 * Total deduction is capped at 100 so the score never goes negative.
 */
const SCORE_WEIGHTS: Record<keyof ScanSignals, number> = {
  dlpFindings: 30,
  piiFindings: 10,
  sensitiveFileReads: 20,
  privilegeEscalation: 15,
  networkExfil: 25,
  pipeToShell: 30,
  evalOfRemote: 30,
  destructiveOps: 15,
  loops: 3,
  longOutputRedactions: 1,
};

/**
 * Compute the 0-100 cleanliness score. Public so other engine consumers
 * can use the same weights without round-tripping through summarizeScan.
 */
export function computeScanScore(signals: ScanSignals): number {
  let deduction = 0;
  for (const key of Object.keys(signals) as Array<keyof ScanSignals>) {
    deduction += signals[key] * SCORE_WEIGHTS[key];
  }
  return Math.max(0, Math.min(100, 100 - deduction));
}

/**
 * Build the network-safe summary from a list of findings + total tool-call
 * count. Deterministic: given the same input the output is identical
 * (important for SaaS-side dedup and ETag-style caching of subsequent
 * tick payloads).
 *
 * Top patterns are sorted by count desc, then alphabetically for stable
 * ordering across calls. topN defaults to 10.
 */
export function summarizeScan(
  findings: ScanFinding[],
  opts: { totalToolCalls?: number; topN?: number } = {}
): ScanSummary {
  const totalToolCalls = opts.totalToolCalls ?? 0;
  const topN = opts.topN ?? 10;

  const signals = emptySignals();
  const sessionIds = new Set<string>();
  const patternCounts = new Map<string, number>();

  for (const f of findings) {
    sessionIds.add(f.sessionId);
    const key = FINDING_TO_SIGNAL[f.type];
    signals[key]++;
    if (f.patternName) {
      patternCounts.set(f.patternName, (patternCounts.get(f.patternName) ?? 0) + 1);
    }
  }

  const topPatterns = [...patternCounts.entries()]
    .sort((a, b) => {
      if (b[1] !== a[1]) return b[1] - a[1];
      return a[0].localeCompare(b[0]);
    })
    .slice(0, topN)
    .map(([patternName, count]) => ({ patternName, count }));

  return {
    totalSessions: sessionIds.size,
    totalToolCalls,
    signals,
    topPatterns,
    score: computeScanScore(signals),
  };
}
