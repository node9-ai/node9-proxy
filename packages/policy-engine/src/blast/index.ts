// @node9/policy-engine — blast-radius summarizer.
//
// Single source of truth for "what's exposed on this machine" used by:
//   - node9-proxy `node9 blast` (the local CLI report)
//   - node9-proxy daemon (pushes summary to SaaS on each policy-sync tick)
//   - node9 SaaS /report aggregation (workspace-wide disk-exposure roll-up)
//
// Pure functions. No I/O, no fs, no env. The host gathers the findings
// (which IS I/O) and passes them in; the engine only summarizes + sanitizes.

/**
 * One sensitive path that the blast walker found readable on disk.
 * `score` is the per-finding deduction this path contributes to the
 * machine's overall blast-radius score (100 = clean).
 */
export interface BlastFinding {
  /** Absolute path on disk. May be home-relative ("~/.aws/credentials"). */
  full: string;
  /** Display label — short form for UI ("~/.ssh/id_rsa", ".env (cwd)"). */
  label: string;
  /** One-line explanation of why this path matters. */
  description: string;
  /** Points deducted from the 100-point score when this path is reachable. */
  score: number;
}

/** One environment variable the DLP scanner flagged as a credential. */
export interface BlastEnvFinding {
  /** Variable name, e.g. "AWS_SECRET_ACCESS_KEY". */
  key: string;
  /** DLP pattern that matched, e.g. "AWS Access Key". */
  patternName: string;
}

/** Full result of a blast walk on one machine. */
export interface BlastResult {
  reachable: BlastFinding[];
  envFindings: BlastEnvFinding[];
  /** 0-100. Higher is better. */
  score: number;
}

/**
 * Compact, network-safe summary of a blast result. This is the shape the
 * proxy sends to the SaaS and the SaaS persists per machine. We deliberately
 * DO NOT send file contents, full paths, or sample values — only:
 *   - the score (already aggregate)
 *   - a count of how many things were exposed
 *   - the top-N worst paths' sanitised labels (truncated to 2 segments)
 *
 * The sanitisation step lives here in the engine so both the proxy (before
 * send) and the SaaS (when validating) reference identical logic.
 */
export interface BlastSummary {
  /** 0-100. Same as BlastResult.score. */
  score: number;
  /** reachable.length + envFindings.length — total exposure count. */
  exposureCount: number;
  /**
   * Top-N worst findings (sorted by individual score deduction desc).
   * Paths are truncated to the last 2 segments so we never exfiltrate
   * project-layout details ("payments-prod/.env.production") — only the
   * basename + parent ("payments-prod/.env.production" → ".env.production"
   * if 1-segment, "payments-prod/.env.production" if 2-segment).
   */
  worstPaths: Array<{ path: string; score: number }>;
  /** Number of env vars flagged as credentials. No keys included. */
  envExposureCount: number;
}

/**
 * Sanitise a sensitive path for transmission. Keeps only the trailing 2
 * segments — enough to identify the kind of file ("~/.aws/credentials"
 * stays useful, "/Users/alice/Code/payments-prod/.env" becomes
 * "payments-prod/.env" which doesn't reveal the home dir or directory tree).
 *
 * Edge cases:
 *   - Already short paths (≤2 segments) are returned as-is.
 *   - Paths with a leading "~" are kept as-is up to 2 segments.
 *   - Empty strings return "".
 *
 * Exported for unit tests + reuse anywhere a path needs the same treatment.
 */
export function truncateBlastPath(full: string): string {
  if (!full) return '';
  // Strip trailing separator, then split on / OR \ to handle Windows.
  const cleaned = full.replace(/[/\\]+$/, '');
  const parts = cleaned.split(/[/\\]+/).filter((p) => p.length > 0);
  if (parts.length <= 2) {
    // Preserve leading "~" if present (path was already home-relative).
    return cleaned.startsWith('~') && !cleaned.startsWith('~/')
      ? cleaned
      : cleaned.startsWith('~/')
        ? cleaned
        : parts.join('/');
  }
  return parts.slice(-2).join('/');
}

/**
 * Build the network-safe summary from a full BlastResult. Deterministic:
 * given the same input the output is identical (important for caching /
 * deduplication on the SaaS side). Top-N defaults to 5, configurable for
 * tests.
 */
export function summarizeBlast(result: BlastResult, opts: { topN?: number } = {}): BlastSummary {
  const topN = opts.topN ?? 5;

  // Sort by score deduction descending — the worst findings come first.
  // Tie-break on label so the order is stable across calls (otherwise the
  // SaaS sees a "new" snapshot every poll even when nothing changed).
  const sorted = [...result.reachable].sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    return a.label.localeCompare(b.label);
  });

  return {
    score: result.score,
    exposureCount: result.reachable.length + result.envFindings.length,
    envExposureCount: result.envFindings.length,
    worstPaths: sorted.slice(0, topN).map((f) => ({
      path: truncateBlastPath(f.label),
      score: f.score,
    })),
  };
}
