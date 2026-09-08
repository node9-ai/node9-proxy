// src/ci-check/types.ts
// Types for `node9 scan-repo` / `node9 ci-check` — the repo agent-security scan.
//
// This scans a repo's AGENT-SECURITY SURFACE (committed .claude/.mcp.json/agentic
// workflows), NOT the machine (a CI runner is ephemeral). Config-only + static:
// it never fetches or executes repo *content*, only parses committed config.
//
// Severity mirrors the posture Severity so renderers/consumers stay consistent.

import type { Severity } from '../posture/types';

export type { Severity };

/** The six governed dimensions (same taxonomy as PolicyStudio / posture). */
export type Dimension = 'workflows' | 'toolRules' | 'mcp' | 'data' | 'files' | 'instructions';

export interface CiFinding {
  /** Which check produced it, e.g. 'CI-2'. */
  check: string;
  /** Stable rule id, e.g. 'CI-3.mcp-unpinned'. Unlike `check` this is granular enough
   *  to identify ONE finding kind, and unlike `title` it never changes with severity or
   *  wording — so it is the half of the identity that survives a rewrite of the copy.
   *  CI-5 diffing, suppression and any external report format key off this. */
  rule: string;
  dimension: Dimension;
  severity: Severity;
  /** One-line headline naming the exposure, e.g.
   *  'Injectable agent workflow — untrusted PR head checked out to root'. */
  title: string;
  /** Repo-relative file the finding anchors to. */
  file: string;
  /** 1-indexed line, when known. */
  line?: number;
  /** The signals that fired + the mitigations seen — the "why this severity"
   *  transparency that makes the nuance auditable (the anti-cry-wolf record). */
  signals: string[];
  mitigations?: string[];
  /** The concrete fix. */
  fix: string;
  /** What this finding points at WITHIN the file — an MCP server name, a hook command.
   *  Empty for a file-level finding (one per file). Together with `rule` and `file` this
   *  is the finding's identity across two scans. MUST be derived from repo content only:
   *  a blob SHA, a PR number or a run id would break the identity on rebase and would not
   *  port to a non-GitHub host. */
  locator?: string;
  /** Disambiguates two findings that are otherwise identical within one file (e.g. the
   *  same hook command registered twice). 0 for the first occurrence; assigned by the
   *  scan, never by a check. */
  ordinal?: number;
}

/** How one finding relates to the base scan. `escalated` is a finding that already
 *  existed and got WORSE — guardrail erosion, which is the thing CI-5 was designed to
 *  catch and which neither `added` nor `unchanged` describes. */
export type DiffStatus = 'added' | 'removed' | 'unchanged' | 'escalated';

export interface EscalatedFinding {
  finding: CiFinding;
  from: Severity;
  to: Severity;
}

/** Whether the base side of a diff is trustworthy. `incomplete` (the base scan ran but
 *  could not read every file) and `did-not-run` are NOT the same as a clean base: both
 *  make every unseen finding look introduced, so both degrade to the absolute answer. */
export type BaseState = 'ok' | 'incomplete' | 'did-not-run';

export interface ScanDiff {
  base: BaseState;
  added: CiFinding[];
  removed: CiFinding[];
  unchanged: CiFinding[];
  escalated: EscalatedFinding[];
  /** Worst severity this PR is answerable for — the gate input. Worst of `added` +
   *  `escalated` when the base is trustworthy; the HEAD's absolute worst otherwise, so a
   *  base that could not run can never be rendered as "nothing new". */
  worstIntroduced: Severity | null;
  /** True when EITHER side could not read every file. A severity cannot express "we did
   *  not finish looking" — `worstIntroduced: null` on an incomplete scan is a statement
   *  about what we read, not about the change — so the third state is carried separately
   *  and no consumer may render an incomplete diff as a pass. */
  incomplete: boolean;
}

/** A fetched agent-surface file. `content` is the raw text (never executed). */
export interface RepoFile {
  path: string;
  content: string;
}

/** The subset of a repo we fetch — config only, never source. */
export interface RepoTree {
  /** github "owner/repo" or a local path label, for display. */
  source: string;
  files: RepoFile[];
  /** Non-fatal fetch notes (rate-limit, missing dir) — surfaced, never thrown. */
  notes: string[];
}

export interface ScanResult {
  source: string;
  findings: CiFinding[];
  /** Files we actually inspected (so a clean result isn't confused with "didn't look"). */
  inspected: string[];
  notes: string[];
  /** Worst severity present, or null when clean. Drives exit code + headline. */
  worst: Severity | null;
  /** True when a fetch was rate-limited / errored — the scan could NOT read every
   *  file, so `worst: null` must NOT be presented as "clean" (false assurance). */
  incomplete: boolean;
}

/** Severity rank for comparison / worst-of. Higher = worse. */
export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  advisory: 1,
};
