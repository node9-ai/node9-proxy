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
export type Dimension = 'workflows' | 'toolRules' | 'mcp' | 'data' | 'files';

export interface CiFinding {
  /** Which check produced it, e.g. 'CI-2'. */
  check: string;
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
}

/** Severity rank for comparison / worst-of. Higher = worse. */
export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  advisory: 1,
};
