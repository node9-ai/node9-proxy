// src/ci-check/index.ts
// Orchestrates the repo agent-security scan: fetch the surface → run the checks →
// aggregate → worst-severity. Never throws: a bad file becomes a note, so a
// scan always returns a result (fail-open on our own bugs).

import { fetchTree, type OnProgress } from './fetch';
import { analyzeWorkflow, analyzeWorkflowSecrets } from './workflows';
import { analyzeAgentConfig } from './agent-config';
import { analyzeMcp } from './mcp';
import { analyzeCodexConfig } from './codex';
import { analyzeInstructionFile } from './instructions';
import type { CiFinding, ScanResult, Severity, RepoTree } from './types';
import { SEVERITY_RANK } from './types';

export type { RepoTree, CiFinding, ScanResult };

function worstOf(findings: CiFinding[]): Severity | null {
  let worst: Severity | null = null;
  for (const f of findings) {
    if (!worst || SEVERITY_RANK[f.severity] > SEVERITY_RANK[worst]) worst = f.severity;
  }
  return worst;
}

/** Run all checks over an already-fetched tree (pure — testable without network). */
export function scanTree(tree: RepoTree): ScanResult {
  const findings: CiFinding[] = [];
  const inspected: string[] = [];
  const notes = [...tree.notes];

  for (const file of tree.files) {
    inspected.push(file.path);
    try {
      if (/\.github\/workflows\/.+\.ya?ml$/.test(file.path)) {
        const f = analyzeWorkflow(file.path, file.content);
        if (f) findings.push(f);
        const s = analyzeWorkflowSecrets(file.path, file.content); // CI-4
        if (s) findings.push(s);
      } else if (/\.claude\/settings(\.local)?\.json$/.test(file.path)) {
        findings.push(...analyzeAgentConfig(file.path, file.content));
      } else if (/\.mcp\.json$|\.cursor\/mcp\.json$/.test(file.path)) {
        findings.push(...analyzeMcp(file.path, file.content));
      } else if (/(^|\/)\.codex\/config\.toml$/.test(file.path)) {
        findings.push(...analyzeCodexConfig(file.path, file.content)); // CI-3 + CI-1 (1c-A)
      } else if (
        /(^|\/)(CLAUDE|AGENTS|GEMINI)\.md$|(^|\/)\.cursorrules$|copilot-instructions\.md$|(^|\/)\.(windsurf|cline)rules$/.test(
          file.path
        )
      ) {
        findings.push(...analyzeInstructionFile(file.path, file.content)); // CI-6
      }
    } catch (err) {
      notes.push(`checker degraded on ${file.path}: ${(err as Error)?.message ?? 'error'}`);
    }
  }

  // Worst-first, then by file for stable output.
  findings.sort(
    (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.file.localeCompare(b.file)
  );

  // A rate-limit / network note means we could NOT read every file — a null
  // worst is then "we couldn't look", not "clean". Surface it so no caller (CLI
  // header, Action, SaaS) renders a partial scan as a clean bill of health.
  const incomplete = notes.some((nt) => /may be INCOMPLETE/i.test(nt));
  return { source: tree.source, findings, inspected, notes, worst: worstOf(findings), incomplete };
}

/** Fetch + scan a repo (URL | owner/repo | local path). `onProgress` is a
 *  best-effort UX hook for a CLI spinner — the scan works without it. */
export async function scanRepo(input: string, onProgress?: OnProgress): Promise<ScanResult> {
  const tree = await fetchTree(input, onProgress);
  return scanTree(tree);
}

export type { OnProgress };
