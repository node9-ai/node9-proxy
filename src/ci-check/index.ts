// src/ci-check/index.ts
// Orchestrates the repo agent-security scan: fetch the surface → run the checks →
// aggregate → worst-severity. Never throws: a bad file becomes a note, so a
// scan always returns a result (fail-open on our own bugs).

import { fetchTree, isUnwalked, type OnProgress } from './fetch';
import { analyzeWorkflow, analyzeWorkflowSecrets } from './workflows';
import { analyzeAgentConfig, analyzeSkillGrants } from './agent-config';
import { analyzeMcp } from './mcp';
import { analyzeCodexConfig } from './codex';
import { analyzeInstructionFile, skillDirsOf } from './instructions';
import { routeOf } from './route';
import { analyzeScript } from './scripts';
import { SUPPRESSIONS_FILE, parseSuppressions, applySuppressions } from './suppress';
import { assignOrdinals } from './diff';
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

  // Same skill directories the selector used, so a supporting file that was fetched is
  // also routed to CI-6 rather than read and silently dropped.
  const skillDirs = skillDirsOf(tree.files.map((f) => f.path));
  // The whole listing, when the reader had one, so the hook check can tell "not committed"
  // from "not read". A listing that is not known to be complete decides nothing.
  const listing = tree.paths
    ? { paths: new Set(tree.paths), complete: tree.pathsComplete === true, unknown: isUnwalked }
    : undefined;
  // The team's suppressions, parsed once. Applied AFTER every check has run, so a check can
  // never see a finding as absent; and never routed to a content analyzer.
  const suppressionsFile = tree.files.find((f) => f.path === SUPPRESSIONS_FILE);
  // A local reader reads content on demand and throws when the file cannot be read; then no
  // suppression applies (stricter, never looser) and the scan says it may be incomplete.
  let suppressions: ReturnType<typeof parseSuppressions> | undefined;
  if (suppressionsFile) {
    try {
      suppressions = parseSuppressions(suppressionsFile.content, new Date());
    } catch (err) {
      notes.push(`${(err as Error)?.message ?? `${SUPPRESSIONS_FILE} could not be read`}`);
    }
  }
  for (const file of tree.files) {
    inspected.push(file.path);
    if (file.path === SUPPRESSIONS_FILE) continue;
    try {
      // Read ONCE: a local reader's content is read on demand and not held (§K), so a second
      // access would read the file again. Everything below uses this one copy.
      const content = file.content;
      // The reader routed each path over the whole plan (K.4); a hand-built tree has no route.
      switch (file.route !== undefined ? file.route : routeOf(file.path, skillDirs)) {
        case 'workflow': {
          const f = analyzeWorkflow(file.path, content);
          if (f) findings.push(f);
          const s = analyzeWorkflowSecrets(file.path, content); // CI-4
          if (s) findings.push(s);
          break;
        }
        case 'agent-config':
          findings.push(...analyzeAgentConfig(file.path, content, listing));
          break;
        case 'hook-script':
          findings.push(...analyzeScript(file.path, content, 'CI-1.hook-script'));
          break;
        case 'skill-script':
          findings.push(...analyzeScript(file.path, content, 'CI-6.skill-script'));
          break;
        case 'mcp':
          findings.push(...analyzeMcp(file.path, content));
          break;
        case 'codex':
          findings.push(...analyzeCodexConfig(file.path, content)); // CI-3 + CI-1 (1c-A)
          break;
        case 'instruction':
          findings.push(...analyzeInstructionFile(file.path, content)); // CI-6: the content
          findings.push(...analyzeSkillGrants(file.path, content)); // CI-1: the grant
          break;
      }
    } catch (err) {
      notes.push(`checker degraded on ${file.path}: ${(err as Error)?.message ?? 'error'}`);
    }
  }

  // K.4: a symlink where agent configuration can live that the scan does not follow is itself
  // the evidence — the agent may load content no reviewer sees.
  // link text is the PR author's: no backticks, control characters or bidi overrides
  const UNSAFE =
    /[`\u0000-\u001f\u007f-\u009f\u2028\u2029\u200e\u200f\u202a-\u202e\u2066-\u2069]+/g; // eslint-disable-line no-control-regex
  const quote = (t: string) => t.replace(UNSAFE, ' ').slice(0, 120);
  for (const u of tree.unfollowed ?? []) {
    findings.push({
      check: 'CI-1',
      rule: 'CI-1.unfollowable-symlink',
      locator: u.link,
      dimension: 'files',
      severity: 'medium',
      title: 'Agent configuration is a symlink this scan does not follow',
      file: u.path,
      signals: [
        `\`${quote(u.link)}\` is a symlink to \`${quote(u.text)}\` — not followed: ${u.why}`,
        'the agent opens whatever the link leads to; no reviewer sees that content in the repository',
      ],
      fix: 'Commit the file itself, or make the link a relative path to a file inside the repository.',
    });
  }

  // Identity before sorting: ordinals are assigned in EMISSION order so two otherwise
  // identical findings in one file keep distinct, stable identities across scans.
  assignOrdinals(findings);

  let suppressedCount = 0;
  if (suppressions) {
    // Loops, not spreads: a spread of a huge array overflows the stack (review H.1).
    for (const f of suppressions.findings) findings.push(f);
    for (const n of suppressions.notes) notes.push(n);
    suppressedCount = applySuppressions(findings, suppressions.active);
  }

  // Worst-first, then by file for stable output.
  findings.sort(
    (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.file.localeCompare(b.file)
  );

  // A rate-limit / network note means we could NOT read every file — a null
  // worst is then "we couldn't look", not "clean". Surface it so no caller (CLI
  // header, Action, SaaS) renders a partial scan as a clean bill of health.
  const incomplete = notes.some((nt) => /may be INCOMPLETE/i.test(nt));
  // `worst` is what the gate judges, so it is computed over the UNSUPPRESSED findings only.
  return {
    source: tree.source,
    findings,
    inspected,
    notes,
    worst: worstOf(findings.filter((f) => !f.suppressed)),
    incomplete,
    ...(suppressions ? { suppressions: suppressions.active, suppressedCount } : {}),
  };
}

/** Fetch + scan a repo (URL | owner/repo | local path). `onProgress` is a
 *  best-effort UX hook for a CLI spinner — the scan works without it. */
export async function scanRepo(input: string, onProgress?: OnProgress): Promise<ScanResult> {
  const tree = await fetchTree(input, onProgress);
  return scanTree(tree);
}

export type { OnProgress };
