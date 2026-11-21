// src/ci-check/index.ts
// Orchestrates the repo agent-security scan: fetch the surface → run the checks →
// aggregate → worst-severity. Never throws: a bad file becomes a note, so a
// scan always returns a result (fail-open on our own bugs).

import { fetchTree, isUnwalked, type OnProgress } from './fetch';
import {
  analyzeWorkflow,
  analyzeWorkflowSecrets,
  setCommittedAgentAllow,
  analyzeWorkflowPlugins,
  analyzeTrustedReaders,
  analyzeForkCodeOnTrust,
  analyzeAgentOutputToEnv,
  issueFormLabels,
  runSourceOf,
  automationLabelsOf,
  localCallsOf,
  type LocalCaller,
} from './workflows';
import { analyzeAgentConfig, analyzeSkillGrants } from './agent-config';
import { analyzeMcp, ownPackageNames } from './mcp';
import { analyzeCodexConfig } from './codex';
import {
  analyzeInstructionFile,
  analyzeWithdrawnGuidance,
  appSkillDirsOf,
  isSkillFile,
  namedDocs,
  skillDirsOf,
} from './instructions';
import { routeOf } from './route';
import {
  analyzeStartup,
  claudeHookTriggers,
  inspectStartupScript,
  vscodeTaskTriggers,
  type StartupScriptInfo,
  type StartupTrigger,
} from './startup';
import { tierOf, isAlert } from './tier';
import { testPathKind } from './harmless';
import { analyzeScript } from './scripts';
import { SUPPRESSIONS_FILE, parseSuppressions, applySuppressions } from './suppress';
import { assignOrdinals } from './diff';
import {
  codexPackageRefs,
  declaredNpmNames,
  mcpPackageRefs,
  textPackageRefs,
  triggerPackageRefs,
  type PackageRef,
} from './packages';
import { checkPackageRefs, type PackageCheckOptions } from './package-check';
import type { CiFinding, ScanResult, Severity, RepoTree } from './types';
import { SEVERITY_RANK } from './types';

// The routes whose findings are about file CONTENT: graded per tier, skipped in fixture trees.
const CONTENT_ROUTES = new Set(['instruction', 'hook-script', 'skill-script']);
// fw#481 S2: config an agent loads from the folder it is opened in. Under a test, fixture or
// example tree it is a test input or a sample, not the repository's own settings.
const CONFIG_ROUTES = new Set(['agent-config', 'codex', 'mcp', 'vscode-tasks']);
const FIXTURE_TREE_SIGNAL =
  'in a test, fixture or example folder: no agent loads this file when the repository root is opened';

export type { RepoTree, CiFinding, ScanResult };

function worstOf(findings: CiFinding[]): Severity | null {
  let worst: Severity | null = null;
  for (const f of findings) {
    if (!worst || SEVERITY_RANK[f.severity] > SEVERITY_RANK[worst]) worst = f.severity;
  }
  return worst;
}

/** What scanTree found for the package step (A1). Kept off the result so its JSON stays small:
 *  a skills collection names thousands of packages. */
const packageState = new WeakMap<
  ScanResult,
  { refs: PackageRef[]; declared: ReadonlySet<string> }
>();

/** The package references a scan collected (tests and the A/B read them). */
export function packageRefsOf(res: ScanResult): PackageRef[] {
  return packageState.get(res)?.refs ?? [];
}

/** Run all checks over an already-fetched tree (pure — testable without network). */
/** The allow lists of the root `.claude/settings.json` and `.claude/settings.local.json`, as one
 *  space-separated grant string. A file that does not parse grants nothing. */
function committedAllowOf(files: RepoTree['files']): string {
  const out: string[] = [];
  for (const file of files) {
    if (file.path !== '.claude/settings.json' && file.path !== '.claude/settings.local.json')
      continue;
    try {
      const cfg = JSON.parse(file.content) as {
        permissions?: { allow?: unknown; allowedTools?: unknown };
      };
      for (const list of [cfg.permissions?.allow, cfg.permissions?.allowedTools])
        if (Array.isArray(list))
          for (const g of list.slice(0, 500))
            if (typeof g === 'string') out.push(JSON.stringify(g));
    } catch {
      /* not JSON: nothing granted */
    }
  }
  return out.join(' ');
}

export function scanTree(tree: RepoTree): ScanResult {
  setCommittedAgentAllow('');
  const findings: CiFinding[] = [];
  const inspected: string[] = [];
  const notes = [...tree.notes];

  // Same skill directories the selector used, so a supporting file that was fetched is
  // also routed to CI-6 rather than read and silently dropped.
  const skillDirs = skillDirsOf(tree.files.map((f) => f.path));
  // The whole listing, when the reader had one, so the hook check can tell "not committed"
  // from "not read". A listing that is not known to be complete decides nothing.
  // C6-c: environments that require a reviewer, when the reader could ask GitHub.
  const environments = tree.environments
    ? { protected: new Set(tree.environments.protected) }
    : null;
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
  const appDirs = appSkillDirsOf(tree.paths ?? tree.files.map((f) => f.path), skillDirs);
  // §N: the docs each app-root skill's SKILL.md names — the only app docs that are graded.
  const named = new Map<string, Set<string>>();
  const namedBy = (docPath: string): boolean => {
    let dir = docPath;
    do dir = dir.slice(0, Math.max(0, dir.lastIndexOf('/')));
    while (dir && !appDirs.has(dir));
    if (!dir) return false;
    if (!named.has(dir)) {
      const skill = tree.files.find(
        (f) =>
          f.path === `${dir}/SKILL.md` || f.path.toLowerCase() === `${dir.toLowerCase()}/skill.md`
      );
      let text = '';
      try {
        text = skill?.content ?? '';
      } catch {
        /* unreadable: the SKILL.md's own entry already says so */
      }
      named.set(dir, namedDocs(dir, text));
    }
    return named.get(dir)!.has(docPath);
  };
  // T.1: who calls each local reusable workflow. Only the caller records are kept: holding
  // every workflow's text until the end undid the one-file memory bound of §K (review, round 2),
  // so the main loop reads each file again.
  const callersOf = new Map<string, LocalCaller[]>();
  // T.6.9: labels an issue form puts on every new issue are not a gate.
  const autoLabels = new Set<string>();
  const routeOfFile = (file: (typeof tree.files)[number]) =>
    file.route !== undefined ? file.route : routeOf(file.path, skillDirs, appDirs);
  // T.3: the package names the repository publishes (its own MCP server is not third-party).
  const manifests: { path: string; content: string }[] = [];
  for (const file of tree.files) {
    if (routeOfFile(file) !== 'manifest') continue;
    try {
      manifests.push({ path: file.path, content: file.content });
    } catch {
      /* unreadable: no own name, so nothing is excused */
    }
  }
  const ownPackages = ownPackageNames(manifests);
  for (const file of tree.files) {
    if (routeOfFile(file) !== 'issue-form') continue;
    try {
      for (const l of issueFormLabels(file.content)) autoLabels.add(l);
    } catch {
      /* unreadable form: its labels are unknown, so none is excluded from the gates */
    }
  }
  // fw#481 L2-a: labels automation adds on a stranger's event with a PAT or an App token.
  for (const file of tree.files) {
    if (routeOfFile(file) !== 'workflow') continue;
    try {
      for (const l of automationLabelsOf(file.path, file.content)) autoLabels.add(l);
    } catch {
      /* unreadable: its labels are unknown */
    }
  }
  // T.4: the workflows no stranger can start, by the name `workflow_run.workflows` uses. A name
  // shared with a stranger-firable workflow is not trusted.
  const runSources = new Map<string, boolean>();
  for (const file of tree.files) {
    if (routeOfFile(file) !== 'workflow') continue;
    try {
      const src = runSourceOf(file.path, file.content, autoLabels);
      if (src) runSources.set(src.name, (runSources.get(src.name) ?? true) && src.trusted);
    } catch {
      /* unreadable: not trusted */
    }
  }
  const trustedRunSources = new Set([...runSources].filter(([, t]) => t).map(([n]) => n));
  // fw#481 L6: the root agent settings the action loads in a checkout of this repository.
  setCommittedAgentAllow(committedAllowOf(tree.files));
  for (const file of tree.files) {
    if (routeOfFile(file) !== 'workflow') continue;
    try {
      const content = file.content;
      for (const { target, caller } of localCallsOf(
        file.path,
        content,
        autoLabels,
        trustedRunSources,
        { owner: tree.owner, repo: tree.repo }
      )) {
        const list = callersOf.get(target) ?? [];
        list.push(caller);
        callersOf.set(target, list);
      }
    } catch {
      /* unreadable: the main loop reports it */
    }
  }
  // A9: start-up triggers and the scripts directly inside `.claude/` / `.vscode/`, judged
  // together after the loop (a trigger and its loader are different files).
  const startupTriggers: StartupTrigger[] = [];
  const startupScripts = new Map<string, StartupScriptInfo>();
  // A1: the registry packages an agent would fetch, checked online after the scan (scanRepo).
  const packageRefs: PackageRef[] = [];
  for (const file of tree.files) {
    // The reader routed each path over the whole plan (K.4); a hand-built tree has no route.
    let route = file.route !== undefined ? file.route : routeOf(file.path, skillDirs, appDirs);
    if (route === 'app-doc') {
      if (!namedBy(file.path)) continue; // the app's own doc: not graded, not inspected
      route = 'instruction';
    }
    if (route === 'issue-form' || route === 'manifest') continue; // read above; not agent surface
    inspected.push(file.path);
    if (file.path === SUPPRESSIONS_FILE) continue;
    // §Q: content under a test, fixture or example tree (see testPathKind): read, and not graded,
    // except what an agent loads there by name, which keeps its alerts.
    const testKind = route && CONTENT_ROUTES.has(route) ? testPathKind(file.path, route) : 'none';
    if (testKind === 'skip') continue;
    const before = findings.length;
    const alertsOnly = testKind === 'alerts-only';
    // A1: a package named under a test or fixture tree is usually made up on purpose. Every
    // surface there is treated as text and keeps only counted findings (a known malicious name).
    const fixture = route ? testPathKind(file.path, route) !== 'none' : false;
    const addRefs = (refs: PackageRef[]) => {
      for (const r of refs)
        packageRefs.push(fixture ? { ...r, autoRun: false, alertsOnly: true } : r);
    };
    try {
      // Read ONCE: a local reader's content is read on demand and not held (§K), so a second
      // access would read the file again. Everything below uses this one copy.
      const content = file.content;
      switch (route) {
        case 'workflow': {
          const callers = callersOf.get(file.path);
          const f = analyzeWorkflow(
            file.path,
            content,
            callers,
            autoLabels,
            trustedRunSources,
            environments
          );
          if (f) findings.push(f);
          const s = analyzeWorkflowSecrets(
            file.path,
            content,
            callers,
            autoLabels,
            trustedRunSources
          ); // CI-4
          if (s) findings.push(s);
          findings.push(...analyzeWorkflowPlugins(file.path, content, tree.owner)); // CI-3: plugin sources
          findings.push(
            ...analyzeTrustedReaders(file.path, content, autoLabels, callers, trustedRunSources)
          ); // T.5
          findings.push(
            ...analyzeForkCodeOnTrust(file.path, content, callers, autoLabels, trustedRunSources)
          ); // T.7
          findings.push(
            ...analyzeAgentOutputToEnv(file.path, content, callers, autoLabels, trustedRunSources)
          ); // gap 4
          break;
        }
        case 'agent-config':
          findings.push(...analyzeAgentConfig(file.path, content, listing));
          for (const t of claudeHookTriggers(file.path, content)) {
            startupTriggers.push(t);
            addRefs(triggerPackageRefs(t.kind, t.file, t.command, t.line, alertsOnly));
          }
          break;
        case 'vscode-tasks':
          for (const t of vscodeTaskTriggers(file.path, content)) {
            startupTriggers.push(t);
            addRefs(triggerPackageRefs(t.kind, t.file, t.command, t.line, alertsOnly));
          }
          break;
        case 'startup-script':
          startupScripts.set(file.path, inspectStartupScript(content));
          break;
        case 'hook-script':
          findings.push(...analyzeScript(file.path, content, 'CI-1.hook-script'));
          addRefs(textPackageRefs(file.path, content, 'hook-script', alertsOnly));
          break;
        case 'skill-script':
          findings.push(...analyzeScript(file.path, content, 'CI-6.skill-script'));
          addRefs(textPackageRefs(file.path, content, 'skill-script', alertsOnly));
          break;
        case 'mcp':
          findings.push(...analyzeMcp(file.path, content, ownPackages));
          addRefs(mcpPackageRefs(file.path, content, alertsOnly));
          break;
        case 'codex':
          findings.push(...analyzeCodexConfig(file.path, content, ownPackages)); // CI-3 + CI-1 (1c-A)
          addRefs(codexPackageRefs(file.path, content, alertsOnly));
          break;
        case 'instruction':
          findings.push(...analyzeInstructionFile(file.path, content)); // CI-6: the content
          // Withdrawn vendor guidance is a claim about a skill: a CLAUDE.md or a note that
          // names the same domain in prose is not a stale copy.
          if (isSkillFile(file.path, skillDirs))
            findings.push(...analyzeWithdrawnGuidance(file.path, content));
          findings.push(...analyzeSkillGrants(file.path, content)); // CI-1: the grant
          addRefs(textPackageRefs(file.path, content, 'doc', alertsOnly));
          break;
      }
    } catch (err) {
      // A checker that throws has not looked: the result may be INCOMPLETE, never clean.
      notes.push(
        `checker degraded on ${file.path}: ${(err as Error)?.message ?? 'error'}; results may be INCOMPLETE`
      );
    }
    if (testKind === 'alerts-only') {
      const kept = findings.splice(before).filter((f) => tierOf(f) === 'alert');
      findings.push(...kept);
    }
    if (fixture && route && CONFIG_ROUTES.has(route)) {
      for (const f of findings.slice(before)) {
        f.fixtureTree = true;
        f.signals = [...f.signals, FIXTURE_TREE_SIGNAL];
      }
    }
  }

  try {
    const startup = analyzeStartup(startupTriggers, startupScripts, listing);
    // A worm finding already says what the hook's script is; the "not graded" review item for
    // the same hook would contradict it. Same file, same script path (both from hookScriptPath).
    const wormHooks = new Set(
      startup
        .filter((f) => f.rule === 'CI-1.worm-startup')
        .map((f) => `${f.file}\u0000${f.locator}`)
    );
    if (wormHooks.size) {
      for (let i = findings.length - 1; i >= 0; i--) {
        const f = findings[i];
        if (f.rule === 'CI-1.hook-script-unscanned' && wormHooks.has(`${f.file}\u0000${f.locator}`))
          findings.splice(i, 1);
      }
    }
    findings.push(...startup);
  } catch (err) {
    notes.push(
      `checker degraded on start-up triggers: ${(err as Error)?.message ?? 'error'}; results may be INCOMPLETE`
    );
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
        `\`${quote(u.link)}\` is a symlink to \`${quote(u.text)}\`, not followed: ${u.why}`,
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

  setCommittedAgentAllow(''); // L6: one scan's settings, never left for the next caller
  // Every finding says whether it counts (§Q); only alerts set the result.
  for (const f of findings) f.tier = tierOf(f);

  // Worst-first, then by file for stable output.
  findings.sort(
    (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.file.localeCompare(b.file)
  );

  // A rate-limit / network note means we could NOT read every file — a null
  // worst is then "we couldn't look", not "clean". Surface it so no caller (CLI
  // header, Action, SaaS) renders a partial scan as a clean bill of health.
  const incomplete = notes.some((nt) => /may be INCOMPLETE/i.test(nt));
  // `worst` is what the gate judges, so it is computed over the UNSUPPRESSED findings only.
  const result: ScanResult = {
    source: tree.source,
    findings,
    inspected,
    notes,
    worst: worstOf(findings.filter((f) => !f.suppressed && isAlert(f))),
    incomplete,
    ...(suppressions ? { suppressions: suppressions.active, suppressedCount } : {}),
  };
  packageState.set(result, { refs: packageRefs, declared: declaredNpmNames(manifests) });
  return result;
}

/**
 * A1: ask the registries about the packages `scanTree` collected and add the findings, with the
 * same suppression, tier and `worst` rules as every other finding. Returns a new result; a scan
 * without package references comes back unchanged.
 */
export async function addPackageFindings(
  res: ScanResult,
  opts: PackageCheckOptions = {}
): Promise<ScanResult> {
  const state = packageState.get(res);
  if (!state || state.refs.length === 0) return res;
  const {
    findings: added,
    notes,
    summary,
  } = await checkPackageRefs(state.refs, {
    declared: state.declared,
    ...opts,
  });
  const out: ScanResult = { ...mergeFindings(res, added, notes), packages: summary };
  packageState.set(out, state);
  return out;
}

/**
 * Add findings produced after `scanTree` (the package and dependency steps) under the same rules
 * as every other finding: the team's suppressions, the tier, the order and `worst`.
 */
export function mergeFindings(res: ScanResult, added: CiFinding[], notes: string[]): ScanResult {
  if (added.length === 0 && notes.length === 0) return res;
  const suppressedNow = res.suppressions ? applySuppressions(added, res.suppressions) : 0;
  for (const f of added) f.tier = tierOf(f);
  const findings = [...res.findings, ...added].sort(
    (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.file.localeCompare(b.file)
  );
  const out: ScanResult = {
    ...res,
    findings,
    notes: [...res.notes, ...notes],
    worst: worstOf(findings.filter((f) => !f.suppressed && isAlert(f))),
    ...(res.suppressions ? { suppressedCount: (res.suppressedCount ?? 0) + suppressedNow } : {}),
  };
  const state = packageState.get(res);
  if (state) packageState.set(out, state);
  return out;
}

/** Fetch + scan a repo (URL | owner/repo | local path). `onProgress` is a
 *  best-effort UX hook for a CLI spinner — the scan works without it. */
export async function scanRepo(
  input: string,
  onProgress?: OnProgress,
  /** A1 registry lookups; `false` skips them (`scan-repo --no-package-check`). */
  packages: PackageCheckOptions | false = {}
): Promise<ScanResult> {
  const tree = await fetchTree(input, onProgress);
  const res = scanTree(tree);
  return packages === false ? res : addPackageFindings(res, packages);
}

export type { OnProgress };
