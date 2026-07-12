// src/ci-check/workflows.ts
// CI-2 — the agentic-workflow analyzer. THE differentiator (see the design doc
// §4.5): the same "pull_request_target + agent" shape can be critical (untrusted
// head to workspace root, no actor gate) or safe (label-gated, base checkout,
// scoped tools). A regex flags them identically and cries wolf; this models
//   danger = reachability(untrusted → agent) × power(tools/secrets) × exposure
// then applies the actor gate and mitigations. Static + parse-only.

import { parse as parseYaml } from 'yaml';
import type { CiFinding, Severity } from './types';
import { SEVERITY_RANK } from './types';

// Known agent actions — a step using one of these runs an LLM with tools.
const AGENT_ACTION_RE =
  /(anthropics\/claude-code(-base)?-action|anthropics\/claude-code|openai\/codex|codex-action|run-?aider|aider-?action|google-github-actions\/run-gemini)/i;

// Broad, write/exfil-capable tool grants (bare or dangerous verbs).
const BROAD_TOOL_RE =
  /(^|["\s,])(Bash|Write|Edit)(\s|,|"|$)|Bash\(\s*\*|Bash\((curl|wget|git push|git commit|git config|git:|rm|sh|bash|eval|npx|pip)/i;

// EXFIL/RCE tools: genuinely arbitrary shell or network egress — the tools that
// let an injected agent steal secrets or run code. Deliberately NARROWER than
// BROAD_TOOL_RE: it EXCLUDES scoped script invocations (`Bash(bash scripts/x.sh)`,
// `Bash(python3 x.py *)`, `Bash(gh api *)`) and bare `Write`/`Edit` (which write
// files but can't exfil on their own). Used by the F11 damage-capability cap.
const EXFIL_RCE_RE =
  /(^|["\s,])Bash(\s|,|"|$)|Bash\(\s*\*|Bash\((curl|wget|sh[\s):]|eval|rm[\s):]|git push)/i;

// A tool that can MODIFY GitHub — needed (alongside a write token) to abuse write
// permissions. `Bash(gh api …)` is arbitrary API; the enumerated pr/issue verbs
// are the write ones (view/diff/list are reads); `git push` / `Bash(git:*)` can
// push. Used by the F12 damage-capability check.
const GH_WRITE_TOOL_RE =
  /Bash\(\s*(gh api|gh:|gh (pr|issue) (comment|edit|merge|close|review|create|ready|lock|reopen)|git push|git:)/i;

// R4-3: a tool that can actually mint+transmit an OIDC token or exfil a secret —
// arbitrary shell or network egress. `id-token:write` is inert without one of these.
// Includes scoped INTERPRETERS (python/node/ruby/…) which can open a socket, and
// `gh api` / `nc` / `ssh` / `npx` which reach the network. (Review R4-round2 #6.)
const EGRESS_TOOL_RE =
  /(^|["\s,])Bash(\s|,|"|$)|Bash\(\s*\*|Bash\(\s*(curl|wget|python|python3|node|deno|bun|ruby|perl|php|pip|pipx|npx|nc|ncat|ssh|scp|http|gh api)|WebFetch|WebSearch/i;

// R4-5: a PER-USER org-membership / collaborator-permission API check (NOT a bare
// member listing — that isn't a gate). When such a step's output guards the agent
// step, that's a fail-closed actor gate expressed as a step. (Review R4-round2 #2:
// tightened to memberships/USER, collaborators/USER/permission — not `.../members`.)
const MEMBERSHIP_CHECK_RE =
  /orgs\/[^/'"\s]+\/memberships\/|teams\/[^/'"\s]+\/memberships\/|getCollaboratorPermissionLevel|collaborators\/[^/'"\s]+\/permission|checkMembershipForUser|getMembershipForUser/i;

// R4-1: activity types a STRANGER (an issue/PR author with no repo permission) can
// fire on their OWN issue/PR. Everything else (labeled/assigned/milestoned/pinned/
// locked/review_requested/…) requires triage or write — the action IS a gate.
// (Review R4-round2 #3: added `closed`/`converted_to_draft` — an author can close or
// convert-to-draft their own issue/PR, so those ARE stranger-firable.)
const STRANGER_ISSUE_TYPES = new Set(['opened', 'edited', 'reopened', 'closed']);
const STRANGER_PR_TYPES = new Set([
  'opened',
  'edited',
  'reopened',
  'closed',
  'synchronize',
  'ready_for_review',
  'converted_to_draft',
]);

interface Step {
  id?: string;
  uses?: string;
  run?: string;
  if?: string;
  with?: Record<string, unknown>;
  env?: Record<string, unknown>;
}
interface Job {
  if?: string;
  permissions?: Record<string, string> | string;
  steps?: Step[];
  env?: Record<string, unknown>;
}
interface Workflow {
  on?: unknown;
  permissions?: Record<string, string> | string;
  jobs?: Record<string, Job>;
}

function str(v: unknown): string {
  return typeof v === 'string' ? v : v == null ? '' : JSON.stringify(v);
}

/** Trigger names, handling the YAML `on:` → could parse as key "on" or, under
 *  YAML 1.1, boolean `true`. */
function triggerKeys(wf: Workflow, raw: Record<string, unknown>): string[] {
  const on = wf.on ?? raw['on'] ?? raw[true as unknown as string];
  if (typeof on === 'string') return [on];
  if (Array.isArray(on)) return on.map(String);
  if (on && typeof on === 'object') return Object.keys(on);
  return [];
}

function onObject(wf: Workflow, raw: Record<string, unknown>): Record<string, unknown> | undefined {
  return (wf.on ?? raw['on'] ?? raw[true as unknown as string]) as
    | Record<string, unknown>
    | undefined;
}
function activityTypes(node: unknown): string[] {
  return node && Array.isArray((node as { types?: unknown }).types)
    ? (node as { types: unknown[] }).types.map(String)
    : [];
}
/** Can an anonymous outsider fire this single trigger key? Honours `types:`. */
function keyStrangerFirable(on: Record<string, unknown>, key: string): boolean {
  switch (key) {
    case 'issue_comment':
    case 'pull_request_review':
    case 'pull_request_review_comment':
    case 'workflow_run':
    case 'discussion':
    case 'discussion_comment':
    case 'fork':
    case 'watch':
    case 'public':
      return true;
    case 'pull_request':
    case 'pull_request_target': {
      const ts = activityTypes(on[key]);
      return ts.length ? ts.some((t) => STRANGER_PR_TYPES.has(t)) : true;
    }
    case 'issues': {
      const ts = activityTypes(on['issues']);
      return ts.length ? ts.some((t) => STRANGER_ISSUE_TYPES.has(t)) : true;
    }
    // workflow_call / workflow_dispatch / schedule / push / create / delete / …
    // are NOT stranger-firable (require write access, or run in a trusted context).
    default:
      return false;
  }
}
/** R4-1: the reachability of a workflow's triggers.
 *  - untrusted: some trigger an anonymous outsider can fire.
 *  - reusable: has `workflow_call` and NO stranger-firable trigger of its own — a
 *    reusable definition whose reachability lives in the (unseen) caller. It is scored
 *    as *potentially* untrusted but CAPPED at medium (Review R4-round2 #5), NOT dropped.
 *    NOTE: push/schedule/dispatch-only (no workflow_call) is NOT reusable — it's a
 *    trusted internal trigger and scores nothing (Review R4-round2 #7).
 *  - secretExposed / privileged: ONLY over stranger-firable triggers.
 *  Returns `keys` so callers don't re-parse (Review R4-round2 #9). */
function triggerReach(wf: Workflow, raw: Record<string, unknown>) {
  const on = onObject(wf, raw) ?? {};
  const keys = triggerKeys(wf, raw);
  const firable = keys.filter((k) => keyStrangerFirable(on, k));
  const untrusted = firable.length > 0;
  const reusable = !untrusted && keys.some((k) => /^workflow_call$/i.test(k));
  const secretExposed = firable.some((t) => /pull_request_target|workflow_run/i.test(t));
  const privileged =
    untrusted &&
    firable.some((t) =>
      /pull_request_target|pull_request_review|workflow_run|issue|discussion/i.test(t)
    );
  return { keys, untrusted, reusable, secretExposed, privileged };
}

/** Job values, dropping null entries. An empty job block (`notify:` with no body) parses
 *  to `null`; a bare `.steps`/`.permissions`/`.if` deref on it throws, and since the caller
 *  (scanTree) try/catches analyzeWorkflow, the throw SILENTLY SUPPRESSES the finding — an
 *  attacker can disable CI-2 for the whole file by adding one empty job. Filter once here. */
function jobList(wf: Workflow): Job[] {
  return Object.values(wf.jobs ?? {}).filter((j): j is Job => j != null);
}

function allSteps(wf: Workflow): { job: Job; step: Step }[] {
  const out: { job: Job; step: Step }[] = [];
  for (const job of jobList(wf)) {
    for (const step of job.steps ?? []) out.push({ job, step });
  }
  return out;
}

function isAgentStep(step: Step): boolean {
  if (step.uses && AGENT_ACTION_RE.test(step.uses)) return true;
  // run-step heuristic: an agent CLI fed event context.
  if (
    step.run &&
    /\b(claude|aider|codex|gemini)\b/i.test(step.run) &&
    /github\.event/.test(step.run)
  )
    return true;
  return false;
}

// G-c: pull ONLY the --allowedTools / --allowed-tools value(s) from a claude_args
// blob. Everything else (`--append-system-prompt`, `--model`, free text) is PROSE and
// must NOT reach the tool regexes — else a safety instruction like "never edit code or
// push commits" reads as an Edit/push grant (the luci-theme-family FP). Extracting only
// the grant flag also naturally excludes `--disallowedTools` (never extracted).
function allowedToolsFromArgs(claudeArgs: string): string {
  let out = '';
  for (const m of claudeArgs.matchAll(/--allowed[-_]?tools[=\s]+("[^"]*"|'[^']*'|\S+)/gi))
    out += ' ' + m[1];
  return out;
}

// Only the allowedTools[] / permissions.allow[] arrays from a settings JSON string —
// never the whole blob (which can carry a systemPrompt full of prose). disallowedTools
// / deny are naturally excluded (not extracted).
function allowedToolsFromSettings(settings: string): string {
  let out = '';
  for (const key of ['allowedTools', 'allow']) {
    for (const m of settings.matchAll(new RegExp(`"${key}"\\s*:\\s*(\\[[^\\]]*\\])`, 'gi')))
      out += ' ' + m[1];
  }
  return out;
}

/** All tool grants declared for the agent steps — ONLY from real tool-grant sources
 *  (`--allowedTools`, the `allowed_tools`/`allowedTools` keys, `settings.allowedTools`),
 *  never prose. See G-c. */
function collectTools(steps: Step[]): string {
  let s = '';
  for (const st of steps) {
    const w = st.with ?? {};
    s += ' ' + allowedToolsFromArgs(str(w['claude_args']));
    s += ' ' + str(w['allowed_tools']) + ' ' + str(w['allowedTools']);
    s += ' ' + allowedToolsFromSettings(str(w['settings']));
  }
  return s;
}

/** Where (if anywhere) an untrusted PR head is checked out. 'root' = into the
 *  workspace (dangerous under pull_request_target); 'subdir' = isolated path.
 *  Takes a step list so callers can scope it to a single job (CI-4 per-job). */
function untrustedHeadCheckout(steps: Step[]): 'root' | 'subdir' | null {
  for (const step of steps) {
    if (!step.uses || !/actions\/checkout/.test(step.uses)) continue;
    const ref = str(step.with?.['ref']);
    // Also catch reusable-workflow inputs that carry the fork head
    // (inputs.expected_head_sha / inputs.head_ref), not just github.event.*.
    if (
      /pull_request\.head|head[._]sha|head_ref|expected_head|workflow_run\.head|inputs\.[\w]*head/i.test(
        ref
      )
    ) {
      return step.with?.['path'] ? 'subdir' : 'root';
    }
  }
  return null;
}

/** Does an agent step's prompt/args pull in attacker-writable text? */
function promptTakesUntrusted(steps: Step[]): boolean {
  for (const st of steps) {
    const blob =
      str(st.with?.['prompt']) + ' ' + str(st.with?.['direct_prompt']) + ' ' + collectTools([st]);
    if (/github\.event\.(issue|comment|pull_request|review)\.(body|title)/i.test(blob)) return true;
    // A review command over a fork PR reads the untrusted diff.
    if (/pull_request\.number|\/code-review|\/review/i.test(blob)) return true;
  }
  return false;
}

// An `if:` that clearly RESTRICTS the agent to a trusted actor. POLARITY matters (round 5,
// 1a): matching `author_association` / `MEMBER` as a bare substring credited an INVERTED
// check — `!= 'MEMBER'` (runs for everyone else) or `== 'NONE'` / `== 'FIRST_TIME_CONTRIBUTOR'`
// (runs ONLY for untrusted actors) — as a gate, hiding a wide-open workflow (a critical that
// LOOKS gated). So we credit ONLY genuinely-restrictive shapes:
//  · association compared POSITIVELY to a privileged value (`== OWNER|MEMBER|COLLABORATOR`),
//  · a permission level `== 'write'|'admin'|'maintain'`,
//  · `contains(<…>, login|actor|association)` positive-inclusion of a privileged set,
//  · an explicit login allowlist (`github.actor == …`, `user.login == …`),
//  · same-repo (`head.repo.full_name == github.repository`, i.e. not a fork).
// An inverted (`!=`) or unprivileged-target (`== NONE`) check no longer matches — the bare
// `author_association` / `FIRST_TIME_CONTRIBUTOR` / `MEMBER` / `permission` tokens are gone.
// Positive, restrictive clauses that do NOT use contains() (which needs a polarity check —
// see below). Each RESTRICTS the agent to a trusted actor.
const NONCONTAINS_GATE_RE = new RegExp(
  [
    String.raw`==\s*['"]?(OWNER|MEMBER|COLLABORATOR)\b`,
    String.raw`==\s*['"](write|admin|maintain)`,
    String.raw`github\.actor\s*==`,
    String.raw`user\.login\s*==`,
    String.raw`head\.repo\.full_name\s*==\s*github\.repository`,
  ].join('|'),
  'i'
);
// A permission/authorization STEP OUTPUT compared POSITIVELY — a marketplace permission-check
// action whose boolean output guards the agent step (a `uses:` action, so hasStepMembershipGate's
// `run:`-only check misses it). `== 'false'` is an anti-gate, not matched. JOB-SCOPED ONLY (used
// in jobActorGate, NOT the whole-workflow hasActorGate) — a step output is produced in ONE job, so
// crediting it workflow-wide would let a gated job mask an ungated sibling (the R2-1 bug).
const PERMISSION_OUTPUT_GATE_RE =
  /steps\.[\w-]+\.outputs\.[\w-]*(permission|allowed|authoriz|is[_-]?(admin|member|maintainer|collaborator))[\w-]*\s*==\s*['"]?(true|admin|write|maintain)/i;
// A contains()-based inclusion of a privileged set — one level of nested parens for
// `contains(fromJson('[…]'), …)`. POLARITY: `contains(…)` is a positive inclusion (gate), but
// `!contains(…)` runs for everyone EXCEPT the set (an anti-gate) — credit only the former.
const CONTAINS_GATE_RE =
  /contains\((?:[^()]|\([^()]*\))*(login|actor|association|OWNER|MEMBER|COLLABORATOR)/i;
const NEGATED_CONTAINS_RE =
  /!\s*\(?\s*contains\((?:[^()]|\([^()]*\))*(login|actor|association|OWNER|MEMBER|COLLABORATOR)/i;

/** Is a label-type gate configured on an untrusted trigger? F14a: a label gate
 *  counts on pull_request_target OR pull_request (metabase gates a
 *  `pull_request: types:[labeled]` job on the label name). */
function labelTypeConfigured(wf: Workflow, raw: Record<string, unknown>): boolean {
  const on = (wf.on ?? raw['on'] ?? raw[true as unknown as string]) as
    | Record<string, unknown>
    | undefined;
  const prTypes = (t: unknown): string[] =>
    t && Array.isArray((t as { types?: unknown }).types)
      ? (t as { types: unknown[] }).types.map(String)
      : [];
  return (
    prTypes(on?.['pull_request_target']).includes('labeled') ||
    prTypes(on?.['pull_request']).includes('labeled')
  );
}

/** Do these joined `if:` expressions constitute an actor gate? */
function ifsAreGated(ifs: string, labelConfigured: boolean): boolean {
  // Credit a contains() inclusion ONLY when it is not negated (`!contains(…)` = anti-gate).
  const containsGate = CONTAINS_GATE_RE.test(ifs) && !NEGATED_CONTAINS_RE.test(ifs);
  const gated = NONCONTAINS_GATE_RE.test(ifs) || containsGate;
  const labelGated = labelConfigured && /event\.label|label\.name/i.test(ifs);
  return gated || labelGated;
}

/** An effective actor gate anywhere in the workflow: a label gate (maintainer must
 *  apply) or an if that checks author_association / write permission / specific
 *  logins. Whole-workflow scope — used by CI-2. */
function hasActorGate(wf: Workflow, raw: Record<string, unknown>): boolean {
  const ifs = [jobList(wf).map((j) => j.if), allSteps(wf).map((s) => s.step.if)]
    .flat()
    .map(str)
    .join(' ');
  return ifsAreGated(ifs, labelTypeConfigured(wf, raw));
}

/** R4-5: a fail-closed actor gate expressed as a job STEP — a membership/permission
 *  API check (`gh api /orgs/…/memberships/…`, `getCollaboratorPermissionLevel`, …) whose
 *  output guards the agent step via `if: steps.<gate>.outputs.<x> == …`. openmrs gates this
 *  way; ACTOR_GATE_RE only reads `if:` expressions and misses it. */
function hasStepMembershipGate(job: Job): boolean {
  const steps = job.steps ?? [];
  // Gate steps: a per-user membership/permission CHECK that has an `id` (so a later
  // `if:` can reference its output). Review R4-round2 #2: a bare member-listing or an
  // id-less step is NOT a gate.
  const gateIds = steps
    .filter((s) => s.id && MEMBERSHIP_CHECK_RE.test(str(s.run)))
    .map((s) => s.id as string);
  if (!gateIds.length) return false;
  // The agent step must be guarded by ONE OF THOSE gate steps' outputs specifically —
  // referencing an unrelated `steps.build.outputs.*` does not count.
  return steps.some(
    (s) =>
      isAgentStep(s) &&
      gateIds.some((id) =>
        new RegExp(`steps\\.${id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\.outputs\\.`).test(
          str(s.if)
        )
      )
  );
}

/** Actor gate scoped to a SINGLE job (its own `if:` + its steps' `if:`s). CI-4
 *  evaluates each agent job independently, so a gate on a DIFFERENT job must not
 *  be credited to this one (and vice-versa). */
function jobActorGate(job: Job, wf: Workflow, raw: Record<string, unknown>): boolean {
  const ifs = [job.if, ...(job.steps ?? []).map((s) => s.if)].map(str).join(' ');
  // G-d′: an `assignee.login == '…'` gate (only someone with triage/write access can
  // assign an issue) counts too. Kept in the JOB-scoped check only — NOT in the shared
  // ACTOR_GATE_RE / whole-workflow hasActorGate, so a gated sibling job can't mask an
  // ungated injectable one.
  return (
    ifsAreGated(ifs, labelTypeConfigured(wf, raw)) ||
    /assignee\.login\s*==|event\.assignee\b/i.test(ifs) ||
    PERMISSION_OUTPUT_GATE_RE.test(ifs) || // [2] job-scoped permission-check-output gate
    hasStepMembershipGate(job) // R4-5
  );
}

/** `anthropics/claude-code-action` (the higher-level action — NOT the lower-level
 *  `claude-code-base-action`) runs the agent ONLY for users with WRITE access by
 *  default. `allowed_non_write_users: "*"` removes that gate; anything else keeps
 *  it. So a workflow using it, without the "*" bypass, has an effective IMPLICIT
 *  actor gate — the anonymous-attacker vector is blocked even without an explicit
 *  `if:`. Missing this = crying wolf on the most common claude-code-action setup. */
function hasImplicitActorGate(agentSteps: Step[], bypassActive: boolean): boolean {
  if (bypassActive) return false; // bypass on (and reachable) → the default gate is off
  return agentSteps.some((s) => /anthropics\/claude-code-action@/i.test(s.uses ?? ''));
}

/** G-d: agent steps whose OWN job is injectable — i.e. not actor-gated and not held
 *  by the claude-code-action default gate. Only these contribute to blast radius: a
 *  gated sibling job's tools (chmonitor's `assignee == duyetbot` bare-Bash job) can't
 *  be reached by the untrusted trigger, so they must not inflate the injectable job.
 *  Falls back to all agent steps if none qualify (never blank). */
function injectableJobs(
  wf: Workflow,
  raw: Record<string, unknown>,
  untrustedTrigger: boolean
): Job[] {
  const out: Job[] = [];
  for (const job of jobList(wf)) {
    const a = (job.steps ?? []).filter(isAgentStep);
    if (!a.length) continue;
    const jobStar = str(a.map((s) => s.with?.['allowed_non_write_users']).find(Boolean)) === '*';
    if (jobActorGate(job, wf, raw) || hasImplicitActorGate(a, jobStar && untrustedTrigger))
      continue;
    out.push(job);
  }
  return out;
}

// R4-2: a static PAT reachable in a SPECIFIC set of jobs (the injectable ones) — a
// PAT in a gated job must not be credited to an ungated one.
function usesPatIn(jobs: Job[]): boolean {
  for (const j of jobs)
    for (const step of j.steps ?? []) {
      const gt = str(step.with?.['github_token']);
      if (/secrets\./i.test(gt) && !/secrets\.GITHUB_TOKEN/i.test(gt)) return true;
    }
  return false;
}

/** Effective permissions text for a job. GitHub REPLACES (not merges) the workflow-level
 *  `permissions:` when a job declares its OWN block — so a job with its own permissions is
 *  evaluated on THAT alone (a top-level `write-all` does NOT leak into a job that scoped
 *  itself down to `contents: read`); a job with no block inherits the workflow top-level. */
function jobPerms(wf: Workflow, job: Job): string {
  return job.permissions != null ? str(job.permissions) : str(wf.permissions);
}

/** Does any of `jobs` hold a write scope matching `rx` under its EFFECTIVE (job-override-
 *  aware) permissions? GitHub's `permissions: write-all` shorthand grants WRITE to every
 *  scope, so it satisfies every per-scope write check too — matching only the literal
 *  `contents: write` form would read `write-all` (strictly MORE dangerous) as LESS
 *  dangerous, a false negative on the catastrophe tier. */
function jobsHaveWrite(wf: Workflow, jobs: Job[], rx: RegExp): boolean {
  return jobs.some((j) => {
    const p = jobPerms(wf, j);
    return /\bwrite-all\b/i.test(p) || rx.test(p);
  });
}

/** R4-3: `id-token:write` (cloud OIDC), job-override-aware. NOTE: `write-all` is
 *  deliberately NOT credited — GitHub requires `id-token: write` to be granted explicitly
 *  even under `write-all`, so a `write-all` grant does NOT enable OIDC. */
function hasIdTokenWrite(wf: Workflow, jobs: Job[]): boolean {
  const rx = /["']?id-token["']?\s*:\s*["']?write/i;
  return jobs.some((j) => rx.test(jobPerms(wf, j)));
}

/** R4-4: `pull-requests:write` — lets an injected agent `gh pr review --approve` a malicious PR,
 *  which BYPASSES a required-review branch-protection gate (a code-integrity path) → high. (An
 *  actual merge COMMIT still needs `contents:write`; the risk here is the self-approve, not the
 *  merge.) Distinguished from `issues:write` (comment/label an issue) which is weaker → medium. */
function hasPrWritePerm(wf: Workflow, jobs: Job[]): boolean {
  return jobsHaveWrite(wf, jobs, /["']?pull-requests["']?\s*:\s*["']?write/i);
}

/** F15: `contents`/`packages`/`actions`/`deployments : write` — CATASTROPHIC write
 *  power (push code, publish a package, deploy). With a push/API tool this is code
 *  execution on the repo → critical. (id-token:write is OIDC, handled by F11.) */
function hasCodeWritePerm(wf: Workflow, agentJobs: Job[]): boolean {
  return jobsHaveWrite(
    wf,
    agentJobs,
    /["']?(contents|packages|actions|deployments)["']?\s*:\s*["']?write/i
  );
}

/** F15: `pull-requests`/`issues : write` — BOUNDED write power. An injected agent can
 *  comment / label / approve / close, but CANNOT push code (that needs contents:write).
 *  Real damage (self-approve a malicious PR, spam) but not catastrophic → capped at high. */
function hasMetaWritePerm(wf: Workflow, agentJobs: Job[]): boolean {
  return jobsHaveWrite(wf, agentJobs, /["']?(pull-requests|issues)["']?\s*:\s*["']?write/i);
}

function hasEnvDeny(steps: Step[]): boolean {
  return steps.some((s) => /"?mode"?\s*:\s*"?deny/i.test(str(s.with?.['settings'])));
}

function agentActionsPinned(steps: Step[]): boolean {
  const agent = steps.filter(isAgentStep).filter((s) => s.uses);
  if (agent.length === 0) return false;
  return agent.every((s) => /@[0-9a-f]{40}\b/.test(s.uses ?? ''));
}

function severityFromScore(score: number): Severity | null {
  if (score >= 7) return 'critical';
  if (score >= 4) return 'high';
  if (score >= 2) return 'medium';
  if (score >= 1) return 'advisory';
  return null;
}

/** Analyze one workflow file. Returns a finding, or null if it's not an agentic
 *  workflow or is clean. Never throws (parse errors → null + caller notes). */
export function analyzeWorkflow(path: string, content: string): CiFinding | null {
  let raw: Record<string, unknown>;
  try {
    raw = (parseYaml(content) ?? {}) as Record<string, unknown>;
  } catch {
    return null; // unparseable YAML — caller notes it; we don't guess.
  }
  const wf = raw as Workflow;
  const steps = allSteps(wf).map((s) => s.step);
  const agentSteps = steps.filter(isAgentStep);
  // The job(s) the agent actually runs in — permission checks scope to these, so
  // a separate job's write perms don't get credited to the agent (the medusa bug).
  const agentJobs = [
    ...new Set(
      allSteps(wf)
        .filter((s) => isAgentStep(s.step))
        .map((s) => s.job)
    ),
  ];
  if (agentSteps.length === 0) return null;

  // R4-1: reachability is per-trigger. A stranger must actually be able to FIRE the
  // trigger for it to be untrusted — `issues:[labeled]` needs triage/write to fire (the
  // label IS the gate). `workflow_call` with no stranger trigger is `reusable` (scored
  // as potentially-untrusted, capped at medium below). F14: privileged = runs the
  // untrusted actor with the base-repo write token + secrets. See triggerReach.
  const {
    keys: triggers,
    untrusted: forkInput,
    secretExposed,
    reusable,
    privileged,
  } = triggerReach(wf, raw);

  const nonWrite = str(agentSteps.map((s) => s.with?.['allowed_non_write_users']).find(Boolean));
  const nonWriteStar = nonWrite === '*';
  const nonWriteList = !!nonWrite && nonWrite !== '*';

  // reusable (workflow_call) is scored as potentially-untrusted — its caller may wire an
  // untrusted trigger — but capped at medium below since we can't see the caller.
  const untrustedTrigger = forkInput || reusable;
  const bypassActive = nonWriteStar && untrustedTrigger;

  const head = untrustedHeadCheckout(steps);
  const promptUntrusted = promptTakesUntrusted(agentSteps);

  // G-d / R4-2 / R4-round2#1: reach AND power come only from the INJECTABLE job(s) — a
  // gated sibling job's tools/perms/PAT can't be reached by the untrusted trigger, and
  // must NOT downgrade (mask) an ungated sibling either. Compute injectable jobs FIRST.
  const injJobs = injectableJobs(wf, raw, untrustedTrigger);
  // Fallback to all agent jobs only matters for the signal strings when NO job is
  // injectable — in that case reach is 0 (below), so the fallback never drives severity.
  const powerJobs = injJobs.length ? injJobs : agentJobs;
  const powerSteps = injJobs.flatMap((j) => (j.steps ?? []).filter(isAgentStep));
  const scopedSteps = powerSteps.length ? powerSteps : agentSteps; // fallback: never blank
  const toolsBlob = collectTools(scopedSteps);

  // Reach REQUIRES an untrusted trigger AND at least one injectable (ungated) agent job.
  // If every agent job is actor-gated (injJobs empty), an untrusted trigger can't reach
  // any agent → reach 0. B (F10): only under an untrusted event can an attacker supply a
  // malicious head / prompt text / trigger the "*" bypass.
  const reach =
    untrustedTrigger && injJobs.length
      ? Math.max(
          head === 'root' ? 3 : head === 'subdir' ? 1 : 0,
          promptUntrusted ? 2 : 0,
          bypassActive ? 2 : 0
        )
      : 0;

  const broadTools = BROAD_TOOL_RE.test(toolsBlob);
  // R4-3: id-token:write is inert without a tool that can mint+exfil the token.
  const egressTool = EGRESS_TOOL_RE.test(toolsBlob);
  const elevated =
    hasCodeWritePerm(wf, powerJobs) || (hasIdTokenWrite(wf, powerJobs) && egressTool);
  const pat = usesPatIn(powerJobs);
  const power = (broadTools ? 2 : 0) + (bypassActive ? 1 : 0) + (elevated ? 1 : 0) + (pat ? 1 : 0);

  const explicitGate = hasActorGate(wf, raw);
  const implicitGate = hasImplicitActorGate(agentSteps, bypassActive);
  // R4-round2#1: the step-membership gate is credited PER-JOB (via jobActorGate →
  // injectableJobs → reach), NOT as a whole-workflow severity cap (which would mask an
  // ungated sibling). We only surface it as a MITIGATION signal when EVERY agent job is
  // gated (injJobs empty), so we never imply a reachable sibling is safe.
  const membershipGated =
    injJobs.length === 0 &&
    jobList(wf).some((j) => (j.steps ?? []).some(isAgentStep) && hasStepMembershipGate(j));
  const gate = explicitGate || implicitGate;
  const envDeny = hasEnvDeny(agentSteps);
  const pinned = agentActionsPinned(agentSteps);

  let score = reach + power;
  if (secretExposed && reach > 0) score += 2; // base secrets + untrusted reaches agent
  if (envDeny) score -= 1;
  if (pinned) score -= 1;
  score = Math.max(0, score);

  // A truly clean agentic workflow (trusted trigger, no untrusted reach, scoped
  // tools) has nothing to report. EXCEPT R4-1a: a reusable (workflow_call) agent
  // workflow always surfaces as an advisory — its safety depends on how callers wire
  // the trigger + gate, which we can't see, so we flag it for a caller review.
  if (score === 0 && !secretExposed && !reusable) return null;

  let severity = severityFromScore(score);
  // F8: a GATED workflow (explicit `if:` OR claude-code-action's default write-
  // access gate) is not externally exploitable — an untrusted user can't trigger
  // the agent — so it's a hardening ADVISORY regardless of how powerful its tools
  // are or whether untrusted content is checked out. Injection needs an UNTRUSTED
  // TRIGGER, which the gate blocks. The signals still name what to harden (static
  // PAT, broad tools, id-token). Only a genuinely UNGATED workflow stays high.
  if (gate && severity && severity !== 'advisory') severity = 'advisory';
  // Reach-required: injection needs untrusted input to REACH the agent. With no
  // reach (e.g. a scheduled job, or a "*" bypass on a non-untrustable trigger),
  // the workflow isn't injectable regardless of tool power → hardening advisory.
  if (reach === 0 && severity && severity !== 'advisory') severity = 'advisory';
  // F9: tool scope caps the blast radius. Without a broad/write-capable tool
  // (bare Bash / curl / wget / git push / Write / Edit), an injected agent is
  // limited to scoped API ops (e.g. mcp github issue tools) — real but not
  // catastrophic → cap high/critical down to medium.
  if (!broadTools && severity && SEVERITY_RANK[severity] > SEVERITY_RANK.medium)
    severity = 'medium';
  // F11 + F12: catastrophe requires DAMAGE CAPABILITY = a permission AND a tool to
  // exercise it. An injected agent can only cause real harm if it can EXFIL/RCE
  // (bare Bash / curl / wget / sh — not a scoped script), OR modify GitHub, which
  // needs BOTH a write token/PAT AND a tool that can use it (`gh api` / `gh pr
  // comment` / `git push`). UKGov has pull-requests:write + id-token but only
  // read-only git + Read/Write tools — no way to touch GitHub or exfil → medium.
  // medusa/sentry (read-only token + scoped scripts) → medium. hyperdx (write +
  // `Bash(gh api:*)`) → correctly stays high/critical.
  const exfilOrRce = EXFIL_RCE_RE.test(toolsBlob);
  const githubWriteTool = GH_WRITE_TOOL_RE.test(toolsBlob);
  // F15: three damage tiers, not one. RCE (bare Bash/curl) and CODE-WRITE (contents:write
  // + a git/gh tool, or a static PAT of unknown scope) are catastrophic → critical-capable.
  // METADATA-WRITE (pull-requests/issues:write + gh tool) is bounded — comment/label/approve,
  // no code push, no shell, no secret exfil → high at most.
  const rce = exfilOrRce;
  // R4-2: damage perms/PAT scoped to the injectable jobs (powerJobs), not all agent jobs.
  const codeWrite = pat || (hasCodeWritePerm(wf, powerJobs) && githubWriteTool);
  const metaWrite = hasMetaWritePerm(wf, powerJobs) && githubWriteTool;
  const canDamage = rce || codeWrite || metaWrite;
  if (!canDamage && severity && SEVERITY_RANK[severity] > SEVERITY_RANK.medium) severity = 'medium';
  // F15: metadata-write-ONLY (no RCE, no code-write) can't be catastrophic → cap critical to high.
  // hyperdx: pull-requests/issues:write + Bash(gh api:*)/Bash(git:*), no bare Bash, no PAT — an
  // injected agent manipulates PRs/issues but can't push code (needs contents:write) → high.
  if (canDamage && !rce && !codeWrite && severity === 'critical') severity = 'high';
  // R4-4: issue-only write (issues:write, NO pull-requests:write, NO code-write) is bounded
  // lower than PR-write — an injected agent can comment/label/close ISSUES but cannot approve
  // a malicious PR or push code. That's medium, not high. (healerbook.)
  const issueOnlyWrite =
    metaWrite && !hasPrWritePerm(wf, powerJobs) && !hasCodeWritePerm(wf, powerJobs);
  if (issueOnlyWrite && !rce && severity && SEVERITY_RANK[severity] > SEVERITY_RANK.medium)
    severity = 'medium';
  // F14b: untrusted reach via a NON-privileged trigger (plain `pull_request` only) is
  // sandboxed — fork PRs run with a read-only token and no secrets, so an injected
  // agent can't write to the repo or exfil (worst case = an ephemeral runner). That's
  // normal CI, not a vulnerability → hardening advisory. (The real risk only appears
  // if it's ever switched to pull_request_target.) Excludes `reusable` — a reusable
  // workflow isn't "plain pull_request"; it has its own medium cap below.
  if (untrustedTrigger && !privileged && !reusable && severity && severity !== 'advisory')
    severity = 'advisory';
  // R4-round2#5 + [6]: a reusable (workflow_call) agent workflow's reachability lives in the
  // unseen caller, so by default we cap it at MEDIUM (visible, not over-claimed). EXCEPTION —
  // a "loaded gun": a reusable that ITSELF checks out an untrusted head to root or ingests
  // untrusted prompt text is built to process attacker input; a caller almost certainly wires
  // it to a fork trigger (the pattern's purpose), so keep its power-derived high/critical.
  const reusableLoadedGun = reusable && (head === 'root' || promptUntrusted);
  if (reusable && !reusableLoadedGun && severity && SEVERITY_RANK[severity] > SEVERITY_RANK.medium)
    severity = 'medium';
  if (!severity) severity = 'advisory';

  // Build the transparent record of WHY this severity.
  const signals: string[] = [];
  if (secretExposed)
    signals.push(
      `runs with base-repo secrets (${triggers.filter((t) => /target|workflow_run/i.test(t)).join(', ')})`
    );
  else if (forkInput) signals.push(`triggered by untrusted input (${triggers.join(', ')})`);
  else if (reusable)
    signals.push(
      reusableLoadedGun
        ? `reusable workflow (${triggers.join(', ')}) that checks out an untrusted head / ingests untrusted input — exploitable the moment a caller wires a fork trigger (reachability depends on the caller, but this workflow is built to process attacker input)`
        : `reusable workflow (${triggers.join(', ')}) — no untrusted trigger of its own; reachability depends on the caller's trigger + actor gate`
    );
  if (forkInput && !privileged && !reusable)
    signals.push(
      'triggered by `pull_request` — fork PRs run with a read-only token (lower risk than pull_request_target)'
    );
  if (head === 'root') signals.push('checks out the untrusted PR head into the workspace root');
  if (head === 'subdir') signals.push('checks out the untrusted PR head into an isolated subdir');
  if (promptUntrusted) signals.push('feeds untrusted PR/issue text to the agent');
  if (broadTools) signals.push('agent has broad/write-capable tools (Bash/Write/curl/git push)');
  if (bypassActive) signals.push('allowed_non_write_users: "*" — any user can trigger the agent');
  if (elevated) signals.push('elevated permissions (contents/id-token: write)');
  if (pat) signals.push('a static PAT is exposed to the agent (recoverable via injection)');
  if (!gate && reach > 0) signals.push('no effective actor gate');
  // The ambiguous case: NO explicit `permissions:` anywhere. The GITHUB_TOKEN then
  // defaults to the repo/org setting, which MAY be write-all (the legacy default). We
  // can't prove it from the file, so we don't inflate severity (that would false-positive
  // on read-default repos) — but when an injectable agent has a write-capable tool, we
  // surface the ambiguity so the reader pins it down.
  const noExplicitPerms = wf.permissions == null && jobList(wf).every((j) => j.permissions == null);
  if (noExplicitPerms && reach > 0 && (broadTools || githubWriteTool))
    signals.push(
      'no explicit `permissions:` — the token defaults to the repo/org setting, which may grant write; set it explicitly to read-only'
    );

  const mitigations: string[] = [];
  if (explicitGate || membershipGated)
    mitigations.push('actor-gated (maintainer/label/write-user required)');
  else if (implicitGate)
    mitigations.push('claude-code-action gates the agent to write-access users by default');
  if (head === 'subdir') mitigations.push('untrusted head isolated in a subdir, not root');
  if (envDeny) mitigations.push('secrets env-denied from the agent subprocess');
  if (pinned) mitigations.push('agent action pinned to a commit SHA');
  if (nonWriteList) mitigations.push('non-write users scoped to a list, not "*"');

  const title =
    severity === 'critical' || severity === 'high'
      ? 'Injectable agent workflow — untrusted input reaches a tool-using agent with secrets'
      : severity === 'medium'
        ? 'Agent workflow with a risky pattern (partially mitigated)'
        : 'Agent workflow on a privileged trigger — review the actor gate';

  return {
    check: 'CI-2',
    dimension: 'workflows',
    severity,
    title,
    file: path,
    signals,
    mitigations: mitigations.length ? mitigations : undefined,
    fix:
      head === 'root' && privileged
        ? 'Do not check out the untrusted PR head into the workspace root under a privileged trigger (pull_request_target/workflow_run) — check out the base ref, or isolate the head in a subdir (--add-dir). Add an actor gate and scope the agent tools.'
        : head === 'root'
          ? 'This runs under `pull_request` (fork PRs get a read-only token), so the head checkout is low-risk today — keep it on `pull_request` (not `pull_request_target`) and keep the actor gate + scoped tools.'
          : 'Add/verify an actor gate, scope the agent tools to read-only, and env-deny secrets. See Anthropic’s claude-code-action security doc.',
  };
}

// ─── CI-4: agent-reachable secrets ───────────────────────────────────────────
// The agent's OWN credential (its API key / the default GITHUB_TOKEN) is expected
// fuel — not a finding. CI-4 fires on EXTRA secrets an agent can reach (cloud OIDC,
// static PATs, DB creds, other API keys) which an injected agent with a shell could
// exfiltrate. Reuses analyzeWorkflow's reachability model — same danger shape.
const AGENT_FUEL_RE =
  /^(ANTHROPIC_API_KEY|ANTHROPIC_AUTH_TOKEN|ANTHROPIC_BASE_URL|CLAUDE_CODE_OAUTH_TOKEN|OPENAI_API_KEY|OPENAI_BASE_URL|GEMINI_API_KEY|GOOGLE_API_KEY|GITHUB_TOKEN)$/i;

// A1: the agent-action INPUT keys that take the LLM credential/endpoint. A secret
// bound to one of these is fuel regardless of its NAME (nvidia_inference_key,
// MY_CLAUDE_KEY, …). Deliberately EXCLUDES `github_token` — a non-default token
// passed there is a recoverable PAT (usesPat/CI-2 already treats it as a real secret).
const FUEL_INPUT_KEYS =
  /^(anthropic_api_key|anthropic_auth_token|anthropic_base_url|claude_code_oauth_token|openai_api_key|openai_base_url|gemini_api_key|google_api_key)$/i;

/** Secret names that are the agent's own fuel by ASSIGNMENT: bound to a fuel input
 *  key (`with:`) or to a fuel-named env var. */
function fuelSecretNames(agentSteps: Step[]): Set<string> {
  const out = new Set<string>();
  const add = (v: unknown) => {
    for (const m of str(v).matchAll(/secrets\.([A-Za-z_][A-Za-z0-9_]*)/gi)) out.add(m[1]);
  };
  for (const st of agentSteps) {
    for (const [k, v] of Object.entries(st.with ?? {})) if (FUEL_INPUT_KEYS.test(k)) add(v);
    for (const [k, v] of Object.entries(st.env ?? {})) if (AGENT_FUEL_RE.test(k)) add(v);
  }
  return out;
}

function classifySecret(name: string): string {
  if (/AWS_|AZURE_|GCP_|GOOGLE_APPLICATION|GCLOUD/i.test(name)) return 'cloud';
  if (/_PAT\b|PAT$|_TOKEN$|GH_TOKEN/i.test(name)) return 'pat';
  if (/DATABASE|_DB_|POSTGRES|MYSQL|REDIS|MONGO|CONNECTION_STRING/i.test(name)) return 'db';
  if (/API_KEY|_KEY$|SECRET|PASSWORD|PASSWD/i.test(name)) return 'api-key';
  return 'generic';
}

interface ReachableSecret {
  name: string;
  kind: string;
}

/** EXTRA secrets (beyond the agent's own fuel) reachable in the agent's job/step
 *  env, plus cloud OIDC when id-token:write is granted. */
function agentReachableSecrets(
  wf: Workflow,
  agentSteps: Step[],
  agentJobs: Job[]
): ReachableSecret[] {
  const blobs: string[] = [];
  for (const st of agentSteps) blobs.push(str(st.env), str(st.with));
  for (const j of agentJobs) blobs.push(str(j.env));
  blobs.push(str((wf as { env?: unknown }).env));
  const fuel = fuelSecretNames(agentSteps); // A1: fuel-by-assignment, not just by-name
  const found = new Map<string, string>();
  for (const b of blobs) {
    for (const m of b.matchAll(/secrets\.([A-Za-z_][A-Za-z0-9_]*)/gi)) {
      const name = m[1];
      if (AGENT_FUEL_RE.test(name) || fuel.has(name)) continue;
      found.set(name, classifySecret(name));
    }
  }
  const idToken = hasIdTokenWrite(wf, agentJobs); // R4-round2#8: single source for the OIDC check
  const out: ReachableSecret[] = [...found].map(([name, kind]) => ({ name, kind }));
  if (idToken) out.push({ name: 'id-token (cloud OIDC)', kind: 'cloud-oidc' });
  return out;
}

interface JobEval {
  severity: Severity;
  secrets: ReachableSecret[];
  injectable: boolean;
  canReadEnv: boolean;
}

/** Evaluate ONE agent job in isolation. The exfiltratable-secret danger — untrusted
 *  reach + a real secret + a shell — must all land in the SAME job, so everything
 *  here is scoped to `job` (its own agent steps, its own env/permissions, its own
 *  gate, its own checkout). Returns null if this job holds no extra secret or its
 *  secrets aren't a finding. This is CI-2's agent-job scoping (F11b) applied to CI-4. */
function evalAgentJob(
  job: Job,
  wf: Workflow,
  raw: Record<string, unknown>,
  untrustedTrigger: boolean,
  reusable: boolean
): JobEval | null {
  const jobSteps = job.steps ?? [];
  const jobAgentSteps = jobSteps.filter(isAgentStep);
  if (jobAgentSteps.length === 0) return null;

  const secrets = agentReachableSecrets(wf, jobAgentSteps, [job]);
  if (secrets.length === 0) return null;

  const nonWriteStar =
    str(jobAgentSteps.map((s) => s.with?.['allowed_non_write_users']).find(Boolean)) === '*';
  const bypassActive = nonWriteStar && untrustedTrigger;
  const head = untrustedHeadCheckout(jobSteps);
  const reach = Math.max(
    head === 'root' ? 3 : head === 'subdir' ? 1 : 0,
    promptTakesUntrusted(jobAgentSteps) ? 2 : 0,
    bypassActive ? 2 : 0
  );
  const gate = jobActorGate(job, wf, raw) || hasImplicitActorGate(jobAgentSteps, bypassActive);
  const injectable = untrustedTrigger && !gate && reach > 0;
  const canReadEnv = EXFIL_RCE_RE.test(collectTools(jobAgentSteps)); // bare shell = read env + exfil

  // Anti-noise: `id-token:write` (cloud OIDC) is extremely common and, on its own,
  // is only a risk when an injectable agent can actually run a shell to use it. So:
  //  - EXPLOITABLE (injectable + bare shell): report, incl. id-token → critical.
  //  - NOT exploitable: only report if there's a REAL secret env-var (a static PAT,
  //    DB cred, API key…) as a hardening advisory. id-token-ONLY here → null (skip).
  const realSecrets = secrets.filter((s) => s.kind !== 'cloud-oidc');
  const hasOidc = secrets.some((s) => s.kind === 'cloud-oidc');
  let severity: Severity;
  if (injectable && canReadEnv) {
    severity =
      hasOidc || realSecrets.some((s) => ['cloud', 'pat', 'db'].includes(s.kind))
        ? 'critical'
        : 'high';
  } else if (realSecrets.length > 0) {
    severity = 'advisory';
  } else {
    return null; // only id-token OIDC and not exploitable — too common to be a finding
  }
  // R4-round2#5 + [6] (consistency with CI-2): cap a reusable at medium UNLESS it is a
  // "loaded gun" — it itself checks out an untrusted head to root or ingests untrusted prompt
  // text, so it is exploitable the moment a caller wires a fork trigger.
  const loadedGun = head === 'root' || promptTakesUntrusted(jobAgentSteps);
  if (reusable && !loadedGun && SEVERITY_RANK[severity] > SEVERITY_RANK.medium) severity = 'medium';
  return { severity, secrets, injectable, canReadEnv };
}

/** CI-4 — secrets an injectable agent could exfiltrate. Sibling of analyzeWorkflow
 *  (reuses its reachability model). Evaluates each agent JOB independently and
 *  reports the worst — a secret + shell in a NON-reachable job must not conflate
 *  with a DIFFERENT job's untrusted trigger. Null when no job is a finding. Never
 *  throws. */
export function analyzeWorkflowSecrets(path: string, content: string): CiFinding | null {
  let raw: Record<string, unknown>;
  try {
    raw = (parseYaml(content) ?? {}) as Record<string, unknown>;
  } catch {
    return null;
  }
  const wf = raw as Workflow;
  const all = allSteps(wf);
  if (!all.some((s) => isAgentStep(s.step))) return null;

  // R4-1: same stranger-firable reachability as CI-2 (labeled-only is not untrusted).
  // A reusable (workflow_call) workflow is scored as potentially-untrusted but capped at
  // medium (consistency with CI-2 — see evalAgentJob).
  const { untrusted: forkInput, reusable } = triggerReach(wf, raw);
  const untrustedTrigger = forkInput || reusable;

  // Per-agent-job: a secret is only exfiltratable if the SAME job is injectable and
  // has a shell. Evaluate each independently, keep the worst.
  const agentJobs = [...new Set(all.filter((s) => isAgentStep(s.step)).map((s) => s.job))];
  const worst = agentJobs
    .map((job) => evalAgentJob(job, wf, raw, untrustedTrigger, reusable))
    .filter((e): e is JobEval => e !== null)
    .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity])[0];
  if (!worst) return null;

  return {
    check: 'CI-4',
    dimension: 'data',
    severity: worst.severity,
    title:
      worst.severity === 'advisory'
        ? 'Secrets reachable by the agent — hardening'
        : 'Exfiltratable secrets reachable by an injectable agent',
    file: path,
    signals: [
      `agent can reach: ${worst.secrets.map((s) => s.name).join(', ')}`,
      worst.injectable
        ? 'the agent is externally triggerable (untrusted trigger, no gate)'
        : 'gated / not externally triggerable — latent risk only',
      worst.canReadEnv
        ? 'agent has arbitrary shell (bare Bash) → can read env and exfiltrate'
        : 'no arbitrary-shell tool — not exfiltratable today, but one tool-add away',
    ],
    fix: 'Move extra secrets to a separate trusted job the agent cannot reach; drop id-token:write if unused; scope the agent tools to read-only and gate the trigger.',
  };
}
