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

interface Step {
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

function allSteps(wf: Workflow): { job: Job; step: Step }[] {
  const out: { job: Job; step: Step }[] = [];
  for (const job of Object.values(wf.jobs ?? {})) {
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

/** All tool grants declared for the agent steps (from claude_args / allowed_tools
 *  / settings blob) as one string to pattern-match. */
function collectTools(steps: Step[]): string {
  // F13: strip DENYLIST clauses first. `--disallowedTools "Bash,Write"` (or a
  // settings `"disallowedTools":[...]`) BLOCKS those tools — the opposite of
  // granting them. Reading the raw string would match "Bash"/"Write" and flag a
  // safe workflow as broad (repomix documents exactly this pattern).
  const stripDeny = (x: string) =>
    x
      .replace(/--disallowed[-_]?tools\s+("[^"]*"|'[^']*'|\S+)/gi, ' ')
      .replace(/["']disallowed[_]?[tT]ools["']\s*:\s*\[[^\]]*\]/g, ' ');
  let s = '';
  for (const st of steps) {
    const w = st.with ?? {};
    s +=
      ' ' +
      stripDeny(str(w['claude_args'])) +
      ' ' +
      str(w['allowed_tools']) +
      ' ' +
      str(w['allowedTools']);
    s += ' ' + stripDeny(str(w['settings'])); // settings JSON often carries allowedTools[]
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

// An `if:` that clearly CHECKS the actor's identity/permission — not a stray word
// in a label name (e.g. `needs-rewrite`), which would falsely mark a dangerous
// workflow as gated and hide it.
const ACTOR_GATE_RE =
  /author_association|FIRST_TIME_CONTRIBUTOR|collaborator|\b(MEMBER|OWNER)\b|permission|github\.actor\s*==|user\.login\s*==|==\s*['"](write|admin|maintain)|contains\([^)]*(login|actor|association)|head\.repo\.full_name\s*==\s*github\.repository/i;

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
  const gated = ACTOR_GATE_RE.test(ifs);
  const labelGated = labelConfigured && /event\.label|label\.name/i.test(ifs);
  return gated || labelGated;
}

/** An effective actor gate anywhere in the workflow: a label gate (maintainer must
 *  apply) or an if that checks author_association / write permission / specific
 *  logins. Whole-workflow scope — used by CI-2. */
function hasActorGate(wf: Workflow, raw: Record<string, unknown>): boolean {
  const ifs = [
    wf.jobs ? Object.values(wf.jobs).map((j) => j.if) : [],
    allSteps(wf).map((s) => s.step.if),
  ]
    .flat()
    .map(str)
    .join(' ');
  return ifsAreGated(ifs, labelTypeConfigured(wf, raw));
}

/** Actor gate scoped to a SINGLE job (its own `if:` + its steps' `if:`s). CI-4
 *  evaluates each agent job independently, so a gate on a DIFFERENT job must not
 *  be credited to this one (and vice-versa). */
function jobActorGate(job: Job, wf: Workflow, raw: Record<string, unknown>): boolean {
  const ifs = [job.if, ...(job.steps ?? []).map((s) => s.if)].map(str).join(' ');
  return ifsAreGated(ifs, labelTypeConfigured(wf, raw));
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

function permsElevated(wf: Workflow, agentJobs: Job[]): boolean {
  const check = (p: Record<string, string> | string | undefined) => {
    const s = str(p);
    // `str` may JSON-stringify a mapping (`{"contents":"write"}`) — the key is
    // then quoted (`contents":"write`), so allow optional quotes around the key
    // and value or the plain `key: write` YAML form.
    return /["']?(contents|id-token|packages)["']?\s*:\s*["']?write/i.test(s);
  };
  // Only the AGENT's own job(s) matter — a separate non-agent job's write perms
  // (e.g. a downstream "post the review" job) can't be abused by the injected agent.
  return check(wf.permissions) || agentJobs.some((j) => check(j.permissions));
}

/** Does the workflow grant the token real GitHub WRITE power (modify the repo /
 *  PRs / issues)? id-token:write is NOT counted — it's OIDC (cloud auth), only
 *  exploitable with an exfil/RCE tool, which the F11 cap handles separately. */
function hasGithubWritePerm(wf: Workflow, agentJobs: Job[]): boolean {
  const check = (p: Record<string, string> | string | undefined) =>
    /["']?(contents|pull-requests|issues|packages|actions|deployments)["']?\s*:\s*["']?write/i.test(
      str(p)
    );
  // Scope to the agent's own job(s) — a separate job's write perms are irrelevant
  // to what an injected agent can do (see medusa: agent in a read-only job).
  return check(wf.permissions) || agentJobs.some((j) => check(j.permissions));
}

function usesPat(wf: Workflow): boolean {
  // A non-GITHUB_TOKEN secret used as the github token → static PAT (recoverable
  // via injection per Anthropic's doc).
  for (const { step } of allSteps(wf)) {
    const gt = str(step.with?.['github_token']);
    if (/secrets\./i.test(gt) && !/secrets\.GITHUB_TOKEN/i.test(gt)) return true;
  }
  return false;
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

  const triggers = triggerKeys(wf, raw);
  const secretExposed = triggers.some((t) => /pull_request_target|workflow_run/i.test(t));
  const forkInput = triggers.some((t) => /issue|pull_request|workflow_call/i.test(t));
  // F14: privilege of an untrusted trigger. A PRIVILEGED trigger runs the untrusted
  // actor with the base-repo write token + secrets (pull_request_target/workflow_run/
  // issues/comments/reviews/discussions). `workflow_call` is privileged too — a
  // reusable workflow inherits its CALLER's (possibly privileged) context, so we
  // can't prove it's sandboxed. ONLY plain `pull_request` is non-privileged — fork
  // PRs get a READ-ONLY token and no secrets, so injection is sandboxed.
  const privileged = triggers.some((t) =>
    /pull_request_target|pull_request_review|workflow_run|workflow_call|issue|discussion/i.test(t)
  );

  const nonWrite = str(agentSteps.map((s) => s.with?.['allowed_non_write_users']).find(Boolean));
  const nonWriteStar = nonWrite === '*';
  const nonWriteList = !!nonWrite && nonWrite !== '*';

  // F10: `allowed_non_write_users: "*"` only MATTERS when an untrusted user can
  // actually trigger the workflow — i.e. an issue/comment/PR event. On a
  // schedule/workflow_dispatch/push there is no untrusted actor to gate, so the
  // "*" is a moot copy-paste and must not inflate severity.
  const untrustedTrigger = secretExposed || forkInput;
  const bypassActive = nonWriteStar && untrustedTrigger;

  const head = untrustedHeadCheckout(steps);
  const promptUntrusted = promptTakesUntrusted(agentSteps);
  // Untrusted reach: a checked-out fork head, untrusted text in the prompt, or an
  // active "*" bypass. B (F10 generalized): reach REQUIRES an untrusted trigger — you
  // can only check out an attacker's head (or feed attacker text) under an untrusted
  // event. A cron/dispatch/push release job that checks out an internal head_sha
  // (JetBrains/youtrackdb) has no attacker to supply a malicious head → reach 0.
  const reach = untrustedTrigger
    ? Math.max(
        head === 'root' ? 3 : head === 'subdir' ? 1 : 0,
        promptUntrusted ? 2 : 0,
        bypassActive ? 2 : 0
      )
    : 0;

  const toolsBlob = collectTools(agentSteps);
  const broadTools = BROAD_TOOL_RE.test(toolsBlob);
  const elevated = permsElevated(wf, agentJobs);
  const pat = usesPat(wf);
  const power = (broadTools ? 2 : 0) + (bypassActive ? 1 : 0) + (elevated ? 1 : 0) + (pat ? 1 : 0);

  const explicitGate = hasActorGate(wf, raw);
  const implicitGate = hasImplicitActorGate(agentSteps, bypassActive);
  const gate = explicitGate || implicitGate;
  const envDeny = hasEnvDeny(agentSteps);
  const pinned = agentActionsPinned(agentSteps);

  let score = reach + power;
  if (secretExposed && reach > 0) score += 2; // base secrets + untrusted reaches agent
  if (envDeny) score -= 1;
  if (pinned) score -= 1;
  score = Math.max(0, score);

  // A truly clean agentic workflow (trusted trigger, no untrusted reach, scoped
  // tools) has nothing to report.
  if (score === 0 && !secretExposed) return null;

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
  const canDamage = exfilOrRce || ((hasGithubWritePerm(wf, agentJobs) || pat) && githubWriteTool);
  if (!canDamage && severity && SEVERITY_RANK[severity] > SEVERITY_RANK.medium) severity = 'medium';
  // F14b: untrusted reach via a NON-privileged trigger (plain `pull_request` only) is
  // sandboxed — fork PRs run with a read-only token and no secrets, so an injected
  // agent can't write to the repo or exfil (worst case = an ephemeral runner). That's
  // normal CI, not a vulnerability → hardening advisory. (The real risk only appears
  // if it's ever switched to pull_request_target.)
  if (untrustedTrigger && !privileged && severity && severity !== 'advisory') severity = 'advisory';
  if (!severity) severity = 'advisory';

  // Build the transparent record of WHY this severity.
  const signals: string[] = [];
  if (secretExposed)
    signals.push(
      `runs with base-repo secrets (${triggers.filter((t) => /target|workflow_run/i.test(t)).join(', ')})`
    );
  else if (forkInput) signals.push(`triggered by untrusted input (${triggers.join(', ')})`);
  if (untrustedTrigger && !privileged)
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

  const mitigations: string[] = [];
  if (explicitGate) mitigations.push('actor-gated (maintainer/label/write-user required)');
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
  const idToken =
    /["']?id-token["']?\s*:\s*["']?write/i.test(str(wf.permissions)) ||
    agentJobs.some((j) => /["']?id-token["']?\s*:\s*["']?write/i.test(str(j.permissions)));
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
  untrustedTrigger: boolean
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

  const triggers = triggerKeys(wf, raw);
  const untrustedTrigger = triggers.some((t) =>
    /pull_request_target|workflow_run|issue|pull_request|workflow_call/i.test(t)
  );

  // Per-agent-job: a secret is only exfiltratable if the SAME job is injectable and
  // has a shell. Evaluate each independently, keep the worst.
  const agentJobs = [...new Set(all.filter((s) => isAgentStep(s.step)).map((s) => s.job))];
  const worst = agentJobs
    .map((job) => evalAgentJob(job, wf, raw, untrustedTrigger))
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
