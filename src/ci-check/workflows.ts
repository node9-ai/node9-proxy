// src/ci-check/workflows.ts
// CI-2 — the agentic-workflow analyzer. THE differentiator (see the design doc
// §4.5): the same "pull_request_target + agent" shape can be critical (untrusted
// head to workspace root, no actor gate) or safe (label-gated, base checkout,
// scoped tools). A regex flags them identically and cries wolf; this models
//   danger = reachability(untrusted → agent) × power(tools/secrets) × exposure
// then applies the actor gate and mitigations. Static + parse-only.

import { parse as parseYaml } from 'yaml';
import type { CiFinding, Severity } from './types';

// Known agent actions — a step using one of these runs an LLM with tools.
const AGENT_ACTION_RE =
  /(anthropics\/claude-code(-base)?-action|anthropics\/claude-code|openai\/codex|codex-action|run-?aider|aider-?action|google-github-actions\/run-gemini)/i;

// Broad, write/exfil-capable tool grants (bare or dangerous verbs).
const BROAD_TOOL_RE =
  /(^|["\s,])(Bash|Write|Edit)(\s|,|"|$)|Bash\(\s*\*|Bash\((curl|wget|git push|git commit|git config|git:|rm|sh|bash|eval|npx|pip)/i;

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
  let s = '';
  for (const st of steps) {
    const w = st.with ?? {};
    s += ' ' + str(w['claude_args']) + ' ' + str(w['allowed_tools']) + ' ' + str(w['allowedTools']);
    s += ' ' + str(w['settings']); // settings JSON often carries allowedTools[]
  }
  return s;
}

/** Where (if anywhere) an untrusted PR head is checked out. 'root' = into the
 *  workspace (dangerous under pull_request_target); 'subdir' = isolated path. */
function untrustedHeadCheckout(wf: Workflow): 'root' | 'subdir' | null {
  for (const { step } of allSteps(wf)) {
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

/** An effective actor gate: a label gate (maintainer must apply) or an if that
 *  checks author_association / write permission / specific logins. */
function hasActorGate(wf: Workflow, raw: Record<string, unknown>): boolean {
  const on = (wf.on ?? raw['on'] ?? raw[true as unknown as string]) as
    | Record<string, unknown>
    | undefined;
  const prt = on?.['pull_request_target'] as { types?: unknown } | undefined;
  const labeled =
    prt && Array.isArray(prt.types) && (prt.types as unknown[]).map(String).includes('labeled');
  const ifs = [
    wf.jobs ? Object.values(wf.jobs).map((j) => j.if) : [],
    allSteps(wf).map((s) => s.step.if),
  ]
    .flat()
    .map(str)
    .join(' ');
  // Only count write/admin/maintain when it's clearly a permission/association
  // CHECK — not a stray word in a label name (e.g. `needs-rewrite`), which would
  // falsely mark a dangerous workflow as gated and hide it.
  const gated =
    /author_association|FIRST_TIME_CONTRIBUTOR|collaborator|\b(MEMBER|OWNER)\b|permission|github\.actor\s*==|user\.login\s*==|==\s*['"](write|admin|maintain)|contains\([^)]*(login|actor|association)|head\.repo\.full_name\s*==\s*github\.repository/i.test(
      ifs
    );
  const labelGated = !!labeled && /event\.label|label\.name/i.test(ifs);
  return gated || labelGated;
}

/** `anthropics/claude-code-action` (the higher-level action — NOT the lower-level
 *  `claude-code-base-action`) runs the agent ONLY for users with WRITE access by
 *  default. `allowed_non_write_users: "*"` removes that gate; anything else keeps
 *  it. So a workflow using it, without the "*" bypass, has an effective IMPLICIT
 *  actor gate — the anonymous-attacker vector is blocked even without an explicit
 *  `if:`. Missing this = crying wolf on the most common claude-code-action setup. */
function hasImplicitActorGate(agentSteps: Step[], nonWriteStar: boolean): boolean {
  if (nonWriteStar) return false; // bypass on → the default gate is off
  return agentSteps.some((s) => /anthropics\/claude-code-action@/i.test(s.uses ?? ''));
}

function permsElevated(wf: Workflow): boolean {
  const check = (p: Record<string, string> | string | undefined) => {
    const s = str(p);
    // `str` may JSON-stringify a mapping (`{"contents":"write"}`) — the key is
    // then quoted (`contents":"write`), so allow optional quotes around the key
    // and value or the plain `key: write` YAML form.
    return /["']?(contents|id-token|packages)["']?\s*:\s*["']?write/i.test(s);
  };
  return check(wf.permissions) || Object.values(wf.jobs ?? {}).some((j) => check(j.permissions));
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
  if (agentSteps.length === 0) return null;

  const triggers = triggerKeys(wf, raw);
  const secretExposed = triggers.some((t) => /pull_request_target|workflow_run/i.test(t));
  const forkInput = triggers.some((t) => /issue|pull_request|workflow_call/i.test(t));

  const nonWrite = str(agentSteps.map((s) => s.with?.['allowed_non_write_users']).find(Boolean));
  const nonWriteStar = nonWrite === '*';
  const nonWriteList = !!nonWrite && nonWrite !== '*';

  const head = untrustedHeadCheckout(wf);
  const promptUntrusted = promptTakesUntrusted(agentSteps);
  // `allowed_non_write_users: "*"` means an untrusted actor can drive the agent
  // directly — that IS untrusted reach even if we don't spot a head checkout.
  const reach = Math.max(
    head === 'root' ? 3 : head === 'subdir' ? 1 : 0,
    promptUntrusted ? 2 : 0,
    nonWriteStar ? 2 : 0
  );

  const toolsBlob = collectTools(agentSteps);
  const broadTools = BROAD_TOOL_RE.test(toolsBlob);
  const elevated = permsElevated(wf);
  const pat = usesPat(wf);
  const power = (broadTools ? 2 : 0) + (nonWriteStar ? 1 : 0) + (elevated ? 1 : 0) + (pat ? 1 : 0);

  const explicitGate = hasActorGate(wf, raw);
  const implicitGate = hasImplicitActorGate(agentSteps, nonWriteStar);
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
  if (!severity) severity = 'advisory';

  // Build the transparent record of WHY this severity.
  const signals: string[] = [];
  if (secretExposed)
    signals.push(
      `runs with base-repo secrets (${triggers.filter((t) => /target|workflow_run/i.test(t)).join(', ')})`
    );
  else if (forkInput) signals.push(`triggered by untrusted input (${triggers.join(', ')})`);
  if (head === 'root') signals.push('checks out the untrusted PR head into the workspace root');
  if (head === 'subdir') signals.push('checks out the untrusted PR head into an isolated subdir');
  if (promptUntrusted) signals.push('feeds untrusted PR/issue text to the agent');
  if (broadTools) signals.push('agent has broad/write-capable tools (Bash/Write/curl/git push)');
  if (nonWriteStar) signals.push('allowed_non_write_users: "*" — any user can trigger the agent');
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
      head === 'root'
        ? 'Do not check out the PR head into the workspace root under pull_request_target — check out the base ref, or isolate the head in a subdir (--add-dir). Add an actor gate and scope the agent tools.'
        : 'Add/verify an actor gate, scope the agent tools to read-only, and env-deny secrets. See Anthropic’s claude-code-action security doc.',
  };
}
