// src/ci-check/workflows.ts
// CI-2 — the agentic-workflow analyzer. THE differentiator (see the design doc
// §4.5): the same "pull_request_target + agent" shape can be critical (untrusted
// head to workspace root, no actor gate) or safe (label-gated, base checkout,
// scoped tools). A regex flags them identically and cries wolf; this models
//   danger = reachability(untrusted → agent) × power(tools/secrets) × exposure
// then applies the actor gate and mitigations. Static + parse-only.

import { explainAgentOutputEnv, explainSecrets, explainWorkflow } from './explain';
import { agentOutputSinks } from './env-sink';
import { parseYamlStrict as parseYaml } from './yaml-strict';
import { parseFrontmatter } from './frontmatter';
import { lineOf, lineOfNth, lineOfRe, withLine } from './lines';
import type { CiFinding, Severity } from './types';
import { SEVERITY_RANK } from './types';
import { safeText } from './suppress';
import { sanitizedListing } from './listing';

// Known agent actions — a step using one of these runs an LLM with tools.
const AGENT_ACTION_RE =
  /(anthropics\/claude-code(-base)?-action|anthropics\/claude-code|^\s*[\w.-]{1,100}\/claude-code-action@|openai\/codex|codex-action|run-?aider|aider-?action|google-github-actions\/run-gemini)/i;

// Broad, write/exfil-capable tool grants (bare or dangerous verbs).
// A10 (fw#481): `gh` with no fixed subcommand (`Bash(gh:*)`, `Bash(gh *)`, `Bash(gh)`) runs any
// subcommand, `gh extension install` and `gh api` writes included; `gh api` with no fixed endpoint
// (`Bash(gh api:*)`, `Bash(gh api *)`) is the whole REST API with the job's token. A grant that
// names an endpoint (`Bash(gh api repos/o/r/pulls/1/comments:*)`) is not counted here.
const BROAD_TOOL_RE =
  /(^|["\s,])(Bash|Write|Edit)(\s|,|"|$)|Bash\(\s*\*|Bash\((curl|wget|git push|git commit|git config|git:|rm|sh|bash|eval|npx|pip)|Bash\(\s*gh\s*(?::|\*|\))|Bash\(\s*gh\s+api\s*(?::\s*\*|\*|\))/i;

// EXFIL/RCE tools: genuinely arbitrary shell or network egress — the tools that
// let an injected agent steal secrets or run code. Deliberately NARROWER than
// BROAD_TOOL_RE: it EXCLUDES scoped script invocations (`Bash(bash scripts/x.sh)`,
// `Bash(python3 x.py *)`, `Bash(gh api *)`) and bare `Write`/`Edit` (which write
// files but can't exfil on their own). Used by the F11 damage-capability cap.
// A10: an unrestricted `gh` grant runs code (`gh extension install` downloads and runs an
// extension), so it is here. `Bash(gh api…)` is not: it reaches only GitHub, and its damage is
// judged by the token (GH_WRITE_TOOL_RE, EGRESS_TOOL_RE).
const EXFIL_RCE_RE =
  /(^|["\s,])Bash(\s|,|"|$)|Bash\(\s*\*|Bash\((curl|wget|sh[\s):]|eval|rm[\s):]|git push)|Bash\(\s*gh\s*(?::|\*|\))/i;

// A tool that can MODIFY GitHub — needed (alongside a write token) to abuse write
// permissions. `Bash(gh api …)` is arbitrary API; the enumerated pr/issue verbs
// are the write ones (view/diff/list are reads); `git push` / `Bash(git:*)` can
// push. Used by the F12 damage-capability check.
const GH_WRITE_TOOL_RE =
  /Bash\(\s*(gh api|gh:|gh (pr|issue) (comment|edit|merge|close|review|create|ready|lock|reopen)|gh (pr|issue)\s*[:*)]|git push|git:)/i;

// N2/P2: a tool through which a write token or a PAT reaches code: git push, any git,
// unrestricted gh or gh api, gh pr merge (also inside an unrestricted `gh pr` grant), the GitHub
// MCP server's file, branch and merge writes. A scoped grant (`Bash(gh issue:*)`,
// `Bash(gh api:repos/*/issues:*)`, `Bash(gh pr comment:*)`) does not.
const CODE_TOOL_RE =
  /Bash\(\s*(git push|git\s*:|git\s+\*|gh\s*(?::|\*|\))|gh\s+api\s*(?::\s*\*|\*|\))|gh pr merge|gh\s+pr\s*(?::|\*|\)))|mcp__github__(merge_pull_request|create_or_update_file|push_files|delete_file|create_branch)|mcp__github_file_ops__/i;
// N2: the GitHub MCP tools that write text where others read it (a comment, an issue, a review),
// including claude-code-action's own comment tools. Read tools (`get_*`, `list_*`) are not here.
const MCP_GH_TEXT_WRITE_RE =
  /mcp__github(?:_inline_comment|_comment)?__(?:create|update|add|submit)_\w+/i;
// N2: a grant that only sets labels: a label flag pinned in the grant
// (`Bash(gh issue edit 12 --add-label:*)`), the labels API path, a label MCP tool. It changes no
// text that people read, so it is not a write channel. Not modelled: a trailing wildcard after
// the label flag also lets `--body` through.
const LABEL_ONLY_TOOL_RE = /--(?:add|remove)-label\b|\/labels\b|mcp__\w*label/i;

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
  /orgs\/[^/'"\s]+\/memberships\/|teams\/[^/'"\s]+\/memberships\/|getCollaboratorPermissionLevel|collaborators\/[^/'"\s]+\/permission|checkMembershipForUser|getMembershipForUser|\bcheckCollaborator\b/i;
// The plain collaborator CHECK, `GET repos/<repo>/collaborators/<user>`: 204 for a collaborator,
// 404 for anyone else. The user is the LAST path segment, so a listing (`…/collaborators`) is
// not a check, and `…/<user>/permission` stays with the pattern above. A collaborator may hold
// read access only: the same trust as an OWNER/MEMBER/COLLABORATOR association, which is
// already a gate; a stranger is never one.
const COLLABORATOR_CHECK_RE = /collaborators\/[^/'"\s)`;|&]{1,200}(?=['"\s)`;|&]|$)/gi;
// The same path with a write method, or with request fields (`gh api -f` sends a POST), adds or
// removes the collaborator: `-X PUT`, `--method`/`--request`, octokit's `'PUT /repos/…'`.
const API_WRITE_METHOD_RE =
  /(?:-X|--method|--request)[=\s]{0,3}["']?(?:PUT|DELETE|PATCH|POST)\b|\s(?:-[fF]|--field|--raw-field)[=\s]|\b(?:PUT|DELETE|PATCH|POST)\s+\/?repos\b/i;
// octokit's object form names the method on a line of its own, next to the url.
const API_WRITE_OPTION_RE = /\bmethod\s*:\s*["'`](?:PUT|DELETE|PATCH|POST)\b/i;

/** Does this script ask GitHub whether ONE user is a member, a collaborator or a writer? */
function isMembershipCheck(code: string): boolean {
  if (MEMBERSHIP_CHECK_RE.test(code)) return true;
  if (code.length > 200_000) return false;
  for (const m of code.matchAll(COLLABORATOR_CHECK_RE)) {
    const at = m.index ?? 0;
    // The command the path sits in: its own line, bounded.
    const from = Math.max(code.lastIndexOf('\n', at) + 1, at - 300);
    const nl = code.indexOf('\n', at);
    const to = Math.min(nl < 0 ? code.length : nl, at + 300);
    if (API_WRITE_METHOD_RE.test(code.slice(from, to))) continue;
    if (API_WRITE_OPTION_RE.test(code.slice(Math.max(0, at - 300), at + 300))) continue;
    return true;
  }
  return false;
}

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
  /** T.2a: the workflow and job `env:` this step sees (set by normalizeWorkflow). */
  scopeEnv?: Record<string, unknown>;
  /** Does that env carry event context? Computed once per job by normalizeWorkflow. */
  scopeEnvEvent?: boolean;
  /** An earlier step of the job signs in to a cloud (AWS or Google). Set by normalizeWorkflow. */
  cloudAuthBefore?: boolean;
  /** An earlier step of the job writes a model key into `$GITHUB_ENV`, so a CLI started later
   *  has it without its own `env:` (fw#481, a pattern behind a missed agent). Set by
   *  normalizeWorkflow. */
  fuelExportedBefore?: boolean;
}
interface Job {
  if?: string;
  /** A job that calls a reusable workflow has `uses:` and no steps. */
  uses?: string;
  needs?: string | string[];
  permissions?: Record<string, string> | string;
  steps?: Step[];
  env?: Record<string, unknown>;
  /** A GitHub environment: a name, `{ name }`, or an expression that picks one. */
  environment?: unknown;
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
    Record<string, unknown> | undefined;
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
/** T.6.9: labels the repository's issue forms apply to every new issue (lower case), set by
 *  analyzeWorkflow(Secrets) for the duration of one synchronous analysis. A label test on one
 *  of these is not a gate: any stranger who opens an issue from that form carries the label. */
let AUTO_LABELS: ReadonlySet<string> = new Set();

/** The `labels:` an issue form (YAML) or issue template (Markdown front matter) applies. Read
 *  with the YAML parser (a compact `- x` list or a comment after the key hid the label from a
 *  line reader, review round 2); the line reader stays only for a form that does not parse. */
export function issueFormLabels(content: string): string[] {
  const text = content.length > 200_000 ? content.slice(0, 200_000) : content;
  let value: unknown;
  let parsed = false;
  if (/^\uFEFF?\s*---[ \t]*\r?\n/.test(text)) {
    const fm = parseFrontmatter(text);
    parsed = fm !== null;
    value = fm?.['labels'];
  } else {
    try {
      const doc = parseYaml(text);
      parsed = true;
      if (doc && typeof doc === 'object' && !Array.isArray(doc))
        value = (doc as Record<string, unknown>)['labels'];
    } catch {
      /* not strict YAML: the line reader below */
    }
  }
  const raw: unknown[] = parsed
    ? Array.isArray(value)
      ? value
      : typeof value === 'string'
        ? value.split(',')
        : []
    : labelLines(text);
  return raw
    .filter((l): l is string => typeof l === 'string')
    .map((l) =>
      l
        .trim()
        .replace(/^['"]|['"]$/g, '')
        .trim()
        .toLowerCase()
    )
    .filter((l) => l && l.length <= 100);
}

/** `labels: a, b`, `labels: [a, b]` or `labels:` and a `- x` list, line by line. */
function labelLines(text: string): string[] {
  const out: string[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const m = /^labels:[ \t]*([^#]*)/.exec(lines[i]);
    if (!m) continue;
    const inline = m[1].trim();
    if (inline) {
      out.push(...inline.replace(/^\[|\]$/g, '').split(','));
    } else {
      for (let j = i + 1; j < lines.length && /^\s*-\s/.test(lines[j]); j++)
        out.push(lines[j].replace(/^\s*-\s/, '').replace(/\s#.*$/, ''));
    }
  }
  return out;
}

/** T.1 (2026-10-11): a workflow in the same repository that calls a reusable one with
 *  `uses: ./.github/workflows/<file>`, and what its trigger and its calling job let in. */
export interface LocalCaller {
  file: string;
  keys: string[];
  untrusted: boolean;
  secretExposed: boolean;
  privileged: boolean;
  workflowRun: boolean;
  /** The calling job is gated (its own `if:` or its `needs:` chain). */
  gated: boolean;
  /** The calling job runs on an upstream job's output (`needs.<job>.outputs.command == 'x'`),
   *  a dispatcher whose branches a static reader cannot tie to this call. */
  dispatched: boolean;
  /** The caller is itself a reusable template: who reaches it lives one level further up. */
  reusable: boolean;
}

/** The local callers of the workflow being analysed, set by analyzeWorkflow(Secrets) for the
 *  duration of one analysis; triggerReach reads them. */
const CALLERS = new WeakMap<Workflow, LocalCaller[]>();

/** R4-1: the reachability of a workflow's triggers.
 *  - untrusted: some trigger an anonymous outsider can fire.
 *  - reusable: has `workflow_call` and NO stranger-firable trigger of its own — a
 *    reusable definition whose reachability lives in the (unseen) caller. It is scored
 *    as *potentially* untrusted but CAPPED at medium (Review R4-round2 #5), NOT dropped.
 *    NOTE: push/schedule/dispatch-only (no workflow_call) is NOT reusable — it's a
 *    trusted internal trigger and scores nothing (Review R4-round2 #7).
 *  - secretExposed / privileged: ONLY over stranger-firable triggers.
 *  Returns `keys` so callers don't re-parse (Review R4-round2 #9). */
/** F14: a stranger-firable event that runs with the base repository's token and secrets. */
const PRIVILEGED_EVENT_RE =
  /pull_request_target|pull_request_review|workflow_run|issue|discussion/i;

function triggerReach(wf: Workflow, raw: Record<string, unknown>) {
  const on = onObject(wf, raw) ?? {};
  const keys = triggerKeys(wf, raw);
  // T.5b: an `issues` trigger whose gate label an issue form applies to every new issue is
  // fired by whoever opens an issue from that form.
  // A `workflow_run` after workflows that are all in the tree and that no stranger can start
  // (push, schedule, dispatch) is not a stranger's run either (round-2 table check, 2026-10-11).
  const firable = keys.filter(
    (k) =>
      (keyStrangerFirable(on, k) && !(/^workflow_run$/i.test(k) && upstreamRunTrusted(wf, raw))) ||
      (/^issues$/i.test(k) && testsAutoLabel(allIfText(wf)))
  );
  const untrusted = firable.length > 0;
  const reusable = !untrusted && keys.some((k) => /^workflow_call$/i.test(k));
  // T.1: a reusable workflow with local callers takes its reach from them.
  const callers = CALLERS.get(wf);
  // A caller that runs on a dispatcher's output is unresolved: when only such callers are left
  // open, the template keeps the reusable score (a gated dispatcher whose ungated branch never
  // sends this command must not turn into an alert).
  const open = (callers ?? []).filter((c) => c.untrusted && !c.gated && !c.dispatched);
  // A caller that is itself a template (A calls B, B calls C) is unresolved the same way.
  const unresolved = (callers ?? []).some(
    (c) => (c.untrusted && !c.gated && c.dispatched) || (c.reusable && !c.gated)
  );
  if (reusable && callers?.length && (open.length || !unresolved)) {
    return {
      keys: [...new Set(open.flatMap((c) => c.keys))],
      untrusted: open.length > 0,
      reusable: false,
      secretExposed: open.some((c) => c.secretExposed),
      privileged: open.some((c) => c.privileged),
      workflowRun: open.some((c) => c.workflowRun),
    };
  }
  const secretExposed = firable.some((t) => /pull_request_target|workflow_run/i.test(t));
  const privileged = untrusted && firable.some((t) => PRIVILEGED_EVENT_RE.test(t));
  const workflowRun = firable.some((t) => /^workflow_run$/i.test(t));
  return { keys, untrusted, reusable, secretExposed, privileged, workflowRun, firable };
}

/** Job values, dropping null entries. An empty job block (`notify:` with no body) parses
 *  to `null`; a bare `.steps`/`.permissions`/`.if` deref on it throws, and since the caller
 *  (scanTree) try/catches analyzeWorkflow, the throw SILENTLY SUPPRESSES the finding — an
 *  attacker can disable CI-2 for the whole file by adding one empty job. Filter once here. */
function jobList(wf: Workflow): Job[] {
  return Object.values(wf.jobs ?? {}).filter((j): j is Job => j != null);
}

// T.6 (2026-10-10): read the workflow the way the runner does, before any check runs.
const ENV_REF_RE =
  /\$\{\{\s*env(?:\.([A-Za-z_][A-Za-z0-9_]{0,100})|\[\s*['"]([A-Za-z_][A-Za-z0-9_]{0,100})['"]\s*\])\s*\}\}/g;
// A step `env:` may itself read `env` (`TASK: ${{ env.REQUEST }}`): follow a few hops.
const ENV_REF_HOPS = 3;
const RESOLVED_MAX_LEN = 100_000;

/** `${{ env.X }}` in an action input, replaced by X from the step, job or workflow `env:`
 *  (first holder wins, as on the runner). One level only; an unknown name stays as written. */
function resolveEnvRefs(v: string, envs: (Record<string, unknown> | undefined)[]): string {
  const holderOf = (name: string) =>
    envs.find((e) => e != null && typeof e === 'object' && name in e);
  for (let hop = 0; hop < ENV_REF_HOPS && v.includes('env'); hop++) {
    // Measure before building: thousands of references to a large value would otherwise build a
    // string past V8's limit and throw, which dropped every finding of the file (review, round 2).
    let projected = v.length;
    let any = false;
    for (const m of v.matchAll(ENV_REF_RE)) {
      const name = m[1] ?? m[2];
      const holder = holderOf(name);
      if (holder) {
        any = true;
        projected += str(holder[name]).length - m[0].length;
      }
      if (projected > RESOLVED_MAX_LEN) return v;
    }
    if (!any) break;
    v = v.replace(ENV_REF_RE, (whole, a: string | undefined, b: string | undefined) => {
      const name = (a ?? b) as string;
      const holder = holderOf(name);
      return holder ? str(holder[name]) : whole;
    });
  }
  return v;
}

/** A job `if:` that can never be true: `false`, `${{ false }}`, `<expr> && false`. */
function ifNeverTrue(v: unknown): boolean {
  if (v === false) return true;
  if (typeof v !== 'string') return false;
  const never = (x: IfExpr): boolean => {
    switch (x.k) {
      case 'atom':
        return /^false$/i.test(x.t.trim());
      case 'not':
        return false;
      case 'and':
        return x.c.some(never);
      case 'or':
        return x.c.every(never);
    }
  };
  const x = parseIf(v);
  return x !== null && never(x);
}

/** T.6: (1) action inputs are case-insensitive, so every `with:` key is lower-cased
 *  (`GITHUB_TOKEN:` under `with:` arms the "*" bypass); (2) `${{ env.X }}` in a
 *  `with:` value is resolved (a common review template passes its prompt and tools that
 *  way); (3) a job that can never run is dropped (`if: false`). Mutates `raw`. */
function normalizeWorkflow(raw: Record<string, unknown>): Workflow {
  const wf = raw as Workflow;
  const wfEnv = (raw as { env?: Record<string, unknown> }).env;
  const jobs = wf.jobs;
  if (!jobs || typeof jobs !== 'object') return wf;
  const wfEnvEvent = EVENT_CONTEXT_RE.test(str(wfEnv));
  for (const [name, job] of Object.entries(jobs)) {
    if (job == null || typeof job !== 'object') continue;
    if (ifNeverTrue(job.if)) {
      delete jobs[name];
      continue;
    }
    if (!Array.isArray(job.steps)) continue;
    // A YAML alias (`- *agent`) is one object in every job that uses it: copy each step, so one
    // job's env never becomes another's (review, round 2).
    job.steps = job.steps.map((st) =>
      st != null && typeof st === 'object' && !Array.isArray(st) ? { ...st } : st
    );
    const scopeEnv = {
      ...(wfEnv && typeof wfEnv === 'object' ? wfEnv : {}),
      ...(job.env && typeof job.env === 'object' ? job.env : {}),
    };
    // Computed once per job, not on every isAgentStep call (a large env times many steps).
    const scopeEnvEvent = wfEnvEvent || EVENT_CONTEXT_RE.test(str(job.env));
    let cloudAuth = false;
    let fuelExported = false;
    for (const step of job.steps) {
      if (step == null || typeof step !== 'object') continue;
      step.scopeEnv = scopeEnv;
      step.scopeEnvEvent = scopeEnvEvent;
      step.cloudAuthBefore = cloudAuth;
      step.fuelExportedBefore = fuelExported;
      if (CLOUD_AUTH_ACTION_RE.test(str(step.uses))) cloudAuth = true;
      if (FUEL_EXPORT_RE.test(str(step.run).slice(0, 20_000))) fuelExported = true;
      if (step.with == null || typeof step.with !== 'object') continue;
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(step.with)) {
        const key = k.toLowerCase();
        if (key in out) continue;
        out[key] = typeof v === 'string' ? resolveEnvRefs(v, [step.env, job.env, wfEnv]) : v;
      }
      step.with = out;
    }
  }
  return wf;
}

// One parse and one normalisation per file, shared by the analyses that read it in a row
// (analyzeWorkflow, …Secrets, …Plugins, …TrustedReaders, …ForkCodeOnTrust). Throws like
// parseYaml. The analyses only read the normalised workflow.
let LOADED: { content: string; raw: Record<string, unknown>; wf: Workflow } | null = null;
function loadWorkflow(content: string): { raw: Record<string, unknown>; wf: Workflow } {
  if (LOADED !== null && LOADED.content === content) return LOADED;
  const raw = (parseYaml(content) ?? {}) as Record<string, unknown>;
  const wf = raw && typeof raw === 'object' ? normalizeWorkflow(raw) : (raw as Workflow);
  LOADED = { content, raw, wf };
  return LOADED;
}

const LOCAL_WORKFLOW_USES_RE = /^\s*\.\/\.github\/workflows\/([\w.-]{1,200}\.ya?ml)\s*$/i;
// Gap 1: the same repository's workflow called by its full path. Owner and repo are compared
// with the scanned repository's (case-insensitive); another repository stays an external call.
const FULL_WORKFLOW_USES_RE =
  /^\s*([\w.-]{1,100})\/([\w.-]{1,100})\/\.github\/workflows\/([\w.-]{1,200}\.ya?ml)@\S{1,200}\s*$/i;

/** The file a job's `uses:` calls in this tree, or null (external, unknown repository). */
function localTarget(uses: string, self?: { owner?: string; repo?: string }): string | null {
  const m = LOCAL_WORKFLOW_USES_RE.exec(uses);
  if (m) return `.github/workflows/${m[1]}`;
  if (!self?.owner || !self.repo) return null;
  const f = FULL_WORKFLOW_USES_RE.exec(uses);
  if (!f) return null;
  return f[1].toLowerCase() === self.owner.toLowerCase() &&
    f[2].toLowerCase() === self.repo.toLowerCase()
    ? `.github/workflows/${f[3]}`
    : null;
}

/** T.1: the local reusable workflows `content` calls, each with this file as the caller. */
export function localCallsOf(
  path: string,
  content: string,
  autoLabels?: ReadonlySet<string>,
  trustedRunSources?: ReadonlySet<string>,
  self?: { owner?: string; repo?: string }
): { target: string; caller: LocalCaller }[] {
  AUTO_LABELS = autoLabels ?? new Set();
  TRUSTED_RUN_SOURCES = trustedRunSources ?? new Set();
  try {
    return localCallsOfInner(path, content, self);
  } finally {
    AUTO_LABELS = new Set();
    TRUSTED_RUN_SOURCES = new Set();
  }
}

function localCallsOfInner(
  path: string,
  content: string,
  self?: { owner?: string; repo?: string }
): { target: string; caller: LocalCaller }[] {
  let raw: Record<string, unknown>;
  try {
    raw = loadWorkflow(content).raw;
  } catch {
    return [];
  }
  if (!raw || typeof raw !== 'object') return [];
  const wf = raw as Workflow; // normalised by loadWorkflow
  CALLERS.delete(wf); // this file's own triggers, never callers left from another analysis
  const reach = triggerReach(wf, raw);
  const out: { target: string; caller: LocalCaller }[] = [];
  for (const job of jobList(wf)) {
    const target = localTarget(str(job.uses), self);
    if (!target) continue;
    out.push({
      target,
      caller: {
        file: path,
        keys: reach.keys,
        untrusted: reach.untrusted,
        secretExposed: reach.secretExposed,
        privileged: reach.privileged,
        workflowRun: reach.workflowRun,
        gated: jobGated(job, wf, raw),
        dispatched: dispatchedByGatedJob(job, wf, raw),
        reusable: reach.reusable,
      },
    });
  }
  return out;
}

/** Does this calling job run on the output of an upstream dispatcher with a gate on at least
 *  one of its branches? Which branch sends which command is not visible statically, so that is
 *  the "unresolved" case triggerReach keeps at the reusable score. A router with no gate at all
 *  that parses a stranger's comment opens every template it calls (review, round 2). */
function dispatchedByGatedJob(job: Job, wf: Workflow, raw: Record<string, unknown>): boolean {
  const names = [...str(job.if).matchAll(/needs\.([\w-]{1,100})\.outputs\./g)].map((m) => m[1]);
  if (!names.length) return false;
  const jobs = (wf.jobs ?? {}) as Record<string, Job | null>;
  const label = labelTypeConfigured(wf, raw);
  const someBranchGated = (x: IfExpr): boolean => {
    switch (x.k) {
      case 'atom':
        return exprGated(x, label);
      case 'not':
        return false;
      case 'and':
      case 'or':
        return x.c.some(someBranchGated);
    }
  };
  return names.every((n) => {
    const up = jobs[n];
    if (up == null) return false;
    if (jobGated(up, wf, raw)) return true;
    const x = parseIf(str(up.if));
    return x !== null && someBranchGated(x);
  });
}

function allSteps(wf: Workflow): { job: Job; step: Step }[] {
  const out: { job: Job; step: Step }[] = [];
  for (const job of jobList(wf)) {
    for (const step of job.steps ?? []) out.push({ job, step });
  }
  return out;
}

// T.2a (2026-10-11): an agent CLI invoked to do work (not `--version` or an install), or an
// agent SDK script, or a hosted agent's session API.
const AGENT_CLI_RE = new RegExp(
  [
    // The binary at a command start, then its "do work" flag anywhere on the same command
    // (`claude --model x -p`, `claude "$Q" --print`, `npx @anthropic-ai/claude-code -p`): the
    // flag had to come first (review, round 2). Bounded: at most 300 characters per command.
    String.raw`(?:^|[\s|;&(])(?:claude|@anthropic-ai/claude-code(?:@[\w.-]{1,40})?)(?=\s)[^\n;&|]{0,300}?\s(?:-p|--print|--continue|--resume)(?=[\s"'=]|$)`,
    String.raw`(?:^|[\s|;&(])(?:codex|@openai/codex(?:@[\w.-]{1,40})?)(?=\s)[^\n;&|]{0,300}?\sexec\b`,
    String.raw`(?:^|[\s|;&(])(?:gemini|@google/gemini-cli(?:@[\w.-]{1,40})?)(?=\s)[^\n;&|]{0,300}?\s(?:-p|--prompt)(?=[\s"'=]|$)`,
    String.raw`(?:^|[\s|;&(])copilot(?=\s)[^\n;&|]{0,300}?\s(?:-p|--prompt|--allow-all-tools)(?=[\s"'=]|$)`,
    String.raw`\b(?:aider\s|opencode\s+run\b|goose\s+run\b|kilo\s+run\b|pi\s+--print\b|llmproc\s|acpx\s|harbor\s+(?:check|run)\b)`,
    String.raw`api\.devin\.ai/|software-agent-sdk|\bagent_script\.py\b`,
  ].join('|'),
  'i'
);
// A step that hands a model key to the later steps of its job through `$GITHUB_ENV`.
const FUEL_EXPORT_RE =
  /\b(?:ANTHROPIC_API_KEY|ANTHROPIC_AUTH_TOKEN|CLAUDE_CODE_OAUTH_TOKEN|OPENAI_API_KEY|GEMINI_API_KEY)=[^\n]{0,300}>>\s*["']?\$\{?GITHUB_ENV\b/;
// The model credential a run-step agent is started with.
const RUN_FUEL_ENV_RE =
  /^(ANTHROPIC_API_KEY|ANTHROPIC_AUTH_TOKEN|CLAUDE_CODE_OAUTH_TOKEN|OPENAI_API_KEY|GEMINI_API_KEY|GOOGLE_API_KEY|KILO_API_KEY|OPENCODE_API_KEY|DEVIN_API_KEY|LLM_API_KEY|AWS_BEARER_TOKEN_BEDROCK)$/i;
const EVENT_CONTEXT_RE = /github\.event|context\.payload/;
// Gap 2: a CLI that reaches its model through a cloud provider holds no model key of its own.
// It is switched to Bedrock or Vertex by env, or runs after a step that signs in to the cloud.
const CLOUD_MODEL_ENV_RE = /^CLAUDE_CODE_USE_(BEDROCK|VERTEX)$/i;
const CLOUD_AUTH_ACTION_RE =
  /^\s*(aws-actions\/configure-aws-credentials|google-github-actions\/auth)@/i;
// fw#481 S3: a step that signs the job in to a cloud account. With one, `id-token: write` or a
// shell reaches that account; without one, `id-token: write` is only what claude-code-action
// itself asks for to get its GitHub App token.
const CLOUD_LOGIN_RE =
  /^\s*(aws-actions\/configure-aws-credentials|google-github-actions\/auth|azure\/login)@/i;
// Secrets whose loss outlives the job: a cloud key, a token (PAT, registry, publish), a database.
const LASTING_SECRET_KINDS = new Set(['cloud', 'pat', 'db', 'cloud-file']);
// fw#481 S4-b: google-github-actions/auth given a service-account key writes it to a
// `gha-creds-*.json` file in the workspace (unless `create_credentials_file: false`), where an
// agent with a file-read tool finds it without any shell.
const GCP_AUTH_RE = /^\s*google-github-actions\/auth@/i;
const FILE_READ_TOOL_RE = /(^|["\s,])(Read|Grep|Glob|LS|View)(\(|\s|,|"|$)/;

/** The secret a cloud login step leaves as a key file in the workspace before one of `agents`
 *  runs, or null. A login step whose own `if:` is an actor gate does not run for a stranger. */
function workspaceKeyFile(job: Job, agents: Step[], label: LabelConfig): string | null {
  const steps = job.steps ?? [];
  const last = Math.max(-1, ...agents.map((a) => steps.indexOf(a)));
  for (let i = 0; i < last; i++) {
    const st = steps[i];
    if (!GCP_AUTH_RE.test(str(st.uses))) continue;
    const key = str(st.with?.['credentials_json']);
    if (!key.trim()) continue;
    if (/^\s*["']?false["']?\s*$/i.test(str(st.with?.['create_credentials_file']))) continue;
    const cond = str(st.if);
    if (cond.length <= IF_MAX_LEN) {
      const x = cond.trim() ? parseIf(cond) : null;
      if (x !== null && exprGated(x, label)) continue;
    }
    const name = /secrets\.([A-Za-z_][A-Za-z0-9_]{0,100})/.exec(key)?.[1];
    return name ?? 'service-account key';
  }
  return null;
}

/** `CLAUDE_CODE_USE_BEDROCK` / `_VERTEX` set to anything but an off value. */
function cloudModelEnv(env: Record<string, unknown>): boolean {
  return Object.entries(env).some(
    ([k, v]) => CLOUD_MODEL_ENV_RE.test(k) && !/^\s*(0|false|no|off)?\s*$/i.test(str(v))
  );
}

/** A `run:` step that really invokes an agent (not the loose "agent word next to github.event"
 *  heuristic): only its command line and env are read as the agent's prompt and grants. */
function isRunAgent(step: Step): boolean {
  return typeof step.run === 'string' && !step.uses && AGENT_CLI_RE.test(step.run);
}

// T.2b (2026-10-11): an action input that takes a model credential (either spelling).
const FUEL_WITH_KEY_RE =
  /^(anthropic[_-]api[_-]key|anthropic[_-]auth[_-]token|claude[_-]code[_-]oauth[_-]token|claude[_-]oauth[_-]token|openai[_-]api[_-]key|gemini[_-]api[_-]key|google[_-]api[_-]key)$/i;
// An action path (after the owner) that names an agent runtime. The owner is not read:
// `Kilo-Org/lychee-action` is a link checker.
const AGENT_PATH_RE =
  /(?:^|[/_.-])(claude|codex|gemini|opencode|goose|aider|kilo(?:code)?)(?:$|[/_.-])/i;
const PROMPT_INPUT_RE = /^(prompt|direct_prompt|prompt_file|prompt-file|agent)$/i;
// Gap 3: pr-agent (forks keep the repository name; the image form carries a tag) reviews the PR
// or answers the comment that started it, with no model key input of a known name and no prompt
// input. Its commands are not limited to users with write access.
const PR_AGENT_PATH_RE = /(?:^|\/)pr-agent(?::[\w.-]{1,60})?$/i;

/** The action path after the owner (`owner/path@ref` → `path`). */
function actionPath(uses: string): string {
  return uses.replace(/^\s*[^/@\s]{1,100}\//, '').replace(/@.*$/, '');
}

function isPrAgent(step: Step): boolean {
  return !!step.uses && PR_AGENT_PATH_RE.test(actionPath(str(step.uses)).trim());
}

/** T.2b: a wrapper action runs an agent when it is handed a model key, or when its path names
 *  an agent runtime and it takes a prompt (or the job holds a model key). Not the official
 *  claude-code-action, so no implicit actor gate is credited to it. */
function isWrapperAgent(step: Step): boolean {
  const uses = str(step.uses);
  const w = step.with ?? {};
  if (Object.keys(w).some((k) => FUEL_WITH_KEY_RE.test(k))) return true;
  const env = { ...(step.scopeEnv ?? {}), ...(step.env ?? {}) };
  const fuelEnv = Object.keys(env).some((k) => RUN_FUEL_ENV_RE.test(k));
  // `uses: ./…`: the repository's own action (or, after a head checkout, the fork's).
  if (/^\s*\.\//.test(uses)) return fuelEnv; // the job env reaches the action too (review, round 2)
  if (isPrAgent(step)) return true;
  const pathPart = actionPath(uses);
  return (
    AGENT_PATH_RE.test(pathPart) && (Object.keys(w).some((k) => PROMPT_INPUT_RE.test(k)) || fuelEnv)
  );
}

function isAgentStep(step: Step): boolean {
  if (step.uses && AGENT_ACTION_RE.test(step.uses)) return true;
  if (step.uses && isWrapperAgent(step)) return true;
  if (typeof step.run !== 'string' || !step.run) return false;
  // run-step heuristic: an agent CLI fed event context.
  if (/\b(claude|aider|codex|gemini)\b/i.test(step.run) && /github\.event/.test(step.run))
    return true;
  // T.2a: the event text often reaches the CLI through the step or job `env:`, and a CLI
  // started with a model key is an agent whatever its prompt.
  if (!AGENT_CLI_RE.test(step.run)) return false;
  const env = { ...(step.scopeEnv ?? {}), ...(step.env ?? {}) };
  return (
    !!step.scopeEnvEvent ||
    EVENT_CONTEXT_RE.test(str(step.env)) ||
    Object.keys(env).some((k) => RUN_FUEL_ENV_RE.test(k)) ||
    cloudModelEnv(env) ||
    !!step.cloudAuthBefore ||
    !!step.fuelExportedBefore
  );
}

// G-c: pull ONLY the --allowedTools / --allowed-tools value(s) from a claude_args
// blob. Everything else (`--append-system-prompt`, `--model`, free text) is PROSE and
// must NOT reach the tool regexes — else a safety instruction like "never edit code or
// push commits" reads as an Edit/push grant (the luci-theme-family FP). Extracting only
// the grant flag also naturally excludes `--disallowedTools` (never extracted).
function allowedToolsFromArgs(claudeArgs: string): string {
  let out = '';
  for (const m of claudeArgs.matchAll(/--allowed[-_]?tools(?:=|\s+)/gi)) {
    // fw#481 L1-a: the CLI takes every argument up to the next option, so
    // `--allowedTools Read Grep Bash(gh:*) --max-turns 5` grants three tools, and so does
    // `--allowedTools "Bash(git:*)" "Bash(gh:*)"`. Only the first argument was read, which hid
    // an open `gh` next to a PAT. The first argument is taken as before; each further one only
    // when it reads as a tool list, so a prompt written after the flag is not taken for tools.
    const args = cliArgsAfter(claudeArgs, (m.index ?? 0) + m[0].length);
    args.forEach((a, i) => {
      if (i === 0 || TOOL_LIST_ARG_RE.test(a.replace(/^(["'])([\s\S]*)\1$/, '$2'))) out += ' ' + a;
    });
  }
  return out;
}

// One tool grant (`Read`, `mcp__srv__tool`, `Bash(git log:*)`, `WebFetch(domain:x)`), or a
// comma-separated list of them.
const TOOL_GRANT_SRC = String.raw`[A-Za-z_][\w.-]{0,80}(?:\([^()\n]{0,200}\))?`;
const TOOL_LIST_ARG_RE = new RegExp(`^${TOOL_GRANT_SRC}(?:\\s*,\\s*${TOOL_GRANT_SRC}){0,100}$`);

/** The shell-like arguments that follow `from`, up to the next option (`-x`, `--x`), a shell
 *  operator, or the end of the command. A quoted argument is one argument; an unquoted
 *  `Bash(git log:*)` keeps its parenthesised part whole. A `\` line continuation is skipped.
 *  At most 50 arguments: a real tool list is short. */
function cliArgsAfter(text: string, from: number): string[] {
  const out: string[] = [];
  let i = from;
  const n = Math.min(text.length, from + 20_000);
  while (i < n && out.length < 50) {
    while (i < n && /[ \t]/.test(text[i])) i++;
    if (text[i] === '\\' && (text[i + 1] === '\n' || text[i + 1] === '\r')) {
      i += text[i + 1] === '\r' && text[i + 2] === '\n' ? 3 : 2;
      continue;
    }
    if (i >= n || /[\n\r;|&)]/.test(text[i]) || text[i] === '-') break;
    let j = i;
    if (text[i] === '"' || text[i] === "'") {
      const q = text[i];
      j = text.indexOf(q, i + 1);
      if (j < 0) j = n - 1;
      j++;
    } else {
      let paren = false;
      while (j < n) {
        const c = text[j];
        if (c === '(') paren = true;
        else if (c === ')') {
          if (!paren) break;
          paren = false;
        } else if (!paren && /[\s;|&]/.test(c)) break;
        j++;
      }
    }
    if (j <= i) break;
    out.push(text.slice(i, j));
    i = j;
  }
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

const GEMINI_ACTION_RE = /(?:^|\/)run-?gemini-cli(?:@|$)/i;

function isGeminiStep(st: Step): boolean {
  return GEMINI_ACTION_RE.test(str(st.uses).trim());
}

// C4-a: run-gemini-cli's built-in tools, mapped to the Claude names the tool rules read.
const GEMINI_TOOL_NAMES: Record<string, string> = {
  write_file: 'Write',
  replace: 'Edit',
  web_fetch: 'WebFetch',
  google_web_search: 'WebSearch',
};

/** C4-a: the tool list in run-gemini-cli `settings` (`coreTools`, or `tools.core`), as grants
 *  the tool rules read: `run_shell_command(gh issue edit)` becomes `Bash(gh issue edit:*)`, a
 *  bare `run_shell_command` becomes `Bash`, read tools add nothing. null when the settings
 *  hold no list: the tool policy is then unknown, not empty. */
function geminiToolGrants(settings: string): string | null {
  if (!settings.trim() || settings.length > 100_000) return null;
  let cfg: unknown;
  try {
    cfg = JSON.parse(settings);
  } catch {
    return null; // an expression or malformed JSON: unknown, none invented
  }
  if (!cfg || typeof cfg !== 'object') return null;
  const c = cfg as Record<string, unknown>;
  const tools =
    c['tools'] && typeof c['tools'] === 'object' ? (c['tools'] as Record<string, unknown>) : {};
  const list = Array.isArray(c['coreTools'])
    ? c['coreTools']
    : Array.isArray(tools['core'])
      ? tools['core']
      : null;
  if (!list) return null;
  const out: string[] = [];
  for (const raw of list.slice(0, 500)) {
    if (typeof raw !== 'string') continue;
    const t = raw.trim();
    const shell = /^run_shell_command(?:\(([^)]*)\))?$/i.exec(t);
    if (shell) {
      const cmd = (shell[1] ?? '').trim();
      out.push(cmd ? `Bash(${cmd}:*)` : 'Bash');
      continue;
    }
    const name = GEMINI_TOOL_NAMES[t.toLowerCase()];
    if (name) out.push(name);
  }
  return out.join(' ');
}

/** All tool grants declared for the agent steps — ONLY from real tool-grant sources
 *  (`--allowedTools`, the `allowed_tools`/`allowedTools` keys, `settings.allowedTools`),
 *  never prose. See G-c. */
function collectTools(steps: Step[]): string {
  let s = '';
  for (const st of steps) {
    const w = st.with ?? {};
    const args = str(w['claude_args']) + ' ' + str(w['codex-args']) + ' ' + str(w['codex_args']);
    s += ' ' + allowedToolsFromArgs(args);
    // `with:` keys are lower-cased by normalizeWorkflow.
    s += ' ' + str(w['allowed_tools']) + ' ' + str(w['allowedtools']);
    // fw#481 L5: a wrapper around an agent CLI often takes the list as `tools:` (or
    // `allowed-tools:`). Read only on a recognised wrapper, never on an arbitrary action.
    if (st.uses && isWrapperAgent(st)) s += ' ' + str(w['tools']) + ' ' + str(w['allowed-tools']);
    s += ' ' + allowedToolsFromSettings(str(w['settings']));
    if (isGeminiStep(st)) s += ' ' + (geminiToolGrants(str(w['settings'])) ?? '');
    // T.2a: skipping permissions makes any allow list moot: an unrestricted shell.
    if (PERMISSION_BYPASS_RE.test(args) || /^danger-full-access$/i.test(str(w['sandbox'])))
      s += ' Bash';
    if (st.run && isRunAgent(st)) {
      s += ' ' + allowedToolsFromArgs(st.run);
      if (PERMISSION_BYPASS_RE.test(st.run)) s += ' Bash';
      s += ' ' + permissionEnvGrants({ ...(st.scopeEnv ?? {}), ...(st.env ?? {}) });
    }
  }
  // fw#481 L1-b (founder, 2026-11-18): the legacy colon form `Bash:*` is read as the
  // unrestricted shell it was meant to grant. What the current CLI does with it is not
  // documented; reading it as nothing would hide a shell the author asked for.
  return s.replace(LEGACY_BASH_ALL_RE, '$1Bash');
}

const LEGACY_BASH_ALL_RE = /(^|["'\s,\[])Bash:\*(?=["'\s,\]]|$)/g;

const PERMISSION_BYPASS_RE =
  /--dangerously-skip-permissions|--permission-mode[=\s]+["']?bypassPermissions|--dangerously-bypass-approvals-and-sandbox|--allow-all-tools|--yolo\b|(?:\s-s|--sandbox)[=\s]+["']?danger-full-access/i;

/** T.2a: opencode / Kilo take their tool policy as JSON in an env var. `"bash": "allow"` or a
 *  `"*": "allow"` pattern is an unrestricted shell; any other allowed pattern is a scoped
 *  `Bash(<command>:*)` grant; `"webfetch": "allow"` is network egress. */
function permissionEnvGrants(env: Record<string, unknown>): string {
  let out = '';
  for (const key of ['OPENCODE_PERMISSION', 'KILO_PERMISSION']) {
    const raw = str(env[key]);
    if (!raw || raw.length > 20_000) continue;
    let cfg: unknown;
    try {
      cfg = JSON.parse(raw);
    } catch {
      continue; // an expression or malformed JSON: no grant read, none invented
    }
    if (!cfg || typeof cfg !== 'object') continue;
    const c = cfg as Record<string, unknown>;
    const bash = c['bash'];
    if (bash === 'allow') out += ' Bash';
    else if (bash && typeof bash === 'object') {
      for (const [pat, v] of Object.entries(bash as Record<string, unknown>)) {
        if (v !== 'allow') continue;
        const cmd = pat.replace(/\*+\s*$/, '').trim();
        out += cmd ? ` Bash(${cmd}:*)` : ' Bash';
      }
    }
    if (c['webfetch'] === 'allow') out += ' WebFetch';
  }
  return out;
}

/** Split a collected-tools blob into individual grant tokens. Grants are comma/space
 *  separated; a `Bash(...)` group may itself contain a comma, so we DON'T split inside
 *  parens — tracked as a boolean toggle (NOT a depth counter) so an unbalanced paren in
 *  one malformed grant can't swallow every following grant into one token. Each token is
 *  stripped of the syntax cruft the extractors leave behind (JSON array brackets/quotes
 *  from `settings.allowedTools`, wrapping quotes from `--allowedTools`) and of any char
 *  that could break out of the code span the signal renders it in (backtick, newline). */
function toolTokens(blob: string): string[] {
  const out: string[] = [];
  let buf = '';
  let inParen = false;
  const flush = () => {
    const t = buf.replace(/[[\]"'`\r\n]/g, '').trim();
    if (t) out.push(t);
    buf = '';
  };
  for (const ch of blob) {
    if (ch === '(') inParen = true;
    else if (ch === ')') inParen = false;
    if (!inParen && (ch === ',' || /\s/.test(ch))) {
      flush();
      continue;
    }
    buf += ch;
  }
  flush();
  return out;
}

/** The SPECIFIC grant(s) that make a tool-set "broad" (each individually matches
 *  BROAD_TOOL_RE), deduped + readable. The signal names what actually fired — never a
 *  canned exemplar that could list tools the workflow doesn't grant (the honesty fix:
 *  a finding must not misdescribe the file). Dedup keys on the FULL token so two long
 *  grants that share a 40-char prefix aren't collapsed; truncation is display-only. */
function matchedBroadTools(blob: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const tok of toolTokens(blob)) {
    // Wrap in delimiters so BROAD_TOOL_RE's bare-name branch can anchor on a lone token.
    if (!BROAD_TOOL_RE.test(`,${tok},`)) continue;
    if (seen.has(tok)) continue;
    seen.add(tok);
    out.push(tok.length > 40 ? tok.slice(0, 40) + '…' : tok);
  }
  return out;
}

/** Where (if anywhere) an untrusted PR head is checked out. 'root' = into the
 *  workspace (dangerous under pull_request_target); 'subdir' = isolated path.
 *  Takes a step list so callers can scope it to a single job (CI-4 per-job). */
// T.7 (2026-10-11): the PR head also arrives by `refs/pull/<n>/head|merge`, by `gh pr checkout`,
// and by fetching `pull/<n>/head` and checking it out in a run step.
const GH_PR_CHECKOUT_RE = /\bgh\s+pr\s+checkout\b/;
const FETCH_PULL_RE = /\bgit\s+fetch\b[^\n]{0,200}\bpull\/[^\s/]{1,80}\/(?:head|merge)\b/;
const GIT_CHECKOUT_RE = /\bgit\s+(?:checkout|switch)\b/;
/** Linear (the one-regex form was quadratic on a run of newlines, review round 2). */
function runChecksOutHead(run: string): boolean {
  if (GH_PR_CHECKOUT_RE.test(run)) return true;
  const m = FETCH_PULL_RE.exec(run);
  return m !== null && GIT_CHECKOUT_RE.test(run.slice(m.index));
}

function untrustedHeadCheckout(steps: Step[]): 'root' | 'subdir' | null {
  for (const step of steps) {
    if (!step.uses && typeof step.run === 'string' && runChecksOutHead(step.run)) return 'root';
    if (!step.uses || !/actions\/checkout/.test(step.uses)) continue;
    const ref = str(step.with?.['ref']);
    if (/refs\/pull\//.test(ref)) return step.with?.['path'] ? 'subdir' : 'root';
    // Also catch reusable-workflow inputs that carry the fork head
    // (inputs.expected_head_sha / inputs.head_ref), not just github.event.*.
    if (
      /pull_request\.head|head[._-]sha|head_ref|expected_head|workflow_run\.head|inputs(?:\.|\[\s*['"])[\w-]*head/i.test(
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
      str(st.with?.['prompt']) +
      ' ' +
      str(st.with?.['direct_prompt']) +
      ' ' +
      collectTools([st]) +
      // T.2a: a run-step agent's prompt is its command line and the env it reads.
      (isRunAgent(st) ? ' ' + st.run + ' ' + str(st.env) + ' ' + str(st.scopeEnv) : '');
    if (/github\.event\.(issue|comment|pull_request|review)\.(body|title)/i.test(blob)) return true;
    // A review command over a fork PR reads the untrusted diff.
    // A command, not a path: `.git/review-policy.diff` is not `/review` (surfaced once
    // T.6 resolved `${{ env.X }}` into the prompt).
    if (/pull_request\.number|(?<![\w./-])\/(?:code-)?review(?![\w-])/i.test(blob)) return true;
  }
  return false;
}

// S.1 (2026-10-09): untrusted text that reaches the agent WITHOUT sitting in its prompt.
// The issue-triage and dedupe templates pass the item NUMBER (or nothing) and let the agent
// fetch the text itself, or an earlier step writes the body into a prompt file. 216 hand-
// verified misses on 2.27.0 included ~60 of this shape.
//
// A tool that reads issues/PRs (the triggering one, or any one an injected agent names).
const ITEM_READ_TOOL_RE =
  /mcp__github__(get_issue|get_issue_comments|get_pull_request|get_pull_request_diff|get_pull_request_files|get_pull_request_comments|get_pull_request_reviews|search_issues|list_issues)\b|Bash\(\s*gh\s+(issue|pr)\s+(view|diff|list)\b|Bash\(\s*gh\s+(api|search)\b|Bash\(\s*gh\s*:/i;
// The handle an agent dereferences: the triggering item's number or comment id.
const ITEM_HANDLE_RE =
  /github\.event\.(issue|pull_request|discussion)\.number|github\.event\.number\b|github\.event\.comment\.id/i;
// Attacker-writable text, in workflow expression or github-script form.
const PAYLOAD_TEXT_RE =
  /github\.event\.(issue|comment|pull_request|review|discussion)\.(body|title)|context\.payload\.(issue|comment|pull_request|review|discussion)\b|GITHUB_EVENT_PATH|github\.event_path/i;

/** How (if at all) the agent in this job reads the untrusted item other than through its
 *  prompt text: a read tool, the item's handle, or a prompt file an earlier step built from
 *  the payload. Job-scoped: an earlier step only feeds an agent step of the same job. */
// T.4 (2026-10-11): a step that brings the triggering run's artifacts into the job. On a
// workflow_run of a fork PR's workflow, those files are the fork's.
const RUN_ARTIFACT_RE =
  /gh\s+run\s+download\b|\/runs\/\$\{\{\s*github\.event\.workflow_run\.id\s*\}\}\/(?:artifacts|logs)/i;
/** T.4 (review, round 2): the names of this tree's workflows that no stranger can start, set for
 *  one analysis. Artifacts of a run of one of them were not produced by a PR. */
let TRUSTED_RUN_SOURCES: ReadonlySet<string> = new Set();
let UPSTREAM_TRUSTED = false;

/** C6-c: which GitHub environments of this repository require a reviewer, when the reader could
 *  ask GitHub (hosted scan, Action). null = not read: the scan cannot see the rule. */
export interface EnvironmentInfo {
  protected: ReadonlySet<string>;
}
let ENVIRONMENTS: EnvironmentInfo | null = null;

// fw#481 L6: the allow lists of the repository's own committed `.claude/settings.json` and
// `.claude/settings.local.json`, set by scanTree for the length of one scan. claude-code-action
// loads user, project and local settings (its SDK option `settingSources`, v1.0.269), and on PR
// events it restores `.claude/` from the base branch, which is this same committed copy. So an
// agent step of the action that runs in a checkout of the repository gets these grants on top of
// its `--allowedTools` (founder, 2026-11-18: read as additive, as every CLI release we know).
let COMMITTED_ALLOW = '';
export function setCommittedAgentAllow(grants: string): void {
  COMMITTED_ALLOW = grants.slice(0, 20_000);
}

/** The committed grants an agent step of this job picks up: an official claude-code-action or
 *  base-action step, after a checkout into the workspace root, that does not narrow the
 *  settings sources to exclude the project. */
function committedGrantsFor(job: Job, steps: Step[]): string {
  if (!COMMITTED_ALLOW) return '';
  const all = job.steps ?? [];
  for (const st of steps) {
    const claude =
      !!claudeActionBuild(st.uses)?.official || CLAUDE_BASE_ACTION_RE.test(str(st.uses));
    if (!claude || settingSourcesSkipProject(str(st.with?.['claude_args']))) continue;
    const k = all.indexOf(st);
    const checkedOut = all.some(
      (c, n) =>
        n < k && /^\s*actions\/checkout@/i.test(str(c.uses)) && !str(c.with?.['path']).trim()
    );
    if (checkedOut) return COMMITTED_ALLOW;
  }
  return '';
}

const ENV_BY_EVENT_RE =
  /^\$\{\{\s*github\.event_name\s*==\s*'([\w-]{1,60})'\s*&&\s*'([^']{0,200})'\s*\|\|\s*'([^']{0,200})'\s*\}\}$/i;

/** C6-c: the environment a job runs in on event `ev`. A literal name, or the name an expression of
 *  the form `github.event_name == 'x' && 'name' || 'other'` picks for that event. '' = none,
 *  null = an expression the scan cannot read. */
function jobEnvironmentOn(job: Job, ev: string): string | null {
  const e = job.environment;
  const v = e && typeof e === 'object' ? (e as Record<string, unknown>)['name'] : e;
  if (v == null) return '';
  const s = str(v).trim();
  if (!s.includes('${{')) return s;
  const m = ENV_BY_EVENT_RE.exec(s);
  if (!m) return null;
  return m[1].toLowerCase() === ev ? m[2].trim() : m[3].trim();
}

/** C6-c: on event `ev`, does this job wait for a reviewer's approval before it runs? */
function environmentHoldsOn(job: Job, ev: string): boolean {
  if (!ENVIRONMENTS) return false;
  const name = jobEnvironmentOn(job, ev);
  return !!name && ENVIRONMENTS.protected.has(name);
}

/** C6-c: every environment name an agent job of this workflow may run in (literal names, and the
 *  quoted names inside an environment expression), for the reader to ask GitHub about. */
export function agentJobEnvironmentNames(content: string): string[] {
  let wf: Workflow;
  try {
    wf = loadWorkflow(content).wf;
  } catch {
    return [];
  }
  const out = new Set<string>();
  for (const job of jobList(wf))
    if ((job.steps ?? []).some(isAgentStep)) for (const n of jobEnvironmentNames(job)) out.add(n);
  return [...out].slice(0, 50);
}

/** The environment names a job may run in: a literal, or both names of an event expression. */
function jobEnvironmentNames(job: Job): string[] {
  const e = job.environment;
  const v = str(e && typeof e === 'object' ? (e as Record<string, unknown>)['name'] : e).trim();
  if (!v) return [];
  if (!v.includes('${{')) return [v];
  const m = ENV_BY_EVENT_RE.exec(v);
  return m ? [m[2].trim(), m[3].trim()].filter(Boolean) : [];
}

/** Does every workflow this one runs after (`workflow_run.workflows`) belong to the tree and run
 *  on no stranger-firable trigger? */
function upstreamRunTrusted(wf: Workflow, raw: Record<string, unknown>): boolean {
  const on = onObject(wf, raw);
  const run = on?.['workflow_run'] as { workflows?: unknown } | undefined;
  const names = Array.isArray(run?.workflows) ? run.workflows.map(String) : [];
  return names.length > 0 && names.every((n) => TRUSTED_RUN_SOURCES.has(n));
}

/** fw#481 L2-a: labels that automation adds, on an event a stranger starts, with a token that
 *  is not the job's default one (a PAT or an App token). Unlike a label made with
 *  `GITHUB_TOKEN`, such a label starts the workflows that listen for it, so it is no gate, like
 *  a label an issue form applies (T.6.9). Literal names only: a computed label is not followed.
 *  Read by scanTree before the analyses. */
export function automationLabelsOf(path: string, content: string): string[] {
  let raw: Record<string, unknown>;
  try {
    raw = loadWorkflow(content).raw;
  } catch {
    return [];
  }
  if (!raw || typeof raw !== 'object') return [];
  const wf = raw as Workflow;
  CALLERS.delete(wf);
  if (!triggerReach(wf, raw).untrusted) return [];
  const out = new Set<string>();
  for (const job of jobList(wf)) {
    if (jobGated(job, wf, raw)) continue;
    const jobEnv = str(job.env);
    for (const st of job.steps ?? []) {
      const code = str(st.run) + ' ' + str(st.with?.['script']);
      if (code.length > 200_000 || !/add-?label|addLabels|labels\s*:/i.test(code)) continue;
      const token =
        str(st.env?.['GH_TOKEN']) +
        ' ' +
        str(st.env?.['GITHUB_TOKEN']) +
        ' ' +
        str(st.with?.['github-token']) +
        ' ' +
        jobEnv;
      if (
        !/secrets\.(?!GITHUB_TOKEN\b)[A-Za-z_]|steps\.[\w-]+\.outputs\.token|env\.\w*(?:PAT|APP|BOT)\w*TOKEN/i.test(
          token
        )
      )
        continue;
      for (const m of code.matchAll(/--add-label[=\s]+["']?([^"'\n]{1,200})/gi))
        for (const l of m[1].split(',')) if (l.trim()) out.add(l.trim());
      for (const m of code.matchAll(/labels\s*:\s*\[([^\]]{0,500})\]/gi))
        for (const q of m[1].matchAll(/["'`]([^"'`]{1,100})["'`]/g)) out.add(q[1]);
      if (out.size > 200) return [...out];
    }
  }
  return [...out];
}

/** T.4: a workflow's name for `workflow_run.workflows` (its `name:`, else its path), and
 *  whether a stranger can start it. Read by scanTree before the analyses. */
export function runSourceOf(
  path: string,
  content: string,
  autoLabels?: ReadonlySet<string>
): { name: string; trusted: boolean } | null {
  AUTO_LABELS = autoLabels ?? new Set();
  try {
    let raw: Record<string, unknown>;
    try {
      raw = loadWorkflow(content).raw;
    } catch {
      return null;
    }
    if (!raw || typeof raw !== 'object') return null;
    const wf = raw as Workflow;
    CALLERS.delete(wf);
    const reach = triggerReach(wf, raw);
    const name = typeof raw['name'] === 'string' && raw['name'] ? (raw['name'] as string) : path;
    return { name, trusted: !reach.untrusted && !reach.reusable };
  } finally {
    AUTO_LABELS = new Set();
  }
}

function downloadsRunArtifacts(st: Step): boolean {
  if (UPSTREAM_TRUSTED) return false;
  if (/actions\/download-artifact/i.test(str(st.uses)))
    return /workflow_run\.id/.test(str(st.with?.['run-id']) + ' ' + str(st.with?.['run_id']));
  return RUN_ARTIFACT_RE.test(str(st.run) + ' ' + str(st.with?.['script']));
}
const STEP_OUTPUT_REF_RE = /steps\.([\w-]{1,100})\.outputs\./g;

type ItemRead = 'tool' | 'handle' | 'prompt-file' | 'artifact' | 'step-output';

function jobReadsUntrustedItem(job: Job): ItemRead | null {
  const steps = job.steps ?? [];
  const agent = steps.filter(isAgentStep);
  if (!agent.length) return null;
  if (ITEM_READ_TOOL_RE.test(collectTools(agent))) return 'tool';
  // pr-agent reads the PR or comment that started it from the event itself.
  if (agent.some(isPrAgent)) return 'handle';
  for (const st of agent)
    if (
      ITEM_HANDLE_RE.test(
        str(st.with) +
          ' ' +
          str(st.env) +
          ' ' +
          str(job.env) +
          ' ' +
          (isRunAgent(st) ? str(st.run) : '')
      )
    )
      return 'handle';
  for (let i = 0; i < steps.length; i++) {
    const st = steps[i];
    // `prompt_file` (claude-code-action) or `prompt-file` (openai/codex-action).
    if (!isAgentStep(st) || !str(st.with?.['prompt_file'] ?? st.with?.['prompt-file'])) continue;
    const earlier = steps.slice(0, i).filter((p) => !isAgentStep(p));
    if (
      earlier.some((p) => PAYLOAD_TEXT_RE.test(str(p.run) + ' ' + str(p.with) + ' ' + str(p.env)))
    )
      return 'prompt-file';
  }
  // T.4: the triggering run's artifacts land in the workspace before an agent step runs.
  const firstDownload = steps.findIndex(downloadsRunArtifacts);
  if (firstDownload >= 0 && steps.slice(firstDownload + 1).some(isAgentStep)) return 'artifact';
  // T.4: the prompt is an earlier step's output, and that step handled payload text.
  for (let i = 0; i < steps.length; i++) {
    const st = steps[i];
    if (!isAgentStep(st)) continue;
    const input =
      str(st.with?.['prompt']) +
      ' ' +
      str(st.with?.['direct_prompt']) +
      ' ' +
      str(st.with?.['prompt_file'] ?? st.with?.['prompt-file']);
    // Each referenced step once (review, round 2: K references to one large step cost K x S).
    const ids = new Set<string>();
    for (const m of input.matchAll(STEP_OUTPUT_REF_RE)) ids.add(m[1]);
    for (const id of ids) {
      const src = steps.slice(0, i).find((p) => p.id === id);
      if (src && PAYLOAD_TEXT_RE.test(str(src.run) + ' ' + str(src.with) + ' ' + str(src.env)))
        return 'step-output';
    }
  }
  return null;
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
// in jobActorGate; there is no whole-workflow gate test any more) — a step output is produced in ONE job, so
// crediting it workflow-wide would let a gated job mask an ungated sibling (the R2-1 bug).
// Linear form (review, round 2): `[\w-]*(keyword)[\w-]*` around the identifier backtracked
// quadratically on a long one. Match the identifier once, then look for the keyword inside it.
const PERMISSION_OUTPUT_RE =
  /steps\.[\w-]{1,100}\.outputs\.([\w-]{1,200})\s*==\s*['"]?(?:true|admin|write|maintain)/gi;
const PERMISSION_OUTPUT_NAME_RE =
  /permission|allowed|authoriz|is[_-]?(?:admin|member|maintainer|collaborator)/i;
const PERMISSION_OUTPUT_GATE_RE = {
  test(ifs: string): boolean {
    for (const m of ifs.matchAll(PERMISSION_OUTPUT_RE))
      if (PERMISSION_OUTPUT_NAME_RE.test(m[1])) return true;
    return false;
  },
};
// A contains()-based inclusion of a privileged set — one level of nested parens for
// `contains(fromJson('[…]'), …)`. POLARITY: `contains(…)` is a positive inclusion (gate), but
// `!contains(…)` runs for everyone EXCEPT the set (an anti-gate) — credit only the former.
const CONTAINS_GATE_RE =
  /contains\((?:[^()]|\([^()]*\))*(login|actor|association|OWNER|MEMBER|COLLABORATOR)/i;
const NEGATED_CONTAINS_RE =
  /!\s*\(?\s*contains\((?:[^()]|\([^()]*\))*(login|actor|association|OWNER|MEMBER|COLLABORATOR)/i;

// C6-a: an allow-list of numeric user IDs (or the triggering actor) written as a LITERAL list:
// `contains(fromJSON('[1001,1002]'), github.event.pull_request.user.id)`. Read on masked text,
// so the list is `fromJSON('_')`. A list in `vars.*` can hold anything and is not credited.
const ID_ALLOWLIST_G =
  /contains\(\s*fromJSON\(\s*'[^']*'\s*\)\s*,\s*github\.(?:event\.(?:pull_request|issue|comment|review|sender)(?:\.user)?\.id|actor_id|triggering_actor)\s*\)/gi;
// The same identity compared with a number: `github.actor_id == 1001`.
const ID_EQUALS_RE = /\b(?:actor_id|user\.id|sender\.id)\s*==\s*\d{1,20}\b/i;

function idAllowListGate(masked: string): boolean {
  if (ID_EQUALS_RE.test(masked)) return true;
  for (const m of masked.matchAll(ID_ALLOWLIST_G)) {
    const before = masked.slice(Math.max(0, (m.index ?? 0) - 10), m.index ?? 0);
    if (!/!\s*\(?\s*$/.test(before)) return true; // `!contains(…)` admits everyone else
  }
  return false;
}

/** Which label gates a workflow's triggers make meaningful. F14a: a PR label counts on
 *  pull_request_target OR pull_request with `types: [labeled]` (a backport resolver gates a
 *  `pull_request: types:[labeled]` job on the label name). T.6.9: an issue's labels are set by
 *  someone with triage access, but only when `issues` is the sole stranger-firable trigger: on
 *  an `issue_comment` job a labelled issue still takes anyone's comment (review, round 2). */
interface LabelConfig {
  pr: boolean;
  issues: boolean;
}
function labelTypeConfigured(wf: Workflow, raw: Record<string, unknown>): LabelConfig {
  const on = (wf.on ?? raw['on'] ?? raw[true as unknown as string]) as
    Record<string, unknown> | undefined;
  const prTypes = (t: unknown): string[] =>
    t && Array.isArray((t as { types?: unknown }).types)
      ? (t as { types: unknown[] }).types.map(String)
      : [];
  const pr =
    prTypes(on?.['pull_request_target']).includes('labeled') ||
    prTypes(on?.['pull_request']).includes('labeled');
  const onObj = onObject(wf, raw) ?? {};
  const issues =
    on != null &&
    typeof on === 'object' &&
    'issues' in on &&
    triggerKeys(wf, raw).every((k) => /^issues$/i.test(k) || !keyStrangerFirable(onObj, k));
  return { pr, issues };
}

// The label of a `labeled` event, tested positively. `label.name != 'skip-ai'` admits every
// event without that label, an `opened` issue included (review, round 2).
const EVENT_LABEL_GATE_RE =
  /\blabel\.name\s*==\s*'|\b(?:contains|startsWith)\(\s*github\.event\.label\.name\b/i;
// A label already on the issue (not the PR) when the job runs.
const ISSUE_LABEL_GATE_RE =
  /(?<!!\s{0,5}\(?\s{0,5})contains\(\s*github\.event\.issue\.labels\.\*\.name\s*,\s*'[^']{1,100}'\s*\)(?!\s*(?:==\s*false|!=\s*true))/i;

// `!contains(…labels…, 'skip-ai')`, `contains(…) == false`, `labels[0] == null` admit every PR
// that lacks an opt-out label, i.e. every stranger's PR; only a positive contains() is a gate.
const PR_LABEL_GATE_RE =
  /(?<!!\s{0,5}\(?\s{0,5})contains\(\s*github\.event\.(?:pull_request|issue)\.labels\.\*\.name\s*,\s*'[^']{1,100}'\s*\)(?!\s*(?:==\s*false|!=\s*true))/i;

// T.6.4 (2026-10-10): a literal association set that also admits a role without write access is
// not a gate. CONTRIBUTOR is anyone with one merged commit.
// A plain string set (`contains('OWNER,…,CONTRIBUTOR', …)`) is a substring test, the same thing
// (review, round 2).
const NONWRITE_SET_RE =
  /contains\(\s*(?:fromjson\(\s*['"]\[[^\]]{0,400}|'[^']{0,400})\b(CONTRIBUTOR|FIRST_TIME_CONTRIBUTOR|FIRST_TIMER|NONE|MANNEQUIN)\b/i;

/** Every job and step `if:` of the workflow, joined (bounded like stepIfText). */
function allIfText(wf: Workflow): string {
  const s = jobList(wf)
    .map((j) => str(j.if) + ' ' + (j.steps ?? []).map((st) => str(st.if)).join(' '))
    .join(' ');
  return s.length > IF_MAX_LEN ? '' : s;
}

/** Does this expression test a label that an issue form applies on its own (T.6.9)? */
function testsAutoLabel(ifs: string): boolean {
  if (AUTO_LABELS.size === 0) return false;
  for (const m of ifs.matchAll(
    /labels\.\*\.name\s*,\s*'([^']{1,100})'|label\.name\s*==\s*'([^']{1,100})'/gi
  ))
    if (AUTO_LABELS.has((m[1] ?? m[2]).toLowerCase())) return true;
  return false;
}

/** Do these joined `if:` expressions constitute an actor gate? */
function ifsAreGated(ifs: string, label: LabelConfig): boolean {
  // The gate shapes are read with string literals emptied (maskLiterals); the role set and the
  // auto-applied labels are read from the literals themselves.
  const m = maskLiterals(ifs);
  // Credit a contains() inclusion ONLY when it is not negated (`!contains(…)` = anti-gate).
  const containsGate =
    CONTAINS_GATE_RE.test(m) && !NEGATED_CONTAINS_RE.test(m) && !NONWRITE_SET_RE.test(ifs);
  const gated = NONCONTAINS_GATE_RE.test(m) || containsGate || idAllowListGate(m);
  // A label already on the PR (`contains(github.event.pull_request.labels.*.name, 'x')`) was put
  // there by someone with triage access, like the `label.name` of a labeled event. Only a
  // POSITIVE test counts (second review): see PR_LABEL_GATE_RE.
  const labelGated =
    (((label.pr || label.issues) && EVENT_LABEL_GATE_RE.test(m)) ||
      (label.pr && PR_LABEL_GATE_RE.test(m)) ||
      (label.issues && ISSUE_LABEL_GATE_RE.test(m))) &&
    !testsAutoLabel(ifs);
  return gated || labelGated;
}

/** R4-5: a fail-closed actor gate expressed as a job STEP — a membership/permission
 *  API check (`gh api /orgs/…/memberships/…`, `getCollaboratorPermissionLevel`, …) whose
 *  output guards the agent step via `if: steps.<gate>.outputs.<x> == …`. Some repositories gate
 *  this way; ACTOR_GATE_RE only reads `if:` expressions and misses it. */
// GitHub's agentic workflows start the agent through their egress firewall.
const AWF_RE = /(?:^|[\s;&|(])awf\s+(?:--config|--allow-domains)\b/;

// fw#481 L4: an event field a stranger writes, expanded by `${{ }}` straight into a `run:`
// script. The runner pastes the text into the script before the shell reads it, so the text
// runs as code in that job. Passing it through `env:` and quoting `"$VAR"` is the safe form and
// does not match.
const UNTRUSTED_EXPR_RE =
  /\$\{\{[^}]{0,300}?\b(?:github\.event\.(?:issue\.(?:title|body)|comment\.body|pull_request\.(?:title|body|head\.ref|head\.label)|review\.body|review_comment\.body|discussion\.(?:title|body)|head_commit\.message|workflow_run\.(?:head_branch|display_title|head_commit\.message))|github\.head_ref)\b/;

/** Does a `run:` script of this job paste stranger-written event text into the shell? */
function jobInjectsUntrusted(job: Job): boolean {
  return (job.steps ?? []).some((st) => {
    const run = str(st.run);
    return run.length > 0 && run.length <= 200_000 && UNTRUSTED_EXPR_RE.test(run);
  });
}

function hasStepMembershipGate(job: Job): boolean {
  const steps = job.steps ?? [];
  // fw#481 L4-b: a check computed in a job whose script runs a stranger's text is theirs to
  // answer: the injected script writes the output the agent step reads. Only a script that
  // runs before the first agent step can do that.
  const firstAgent = steps.findIndex(isAgentStep);
  if (firstAgent > 0 && jobInjectsUntrusted({ steps: steps.slice(0, firstAgent) } as Job))
    return false;
  // Gate steps: a per-user membership/permission CHECK that has an `id` (so a later
  // `if:` can reference its output). Review R4-round2 #2: a bare member-listing or an
  // id-less step is NOT a gate.
  // The check is a `run:` command or the body of an `actions/github-script` step.
  const gateIds = steps
    .filter((s) => s.id && isMembershipCheck(str(s.run) + ' ' + str(s.with?.['script'])))
    .map((s) => s.id as string);
  if (!gateIds.length) return false;
  // The agent step must be guarded by ONE OF THOSE gate steps' outputs specifically —
  // referencing an unrelated `steps.build.outputs.*` does not count — and it must run on the
  // check's YES: `outputs.is_member != 'true'` runs the agent for everyone else.
  return steps.some((s) => isAgentStep(s) && gateIds.some((id) => stepOutputAllows(str(s.if), id)));
}

// An output that says NO when it is true (`should_skip`, `denied`, `blocked`): the agent runs on
// its false.
const SKIP_OUTPUT_NAME_RE =
  /skip|den(?:y|ied)|block|reject|unauthor|forbid|not[_-]?allowed|no[_-]?access|outsider|external/i;

/** Does this `if:` run on a YES of gate step `id`? One of its outputs must be read as an allow:
 *  positively, or negatively when the output's name is a refusal. */
function stepOutputAllows(readerIf: string, id: string): boolean {
  if (readerIf.length > IF_MAX_LEN) return false;
  const base = `steps\\.${escapeRe(id)}\\.outputs\\.`;
  const seen = new Set<string>();
  for (const m of readerIf.matchAll(new RegExp(`${base}([\\w-]{1,100})`, 'g'))) {
    if (seen.has(m[1])) continue;
    seen.add(m[1]);
    const positive = readsRefPositively(readerIf, `${base}${escapeRe(m[1])}(?![\\w-])`);
    if (positive !== SKIP_OUTPUT_NAME_RE.test(m[1])) return true;
  }
  return false;
}

// ─── `if:` expressions (S.2/S.5, rewritten after the 2026-10-09 pre-release review) ─────
// Searching the text for a gate credited `a && (b || gate)` and `owner == 'x' && (open || gate)`
// as gated, and read a trusted-event pin across a nested group or through `!`. The expression
// is now parsed: `||` is a gate only when EVERY branch is, `&&` when ANY part is, `!` never.
type IfExpr =
  | { k: 'or'; c: IfExpr[] }
  | { k: 'and'; c: IfExpr[] }
  | { k: 'not'; c: IfExpr }
  | { k: 'atom'; t: string };

const IF_MAX_DEPTH = 64; // GitHub rejects far shallower nesting; deeper is not a real workflow
const IF_MAX_LEN = 20_000;

/** Parse a GitHub `if:` expression into `||`, `&&`, `!`, groups and atoms. A function call's
 *  parentheses and a single-quoted string (`''` escapes a quote) stay inside their atom.
 *  Null when the text is empty, too long, too deep or unbalanced: the caller reads null as
 *  "not a gate", so an unreadable expression never hides a finding. Never throws. */
function parseIf(src: string): IfExpr | null {
  let e = src.trim();
  const wrapped = /^\$\{\{([\s\S]*)\}\}$/.exec(e);
  if (wrapped) e = wrapped[1].trim();
  // Text outside one `${{ }}` (`false && ${{ x }}`, `${{ a }} && ${{ b }}`) is a template: the
  // runner reads the whole `if:` as a non-empty string, which is always true (review, round 2).
  if (e.includes('${{')) return null;
  if (!e || e.length > IF_MAX_LEN) return null;
  let i = 0;
  let depth = 0;
  class Bad extends Error {}
  const ws = () => {
    while (i < e.length && /\s/.test(e[i])) i++;
  };
  const deeper = () => {
    if (++depth > IF_MAX_DEPTH) throw new Bad();
  };
  const atom = (): IfExpr => {
    const start = i;
    let calls = 0;
    let quote = false;
    while (i < e.length) {
      const ch = e[i];
      if (quote) {
        if (ch === "'" && e[i + 1] === "'") i += 2;
        else {
          if (ch === "'") quote = false;
          i++;
        }
        continue;
      }
      if (ch === "'") quote = true;
      else if (ch === '(') {
        if (++calls > IF_MAX_DEPTH) throw new Bad();
      } else if (ch === ')') {
        if (calls === 0) break;
        calls--;
      } else if (calls === 0 && (e.startsWith('&&', i) || e.startsWith('||', i))) break;
      i++;
    }
    const t = e.slice(start, i).trim();
    if (!t || quote || calls > 0) throw new Bad();
    return { k: 'atom', t };
  };
  const unary = (): IfExpr => {
    ws();
    if (e[i] === '!' && e[i + 1] !== '=') {
      i++;
      deeper();
      const c = unary();
      depth--;
      return { k: 'not', c };
    }
    if (e[i] === '(') {
      i++;
      deeper();
      const c = or();
      ws();
      if (e[i] !== ')') throw new Bad();
      i++;
      depth--;
      return c;
    }
    return atom();
  };
  const list = (op: '&&' | '||', next: () => IfExpr, k: 'and' | 'or'): IfExpr => {
    const c = [next()];
    for (;;) {
      ws();
      if (!e.startsWith(op, i)) break;
      i += 2;
      c.push(next());
    }
    return c.length === 1 ? c[0] : { k, c };
  };
  const and = (): IfExpr => list('&&', unary, 'and');
  const or = (): IfExpr => list('||', and, 'or');
  try {
    const x = or();
    ws();
    return i === e.length ? x : null;
  } catch {
    return null; // unbalanced, too deep, or empty operand
  }
}

// An atom that only holds for an event a stranger cannot fire (needs write access or runs in a
// trusted context). `!=` does not match: it admits every OTHER event.
// The whole atom (second review): the same text inside a string literal is not a pin.
const TRUSTED_EVENT_ATOM_RE =
  /^github\.event_name\s*==\s*'(workflow_dispatch|schedule|push|workflow_call|repository_dispatch)'$/i;
const ASSIGNEE_GATE_RE = /assignee\.login\s*==|event\.assignee\b/i;

/** The steps' `if:`s joined for the gate search, or '' when longer than IF_MAX_LEN: no real gate
 *  is that long, and the gate regexes must never run super-linearly on scanned text (second
 *  review: a 640 KB step `if:` took minutes). '' reads as "not a gate". */
function stepIfText(steps: Step[]): string {
  const s = steps.map((st) => str(st.if)).join(' ');
  return s.length > IF_MAX_LEN ? '' : s;
}

/** `ifs` with every string literal emptied, except one compared with `==` / `!=` (the value a
 *  gate tests): `contains('github.actor == x', 'g')` holds gate text in a string and is always
 *  true (review, round 2). */
function maskLiterals(ifs: string): string {
  return ifs.replace(/(==|!=)?(\s*)'(?:[^']|'')*'/g, (m, op: string | undefined, sp: string) =>
    op ? m : `${sp}'_'`
  );
}
// `a == 'x' == false` compares the result of a comparison: "not x", true for every stranger.
const CHAINED_COMPARE_RE = /(?:==|!=)[^=!]*(?:==|!=)/;

/** Is this text an actor gate? The gate shapes of ifsAreGated, plus the job-scoped ones. */
function gatedText(ifs: string, labelConfigured: LabelConfig): boolean {
  // G-d′: an `assignee.login == '…'` gate (only someone with triage/write access can
  // assign an issue) counts too. Kept in the JOB-scoped check only — NOT in the shared
  // ACTOR_GATE_RE; gating is judged per job, so a gated sibling job can't mask an
  // ungated injectable one.
  const masked = maskLiterals(ifs);
  return (
    ifsAreGated(ifs, labelConfigured) ||
    ASSIGNEE_GATE_RE.test(masked) ||
    PERMISSION_OUTPUT_GATE_RE.test(masked) // [2] job-scoped permission-check-output gate
  );
}

/** Does this expression keep strangers out? */
function exprGated(x: IfExpr, labelConfigured: LabelConfig): boolean {
  switch (x.k) {
    case 'atom':
      if (CHAINED_COMPARE_RE.test(maskLiterals(x.t))) return false;
      return gatedText(x.t, labelConfigured) || TRUSTED_EVENT_ATOM_RE.test(x.t);
    case 'not':
      return false;
    case 'and':
      return x.c.some((c) => exprGated(c, labelConfigured));
    case 'or':
      return x.c.every((c) => exprGated(c, labelConfigured));
  }
}

/** Is a job-level `if:` an actor gate? Shared by the job's own gate and the needs chain, so the
 *  two cannot disagree. */
function jobIfGated(jobIf: string, labelConfigured: LabelConfig): boolean {
  const x = parseIf(jobIf);
  return x !== null && exprGated(x, labelConfigured);
}

/** Can this expression be true for event `ev`? Only `github.event_name ==/!= '<x>'` atoms decide;
 *  anything else, `!` included, might be true. */
function exprAllowsEvent(x: IfExpr, ev: string): boolean {
  switch (x.k) {
    case 'atom': {
      const m = /^github\.event_name\s*(==|!=)\s*'([\w-]+)'$/i.exec(x.t);
      if (!m) return true;
      return (m[2].toLowerCase() === ev) === (m[1] === '==');
    }
    case 'not':
      return true;
    case 'and':
      return x.c.every((c) => exprAllowsEvent(c, ev));
    case 'or':
      return x.c.some((c) => exprAllowsEvent(c, ev));
  }
}

/** C6-b: can this expression be true on event `ev` with no actor gate holding it? An atom that
 *  pins another event, or that is a gate, cannot; `!x` is read as open (as in exprGated). */
function ungatedOn(x: IfExpr, ev: string, label: LabelConfig): boolean {
  switch (x.k) {
    case 'atom':
      if (!exprAllowsEvent(x, ev)) return false;
      if (CHAINED_COMPARE_RE.test(maskLiterals(x.t))) return true;
      return !(gatedText(x.t, label) || TRUSTED_EVENT_ATOM_RE.test(x.t));
    case 'not':
      return true;
    case 'and':
      return x.c.every((c) => ungatedOn(c, ev, label));
    case 'or':
      return x.c.some((c) => ungatedOn(c, ev, label));
  }
}

/** C6-b: does this job run on event `ev` without its own `if:` gating it? No `if:`, or one
 *  that does not parse, is open. */
function jobRunsUngatedOn(job: Job, ev: string, label: LabelConfig): boolean {
  if (environmentHoldsOn(job, ev.toLowerCase())) return false; // C6-c: a reviewer approves each run
  const src = str(job.if).trim();
  if (!src) return true;
  const x = parseIf(src);
  return x === null || ungatedOn(x, ev.toLowerCase(), label);
}

/** Review finding 5: does THIS job run on a stranger-firable workflow_run? A job whose `if:`
 *  pins it to another event (`github.event_name == 'issue_comment' && …`) does not, although
 *  the workflow also lists workflow_run. */
function jobOnWorkflowRun(job: Job, workflowRun: boolean): boolean {
  if (!workflowRun) return false;
  const x = parseIf(str(job.if));
  return x === null || exprAllowsEvent(x, 'workflow_run');
}

/** Actor gate scoped to a SINGLE job (its own `if:` + its steps' `if:`s). CI-4
 *  evaluates each agent job independently, so a gate on a DIFFERENT job must not
 *  be credited to this one (and vice-versa). */
function jobActorGate(job: Job, wf: Workflow, raw: Record<string, unknown>): boolean {
  const labelConfigured = labelTypeConfigured(wf, raw);
  // T.6.1 (2026-10-10): a step `if:` guards only its own step. The joined step text credited
  // the same-repo test of an "internal review" step to the "fork review" agent step beside it
  // (a common review template). Every agent step must carry its own gate.
  const agent = (job.steps ?? []).filter(isAgentStep);
  // The same total bound the joined step text had (stepIfText): hundreds of long `if:`s, each
  // parsed and gate-tested, cost 20x more than before (review, round 2). Too long is not a gate.
  const ifTotal = agent.reduce((n, s) => n + str(s.if).length, 0);
  const agentStepsGated =
    agent.length > 0 &&
    ifTotal <= IF_MAX_LEN &&
    agent.every((s) => {
      const x = parseIf(str(s.if));
      return x !== null && exprGated(x, labelConfigured);
    });
  return (
    jobIfGated(str(job.if), labelConfigured) || agentStepsGated || hasStepMembershipGate(job) // R4-5
  );
}

/** Is this job actor-gated, either on its own or through its `needs:` chain?
 *
 *  GitHub prefixes a job's `if:` with an implicit `success() &&` unless the expression itself
 *  calls a status function (success/failure/always/cancelled). With that implicit check, a
 *  skipped or failed job ANYWHERE upstream in the needs: chain skips this job, even if a job in
 *  between ran under always() (actions/runner#491). With an explicit status function the
 *  expression alone decides, so an upstream gate counts only if the expression also requires
 *  that gating job's result, as in the common `always() && needs.check.result == 'success'`.
 *
 *  An upstream job gates when its JOB-LEVEL `if:` is an actor gate with no top-level `||` (an
 *  `a || github.actor == x` clause lets everyone through on `a`), or when it gates at step level
 *  and turns that into a skip or failure the dependent sees: it has a failing step (`exit 1`,
 *  `core.setFailed`), or the dependent's `if:` reads its outputs. A step gate alone does not:
 *  the upstream job still succeeds and the dependent runs.
 *
 *  Before 2026-09-26 CI-2 used a whole-workflow gate test, so a gated sibling job masked an
 *  ungated one in the same file (a false negative found in review). */
const ACTOR_ALLOWLIST_RE =
  /\.includes\(\s*(?:context\.actor|github\.actor|context\.payload\.sender\.login|[\w.]{0,40}user\.login|login)\b|\b(?:context\.actor|github\.actor)\s*===?\s*['"]/;
const ACTOR_ALLOWLIST_G = new RegExp(ACTOR_ALLOWLIST_RE.source, 'g');
const BLOCK_LIST_NAME_RE = /block|deny|ban|spam|abuse|exclu|ignore/i;

/** Does an upstream script ADMIT by the actor? Read for polarity (review, round 2): a block list
 *  (`blocked.includes(context.actor) ? 'false' : 'true'`) admits everyone it does not name.
 *  Without a ternary (`if (!allowed.includes(actor)) core.setFailed(…)`) the test is credited. */
function scriptAllowsByActor(code: string): boolean {
  if (code.length > 200_000) return false;
  for (const m of code.matchAll(ACTOR_ALLOWLIST_G)) {
    const at = m.index ?? 0;
    const before = code.slice(Math.max(0, at - 80), at);
    if (m[0].startsWith('.includes')) {
      const list = /([\w$.]{1,60})$/.exec(before)?.[1] ?? '';
      if (BLOCK_LIST_NAME_RE.test(list)) continue;
    }
    const negated = /!\s{0,3}\(?\s{0,3}[\w$.]{0,60}$/.test(before);
    const ternary = /^[^?;\n]{0,150}\?\s{0,5}['"`]?(true|false)\b/.exec(code.slice(at, at + 200));
    if (!ternary || (ternary[1] === 'true') !== negated) return true;
  }
  return false;
}

/** Does the dependent's `if:` run on a YES from upstream job `name`? `!needs.x.outputs.ok`,
 *  `!= 'true'` and `== 'false'` run on a NO. */
function readsOutputPositively(readerIf: string, name: string): boolean {
  return readsRefPositively(readerIf, `needs\\.${escapeRe(name)}\\.outputs\\.[\\w-]{1,100}`);
}

/** The same for any output reference, given as a regex source. */
function readsRefPositively(readerIf: string, ref: string): boolean {
  if (!new RegExp(ref).test(readerIf)) return false;
  const no = `'(?:false|no|0|)'(?![\\w'])`;
  // `!= 'none'` admits `read`, which every stranger has: only `!=` a "no" word runs on a yes.
  return !new RegExp(
    `!\\s{0,5}\\(?\\s{0,5}(?:fromjson\\(\\s{0,5})?${ref}|${ref}\\s{0,5}\\)?\\s{0,5}(?:!=\\s{0,5}(?!${no})|==\\s{0,5}${no})`,
    'i'
  ).test(readerIf);
}

const STATUS_FN_RE = /\b(success|failure|always|cancelled)\s*\(/i;
const FAILING_STEP_RE =
  /\bexit\s+[1-9]|core\.setFailed|process\.exit\(\s*[1-9]|actions\.cancelWorkflowRun\b/;

function needsOf(job: Job): string[] {
  return (Array.isArray(job.needs) ? job.needs : job.needs ? [job.needs] : []).map(String);
}

function escapeRe(x: string): string {
  return x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Does upstream job `name` itself turn untrusted actors into a skip/failure downstream?
 *  `readerIf` is the dependent's `if:` (only a DIRECT dependent can read `needs.<name>`). */
function upstreamJobGates(
  name: string,
  dep: Job,
  wf: Workflow,
  raw: Record<string, unknown>,
  readerIf: string | null
): boolean {
  const depIf = str(dep.if);
  const label = labelTypeConfigured(wf, raw);
  // S.5 (2026-10-09): judged per top-level `||` branch, like the job's own gate. The old test
  // refused any `||`, even one inside a group whose every alternative is gated
  // (a repository hand-verified as clean was scored medium).
  if (depIf && jobIfGated(depIf, label)) return true;
  // fw#481 L4-b: past this point the gate is decided by the job's steps. A step that pastes a
  // stranger's text into its script runs their code first, which can write the very output or
  // status the dependent reads. A job-level `if:` (above) is decided before any step runs.
  if (jobInjectsUntrusted(dep)) return false;
  const steps = dep.steps ?? [];
  // T.1: an upstream job whose script decides by the actor (a permission or membership call,
  // or an allowlist compared with the actor) gates a dependent that reads its outputs.
  if (
    readerIf !== null &&
    readsOutputPositively(readerIf, name) &&
    steps.some((st) => {
      const code = str(st.run) + ' ' + str(st.with?.['script']);
      return isMembershipCheck(code) || scriptAllowsByActor(code);
    })
  )
    return true;
  // A permission or membership call in a script step counts too (a compiled agentic workflow
  // checks the actor in a github-script step, then cancels the run for anyone else).
  const stepGated =
    ifsAreGated(stepIfText(steps), label) ||
    hasStepMembershipGate(dep) ||
    steps.some((st) => isMembershipCheck(str(st.with?.['script'])));
  if (!stepGated) return false;
  if (
    steps.some(
      (st) => FAILING_STEP_RE.test(str(st.run)) || FAILING_STEP_RE.test(str(st.with?.['script']))
    )
  )
    return true;
  return readerIf !== null && readsOutputPositively(readerIf, name);
}

/** Names of every job upstream of `job` (transitively) that gates, per upstreamJobGates. */
function gatingAncestors(job: Job, wf: Workflow, raw: Record<string, unknown>): Set<string> {
  const out = new Set<string>();
  const seen = new Set<string>();
  const visit = (j: Job, readerIf: string | null) => {
    for (const name of needsOf(j)) {
      const dep = wf.jobs?.[name];
      if (!dep) continue;
      if (upstreamJobGates(name, dep, wf, raw, readerIf)) out.add(name);
      if (seen.has(name)) continue;
      seen.add(name);
      visit(dep, str(dep.if));
    }
  };
  visit(job, str(job.if));
  return out;
}

function jobGated(job: Job, wf: Workflow, raw: Record<string, unknown>): boolean {
  if (jobActorGate(job, wf, raw)) return true;
  const gating = gatingAncestors(job, wf, raw);
  if (gating.size === 0) return false;
  const ownIf = str(job.if);
  if (!STATUS_FN_RE.test(ownIf)) return true; // implicit success(): any gating ancestor skips it
  // Explicit status function: credit only a required success of a gating DIRECT dependency.
  return needsOf(job).some(
    (n) =>
      gating.has(n) &&
      new RegExp(`needs\\.${escapeRe(n)}\\.result\\s*==\\s*['"]success['"]`).test(ownIf)
  );
}

/** fw#481 S4-a: the stranger-firable events `job` runs on with no gate of its own and none it
 *  inherits. C6-b reads a job `if:` per event (`pull_request` open, the comment command held to
 *  members), but only on the agent job itself: the same condition one job up, on the job the
 *  agent job `needs`, was not followed, so a gated dependency-update workflow was graded high.
 *  GitHub skips a job when any job upstream in its `needs:` chain was skipped, unless the job's
 *  own `if:` calls a status function (see jobGated). So an event on which an ancestor does not
 *  run ungated is one this job does not run on for a stranger either. With an explicit status
 *  function, only a required success of a direct dependency carries the gate. Bounded: at most
 *  HOLDERS_MAX ancestors are read; the rest are ignored, which credits less, never more. */
const HOLDERS_MAX = 64;
// One answer per job and event within one analysis: a job is an ancestor of many agent jobs, and
// its `if:` (the PR author's, in the Action) would otherwise be parsed once per descendant and
// event. Cleared at the start of each analysis: the answer depends on that run's label and
// environment facts.
let UNGATED_MEMO = new WeakMap<Job, Map<string, boolean>>();
function ungatedOnMemo(job: Job, ev: string, label: LabelConfig): boolean {
  let m = UNGATED_MEMO.get(job);
  if (!m) UNGATED_MEMO.set(job, (m = new Map()));
  let v = m.get(ev);
  if (v === undefined) m.set(ev, (v = jobRunsUngatedOn(job, ev, label)));
  return v;
}
function openEventsOf(job: Job, wf: Workflow, firable: string[], label: LabelConfig): string[] {
  const own = firable.filter((ev) => ungatedOnMemo(job, ev, label));
  if (!own.length) return own;
  const ownIf = str(job.if);
  const holders: Job[] = [];
  if (STATUS_FN_RE.test(ownIf)) {
    for (const n of needsOf(job)) {
      const dep = wf.jobs?.[n];
      if (
        dep &&
        holders.length < HOLDERS_MAX &&
        new RegExp(`needs\\.${escapeRe(n)}\\.result\\s*==\\s*['"]success['"]`).test(ownIf)
      )
        holders.push(dep);
    }
  } else {
    const seen = new Set<string>();
    const visit = (j: Job) => {
      for (const n of needsOf(j)) {
        if (seen.has(n) || holders.length >= HOLDERS_MAX) continue;
        seen.add(n);
        const dep = wf.jobs?.[n];
        if (!dep) continue;
        holders.push(dep);
        visit(dep);
      }
    };
    visit(job);
  }
  if (!holders.length) return own;
  return own.filter((ev) => holders.every((h) => ungatedOnMemo(h, ev, label)));
}

/** claude-code-action bypasses its write-permission gate only when the SAME step also passes
 *  its own `github_token`: action.yml wires `inputs.github_token` to OVERRIDE_GITHUB_TOKEN, and
 *  permissions.ts checks `allowedNonWriteUsers && githubTokenProvided` (present since the input
 *  was added, #550, 2025-09-07). `"*"` alone leaves the default write gate ON. Measured against
 *  live workflows 2026-09-24: 4 of 114 medium "gate-off" findings had `"*"` and no token, and
 *  were really gated. A step may also set the env var the action reads directly. */
function claudeBypassArmed(s: Step): boolean {
  return (
    nonWriteOpen(str(s.with?.['allowed_non_write_users'])) &&
    (!!str(s.with?.['github_token']) || !!str(s.env?.['OVERRIDE_GITHUB_TOKEN']))
  );
}

/** `<owner>/codex-action@<ref>` → who built it; null for anything else. */
function codexActionBuild(uses?: string): { official: boolean; owner: string } | null {
  const m = /^\s*([\w.-]{1,100})\/codex-action@\S/i.exec(uses ?? '');
  return m ? { official: m[1].toLowerCase() === 'openai', owner: m[1] } : null;
}

/** codex-action checks that the actor has write access before it starts Codex (its "Check
 *  repository write access" step, in every release since v1.0: GITHUB_ACTOR must hold admin,
 *  write or maintain, and any error rejects). `allow-users: "*"` approves every actor; so does a
 *  value bound to whoever fired the event. No token is involved, unlike the Claude bypass. */
function codexOpen(s: Step): boolean {
  return !!codexActionBuild(s.uses) && nonWriteOpen(str(s.with?.['allow-users']));
}

function bypassArmed(steps: Step[]): boolean {
  return steps.some((s) => claudeBypassArmed(s) || codexOpen(s));
}

// Commands that read or move files and talk to git or GitHub, and run nothing from the
// checkout. Anything else in a `run:` step (an install, a build, a test, a script, an
// interpreter, `eval`, `source`, `xargs`) may run the checked-out code, and is not listed.
const INERT_COMMAND_RE =
  /^(?:git|gh|echo|printf|mkdir|cd|export|set|unset|test|\[\[?|jq|cat|ls|pwd|true|false|sleep|date|rm|cp|mv|touch|tee|head|tail|grep|wc|sort|uniq|cut|tr|exit|:)(?=[\s"'=);]|$)/;
// Words that only introduce a command (`if npm test; then`): the command after them is judged.
const SHELL_LEAD_RE = /^(?:if|elif|while|until|then|do|else|time|!|\{|\()(?:\s+|$)/;
const SHELL_CLOSE_RE = /^(?:fi|done|esac|\}|;;)?$/;
// A bare assignment with nothing after it (`SHA=`, `X="a b"`); `X=1 npm ci` is a command.
const BARE_ASSIGN_RE = /^[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|[^\s"']*)$/;
const LOOP_HEAD_RE = /^(?:for\s+[A-Za-z_]\w*\s+in\b|case\s[^\n]{0,200}\sin$)/;
// A step that sets the environment or the search path of LATER steps (the action's own check
// runs `node`), plants a file in the home directory, or reconfigures git, can make a harmless
// command run the checkout's code.
const RUN_REDIRECTS_LATER_RE =
  /GITHUB_(?:ENV|PATH)\b|\bBASH_ENV\b|\bPATH=|\bNODE_OPTIONS\b|(?:~|\$HOME|\$\{HOME\})\/|\bgit\s+config\b/;

/** Is every command of this `run:` script one that cannot execute the checked-out files? Read
 *  conservatively: a command substitution is judged like a command of its own, and an unknown
 *  first word means "may run code". */
function runIsInert(run: string): boolean {
  if (run.length > 20_000 || RUN_REDIRECTS_LATER_RE.test(run)) return false;
  for (const raw of run.replace(/\\\r?\n/g, ' ').split(/\r?\n/)) {
    const line = raw.trim().replace(/\d*>&\d*-?|&>>?/g, ' '); // `2>&1`, `&>` are redirections
    if (!line || line.startsWith('#')) continue;
    for (const part of line.split(/&&?|\|\|?|[;`]|\$\(|[<>]\(/)) {
      let cmd = part.trim();
      for (let n = 0; n < 6 && cmd && SHELL_LEAD_RE.test(cmd); n++)
        cmd = cmd.replace(SHELL_LEAD_RE, '');
      cmd = cmd.replace(/\)+$/, '').trim(); // the close of a `$( … )`
      if (SHELL_CLOSE_RE.test(cmd) || BARE_ASSIGN_RE.test(cmd) || LOOP_HEAD_RE.test(cmd)) continue;
      if (!INERT_COMMAND_RE.test(cmd)) return false;
    }
  }
  return true;
}

// Actions that prepare the runner and execute nothing from the checkout. Any other `uses:` step
// between the checkout and the agent may (a dependency install, an image build, a script step
// that requires a local file), like the checkout's own `./` action.
const INERT_ACTION_RE =
  /^\s*actions\/(?:checkout|setup-(?:node|python|go|java|dotnet)|cache(?:\/restore|\/save)?|upload-artifact|download-artifact|create-github-app-token)@/i;

/** Has the job checked out the untrusted head into the workspace root AND run something that
 *  may execute it, before this agent step? An action's own actor check starts with its step:
 *  whatever ran before it (an install, a build, the head's local action) has already run for a
 *  stranger. A `git fetch` or an `echo` between the two runs nothing of the head. */
function headUsedBefore(job: Job, agentStep: Step): boolean {
  const steps = job.steps ?? [];
  const k = steps.indexOf(agentStep);
  if (k < 0) return false;
  const i = steps.findIndex((st, n) => n < k && untrustedHeadCheckout([st]) === 'root');
  if (i < 0) return false;
  return steps
    .slice(i + 1, k)
    .some((st) =>
      st.uses
        ? !INERT_ACTION_RE.test(str(st.uses))
        : typeof st.run === 'string' && !!st.run.trim() && !runIsInert(st.run)
    );
}

/** fw#481 L3-a: does a `run:` step after the job's root head checkout run something that may
 *  execute the checked-out files? Agent steps are judged by their tools, not here. */
function jobRunsHeadScript(job: Job): boolean {
  const steps = job.steps ?? [];
  const i = steps.findIndex((st) => untrustedHeadCheckout([st]) === 'root');
  if (i < 0) return false;
  return steps
    .slice(i + 1)
    .some(
      (st) =>
        !st.uses &&
        typeof st.run === 'string' &&
        !!st.run.trim() &&
        !isRunAgent(st) &&
        !runChecksOutHead(st.run) &&
        runExecutesCheckout(withoutHeredocBodies(st.run))
    );
}

// fw#481 L3-a: a command that runs files of the checkout: a script by its relative path, an
// interpreter on a repository file, or a package manager or build tool that runs the project's
// own install and build scripts. Positive evidence only: `runIsInert` reads an unknown word as
// "may run code", which is right before an agent's own check and too broad here (`set -e`,
// `date`, `sha256sum` and shell functions would count). A path under a directory the job filled
// from the base branch (`.trusted*`) is not the PR's code.
const CHECKOUT_EXEC_RE = new RegExp(
  [
    String.raw`(?:^|[\s;&|(])(?:python3?|node|ruby|perl|php|bash|sh|zsh|tsx|ts-node|deno\s+run|bun\s+run)\s+(?:-[A-Za-z]\s+)*(?!-|/|\$|~)(?!\.?/?\.?trusted)[\w./-]+\.(?:py|js|mjs|cjs|ts|rb|pl|php|sh)\b`,
    String.raw`(?:^|[\s;&|(])\./(?!\.?trusted)[\w.][\w./-]*`,
    String.raw`(?:^|[\s;&|(])(?:npm|pnpm)\s+(?:ci|install|i|run|test|exec|rebuild)\b`,
    String.raw`(?:^|[\s;&|(])yarn(?:\s+(?:install|run|test|build)\b|\s*(?:$|[;&|]))`,
    String.raw`(?:^|[\s;&|(])bun\s+(?:install|i|test)\b`,
    String.raw`(?:^|[\s;&|(])pip3?\s+install\s+(?:--?\w[\w-]*\s+)*(?:-e\s+)?(?:\.(?:\s|$|\[)|-r\b)`,
    String.raw`(?:^|[\s;&|(])(?:uv\s+(?:sync|run)|poetry\s+(?:install|run)|pytest|tox|make|mvn|gradle|\./gradlew)\b`,
    String.raw`(?:^|[\s;&|(])(?:cargo\s+(?:build|test|run|check)|go\s+(?:build|test|run|generate)|bazel\s+(?:build|test|run))\b`,
  ].join('|'),
  'm'
);

/** Does this script run files of the checkout? Comment lines are skipped. */
function runExecutesCheckout(run: string): boolean {
  if (run.length > 200_000) return true;
  // `--ignore-scripts` installs without running any package's own scripts.
  return run
    .split('\n')
    .some((l) => !/^\s*#/.test(l) && !/--ignore-scripts\b/.test(l) && CHECKOUT_EXEC_RE.test(l));
}

/** A heredoc's body is data handed to a command, not commands. Its lines (often an expanded
 *  `${{ }}` value) would otherwise read as unknown commands. Bounded to 200 heredocs. */
function withoutHeredocBodies(run: string): string {
  const lines = run.split('\n');
  const out: string[] = [];
  let end: string | null = null;
  let seen = 0;
  for (const line of lines) {
    if (end !== null) {
      if (line.trim() === end) end = null;
      continue;
    }
    out.push(line);
    const m = seen < 200 ? /<<-?\s*(['"]?)([A-Za-z_][\w-]{0,40})\1/.exec(line) : null;
    if (m) {
      end = m[2];
      seen++;
    }
  }
  return out.join('\n');
}

/** `allow-bots: true` approves `github-actions[bot]`, and `allow-bot-users` the bots it names.
 *  A bot is the actor of a run that another workflow starts with a dispatch, whoever started
 *  that workflow. */
function codexAdmitsBots(s: Step): boolean {
  return (
    /^\s*["']?true["']?\s*$/i.test(str(s.with?.['allow-bots'])) ||
    !!str(s.with?.['allow-bot-users']).trim()
  );
}

/** Can another workflow (or an API call) start this one? Its actor is then the caller's token. */
function dispatchable(wf: Workflow, raw: Record<string, unknown>): boolean {
  return triggerKeys(wf, raw).some((k) => /^(?:workflow_dispatch|repository_dispatch)$/i.test(k));
}

/** An official codex-action step whose own write check is on but comes too late (see above). */
function codexCheckTooLate(job: Job): boolean {
  return (job.steps ?? []).some(
    (s) => !!codexActionBuild(s.uses)?.official && !codexOpen(s) && headUsedBefore(job, s)
  );
}

// T.6.5 (2026-10-10): a value bound to the user who fired the event allows that user, whoever
// it is, so it is "*" in effect (`${{ github.event.issue.user.login }}`).
const ACTOR_BOUND_RE =
  /\$\{\{[^}]{0,200}\b(github\.event\.[\w.]{0,80}\b(?:user|sender)\.login|github\.event\.sender\.login|github\.actor|github\.triggering_actor)\b/i;

/** Does this allowed_non_write_users value admit any user? */
function nonWriteOpen(v: string): boolean {
  const t = v.trim();
  if (t === '*') return true;
  // A real value is a login list or one expression; a megabyte of text is neither, and the
  // regex below costs ~100 steps a character on it (review, round 2).
  return t.length <= 1_000 && ACTOR_BOUND_RE.test(t);
}

/** `anthropics/claude-code-action` (the higher-level action — NOT the lower-level
 *  `claude-code-base-action`) runs the agent ONLY for users with WRITE access by
 *  default. `allowed_non_write_users: "*"` removes that gate; anything else keeps
 *  it. So a workflow using it, without the "*" bypass, has an effective IMPLICIT
 *  actor gate — the anonymous-attacker vector is blocked even without an explicit
 *  `if:`. Missing this = crying wolf on the most common claude-code-action setup. */
function hasImplicitActorGate(
  agentSteps: Step[],
  bypassActive: boolean,
  workflowRun = false,
  /** The job the steps belong to, in step order, and whether the workflow can be started by a
   *  dispatch. Without it (the whole-workflow wording call) every step is read on its own. */
  scope?: { job: Job; dispatchable: boolean }
): boolean {
  if (bypassActive) return false; // bypass on (and reachable) → the default gate is off
  const held = (s: Step): boolean => {
    // The official codex-action checks the actor on every event, in every release. Not a
    // third-party build (its own code decides), not when the job has already run the PR's code
    // by the time the check starts, and not when a dispatched run's bot actor is let through.
    if (codexActionBuild(s.uses)?.official)
      return !(
        scope &&
        (headUsedBefore(scope.job, s) || (scope.dispatchable && codexAdmitsBots(s)))
      );
    const build = claudeActionBuild(s.uses);
    if (!build) return false;
    // A third-party build's own code decides whether any gate exists (founder decision, round-2
    // review B21, 2026-10-11): only the official action is credited, on every event.
    if (!build.official) return false;
    // Entity events (issues, comments, PRs): every official release checks write access.
    if (!workflowRun) return true;
    // S.4 (2026-10-09): on workflow_run the official action checks the actor only from
    // v1.0.185 (#1590).
    return workflowRunChecked(build.ref);
  };
  if (!scope) return agentSteps.some(held);
  // Per job: the check of an action guards the steps AFTER it (its failure ends the job), not
  // an agent that ran before, and nothing at all when its failure is ignored
  // (`continue-on-error`). Walk the job's agents in order:
  //  · only a step that certainly starts an agent counts (an action, or the CLI invoked to do
  //    work): the looser "an agent word next to github.event" reading of a `run:` step also
  //    matches a step that merely prepares the prompt;
  //  · an agent with an `if:` of its own is skipped: who it runs for is decided by that
  //    condition (often a step output), which is not read here, so it neither holds nor opens.
  const starts = agentSteps.filter((s) => (s.uses ? true : isRunAgent(s)));
  let sawHeld = false;
  for (const s of starts) {
    if (!held(s)) {
      if (str(s.if).trim()) continue;
      return false; // an unconditional agent that no effective check precedes
    }
    const ignored = str((s as { 'continue-on-error'?: unknown })['continue-on-error']);
    if (!/^\s*["']?true["']?\s*$/i.test(ignored)) return true;
    sawHeld = true;
  }
  return sawHeld;
}

/** fw#481 S4-b: the agent steps of a job that a stranger can actually start. A job can hold two
 *  steps of the official action: one for same-repository PRs that keeps the default write check
 *  and has the write tools, one for forks with the check switched off and read-only tools. The
 *  first refuses a stranger, so its tools and secrets are not theirs to use; joining the two
 *  graded a read-only fork review as a push-capable agent anyone can start. A step is held when
 *  it is an official claude-code-action or codex-action step whose own switch is not set (and
 *  that checks the actor on this job's events). When no step is open on its own, all are
 *  returned: the job-level verdict already decided. */
function strangerSteps(
  job: Job,
  wf: Workflow,
  raw: Record<string, unknown>,
  workflowRun: boolean
): Step[] {
  const agents = (job.steps ?? []).filter(isAgentStep);
  if (agents.length < 2) return agents;
  const scope = { job, dispatchable: dispatchable(wf, raw) };
  const onRun = jobOnWorkflowRun(job, workflowRun);
  const open = agents.filter(
    (s) => claudeBypassArmed(s) || codexOpen(s) || !hasImplicitActorGate([s], false, onRun, scope)
  );
  return open.length ? open : agents;
}

/** `<owner>/claude-code-action@<ref>` → who built it and which ref; null for anything else
 *  (claude-code-base-action included: it has no write gate at all). */
function claudeActionBuild(
  uses?: string
): { official: boolean; owner: string; ref: string } | null {
  const m = /^\s*([\w.-]{1,100})\/claude-code-action@(\S{1,200})/i.exec(uses ?? '');
  if (!m) return null;
  return { official: m[1].toLowerCase() === 'anthropics', owner: m[1], ref: m[2] };
}

const CLAUDE_BASE_ACTION_RE = /^\s*anthropics\/claude-code-base-action@\S/i;

/** Official claude-code-action in tag mode (no `prompt`): it keeps a tracking comment the agent
 *  edits, allows Read, Glob and Grep, and commits to a branch through its own file tool. */
function claudeTagMode(st: Step): boolean {
  return !!claudeActionBuild(st.uses)?.official && !str(st.with?.['prompt']).trim();
}

/** Tag mode, or `track_progress: true`: the action grants its own comment tool and the file-read
 *  tools, whatever `--allowedTools` says. */
function claudeOwnTools(st: Step): boolean {
  return (
    claudeTagMode(st) ||
    (!!claudeActionBuild(st.uses)?.official &&
      /^\s*["']?true/i.test(str(st.with?.['track_progress'])))
  );
}

/** C4-c: can the scan read this agent step's whole tool policy? Only these:
 *  - official codex-action in a read-only sandbox (`sandbox: read-only` or `:read-only`);
 *  - official claude-code-action / claude-code-base-action given a prompt (agent mode, not the
 *    tag mode that adds its own tools) and an explicit allowed-tools list;
 *  - run-gemini-cli with an explicit core-tools list.
 *  Anything else (no list, a named profile, a CLI run, a slash command that grants its own
 *  tools) is unknown, and an unknown policy is never read as "no tools". */
function toolPolicyKnown(st: Step, job: Job): boolean {
  const w = st.with ?? {};
  if (codexActionBuild(st.uses)?.official) return readOnlySandbox(st);
  // Claude Code and Gemini CLI also load the checked-out repository's own settings
  // (`.claude/settings.json`, `.gemini/settings.json`), whose allow lists add tools. The list in
  // the workflow is the whole policy only when nothing is checked out at the workspace root, or
  // when Claude is told not to load project settings.
  const projectSettings = rootCheckout(job) && !settingSourcesSkipProject(str(w['claude_args']));
  if (claudeActionBuild(st.uses)?.official || CLAUDE_BASE_ACTION_RE.test(str(st.uses))) {
    const prompt = str(w['prompt']).trim() || str(w['direct_prompt']).trim();
    // A slash command (`/name`) takes the tools its command file grants, which is not read here.
    if (!prompt || prompt.startsWith('/')) return false;
    const explicit =
      allowedToolsFromArgs(str(w['claude_args'])).trim() ||
      str(w['allowed_tools']).trim() ||
      str(w['allowedtools']).trim();
    return !!explicit && !PERMISSION_BYPASS_RE.test(str(w['claude_args'])) && !projectSettings;
  }
  if (isGeminiStep(st)) return geminiToolGrants(str(w['settings'])) !== null && !rootCheckout(job);
  return false;
}

/** Does the job check a repository out into the workspace root (an `actions/checkout` with no
 *  `path:`, or a `gh pr checkout` / `git clone` run)? Its settings files are then in the agent's
 *  working directory. */
function rootCheckout(job: Job): boolean {
  return (job.steps ?? []).some((s) => {
    if (/^\s*actions\/checkout@/i.test(str(s.uses))) {
      const p = str(s.with?.['path'])
        .trim()
        .replace(/^\.\/?$/, '');
      return p === '';
    }
    return /\bgh\s+pr\s+checkout\b|\bgit\s+clone\b/.test(str(s.run));
  });
}

/** `--setting-sources user` (no `project`, no `local`): Claude ignores the repository's settings. */
function settingSourcesSkipProject(claudeArgs: string): boolean {
  const m = /--setting-sources[=\s]+["']?([\w,\s]{1,60})/i.exec(claudeArgs);
  return !!m && !/\b(project|local)\b/i.test(m[1]);
}

const SECRET_REF_G = /\bsecrets\.([A-Za-z_][\w-]{0,100})/g;

/** C4-c: does the agent step's environment (workflow, job and step `env:`) hold a secret? The
 *  model key handed to the action through its own input is not counted: codex-action keeps it in
 *  its proxy, and the other actions pass it to the model client. The job token counts unless the
 *  job's permissions are explicitly read-only. Claude actions export the token they are given
 *  (or mint one), so for them a token that can write, or `id-token: write`, always counts. */
function agentEnvHoldsSecret(wf: Workflow, job: Job, st: Step): boolean {
  const perms = jobPerms(wf, job);
  const readOnlyToken = perms.trim() !== '' && !/write/i.test(perms);
  const claude = !!claudeActionBuild(st.uses) || CLAUDE_BASE_ACTION_RE.test(str(st.uses));
  if (claude && !readOnlyToken) return true;
  const env = { ...(st.scopeEnv ?? {}), ...(st.env ?? {}) };
  for (const v of Object.values(env)) {
    const s = str(v);
    for (const m of s.matchAll(SECRET_REF_G)) {
      if (m[1].toUpperCase() === 'GITHUB_TOKEN' && readOnlyToken) continue;
      // `secrets.X != ''` yields true or false, never the value.
      const at = m.index ?? 0;
      const after = s.slice(at + m[0].length, at + m[0].length + 8);
      const before = s.slice(Math.max(0, at - 8), at);
      if (/^\s*[=!]=/.test(after) || /[=!]=\s*$/.test(before)) continue;
      return true;
    }
    if (/\bgithub\.token\b/.test(s) && !readOnlyToken) return true;
  }
  return false;
}

/** Which official action's own write check holds these agent steps, for the report's wording. */
function defaultGateOwner(agentSteps: Step[]): string {
  const claude = agentSteps.some((s) => claudeActionBuild(s.uses)?.official);
  const codex = agentSteps.some((s) => codexActionBuild(s.uses)?.official);
  return claude && codex
    ? 'claude-code-action and codex-action'
    : codex
      ? 'codex-action'
      : 'claude-code-action';
}

const WORKFLOW_RUN_CHECK_MIN = 185; // claude-code-action v1.0.185, #1590 (2026-08-04)
const SHA_REF_RE = /^[0-9a-f]{40}$/i;

/** Does this ref of the official action check the actor on workflow_run? `@beta` and explicit
 *  `v1.0.N` with N < 185 do not. A moving ref (`v1`, `main`) does. A SHA pin is unknown to a
 *  static scanner and is given the benefit of the doubt; the finding asks to confirm it. */
function workflowRunChecked(ref: string): boolean {
  if (/^beta\b/i.test(ref) || /^v0(\.|$)/i.test(ref)) return false;
  const v = /^v1\.0\.(\d+)$/.exec(ref);
  if (v) return Number(v[1]) >= WORKFLOW_RUN_CHECK_MIN;
  return true;
}

/** G-d: agent steps whose OWN job is injectable — i.e. not actor-gated and not held
 *  by the claude-code-action default gate. Only these contribute to blast radius: a
 *  gated sibling job's tools (a bare-Bash job gated on `assignee == <bot>`) can't
 *  be reached by the untrusted trigger, so they must not inflate the injectable job.
 *  Falls back to all agent steps if none qualify (never blank). */
function injectableJobs(
  wf: Workflow,
  raw: Record<string, unknown>,
  untrustedTrigger: boolean
): Job[] {
  const out: Job[] = [];
  const { workflowRun } = triggerReach(wf, raw);
  for (const job of jobList(wf)) {
    const a = (job.steps ?? []).filter(isAgentStep);
    if (!a.length) continue;
    const jobStar = bypassArmed(a);
    if (
      jobGated(job, wf, raw) ||
      hasImplicitActorGate(a, jobStar && untrustedTrigger, jobOnWorkflowRun(job, workflowRun), {
        job,
        dispatchable: dispatchable(wf, raw),
      })
    )
      continue;
    out.push(job);
  }
  return out;
}

// GitHub evaluates `a || b || c` left to right, and `secrets.GITHUB_TOKEN` / `github.token`
// is always set, so when it is the FIRST operand every operand after it can never be used:
// `${{ secrets.GITHUB_TOKEN || secrets.GH_PAT }}` reaches only the default token, while
// `${{ secrets.GH_PAT || secrets.GITHUB_TOKEN }}` reaches the PAT whenever one is configured.
// Only that exact shape is stripped. The token must open the expression (right after `${{`,
// `(` or a `,` argument separator), every later operand must be a plain reference or quoted
// literal, and the chain must end the expression (`}}`, `)` or `,`). Anything else is left
// alone, because `&&` binds tighter than `||`: in `cond && secrets.GITHUB_TOKEN || secrets.PAT`
// (GitHub's documented ternary idiom) the PAT is live whenever `cond` is false.
// The operand alternatives must not overlap: `secrets.X` and `github.token` are already
// matched by the plain-reference branch, and listing them separately made the `(...)+`
// ambiguous, which backtracks exponentially on a crafted `||secrets._||secrets._…` input
// (CodeQL js/redos). Scanned workflow files are attacker-controlled, so this must stay linear.
const DEAD_SECRET_TAIL_RE =
  /(?<=(?:\$\{\{|\(|,)\s*)(secrets\.GITHUB_TOKEN|github\.token)(?:\s*\|\|\s*(?:'[^']*'|[A-Za-z_][A-Za-z0-9_.]*))+(?=\s*(?:\}\}|\)|,))/gi;
function dropDeadSecretRefs(text: string): string {
  return text.replace(DEAD_SECRET_TAIL_RE, '$1');
}

// R4-2: a static PAT reachable in a SPECIFIC set of jobs (the injectable ones) — a
// PAT in a gated job must not be credited to an ungated one.
function usesPatIn(jobs: Job[]): boolean {
  for (const j of jobs)
    for (const step of j.steps ?? [])
      if (namesOtherSecret(step.with?.['github_token'])) return true;
  return false;
}

/** Any secret other than the default token that can actually be reached is a static PAT.
 *  (Before 2026-09-25 this tested "no GITHUB_TOKEN anywhere in the expression", which missed
 *  `secrets.GH_PAT || secrets.GITHUB_TOKEN` and flagged the reverse.) */
function namesOtherSecret(v: unknown): boolean {
  return /secrets\.(?!GITHUB_TOKEN\b)[A-Za-z_]/i.test(dropDeadSecretRefs(str(v)));
}

/** A secret other than the default token handed to these steps as their GitHub token (the
 *  action's `github_token` input, or `GH_TOKEN` / `GITHUB_TOKEN` in the step env): a PAT by use,
 *  whatever it is called. fw#481 S3-a: a maintainer PAT whose name did not end in `_TOKEN` or
 *  `_PAT` was critical only because `id-token: write` stood next to it. */
function stepsHoldPat(steps: Step[]): boolean {
  return steps.some(
    (s) =>
      namesOtherSecret(s.with?.['github_token']) ||
      namesOtherSecret(s.env?.['GH_TOKEN']) ||
      namesOtherSecret(s.env?.['GITHUB_TOKEN'])
  );
}

// A GitHub App installation token minted in the job. Its reach is the App's, not the job's
// `permissions:` block, so like a PAT its scope is not visible here.
const APP_TOKEN_ACTION_RE = /^\s*(actions\/create-github-app-token|tibdex\/github-app-token)@/i;

/** Is a token minted by an App-token step of `job` handed to one of `steps` (its `with:` or
 *  `env:`, or the job env)? Read by reference (`steps.<id>.outputs.token`), so a token minted
 *  only for a later posting step is not counted. */
function stepsHoldAppToken(job: Job, steps: Step[]): boolean {
  const ids = (job.steps ?? [])
    .filter((st) => APP_TOKEN_ACTION_RE.test(str(st.uses)))
    .map((st) => str((st as { id?: unknown }).id).trim())
    .filter((id) => /^[\w-]{1,100}$/.test(id));
  if (!ids.length) return false;
  const text = steps.map((s) => str(s.with) + ' ' + str(s.env)).join(' ') + ' ' + str(job.env);
  return ids.some((id) => text.includes(`steps.${id}.outputs.token`));
}

/** Does the job sign in to a cloud account? A login action step, or the agent itself told to
 *  use a cloud model (`use_bedrock` / `use_vertex`, or the CLI's own switch in its env): a login
 *  wrapped in a local composite action is not visible, the cloud model switch is. */
function jobSignsInToCloud(job: Job, agents: Step[]): boolean {
  if ((job.steps ?? []).some((st) => CLOUD_LOGIN_RE.test(str(st.uses)))) return true;
  const on = (v: unknown) => !/^\s*["']?(0|false|no|off)?["']?\s*$/i.test(str(v));
  return agents.some(
    (s) =>
      on(s.with?.['use_bedrock']) ||
      on(s.with?.['use_vertex']) ||
      cloudModelEnv({ ...(s.scopeEnv ?? {}), ...(s.env ?? {}) })
  );
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

const CLAUDE_CODE_ACTION_RE = /anthropics\/claude-code-action@/i;
// claude-code-base-action takes the same `show_full_output` input and logs the same way, but
// has no allowed_non_write_users and no auto-scrub, so only the full-output check covers it.
const FULL_OUTPUT_ACTION_RE = /anthropics\/claude-code(-base)?-action@/i;

/** Does `uses` pin an exact release BELOW `min`? Floating refs (`v1`, `main`), SHAs and
 *  anything unparseable return false: writing the setting at all implies a release that has
 *  it, and a SHA cannot be dated from the file. Only a provably older tag is excluded. */
function pinnedBelow(uses: string, min: [number, number, number]): boolean {
  const m = /@v?(\d+)\.(\d+)\.(\d+)$/.exec(uses.trim());
  if (!m) return false;
  const v = [Number(m[1]), Number(m[2]), Number(m[3])];
  for (let i = 0; i < 3; i++) if (v[i] !== min[i]) return v[i] < min[i];
  return false;
}
const FULL_OUTPUT_MIN: [number, number, number] = [1, 0, 16]; // #580, 2025-10-28
const ENV_SCRUB_MIN: [number, number, number] = [1, 0, 77]; // #1093, 2026-03-23

/** `show_full_output: true` on a claude-code(-base)-action step. The action then writes every
 *  agent message and tool result to the Actions log, which its own input description calls
 *  publicly visible. The action compares the input strictly to "true", so a quoted "True" does
 *  not enable it (unquoted True/TRUE is a YAML boolean and arrives as "true"). Before v1.0.16
 *  the output was always printed and the input did not exist, so the setting is not blamed on
 *  an older exact pin. (2026-09-25.) */
function showsFullOutput(steps: Step[]): boolean {
  return steps.some(
    (s) =>
      FULL_OUTPUT_ACTION_RE.test(s.uses ?? '') &&
      !pinnedBelow(s.uses ?? '', FULL_OUTPUT_MIN) &&
      str(s.with?.['show_full_output']) === 'true'
  );
}

/** The action's subprocess secret scrub was ON for this step and the workflow switched it off.
 *  On: claude-code-action >= v1.0.77 auto-sets CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1 exactly when
 *  the step's allowed_non_write_users is non-empty (action.yml:
 *  `env.CLAUDE_CODE_SUBPROCESS_ENV_SCRUB || (inputs.allowed_non_write_users != '' && '1') || ''`).
 *  Without that input the scrub was never on, so there is nothing to have switched off.
 *  Off: the effective env value (step, else job, else workflow; a key present with an empty or
 *  null value still wins and falls through to '1') is non-empty, not an expression, and not one
 *  the CLI accepts as on (1/true/yes/on). */
function envScrubOptedOut(pairs: { job: Job; step: Step }[], wf: Workflow): boolean {
  const wfEnv = (wf as { env?: Record<string, unknown> }).env;
  const KEY = 'CLAUDE_CODE_SUBPROCESS_ENV_SCRUB';
  return pairs.some(({ job, step }) => {
    const uses = step.uses ?? '';
    if (!CLAUDE_CODE_ACTION_RE.test(uses) || pinnedBelow(uses, ENV_SCRUB_MIN)) return false;
    if (!str(step.with?.['allowed_non_write_users']).trim()) return false;
    const holder = [step.env, job.env, wfEnv].find((e) => e != null && KEY in e);
    if (!holder) return false;
    const v = str(holder[KEY]).trim();
    if (!v || /\$\{\{/.test(v)) return false;
    return !/^(1|true|yes|on)$/i.test(v);
  });
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
export function analyzeWorkflow(
  path: string,
  content: string,
  callers?: LocalCaller[],
  autoLabels?: ReadonlySet<string>,
  trustedRunSources?: ReadonlySet<string>,
  environments?: EnvironmentInfo | null
): CiFinding | null {
  AUTO_LABELS = autoLabels ?? new Set();
  TRUSTED_RUN_SOURCES = trustedRunSources ?? new Set();
  ENVIRONMENTS = environments ?? null;
  try {
    return analyzeWorkflowInner(path, content, callers);
  } finally {
    AUTO_LABELS = new Set();
    TRUSTED_RUN_SOURCES = new Set();
    UPSTREAM_TRUSTED = false;
    ENVIRONMENTS = null;
  }
}

function analyzeWorkflowInner(
  path: string,
  content: string,
  callers?: LocalCaller[]
): CiFinding | null {
  let raw: Record<string, unknown>;
  try {
    raw = loadWorkflow(content).raw;
  } catch {
    return null; // unparseable YAML — caller notes it; we don't guess.
  }
  const wf = raw as Workflow; // normalised by loadWorkflow
  // The parsed workflow is shared by files with identical content (loadWorkflow), so the callers
  // are set or cleared on every analysis, never left from another path.
  if (callers?.length) CALLERS.set(wf, callers);
  else CALLERS.delete(wf);
  UPSTREAM_TRUSTED = upstreamRunTrusted(wf, raw);
  UNGATED_MEMO = new WeakMap();
  const steps = allSteps(wf).map((s) => s.step);
  const agentSteps = steps.filter(isAgentStep);
  // The job(s) the agent actually runs in — permission checks scope to these, so
  // a separate job's write perms don't get credited to the agent (the two-job bug).
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
  const reachOf = triggerReach(wf, raw);
  const { keys: triggers, untrusted: forkInput, reusable, workflowRun } = reachOf;
  // Narrowed below (C6-b) to the events an injectable job runs on without a gate.
  let { secretExposed, privileged } = reachOf;

  const nonWrite = str(agentSteps.map((s) => s.with?.['allowed_non_write_users']).find(Boolean));
  const nonWriteStar = bypassArmed(agentSteps);
  const claudeOpen = agentSteps.some(claudeBypassArmed);
  // "*" written but no github_token on that step: the action ignores it and keeps its gate.
  const starWithoutToken = nonWriteOpen(nonWrite) && !claudeOpen;
  const codexOpenStep = agentSteps.find(codexOpen);
  const codexList =
    !codexOpenStep &&
    agentSteps.some((s) => !!codexActionBuild(s.uses) && !!str(s.with?.['allow-users']).trim());
  const nonWriteList = (!!nonWrite && !nonWriteOpen(nonWrite)) || codexList;
  const nonWriteActor = nonWrite.trim() !== '*' && nonWriteOpen(nonWrite);

  // reusable (workflow_call) is scored as potentially-untrusted — its caller may wire an
  // untrusted trigger — but capped at medium below since we can't see the caller.
  const untrustedTrigger = forkInput || reusable;
  const bypassActive = nonWriteStar && untrustedTrigger;

  // An agent in a read-only sandbox runs none of the checked-out code (review, round 2).
  const head =
    agentSteps.length && agentSteps.every(readOnlySandbox) ? null : untrustedHeadCheckout(steps);
  const promptUntrusted = promptTakesUntrusted(agentSteps);

  // G-d / R4-2 / R4-round2#1: reach AND power come only from the INJECTABLE job(s) — a
  // gated sibling job's tools/perms/PAT can't be reached by the untrusted trigger, and
  // must NOT downgrade (mask) an ungated sibling either. Compute injectable jobs FIRST.
  let injJobs = injectableJobs(wf, raw, untrustedTrigger);
  // C6-b: a job `if:` can gate some events and not others (`pull_request` open, the comment
  // command gated to members). Keep only the stranger-firable events an injectable job runs on
  // WITHOUT a gate, and judge privilege and base secrets by those. Only for the workflow's own
  // triggers: a reusable template takes its events from its callers.
  const firable = 'firable' in reachOf ? reachOf.firable : undefined;
  if (forkInput && !reusable && firable?.length && injJobs.length) {
    const label = labelTypeConfigured(wf, raw);
    const openOn = (j: Job) => openEventsOf(j, wf, firable, label); // S4-a: own gate + inherited
    const open = [...new Set(injJobs.flatMap(openOn))];
    if (open.length < firable.length) {
      injJobs = injJobs.filter((j) => openOn(j).length > 0);
      // Every event gated: the jobs are held, and the finding stays a hardening note about the
      // privileged trigger (as for any gated job). Some open: judge by those events only.
      if (open.length) {
        privileged = open.some((t) => PRIVILEGED_EVENT_RE.test(t));
        secretExposed = open.some((t) => /pull_request_target|workflow_run/i.test(t));
      }
    }
  }
  // Fallback to all agent jobs only matters for the signal strings when NO job is
  // injectable — in that case reach is 0 (below), so the fallback never drives severity.
  const powerJobs = injJobs.length ? injJobs : agentJobs;
  // S4-b: only the steps a stranger can start (a held sibling step's tools are not theirs).
  const powerSteps = injJobs.flatMap((j) => strangerSteps(j, wf, raw, workflowRun));
  const scopedSteps = powerSteps.length ? powerSteps : agentSteps; // fallback: never blank
  // T.2b: `uses: ./…` after checking out the untrusted head to the workspace root runs the
  // head's own action code with the job's secrets: code execution, whatever the agent does.
  const headActionRuns = head === 'root' && powerSteps.some((st) => /^\s*\.\//.test(str(st.uses)));
  // fw#481 L3-a: a `run:` step after the root head checkout that may execute the checkout
  // (`python scripts/x.py`, `npm ci`, `make`) does the same as `uses: ./`, under a trigger that
  // hands the job the base repository's secrets. Only for the open jobs; a gated job is the
  // fork-code-on-trust rule's (T.7).
  const headScriptRuns =
    !headActionRuns && head === 'root' && secretExposed && injJobs.some(jobRunsHeadScript);
  // fw#481 L4-a: an open job whose script pastes a stranger's text runs it as shell, with the
  // job's token and secrets, whatever the agent's own tool list says.
  const injectedScript = forkInput && injJobs.some(jobInjectsUntrusted);
  // fw#481 L6: the repository's committed allow lists, loaded by the action in that checkout.
  const committedGrants = [...new Set(injJobs.map((j) => committedGrantsFor(j, powerSteps)))]
    .filter(Boolean)
    .join(' ');
  const toolsBlob =
    collectTools(scopedSteps) +
    (committedGrants ? ' ' + committedGrants : '') +
    (headActionRuns || headScriptRuns || injectedScript ? ' Bash' : '');
  // S.1: the agent reads the untrusted item itself (tool, handle, payload-built prompt file).
  // Scoped to the INJECTABLE jobs, like the tools above: a gated job's read tool is unreachable.
  // Only for a workflow with its OWN stranger-firable trigger: a reusable template given the
  // item number is how a gated caller uses it too, and the caller is not visible here.
  const itemRead = forkInput ? (injJobs.map(jobReadsUntrustedItem).find(Boolean) ?? null) : null;

  // Reach REQUIRES an untrusted trigger AND at least one injectable (ungated) agent job.
  // If every agent job is actor-gated (injJobs empty), an untrusted trigger can't reach
  // any agent → reach 0. B (F10): only under an untrusted event can an attacker supply a
  // malicious head / prompt text / trigger the "*" bypass.
  const reach =
    untrustedTrigger && injJobs.length
      ? Math.max(
          head === 'root' ? 3 : head === 'subdir' ? 1 : 0,
          promptUntrusted || itemRead ? 2 : 0,
          bypassActive ? 2 : 0
        )
      : 0;

  const broadTools = BROAD_TOOL_RE.test(toolsBlob);
  // R4-3: id-token:write is inert without a tool that can mint+exfil the token.
  const egressTool = EGRESS_TOOL_RE.test(toolsBlob);
  const elevated =
    hasCodeWritePerm(wf, powerJobs) || (hasIdTokenWrite(wf, powerJobs) && egressTool);
  const pat = usesPatIn(powerJobs);
  // The Claude bypass needs the job's token handed to the action (`github_token`), which is the
  // extra power counted here. The Codex switch hands the agent nothing: it opens the door
  // (reach) and no more, so a read-only labeler anyone can start stays a note.
  const power =
    (broadTools ? 2 : 0) +
    (bypassActive && claudeOpen ? 1 : 0) +
    (elevated ? 1 : 0) +
    (pat ? 1 : 0);

  // Jobs that run on a stranger-firable workflow_run (review finding 5: decided per job).
  const workflowRunJobs = agentJobs.filter((j) => jobOnWorkflowRun(j, workflowRun));
  const implicitGate = hasImplicitActorGate(agentSteps, bypassActive, workflowRunJobs.length > 0);
  // R4-round2#1: the step-membership gate is credited PER-JOB (via jobActorGate →
  // injectableJobs → reach), NOT as a whole-workflow severity cap (which would mask an
  // ungated sibling). We only surface it as a MITIGATION signal when EVERY agent job is
  // gated (injJobs empty), so we never imply a reachable sibling is safe.
  const membershipGated =
    injJobs.length === 0 &&
    jobList(wf).some((j) => (j.steps ?? []).some(isAgentStep) && hasStepMembershipGate(j));
  // The severity cap below applies only when EVERY agent job is gated (per job, including the
  // needs: chain, or by claude-code-action's default gate). injectableJobs already made that
  // call per job, so an empty injJobs is exactly "all gated". A whole-workflow test would let
  // one gated job mask an open sibling.
  const gate = injJobs.length === 0;
  const gatedSiblings = agentJobs.filter((j) => !injJobs.includes(j)).length;
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
  const githubWriteTool = GH_WRITE_TOOL_RE.test(toolsBlob);
  // claude-code-action in tag mode or with `track_progress` posts and edits its own comment
  // through a tool it always grants; in tag mode it also commits to the branch.
  const tagMode = scopedSteps.some(claudeTagMode);
  const actionComments = scopedSteps.some(claudeOwnTools);
  const writerTokens = toolTokens(toolsBlob).filter(
    (t) => GH_WRITE_TOOL_RE.test(t) || MCP_GH_TEXT_WRITE_RE.test(t)
  );
  const labelOnly =
    writerTokens.length > 0 && writerTokens.every((t) => LABEL_ONLY_TOOL_RE.test(t));
  const textWriteTool =
    actionComments || ((githubWriteTool || MCP_GH_TEXT_WRITE_RE.test(toolsBlob)) && !labelOnly);
  // fw#481 N2 (founder, 2026-11-21): a stranger who steers an agent that can write text to
  // GitHub (comment, edit, review) with a credential that can write threads (issues or
  // pull-requests write, or a PAT handed to it) acts with that credential: high, however narrow
  // the tool list. `contents: write` alone cannot comment. A grant that only sets labels is not
  // such a tool and keeps the grade it had.
  const writeChannel = textWriteTool && (hasMetaWritePerm(wf, powerJobs) || pat);
  // F9: tool scope caps the blast radius. Without a broad/write-capable tool
  // (bare Bash / curl / wget / git push / Write / Edit), an injected agent is
  // limited to scoped API ops (e.g. mcp github issue tools) — real but not
  // catastrophic → cap high/critical down to medium. N2: not when it can write to GitHub with a
  // write credential (F15 below caps that at high).
  if (!broadTools && !writeChannel && severity && SEVERITY_RANK[severity] > SEVERITY_RANK.medium)
    severity = 'medium';
  // F11 + F12: catastrophe requires DAMAGE CAPABILITY = a permission AND a tool to
  // exercise it. An injected agent can only cause real harm if it can EXFIL/RCE
  // (bare Bash / curl / wget / sh — not a scoped script), OR modify GitHub, which
  // needs BOTH a write token/PAT AND a tool that can use it (`gh api` / `gh pr
  // comment` / `git push`). pull-requests:write + id-token but only read-only git +
  // Read/Write tools — no way to touch GitHub or exfil → medium. A read-only token +
  // scoped scripts → medium. Write + `Bash(gh api:*)` → correctly stays high/critical.
  const exfilOrRce = EXFIL_RCE_RE.test(toolsBlob);
  // F15: three damage tiers, not one. RCE (bare Bash/curl) and CODE-WRITE (contents:write
  // + a git/gh tool, or a static PAT of unknown scope) are catastrophic → critical-capable.
  // METADATA-WRITE (pull-requests/issues:write + gh tool) is bounded — comment/label/approve,
  // no code push, no shell, no secret exfil → high at most.
  const rce = exfilOrRce;
  // R4-2: damage perms/PAT scoped to the injectable jobs (powerJobs), not all agent jobs.
  // N2/P2 (founder, 2026-11-21): critical needs a tool that reaches code with the token (a shell,
  // git push, unrestricted gh / gh api, gh pr merge, MCP file writes, tag-mode commits). A PAT or
  // contents: write behind narrow gh issue/pr tools edits threads only.
  const codeTool = rce || CODE_TOOL_RE.test(toolsBlob) || tagMode;
  const codeWrite = (pat || hasCodeWritePerm(wf, powerJobs)) && codeTool;
  const metaWrite = (hasMetaWritePerm(wf, powerJobs) || pat) && (textWriteTool || githubWriteTool);
  const canDamage = rce || codeWrite || metaWrite;
  if (!canDamage && severity && SEVERITY_RANK[severity] > SEVERITY_RANK.medium) severity = 'medium';
  // F15: metadata-write-ONLY (no RCE, no code-write) can't be catastrophic → cap critical to high.
  // pull-requests/issues:write + Bash(gh api:*)/Bash(git:*), no bare Bash, no PAT — an
  // injected agent manipulates PRs/issues but can't push code (needs contents:write) → high.
  if (canDamage && !rce && !codeWrite && severity === 'critical') severity = 'high';
  // fw#481 S3-b (founder, 2026-11-18): critical needs reach that outlives the job or touches
  // what users install. A shell (or the PR's own code) next to only the model key and a comment
  // token is high: the key and the token can be taken and threads edited, but nothing is pushed,
  // published or deployed. Lasting reach = a code-write permission the agent can use (a tool
  // that writes to GitHub, or a shell with the checkout's token), a PAT, a cloud login step in
  // the job, or a cloud, token or database secret in the agent's environment. Hand review of 61
  // repositories graded every critical without one of these as high. Not modelled: poisoning
  // the Actions cache a release workflow later restores.
  if (severity === 'critical') {
    const lasting =
      codeWrite ||
      (rce && hasCodeWritePerm(wf, powerJobs)) ||
      stepsHoldPat(scopedSteps) ||
      powerJobs.some(
        (j) => stepsHoldAppToken(j, scopedSteps) || jobSignsInToCloud(j, scopedSteps)
      ) ||
      agentReachableSecrets(wf, scopedSteps, powerJobs).some((s) =>
        LASTING_SECRET_KINDS.has(s.kind)
      );
    if (!lasting) severity = 'high';
  }
  // R4-4, narrowed by N2 to label-only grants: with issues write alone (no pull-requests write,
  // no code write) and no tool that writes text, an injected agent can relabel issues. Medium.
  const issueOnlyWrite =
    metaWrite && !hasPrWritePerm(wf, powerJobs) && !hasCodeWritePerm(wf, powerJobs);
  if (
    issueOnlyWrite &&
    !writeChannel &&
    !rce &&
    severity &&
    SEVERITY_RANK[severity] > SEVERITY_RANK.medium
  )
    severity = 'medium';
  // N2 (founder, 2026-11-21): a stranger who can make the agent write text to GitHub with a
  // write credential gets high, whatever the score of its narrow tools. The plain-pull_request,
  // reusable and text-only caps below still apply.
  if (writeChannel && reach > 0 && !gate && severity === 'medium') severity = 'high';
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
  // C4-c: an agent that can only produce text. Every reachable agent step has a tool policy the
  // scan can read, and together they give no shell, no write or egress tool, no PAT, and no
  // secret in the agent's environment. Anyone may start it; the worst it does is write untrusted
  // text, which the output rules (CI-2 output-to-env, trusted readers) judge on their own.
  const reachableAgents = injJobs.flatMap((j) =>
    strangerSteps(j, wf, raw, workflowRun).map((st) => ({ job: j, st }))
  );
  const textOnly =
    reach > 0 &&
    reachableAgents.length > 0 &&
    reachableAgents.every(
      ({ job, st }) => toolPolicyKnown(st, job) && !agentEnvHoldsSecret(wf, job, st)
    ) &&
    !broadTools &&
    !exfilOrRce &&
    !egressTool &&
    !githubWriteTool &&
    !writeChannel &&
    !pat;
  if (textOnly && severity && severity !== 'advisory') severity = 'advisory';
  if (!severity) severity = 'advisory';

  // Build the transparent record of WHY this severity.
  const signals: string[] = [];
  // T.1: name the local caller whose trigger the template was scored with.
  const openCallers = (callers ?? []).filter((c) => c.untrusted && !c.gated && !c.dispatched);
  if (openCallers.length)
    signals.push(
      `called by ${openCallers.map((c) => `${safeText(c.file, 120)} (${c.keys.map((k) => safeText(k, 40)).join(', ')})`).join('; ')}`
    );
  if (secretExposed)
    signals.push(
      `runs with base-repo secrets (${triggers
        .filter((t) => /target|workflow_run/i.test(t))
        .map((t) => safeText(t, 40))
        .join(', ')})`
    );
  else if (forkInput)
    signals.push(
      `triggered by untrusted input (${triggers.map((t) => safeText(t, 40)).join(', ')})`
    );
  else if (reusable)
    signals.push(
      reusableLoadedGun
        ? `reusable workflow (${triggers.map((t) => safeText(t, 40)).join(', ')}) that checks out an untrusted head / ingests untrusted input: exploitable the moment a caller wires a fork trigger (reachability depends on the caller, but this workflow is built to process attacker input)`
        : `reusable workflow (${triggers.map((t) => safeText(t, 40)).join(', ')}): no untrusted trigger of its own; reachability depends on the caller's trigger + actor gate`
    );
  if (forkInput && !privileged && !reusable)
    signals.push(
      'triggered by `pull_request`: fork PRs run with a read-only token (lower risk than pull_request_target)'
    );
  if (head === 'root') signals.push('checks out the untrusted PR head into the workspace root');
  if (committedGrants && BROAD_TOOL_RE.test(committedGrants))
    signals.push(
      "the action loads the repository's committed `.claude/settings` allow list in this checkout, and it adds broad tools to the agent's own list"
    );
  if (injectedScript)
    signals.push(
      "a `run:` script expands stranger-written event text with `${{ }}` (shell injection): it runs as code in the agent's job, with its token and secrets. Pass it through `env:` and quote it instead"
    );
  if (headScriptRuns)
    signals.push(
      "a `run:` step executes the checked-out PR code (a script, an install or a build): the PR author's code runs with the job's token and secrets"
    );
  if (headActionRuns)
    signals.push(
      "runs the checked-out head's own action (`uses: ./…`): the PR author's code runs with the job's secrets"
    );
  if (head === 'subdir') signals.push('checks out the untrusted PR head into an isolated subdir');
  // S.4: which claude-code-action build runs, and whether it checks the actor. A third-party
  // build is never credited with the official write gate (B21), on any event.
  const thirdParty = agentSteps
    .map((st) => claudeActionBuild(st.uses))
    .find((b) => b !== null && !b.official);
  if (thirdParty && !implicitGate)
    signals.push(
      `third-party build of claude-code-action (\`${safeText(thirdParty.owner, 40)}\`): not assumed to check the actor's write access like the official action`
    );
  const thirdPartyCodex = agentSteps
    .map((st) => codexActionBuild(st.uses))
    .find((b) => b !== null && !b.official);
  if (thirdPartyCodex && !implicitGate)
    signals.push(
      `third-party build of codex-action (\`${safeText(thirdPartyCodex.owner, 40)}\`): not assumed to check the actor's write access like the official action`
    );
  if (reach > 0 && injJobs.some(codexCheckTooLate))
    signals.push(
      "codex-action's own write check runs after the job has checked out and used the PR's code"
    );
  if (workflowRunJobs.length) {
    const builds = workflowRunJobs
      .flatMap((j) => (j.steps ?? []).filter(isAgentStep))
      .map((st) => claudeActionBuild(st.uses))
      .filter((b) => b !== null);
    const old = builds.find((b) => b.official && !workflowRunChecked(b.ref));
    if (old)
      signals.push(
        `claude-code-action \`@${safeText(old.ref, 40)}\` predates v1.0.185, so it does not check the actor on workflow_run`
      );
    else if (builds.some((b) => b.official && SHA_REF_RE.test(b.ref)))
      signals.push(
        'claude-code-action is pinned by SHA on workflow_run: its actor check there exists from v1.0.185; confirm the pinned commit is that release or newer'
      );
  }
  if (promptUntrusted) signals.push('feeds untrusted PR/issue text to the agent');
  else if (itemRead)
    signals.push(
      itemRead === 'prompt-file'
        ? 'an earlier step writes untrusted PR/issue text into the prompt file the agent reads'
        : itemRead === 'artifact'
          ? 'the job downloads the artifacts of the triggering run (produced by the PR) before the agent runs'
          : itemRead === 'step-output'
            ? "the agent's prompt is an earlier step's output, built from untrusted PR/issue text"
            : itemRead === 'tool'
              ? 'the agent fetches PR/issue text itself with a read tool (the text never appears in the prompt)'
              : 'the agent is given the PR/issue number and reads the text itself (the text never appears in the prompt)'
    );
  if (broadTools) {
    // Names embed scanned-file text that flows into the Action's PR comment (render.ts).
    // Wrap each in a backtick code span (the repo convention, cf. agent-config's hook
    // signal) — combined with toolTokens stripping backticks/newlines, attacker-controlled
    // grant text cannot inject markdown into the trusted comment.
    const names = matchedBroadTools(toolsBlob);
    signals.push(
      names.length
        ? `agent has broad/write-capable tools: ${names.map((n) => `\`${safeText(n, 80)}\``).join(', ')}`
        : 'agent has broad/write-capable tool grants'
    );
  }
  if (!broadTools && writerTokens.length)
    signals.push(
      `agent can write to GitHub with: ${writerTokens.map((n) => `\`${safeText(n, 80)}\``).join(', ')}`
    );
  if (textOnly)
    signals.push(
      'the agent can only produce text: read-only tools, no write token it can use, no secret in its environment'
    );
  if (bypassActive && claudeOpen)
    signals.push(
      nonWriteActor
        ? "allowed_non_write_users is the triggering user's own login, with github_token, so any user can trigger the agent"
        : 'allowed_non_write_users: "*" with github_token, so any user can trigger the agent'
    );
  if (bypassActive && codexOpenStep)
    signals.push(
      str(codexOpenStep.with?.['allow-users']).trim() === '*'
        ? 'allow-users: "*", so any user can trigger the agent'
        : "allow-users is the triggering user's own login, so any user can trigger the agent"
    );
  if (elevated) signals.push('elevated permissions (contents/id-token: write)');
  if (pat) signals.push('a static PAT is exposed to the agent (recoverable via injection)');
  // Scoped to the reachable agent jobs, like the tool and PAT signals above. By job, not by
  // step identity: a YAML-anchored step is the same object in a gated job and an open one.
  const scopedPairs = allSteps(wf).filter(
    (p) => isAgentStep(p.step) && (injJobs.length === 0 || injJobs.includes(p.job))
  );
  const fullOutput = showsFullOutput(scopedPairs.map((p) => p.step));
  const scrubOff = envScrubOptedOut(scopedPairs, wf);
  if (fullOutput)
    signals.push(
      '`show_full_output: true` writes every agent command and its output to the Actions log, public on a public repo; GitHub masks known secret values there, but an agent told to encode one first can publish it without any network tool'
    );
  if (scrubOff)
    signals.push(
      "`CLAUDE_CODE_SUBPROCESS_ENV_SCRUB` is switched off, so the action no longer scrubs the Anthropic key, cloud credentials and Actions runtime tokens from the agent's shell"
    );
  if (!gate && reach > 0) signals.push('no effective actor gate');
  if (!gate && reach > 0 && gatedSiblings > 0) {
    const siblings = agentJobs.filter((j) => !injJobs.includes(j));
    const explicit = siblings.filter((j) => jobGated(j, wf, raw)).length;
    const byDefault = siblings.length - explicit;
    const n = (k: number) => `${k} other agent job${k === 1 ? '' : 's'}`;
    const defaultSteps = siblings
      .filter((j) => !jobGated(j, wf, raw))
      .flatMap((j) => (j.steps ?? []).filter(isAgentStep));
    const parts = [
      explicit ? `${n(explicit)} ${explicit === 1 ? 'is' : 'are'} actor-gated` : '',
      byDefault
        ? `${n(byDefault)} ${byDefault === 1 ? 'is' : 'are'} held by ${defaultGateOwner(defaultSteps)}'s default write-access gate`
        : '',
    ].filter(Boolean);
    signals.push(
      `${parts.join('; ')} in this workflow; this finding is about the ungated one${injJobs.length === 1 ? '' : 's'}`
    );
  }
  // The ambiguous case: NO explicit `permissions:` anywhere. The GITHUB_TOKEN then
  // defaults to the repo/org setting, which MAY be write-all (the legacy default). We
  // can't prove it from the file, so we don't inflate severity (that would false-positive
  // on read-default repos) — but when an injectable agent has a write-capable tool, we
  // surface the ambiguity so the reader pins it down.
  const noExplicitPerms = wf.permissions == null && jobList(wf).every((j) => j.permissions == null);
  if (noExplicitPerms && reach > 0 && (broadTools || githubWriteTool))
    signals.push(
      'no explicit `permissions:` block. The token defaults to the repo/org setting, which may grant write; set it explicitly to read-only'
    );

  const mitigations: string[] = [];
  if (gate && (membershipGated || agentJobs.some((j) => jobGated(j, wf, raw))))
    mitigations.push('actor-gated (maintainer/label/write-user required)');
  else if (
    gate &&
    implicitGate &&
    // Not when the switch that removes the check is set (on a trigger no stranger fires).
    agentSteps.some(
      (s) =>
        (!!codexActionBuild(s.uses)?.official && !codexOpen(s)) ||
        (!!claudeActionBuild(s.uses)?.official && !claudeBypassArmed(s))
    )
  ) {
    const owner = defaultGateOwner(agentSteps);
    mitigations.push(
      `${owner} ${owner.includes(' and ') ? 'gate' : 'gates'} the agent to write-access users by default`
    );
  }
  if (head === 'subdir') mitigations.push('untrusted head isolated in a subdir, not root');
  if (envDeny) mitigations.push('secrets env-denied from the agent subprocess');
  if (pinned) mitigations.push('agent action pinned to a commit SHA');
  if (nonWriteList) mitigations.push('non-write users scoped to a list, not "*"');
  // C6-c: the GitHub environment an agent job runs in. Read from GitHub when the reader could ask.
  const envNames = [...new Set(agentJobs.flatMap(jobEnvironmentNames))].slice(0, 3);
  for (const n of envNames) {
    const name = `\`${safeText(n, 60)}\``;
    if (ENVIRONMENTS?.protected.has(n))
      mitigations.push(
        `runs in environment ${name}, which requires a reviewer to approve each run`
      );
    else if (!ENVIRONMENTS)
      mitigations.push(
        `runs in environment ${name}: if it requires reviewers, a stranger's run waits for approval (not visible to this scan)`
      );
  }
  if (starWithoutToken)
    mitigations.push(
      'allowed_non_write_users: "*" is set without github_token, so the action keeps its default write gate'
    );

  const title =
    severity === 'critical' || severity === 'high'
      ? 'Injectable agent workflow: untrusted input reaches a tool-using agent with secrets'
      : severity === 'medium'
        ? 'Agent workflow with a risky pattern (partially mitigated)'
        : 'Agent workflow on a privileged trigger: review the actor gate';

  // S4-b: anchor at a step a stranger can start, not at the first agent step in the file. Two
  // steps often share one `uses:` string, so the step's place among them picks the occurrence.
  // An open job whose agent is a `run:` step has no `uses:` to point at: the first agent action
  // in the file stays the anchor, as before.
  const hasUses = (st: Step) => typeof st.uses === 'string';
  const anchor = powerSteps.find(hasUses) ?? agentSteps.find(hasUses);
  const agentUses = anchor?.uses;
  const nth = anchor ? steps.filter((st) => st.uses === agentUses).indexOf(anchor) : 0;
  const line =
    (agentUses ? lineOfNth(content, agentUses, nth) : undefined) ??
    lineOfRe(
      content,
      /^[ \t]*(pull_request_target|issue_comment|issues|workflow_run|pull_request_review_comment|pull_request)[ \t]*:/m
    );
  const finding: CiFinding = {
    ...(line ? { line } : {}),
    check: 'CI-2',
    // One verdict per workflow file — the finding IS the file's reachability score.
    rule: 'CI-2.injectable-workflow',
    dimension: 'workflows',
    severity,
    title,
    file: path,
    signals,
    mitigations: mitigations.length ? mitigations : undefined,
    fix:
      head === 'root' && privileged
        ? 'Do not check out the untrusted PR head into the workspace root under a privileged trigger (pull_request_target/workflow_run): check out the base ref, or isolate the head in a subdir (--add-dir). Add an actor gate and scope the agent tools.'
        : head === 'root'
          ? 'This runs under `pull_request` (fork PRs get a read-only token), so the head checkout is low-risk today: keep it on `pull_request` (not `pull_request_target`) and keep the actor gate + scoped tools.'
          : bypassActive && codexOpenStep && !claudeOpen
            ? 'Remove `allow-users: "*"` so that only people with write access start Codex. To keep it open, give the Codex step no write token: read-only job permissions, a read-only sandbox, and a separate step that posts the result. See the codex-action security doc.'
            : 'Add/verify an actor gate, scope the agent tools to read-only, and env-deny secrets. See Anthropic’s claude-code-action security doc.',
  };
  const extraFix = [
    fullOutput
      ? 'Remove `show_full_output: true` (the action documents it for debugging only).'
      : '',
    scrubOff ? 'Remove the `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB` opt-out.' : '',
  ]
    .filter(Boolean)
    .join(' ');
  if (extraFix) finding.fix = `${finding.fix} ${extraFix}`;
  finding.explain = explainWorkflow({
    severity,
    anyone: bypassActive && !gate,
    anyoneInput: codexOpenStep && !claudeOpen ? 'allow-users' : 'allowed_non_write_users',
    ungated: !gate && reach > 0,
    gated: gate,
    triggers,
    secretTriggers: secretExposed ? triggers.filter((t) => /target|workflow_run/i.test(t)) : [],
    head: head === 'root' || head === 'subdir' ? head : null,
    readsText: promptUntrusted,
    tools: broadTools ? matchedBroadTools(toolsBlob) : [],
    shell: rce,
    pushCode: codeWrite,
    editThreads: metaWrite,
    pat,
    publicOutput: fullOutput,
    scrubOff,
    reusable,
  });
  return finding;
}

// ─── CI-4: agent-reachable secrets ───────────────────────────────────────────
// The agent's OWN credential (its API key / the default GITHUB_TOKEN) is expected
// fuel — not a finding. CI-4 fires on EXTRA secrets an agent can reach (cloud OIDC,
// static PATs, DB creds, other API keys) which an injected agent with a shell could
// exfiltrate. Reuses analyzeWorkflow's reachability model — same danger shape.
// `OPENAI_KEY` / `OPENAI.KEY` / `ANTHROPIC.KEY`: the names pr-agent reads its model key from.
const AGENT_FUEL_RE =
  /^(ANTHROPIC_API_KEY|ANTHROPIC_AUTH_TOKEN|ANTHROPIC_BASE_URL|CLAUDE_CODE_OAUTH_TOKEN|OPENAI_API_KEY|OPENAI_BASE_URL|GEMINI_API_KEY|GOOGLE_API_KEY|GITHUB_TOKEN|OPENAI_KEY|OPENAI\.KEY|ANTHROPIC\.KEY)$/i;

// A1: the agent-action INPUT keys that take the LLM credential/endpoint. A secret
// bound to one of these is fuel regardless of its NAME (nvidia_inference_key,
// MY_CLAUDE_KEY, …). Deliberately EXCLUDES `github_token` — a non-default token
// passed there is a recoverable PAT (usesPat/CI-2 already treats it as a real secret).
const FUEL_INPUT_KEYS =
  /^(anthropic[_-]api[_-]key|anthropic[_-]auth[_-]token|anthropic[_-]base[_-]url|claude[_-]code[_-]oauth[_-]token|claude[_-]oauth[_-]token|openai[_-]api[_-]key|openai[_-]base[_-]url|gemini[_-]api[_-]key|google[_-]api[_-]key)$/i;

/** Secret names that are the agent's own fuel by ASSIGNMENT: bound to a fuel input
 *  key (`with:`) or to a fuel-named env var. */
function fuelSecretNames(agentSteps: Step[]): Set<string> {
  const out = new Set<string>();
  const add = (v: unknown) => {
    for (const m of dropDeadSecretRefs(str(v)).matchAll(/secrets\.([A-Za-z_][A-Za-z0-9_]*)/gi))
      out.add(m[1]);
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
  for (const b of blobs.map(dropDeadSecretRefs)) {
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
  /** No shell, but a file-read tool and a cloud key file in the workspace (S4-b). */
  readsKeyFile: boolean;
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

  const bypassActive = bypassArmed(jobAgentSteps) && untrustedTrigger;
  const head = untrustedHeadCheckout(jobSteps);
  const reachOf = triggerReach(wf, raw);
  const label = labelTypeConfigured(wf, raw);
  // S4-c: the same per-event reading CI-2 uses (C6-b), with gates inherited through `needs:`
  // (S4-a). CI-4 used to call a job open that CI-2, in the same file, called gated.
  const firable = 'firable' in reachOf ? reachOf.firable : undefined;
  const heldOnEveryEvent =
    reachOf.untrusted &&
    !reusable &&
    !!firable?.length &&
    openEventsOf(job, wf, firable, label).length === 0;
  const gate =
    heldOnEveryEvent ||
    jobGated(job, wf, raw) ||
    hasImplicitActorGate(jobAgentSteps, bypassActive, jobOnWorkflowRun(job, reachOf.workflowRun), {
      job,
      dispatchable: dispatchable(wf, raw),
    });
  // S4-b: an open job is judged by the steps a stranger can start. A gated one keeps the whole
  // list, so its hardening note still names every secret in the job.
  const live = gate ? jobAgentSteps : strangerSteps(job, wf, raw, reachOf.workflowRun);
  const reach = Math.max(
    head === 'root' ? 3 : head === 'subdir' ? 1 : 0,
    promptTakesUntrusted(live) || (!reusable && jobReadsUntrustedItem(job)) ? 2 : 0,
    bypassActive ? 2 : 0
  );
  const injectable = untrustedTrigger && !gate && reach > 0;
  const tools = collectTools(live) + ' ' + committedGrantsFor(job, live); // L6
  const canReadEnv = EXFIL_RCE_RE.test(tools); // bare shell = read env + exfil

  const secrets = agentReachableSecrets(wf, live, [job]);
  // S4-b: a cloud key written into the workspace by a login step, where a file-read tool finds it.
  const keyFile = injectable ? workspaceKeyFile(job, live, label) : null;
  // claude-code-action in tag mode (no `prompt`, or `track_progress`) always allows Read, Glob
  // and Grep, whatever `--allowedTools` adds.
  const canReadFiles = FILE_READ_TOOL_RE.test(tools) || live.some(claudeOwnTools);
  const readsKeyFile = !!keyFile && !canReadEnv && canReadFiles;
  if (keyFile && (canReadEnv || readsKeyFile))
    secrets.push({
      name: `${keyFile} (key file the cloud login step writes into the workspace)`,
      kind: 'cloud-file',
    });
  if (secrets.length === 0) return null;

  // Anti-noise: `id-token:write` (cloud OIDC) is extremely common and, on its own,
  // is only a risk when an injectable agent can actually run a shell to use it. So:
  //  - EXPLOITABLE (injectable + bare shell): report, incl. id-token → critical.
  //  - NOT exploitable: only report if there's a REAL secret env-var (a static PAT,
  //    DB cred, API key…) as a hardening advisory. id-token-ONLY here → null (skip).
  const realSecrets = secrets.filter((s) => s.kind !== 'cloud-oidc');
  const hasOidc = secrets.some((s) => s.kind === 'cloud-oidc');
  // fw#481 S3-a: `id-token: write` reaches a cloud account only when the job signs in to one.
  // On its own it is what claude-code-action asks for to get its GitHub App token: 9 of 16
  // critical findings in the hosted scan named nothing else. Still high with a shell: the token
  // it mints is accepted by whatever trusts this repository's workflows.
  const cloudLogin = jobSignsInToCloud(job, live);
  let severity: Severity;
  if (injectable && canReadEnv) {
    severity =
      (hasOidc && cloudLogin) ||
      realSecrets.some((s) => LASTING_SECRET_KINDS.has(s.kind)) ||
      stepsHoldPat(live) ||
      stepsHoldAppToken(job, live)
        ? 'critical'
        : 'high';
  } else if (injectable && readsKeyFile) {
    severity = 'high'; // read and repeated in the agent's output: no shell needed
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
  return { severity, secrets, injectable, canReadEnv, readsKeyFile };
}

/** CI-4 — secrets an injectable agent could exfiltrate. Sibling of analyzeWorkflow
 *  (reuses its reachability model). Evaluates each agent JOB independently and
 *  reports the worst — a secret + shell in a NON-reachable job must not conflate
 *  with a DIFFERENT job's untrusted trigger. Null when no job is a finding. Never
 *  throws. */
export function analyzeWorkflowSecrets(
  path: string,
  content: string,
  callers?: LocalCaller[],
  autoLabels?: ReadonlySet<string>,
  trustedRunSources?: ReadonlySet<string>
): CiFinding | null {
  AUTO_LABELS = autoLabels ?? new Set();
  TRUSTED_RUN_SOURCES = trustedRunSources ?? new Set();
  try {
    return analyzeWorkflowSecretsInner(path, content, callers);
  } finally {
    AUTO_LABELS = new Set();
    TRUSTED_RUN_SOURCES = new Set();
    UPSTREAM_TRUSTED = false;
  }
}

function analyzeWorkflowSecretsInner(
  path: string,
  content: string,
  callers?: LocalCaller[]
): CiFinding | null {
  let raw: Record<string, unknown>;
  try {
    raw = loadWorkflow(content).raw;
  } catch {
    return null;
  }
  const wf = raw as Workflow; // normalised by loadWorkflow
  // The parsed workflow is shared by files with identical content (loadWorkflow), so the callers
  // are set or cleared on every analysis, never left from another path.
  if (callers?.length) CALLERS.set(wf, callers);
  else CALLERS.delete(wf);
  UPSTREAM_TRUSTED = upstreamRunTrusted(wf, raw);
  UNGATED_MEMO = new WeakMap();
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

  const firstSecret = worst.secrets[0]?.name ?? '';
  // A key file is anchored at the login step that writes it (its display name is not a
  // `secrets.` reference, and it is the reason for the grade when the agent has no shell).
  const secretLine =
    worst.readsKeyFile || worst.secrets[0]?.kind === 'cloud-file'
      ? lineOfRe(content, /^[ \t]*credentials_json[ \t]*:/m)
      : /^id-token/.test(firstSecret)
        ? lineOfRe(content, /^[ \t]*id-token[ \t]*:[ \t]*write/m)
        : lineOf(content, `secrets.${firstSecret}`);
  return {
    ...(secretLine ? { line: secretLine } : {}),
    check: 'CI-4',
    rule: 'CI-4.agent-reachable-secret',
    dimension: 'data',
    severity: worst.severity,
    title:
      worst.severity === 'advisory'
        ? 'Secrets reachable by the agent: hardening'
        : 'Exfiltratable secrets reachable by an injectable agent',
    file: path,
    signals: [
      `agent can reach: ${worst.secrets.map((s) => s.name).join(', ')}`,
      worst.injectable
        ? 'the agent is externally triggerable (untrusted trigger, no gate)'
        : 'gated / not externally triggerable: latent risk only',
      worst.canReadEnv
        ? 'agent has arbitrary shell (bare Bash) → can read env and exfiltrate'
        : worst.readsKeyFile
          ? 'agent has a file-read tool: it can read the key file and repeat it in its output, no shell needed'
          : 'no arbitrary-shell tool: not exfiltratable today, but one tool-add away',
    ],
    fix: 'Move extra secrets to a separate trusted job the agent cannot reach; drop id-token:write if unused; scope the agent tools to read-only and gate the trigger.',
    explain: explainSecrets({
      severity: worst.severity,
      secrets: worst.secrets.map((s) => s.name),
      injectable: worst.injectable,
      shell: worst.canReadEnv,
      readsFile: worst.readsKeyFile,
    }),
  };
}

// T.3 (2026-10-11): claude-code-action installs plugins from the marketplaces it is given, on
// every run. A marketplace outside the vendor's own org that is not pinned to a commit lets its
// owner change code and prompts (plugins can ship hooks) that run next to the job's token.
const COMMIT_PIN_RE = /[#@][0-9a-f]{40}\b/i;

/** The GitHub owner a marketplace reference points at: `https://github.com/<o>/…`,
 *  `git@github.com:<o>/…` or the `<o>/<r>` shorthand. Any other host, or a `..` segment, has
 *  none: `https://git.example.net/anthropics/…` is not the vendor's (review, round 2). */
function marketplaceOwner(market: string): string | undefined {
  if (/(^|[/\\])\.\.([/\\]|$)/.test(market)) return undefined;
  return (
    /^(?:https?:\/\/(?:www\.)?|git@|ssh:\/\/git@)?github\.com[:/]([\w.-]{1,100})\/[\w.-]{1,100}(?:\.git)?\/?(?:[#@].*)?$/i.exec(
      market
    )?.[1] ?? /^([\w.-]{1,100})\/[\w.-]{1,100}(?:[#@].*)?$/.exec(market)?.[1]
  );
}

export function analyzeWorkflowPlugins(path: string, content: string, owner?: string): CiFinding[] {
  let raw: Record<string, unknown>;
  try {
    raw = loadWorkflow(content).raw;
  } catch {
    return [];
  }
  if (!raw || typeof raw !== 'object') return [];
  const wf = raw as Workflow; // normalised by loadWorkflow
  const out: CiFinding[] = [];
  const seen = new Set<string>();
  for (const { step } of allSteps(wf)) {
    if (!claudeActionBuild(step.uses)) continue;
    if (!str(step.with?.['plugins']).trim()) continue;
    for (const m of str(step.with?.['plugin_marketplaces']).split(/[\s,]+/)) {
      const market = m.trim();
      if (!market || COMMIT_PIN_RE.test(market)) continue;
      // The repository itself (`./.`) or a repository of the same owner is not a third party.
      if (/^\.{1,2}(\/|$)/.test(market)) continue;
      const mo = marketplaceOwner(market);
      if (mo && mo.toLowerCase() === 'anthropics') continue;
      if (owner && mo && mo.toLowerCase() === owner.toLowerCase()) continue;
      if (seen.has(market)) continue;
      seen.add(market);
      out.push({
        check: 'CI-3',
        rule: 'CI-3.plugin-unpinned',
        locator: safeText(market, 200),
        dimension: 'mcp',
        severity: 'medium',
        title: 'Agent installs plugins from a third-party marketplace on every run',
        file: path,
        signals: [
          `\`plugin_marketplaces: ${safeText(market, 120)}\` is not pinned to a commit: whoever controls it changes the code and prompts the agent runs`,
        ],
        fix: 'Pin the marketplace to a commit (`<url>#<sha>`), or vendor the plugin into this repository.',
      });
    }
  }
  return out;
}

// T.5a (2026-10-11): a SCHEDULED agent (no stranger can fire it, and nobody picks what it reads)
// that still reads content strangers write (open issues and PRs, or the
// web) while it holds a write token. Founder decision (node9Firewall#337): counted, at the
// lowest level (advisory, tier alert).
// "open issues" in prose is a read, except after a verb of making ("and open pull requests for
// the updates" creates them; review, round 2).
const ITEM_LIST_RE =
  /gh\s+(?:issue|pr)\s+(?:list|view)\b|gh\s+search\b|gh\s+api\s+[^\n]{0,80}\/(?:issues|pulls)\b|\blist_issues\b|\bsearch_issues\b|issues\.listForRepo|pulls\.list\b|(?<!\b(?:and|to|then|or|will|should|must|may|can|please|you|also)\s)\bopen (?:issues|pull requests)\b/i;
const WEB_READ_RE = /(^|["\s,])(WebFetch|WebSearch)(\(|\s|,|"|$)/;
// A listing whose output is cut down to a field before the agent sees it (`| grep -o`,
// `--jq '.[].number'`) carries no stranger text.

/** Does this text list items in full on any one command? Judged per command line (a `\`
 *  continuation joined), so a sanitized lookup does not excuse a full listing beside it. */
function readsItemList(text: string): boolean {
  if (text.length > 200_000) return ITEM_LIST_RE.test(text);
  return text
    .replace(/\\\r?\n/g, ' ')
    .split('\n')
    .some((l) => ITEM_LIST_RE.test(l) && !sanitizedListing(l));
}

export function analyzeTrustedReaders(
  path: string,
  content: string,
  autoLabels?: ReadonlySet<string>,
  callers?: LocalCaller[],
  trustedRunSources?: ReadonlySet<string>
): CiFinding[] {
  AUTO_LABELS = autoLabels ?? new Set();
  TRUSTED_RUN_SOURCES = trustedRunSources ?? new Set();
  try {
    return analyzeTrustedReadersInner(path, content, callers);
  } finally {
    AUTO_LABELS = new Set();
    TRUSTED_RUN_SOURCES = new Set();
  }
}

/** A template's triggers are its callers' (T.1), gated ones included: T.5 and T.7 are about the
 *  runs a stranger cannot start (review, round 2: split into caller and template, the same shape
 *  counted nothing). */
function keysWithCallers(keys: string[], callers?: LocalCaller[]): string[] {
  return [...new Set([...keys, ...(callers ?? []).flatMap((c) => c.keys)])];
}

function analyzeTrustedReadersInner(
  path: string,
  content: string,
  callers?: LocalCaller[]
): CiFinding[] {
  let raw: Record<string, unknown>;
  try {
    raw = loadWorkflow(content).raw;
  } catch {
    return [];
  }
  if (!raw || typeof raw !== 'object') return [];
  const wf = raw as Workflow; // normalised by loadWorkflow
  if (callers?.length) CALLERS.set(wf, callers);
  else CALLERS.delete(wf);
  const reach = triggerReach(wf, raw);
  // Stranger-firable workflows are CI-2's; a template with no caller is judged by its callers.
  if (reach.untrusted || reach.reusable) return [];
  const keys = keysWithCallers(reach.keys, callers);
  // The founder's decision is about SCHEDULED agents: nobody chooses what they read. A run a
  // maintainer starts (dispatch, a label, a release) is the maintainer-triggered case (T.7).
  if (!keys.some((k) => /^schedule$/i.test(k))) return [];
  for (const job of jobList(wf)) {
    // A job that runs on schedule reads what nobody picked, whatever other (maintainer-only)
    // triggers the file has; one pinned to an item event is judged per item (review, round 2).
    const jobIf = parseIf(str(job.if));
    if (jobIf !== null && !exprAllowsEvent(jobIf, 'schedule')) continue;
    const steps = job.steps ?? [];
    const agentIdx = steps.findIndex(isAgentStep);
    if (agentIdx < 0) continue;
    const agent = steps.filter(isAgentStep);
    const tools = collectTools(agent);
    const promptText = agent
      .map(
        (st) =>
          str(st.with?.['prompt']) +
          ' ' +
          str(st.with?.['direct_prompt']) +
          ' ' +
          (isRunAgent(st) ? str(st.run) : '')
      )
      .join(' ');
    const earlier = steps
      .slice(0, agentIdx)
      .filter((st) => !isAgentStep(st))
      .map((st) => str(st.run) + ' ' + str(st.with?.['script']));
    const reads: string[] = [];
    // "open pull requests for the updates" creates PRs; a lookup in the prompt cut down to a
    // number reads nothing (review, round 2).
    if (ITEM_READ_TOOL_RE.test(tools) || readsItemList(promptText))
      reads.push('reads open issues or pull requests');
    else if (earlier.some(readsItemList))
      reads.push('an earlier step lists open issues or pull requests for it');
    if (WEB_READ_RE.test(tools)) reads.push('fetches third-party web content');
    if (!reads.length) continue;

    // The write power the agent can reach: a token handed to it, a checkout that keeps the job
    // token (or a PAT) in .git/config, or a PAT. A token withheld (`''`) is none.
    const withheld = agent.every(
      (st) =>
        str(st.with?.['github_token']).trim() === "''" ||
        ('github_token' in (st.with ?? {}) && str(st.with?.['github_token']).trim() === '') ||
        ('GITHUB_TOKEN' in (st.env ?? {}) && str(st.env?.['GITHUB_TOKEN']).trim() === '')
    );
    const checkouts = steps
      .slice(0, agentIdx)
      .filter((st) => /actions\/checkout/i.test(str(st.uses)));
    const persisted = checkouts.some((st) => str(st.with?.['persist-credentials']) !== 'false');
    const checkoutPat = checkouts.some((st) =>
      /secrets\.(?!GITHUB_TOKEN\b)[A-Za-z_]/i.test(str(st.with?.['token']))
    );
    const pat = usesPatIn([job]) || checkoutPat;
    const permWrite = jobsHaveWrite(
      wf,
      [job],
      /["']?(contents|issues|pull-requests)["']?\s*:\s*["']?write/i
    );
    const handsToken = agent.some(
      (st) => !!claudeActionBuild(st.uses) || !!str(st.with?.['github_token']).trim()
    );
    const write = pat || (permWrite && !withheld && (handsToken || persisted));
    // fw#481 L5-b: an unrestricted shell next to a secret whose loss outlives the job turns the
    // same reading into a way out for that secret, whoever starts the run.
    const shell = EXFIL_RCE_RE.test(tools);
    const lasting =
      pat ||
      stepsHoldPat(agent) ||
      steps.some((st) => CLOUD_LOGIN_RE.test(str(st.uses))) ||
      agentReachableSecrets(wf, agent, [job]).some((s) => LASTING_SECRET_KINDS.has(s.kind));
    // An agent started inside GitHub's agentic-workflow firewall (`awf`) reaches only the hosts
    // its config allows, with the model and GitHub keys left out of its environment.
    const firewalled = steps.some((st) => AWF_RE.test(str(st.run).slice(0, 200_000)));
    const high = shell && lasting && !firewalled;
    if (!write && !high) continue;

    const writes = pat
      ? 'a static PAT'
      : write
        ? 'a write token'
        : 'a secret that outlives the run';
    return [
      {
        check: 'CI-2',
        rule: 'CI-2.trusted-trigger-reader',
        dimension: 'workflows',
        severity: high ? 'high' : 'advisory',
        title: high
          ? 'Agent reads content strangers write, with an unrestricted shell and a lasting secret'
          : 'Agent on a trusted trigger reads content strangers write, with a write token',
        file: path,
        signals: [
          `runs on ${keys.map((k) => safeText(k, 40)).join(', ')}: no stranger starts it`,
          ...reads.map((r) => `the agent ${r}`),
          `it holds ${writes}: injected text in that content can act with it`,
          ...(high
            ? [
                'the agent has an unrestricted shell: injected text can send that secret out of the runner',
              ]
            : []),
        ],
        fix: 'Give the agent a read-only token and apply its output in a separate step, or filter the items to trusted authors first.',
      },
    ];
  }
  return [];
}

// T.7 (2026-10-11): fork code in a gated agent job. Founder decision (node9Firewall#337): an
// agent a maintainer starts on fork code is a problem, counted at the lowest level. The gate
// stops a stranger from starting the job; once a maintainer does (a comment, a label, a push
// to the PR branch, a reopen), the agent runs inside the fork's checkout.
// Not pull_request_review(_comment): a fork's review event runs in the fork's context, with no
// secrets and a read-only token, like pull_request (review, round 2).
const FORK_PR_TRIGGER_RE = /^(pull_request_target|issue_comment|workflow_run)$/i;
// An explicit "this repository's own branches only" test: no fork code ever runs.
const SAME_REPO_GATE_RE = new RegExp(
  [
    String.raw`head(?:\.repo|_repository)\.full_name\s*==\s*github\.(?:repository\b|event\.(?:pull_request\.base\.repo|repository)\.full_name)`,
    String.raw`github\.repository\s*==\s*github\.event\.(?:pull_request\.head\.repo|workflow_run\.head_repository)\.full_name`,
    String.raw`head(?:\.repo|_repository)\.fork\s*==\s*false`,
    String.raw`head(?:\.repo|_repository)\.owner\.login\s*==\s*github\.repository_owner`,
    String.raw`workflow_run\.pull_requests\[0\]`,
  ].join('|'),
  'i'
);
// `!github.event.pull_request.head.repo.fork`: the negated spelling of `fork == false`.
const NOT_FORK_ATOM_RE =
  /^github\.event\.(?:pull_request\.head\.repo|workflow_run\.head_repository)\.fork$/i;

const TRUSTED_AUTHOR_GATE_RE =
  /\b(?:pull_request|issue)\.user\.login\s*==|github\.event\.(?:pull_request|issue)\.author_association\s*==\s*['"](?:OWNER|MEMBER|COLLABORATOR)|contains\(\s*fromjson\(\s*['"][^'"]{0,200}\b(?:OWNER|MEMBER|COLLABORATOR)\b[^'"]{0,200}['"]\s*\)\s*,\s*github\.event\.(?:pull_request|issue)\.author_association/i;

/** Does every way through this `if:` hold an atom matching `re`, unnegated and unchained? A way
 *  that cannot run on any of `events` (when given) needs none. */
function requiresAtom(
  src: string,
  re: RegExp,
  events?: string[],
  notRe: RegExp = NOT_FORK_ATOM_RE
): boolean {
  const x = parseIf(src);
  if (!x) return false;
  const req = (e: IfExpr): boolean => {
    if (events?.length && events.every((ev) => !exprAllowsEvent(e, ev))) return true;
    switch (e.k) {
      case 'atom': {
        const m = maskLiterals(e.t);
        return re.test(m) && !CHAINED_COMPARE_RE.test(m);
      }
      case 'not':
        return e.c.k === 'atom' && notRe.test(e.c.t.trim());
      case 'and':
        return e.c.some(req);
      case 'or':
        return e.c.every(req);
    }
  };
  return req(x);
}

const PR_EVENTS = [
  'pull_request_target',
  'pull_request',
  'pull_request_review',
  'pull_request_review_comment',
];
/** The events on which these head checkouts resolve to the PR head, or null for any event. A
 *  fallback to the base (`|| github.sha`) resolves to no head at all on the other events. */
function headRefEvents(heads: Step[]): string[] | null {
  const evs = new Set<string>();
  for (const st of heads) {
    if (st.uses == null) return null; // a `run:` checkout (`gh pr checkout`) works on any event
    const m = /^\s*\$\{\{([\s\S]{1,500})\}\}\s*$/.exec(str(st.with?.['ref']));
    if (!m) return null;
    for (const part of m[1].split('||').map((x) => x.trim())) {
      if (/^github\.event\.workflow_run\.[\w.]+$/.test(part)) evs.add('workflow_run');
      else if (/^github\.event\.pull_request\.[\w.]+$/.test(part))
        PR_EVENTS.forEach((e) => evs.add(e));
      else if (
        !/^(?:github\.(?:sha|ref|ref_name|event\.repository\.default_branch)|'[^']*')$/.test(part)
      )
        return null;
    }
  }
  return evs.size ? [...evs] : null;
}

/** A codex step whose sandbox is read-only and not bypassed by its args: the legacy
 *  `sandbox: read-only`, or the built-in `permission-profile: ":read-only"` (C4-b). A named
 *  profile is defined in a config file the scan does not read, so it is not credited. */
function readOnlySandbox(st: Step): boolean {
  const args = str(st.with?.['codex-args']) + ' ' + str(st.with?.['codex_args']);
  const readOnly =
    /^read-only$/i.test(str(st.with?.['sandbox']).trim()) ||
    /^:read-only$/i.test(str(st.with?.['permission-profile']).trim());
  return readOnly && !PERMISSION_BYPASS_RE.test(args);
}

/** Does every way through this `if:` require the PR's AUTHOR to be trusted? (An `||` branch
 *  that a trusted commenter alone satisfies lets a stranger's PR through.) */
function requiresTrustedAuthor(src: string): boolean {
  const x = parseIf(src);
  if (!x) return false;
  const req = (e: IfExpr): boolean => {
    switch (e.k) {
      case 'atom':
        return (
          TRUSTED_AUTHOR_GATE_RE.test(e.t) &&
          !NONWRITE_SET_RE.test(e.t) &&
          !CHAINED_COMPARE_RE.test(maskLiterals(e.t))
        );
      case 'not':
        return false;
      case 'and':
        return e.c.some(req);
      case 'or':
        return e.c.every(req);
    }
  };
  return req(x);
}

export function analyzeForkCodeOnTrust(
  path: string,
  content: string,
  callers?: LocalCaller[],
  autoLabels?: ReadonlySet<string>,
  trustedRunSources?: ReadonlySet<string>
): CiFinding[] {
  AUTO_LABELS = autoLabels ?? new Set();
  TRUSTED_RUN_SOURCES = trustedRunSources ?? new Set();
  try {
    return analyzeForkCodeOnTrustInner(path, content, callers);
  } finally {
    AUTO_LABELS = new Set();
    TRUSTED_RUN_SOURCES = new Set();
  }
}

function analyzeForkCodeOnTrustInner(
  path: string,
  content: string,
  callers?: LocalCaller[]
): CiFinding[] {
  let raw: Record<string, unknown>;
  try {
    raw = loadWorkflow(content).raw;
  } catch {
    return [];
  }
  if (!raw || typeof raw !== 'object') return [];
  const wf = raw as Workflow; // normalised by loadWorkflow
  // The parsed workflow is shared by files with identical content (loadWorkflow), so the callers
  // are set or cleared on every analysis, never left from another path.
  if (callers?.length) CALLERS.set(wf, callers);
  else CALLERS.delete(wf);
  const reach = triggerReach(wf, raw);
  const forkKeys = keysWithCallers(reach.keys, callers).filter((k) => FORK_PR_TRIGGER_RE.test(k));
  if (!forkKeys.length) return [];
  // A job a stranger can start is CI-2's (injectable-workflow), at its full score.
  const inj = new Set(injectableJobs(wf, raw, reach.untrusted || reach.reusable));
  for (const job of jobList(wf)) {
    if (inj.has(job)) continue;
    const steps = job.steps ?? [];
    const agent = steps.filter(isAgentStep);
    if (!agent.length) continue;
    if (untrustedHeadCheckout(steps) !== 'root') continue;
    // A read-only sandbox runs none of the fork's code (codex `sandbox: read-only`), unless the
    // args switch the sandbox off (review, round 2).
    if (agent.every(readOnlySandbox)) continue;
    // "Same repository only", required on every way into the job, the agent steps, or the
    // head checkouts. A test on an unrelated step guards nothing (review, round 2).
    if (requiresAtom(str(job.if), SAME_REPO_GATE_RE)) continue;
    if (agent.every((st) => requiresAtom(str(st.if), SAME_REPO_GATE_RE))) continue;
    const heads = steps.filter((st) => untrustedHeadCheckout([st]) === 'root');
    if (heads.length && heads.every((st) => requiresAtom(str(st.if), SAME_REPO_GATE_RE))) continue;
    // A head ref read from one event's payload is empty on every other event (the default
    // branch is checked out then): only the branches that run on that event need the test.
    const evs = headRefEvents(heads);
    // No fork trigger of this file checks the head out: the payload field is empty there.
    if (evs && !forkKeys.some((k) => evs.includes(k.toLowerCase()))) continue;
    if (evs && requiresAtom(str(job.if), SAME_REPO_GATE_RE, evs)) continue;
    // The code itself comes from a trusted author: the gate tests who wrote the PR, not who
    // started the run (an author allowlist, or the author's association with the repository).
    if (requiresTrustedAuthor(str(job.if))) continue;
    // Something worth taking: a secret in the job (the model key counts) or a write token.
    const holdsSecret = /secrets\./i.test(str(job.steps) + ' ' + str(job.env));
    if (!holdsSecret && !jobsHaveWrite(wf, [job], /:\s*["']?write/i)) continue;
    return [
      {
        check: 'CI-2',
        rule: 'CI-2.fork-code-on-trust',
        dimension: 'workflows',
        severity: 'advisory',
        title: "A maintainer's action runs the agent inside the fork's code",
        file: path,
        signals: [
          `triggered by ${forkKeys.map((k) => safeText(k, 40)).join(', ')}, behind a gate a maintainer passes (a comment, a label, a push to the PR branch, a reopen)`,
          'checks out the untrusted PR head into the workspace root',
          "the agent loads the fork's CLAUDE.md, .claude/settings.json hooks, .mcp.json and build scripts next to the job's secrets",
        ],
        fix: "Check out the base branch and give the agent the diff, or check the PR head out into a subdirectory the agent does not start in; do not let it run the fork's build or hooks.",
      },
    ];
  }
  return [];
}

// ─── Gap 4: the agent's output written into the job environment ─────────────
// The checks above grade damage by what the agent can do itself. Here the workflow does it: it
// writes the agent's text into `$GITHUB_ENV` or `$GITHUB_PATH`, and every later step of the job
// runs with a value the PR or issue author can steer (`NODE_OPTIONS`, `BASH_ENV`, PATH): code
// execution in the job, whatever tools the agent was given. Within one job; see env-sink.ts.

const GITHUB_PAT_NAME_RE = /(?:^|_)PAT(?:_|$)|^(?:GH|GITHUB)_/i;

// The job fetches the PR's diff before (or in) the agent step: the compare API between the
// event's base and head, `gh pr diff`, or the PR's file list. Its text is the PR author's.
const PR_DIFF_FETCH_RE =
  /\/compare\/[^\s"']{0,200}\.\.\.|\bgh\s+pr\s+diff\b|\/pulls\/[^/\s"']{1,100}\/files\b|\.diff\b[^\n]{0,40}pull/i;
const PR_HEAD_REF_RE =
  /github\.event\.pull_request\.(?:head|number)|github\.event\.number\b|github\.event\.issue\.number/;

function jobFetchesPrDiff(job: Job, steps: Step[]): boolean {
  const first = steps.findIndex(isAgentStep);
  const text = [
    str(job.env),
    ...steps.slice(0, first + 1).map((st) => str(st.run) + ' ' + str(st.with) + ' ' + str(st.env)),
  ].join('\n');
  return PR_DIFF_FETCH_RE.test(text) && PR_HEAD_REF_RE.test(text);
}

/** Secrets the later steps, the job env or the workflow env hand to the job (not the default
 *  token): code running in a later step can read them. */
function laterSecrets(wf: Workflow, job: Job, from: number): string[] {
  const blobs = [str((wf as { env?: unknown }).env), str(job.env)];
  for (const st of (job.steps ?? []).slice(from + 1)) blobs.push(str(st.env), str(st.with));
  const out = new Set<string>();
  for (const b of blobs.map(dropDeadSecretRefs))
    for (const m of b.matchAll(/secrets\.([A-Za-z_][A-Za-z0-9_]*)/gi))
      if (!/^GITHUB_TOKEN$/i.test(m[1])) out.add(m[1]);
  return [...out];
}

export function analyzeAgentOutputToEnv(
  path: string,
  content: string,
  callers?: LocalCaller[],
  autoLabels?: ReadonlySet<string>,
  trustedRunSources?: ReadonlySet<string>
): CiFinding[] {
  AUTO_LABELS = autoLabels ?? new Set();
  TRUSTED_RUN_SOURCES = trustedRunSources ?? new Set();
  try {
    return analyzeAgentOutputToEnvInner(path, content, callers);
  } finally {
    AUTO_LABELS = new Set();
    TRUSTED_RUN_SOURCES = new Set();
    UPSTREAM_TRUSTED = false;
  }
}

function analyzeAgentOutputToEnvInner(
  path: string,
  content: string,
  callers?: LocalCaller[]
): CiFinding[] {
  let raw: Record<string, unknown>;
  try {
    raw = loadWorkflow(content).raw;
  } catch {
    return [];
  }
  if (!raw || typeof raw !== 'object') return [];
  const wf = raw as Workflow; // normalised by loadWorkflow
  if (callers?.length) CALLERS.set(wf, callers);
  else CALLERS.delete(wf);
  UPSTREAM_TRUSTED = upstreamRunTrusted(wf, raw);
  UNGATED_MEMO = new WeakMap();
  const reach = triggerReach(wf, raw);
  const untrustedTrigger = reach.untrusted || reach.reusable;
  if (!untrustedTrigger) return [];
  // Computed once a job has a sink: almost no workflow does.
  let inj: Set<Job> | null = null;

  let best: { severity: Severity; finding: CiFinding } | null = null;
  for (const job of jobList(wf)) {
    const steps = (job.steps ?? []).filter(
      (st): st is Step => st != null && typeof st === 'object'
    );
    const agent = steps.filter(isAgentStep);
    if (!agent.length) continue;
    const sinks = agentOutputSinks(
      steps.map((st) => ({
        id: typeof st.id === 'string' ? st.id : undefined,
        run: !st.uses && typeof st.run === 'string' ? st.run : undefined,
        uses: !!st.uses,
        stepEnv: st.env && typeof st.env === 'object' ? st.env : undefined,
        env: { ...(st.scopeEnv ?? {}), ...(st.env && typeof st.env === 'object' ? st.env : {}) },
        agent: isAgentStep(st) ? (st.uses ? 'action' : 'run') : null,
      })),
      AGENT_CLI_RE
    );
    if (!sinks.length) continue;
    // Untrusted text must reach this job's agent for its output to be the author's. A read-only
    // sandbox limits what the agent does, not what the fork's files make it say.
    const head = untrustedHeadCheckout(steps);
    const promptUntrusted = promptTakesUntrusted(agent);
    const itemRead = reach.untrusted ? jobReadsUntrustedItem(job) : null;
    const bypass = bypassArmed(agent);
    const diffRead = reach.untrusted && jobFetchesPrDiff(job, steps);
    if (!head && !promptUntrusted && !itemRead && !bypass && !diffRead) continue;

    const sink = sinks[0];
    const secrets = laterSecrets(wf, job, sink.step);
    const cloud =
      hasIdTokenWrite(wf, [job]) || steps.some((st) => CLOUD_AUTH_ACTION_RE.test(str(st.uses)));
    // A GitHub token by name (`GH_PAT`, `GITHUB_BOT_TOKEN`), not any `*_TOKEN`: a chat-service
    // token is a secret (high), not a key to the repository.
    const pat = usesPatIn([job]) || secrets.some((s) => GITHUB_PAT_NAME_RE.test(s));
    const codeWrite = hasCodeWritePerm(wf, [job]);
    const prWrite = hasPrWritePerm(wf, [job]);
    inj ??= new Set(injectableJobs(wf, raw, untrustedTrigger));
    const gated = !inj.has(job);
    let severity: Severity =
      codeWrite || pat ? 'critical' : secrets.length || cloud || prWrite ? 'high' : 'medium';
    // Fork PRs on plain `pull_request` run with a read-only token and no secrets.
    const plainPr = reach.untrusted && !reach.privileged && !reach.reusable;
    if (gated || plainPr) severity = 'advisory';
    // A template whose caller is not seen stays capped, unless it is built for attacker input.
    if (
      reach.reusable &&
      !(head === 'root' || promptUntrusted) &&
      SEVERITY_RANK[severity] > SEVERITY_RANK.medium
    )
      severity = 'medium';
    if (best && SEVERITY_RANK[best.severity] >= SEVERITY_RANK[severity]) continue;

    const target = sink.target === 'GITHUB_PATH' ? '$GITHUB_PATH' : '$GITHUB_ENV';
    const signals: string[] = [
      `the agent's output is written to \`${target}\`: \`${safeText(sink.text.trim(), 100)}\``,
      reach.secretExposed
        ? `runs with base-repo secrets (${reach.keys
            .filter((t) => /target|workflow_run/i.test(t))
            .map((t) => safeText(t, 40))
            .join(', ')})`
        : reach.reusable
          ? `reusable workflow (${reach.keys.map((t) => safeText(t, 40)).join(', ')}): reachability depends on the caller's trigger + actor gate`
          : `triggered by untrusted input (${reach.keys.map((t) => safeText(t, 40)).join(', ')})`,
    ];
    if (head === 'root') signals.push('the agent works on the checked-out PR head');
    else if (head === 'subdir') signals.push('the agent reads the PR head checked out in a subdir');
    if (promptUntrusted) signals.push('feeds untrusted PR/issue text to the agent');
    else if (itemRead) signals.push('the agent reads the untrusted PR/issue itself');
    else if (diffRead) signals.push("the job fetches the PR's diff before the agent runs");
    if (bypass) signals.push('allowed_non_write_users is open, with github_token');
    const holds = [
      codeWrite ? 'a write token (contents/packages/actions/deployments)' : '',
      pat ? 'a personal access token' : '',
      prWrite && !codeWrite ? 'pull-requests: write' : '',
      cloud ? 'cloud credentials (id-token: write or a cloud sign-in step)' : '',
      secrets.length
        ? `secrets: ${secrets
            .slice(0, 4)
            .map((s) => `\`${safeText(s, 60)}\``)
            .join(', ')}`
        : '',
    ].filter(Boolean);
    if (holds.length) signals.push(`the job holds ${holds.join('; ')}`);
    if (gated) signals.push('the agent job is actor-gated: latent risk only');
    if (plainPr)
      signals.push(
        'triggered by `pull_request`: fork PRs run with a read-only token and no secrets'
      );
    const noExplicitPerms = wf.permissions == null && job.permissions == null;
    if (noExplicitPerms && !gated && !plainPr)
      signals.push(
        'no explicit `permissions:` block. The token defaults to the repo/org setting, which may grant write; set it explicitly to read-only'
      );
    // The line that writes to the file, searched from the step that holds it (a block's `{` or a
    // repeated `>> "$GITHUB_ENV"` would otherwise match earlier in the file).
    const writeLine =
      sink.text.split('\n').find((l) => /GITHUB_(ENV|PATH)/.test(l)) ?? sink.text.split('\n')[0];
    const stepRun = str(steps[sink.step]?.run).trim().split('\n')[0];
    const from = stepRun ? Math.max(0, content.indexOf(stepRun)) : 0;
    best = {
      severity,
      finding: withLine(
        {
          check: 'CI-2',
          rule: 'CI-2.agent-output-to-env',
          dimension: 'workflows',
          severity,
          title:
            sink.target === 'GITHUB_PATH'
              ? "The agent's output is added to the job's PATH"
              : "The agent's output is written into the job's environment",
          file: path,
          signals,
          fix: `Write the agent's result to a file and read it with a strict parser in the next step (a fixed set of values, or a number); never append free text from the agent to \`${target}\`. If a value must go there, strip newlines (\`tr -d '\\n'\`) and write it under a fixed name, or use a delimiter generated at run time.`,
          explain: explainAgentOutputEnv({
            severity,
            path: sink.target === 'GITHUB_PATH',
            triggers: reach.keys,
            gated,
            plainPr,
            reusable: reach.reusable,
            holds: {
              codeWrite,
              pat,
              prWrite,
              cloud,
              secrets,
            },
          }),
        },
        lineOf(content, writeLine.trim().slice(0, 200), from) ??
          lineOf(content, writeLine.trim().slice(0, 200))
      ),
    };
  }
  return best ? [best.finding] : [];
}
