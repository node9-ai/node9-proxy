Review the current branch's diff against the upstream branch and produce a structured pre-push review.

## Step 1 — Determine the comparison branch

Run these in order; use the first that succeeds:

```
git rev-parse --abbrev-ref --symbolic-full-name @{upstream}
```

If that fails (no upstream), fall back to `origin/main` then `origin/master` then `origin/dev`.

## Step 2 — Read the diff

```
git diff <comparison-branch>...HEAD
```

Also useful for context:

- `git log --oneline <comparison-branch>...HEAD` — commits being pushed
- `git diff --stat <comparison-branch>...HEAD` — file-level summary
- `git status --short` — unstaged changes (warn if non-empty)

If the diff is empty, stop and report "no changes to review."

## Step 3 — Adversarial stance (before dimension checklists)

State the change's **core claim** in one sentence ("this gate blocks X", "this endpoint
returns Y for Z") — then actively try to **refute** it before confirming it. A review that
only _looks for issues_ misses the change whose whole premise is false. Concretely:

- **Liveness — is the new code actually reachable in production?** For any new gate,
  branch, or handler: trace the REAL call site and confirm it's invoked with inputs that
  reach the new path. Don't infer reachability from the diff or its tests. (Real failure:
  a gate keyed on `serverKey && mcpServer` reviewed clean twice, but the real caller never
  sends both — the feature was dead and its green test hid it.)
- **Test honesty — do the tests prove the claim?** Check that test inputs match what the
  real caller sends (payload shape, bare vs namespaced names, headers, props) and that each
  test would fail _for the right reason_, not just fail. A well-formed test on synthetic
  inputs is a false witness.

## Step 4 — Review across the dimensions

For each finding: **file:line** — short description — suggested fix.

### 🐛 Bugs

- Off-by-one, wrong return values, missing returns
- Null / undefined / empty-collection edge cases not handled
- Race conditions, concurrency mistakes
- Silent `catch {}` blocks that swallow real errors
- Resource leaks (unclosed handles, sockets); loop conditions that can run forever
- Wrong comparison (`==` vs `===`, `=` vs `==`), `?? undefined` where `""` must be guarded

### 🔑 Security (this is a security product — review to its threat model, not just OWASP)

- **Fail-closed vs fail-open:** can malformed/oversized/hostile input make an enforcement
  or ingest path reject EVERYTHING (an availability outage) or allow everything? Validation
  on a load-bearing pipeline should degrade (truncate / `.catch` / skip the field), never
  reject the whole payload.
- **Bypass paths:** for any gate/block — enumerate the routes AROUND it (other hooks,
  direct wiring, mode branches like observe/audit, missing meta). Is a "block" enforceable
  from every path that matters, and are the unenforced paths documented?
- **Tenant scoping:** every DB query on shared tables filters by `workspaceId`/org; every
  write path re-checks membership. Never trust an id from the request body.
- **Privilege gating:** governance/config writes are admin-gated on the SERVER (a disabled
  UI control is not a gate). The agent must never be able to weaken its own controls.
- **Untrusted machine/device input:** Json fields from devices are untyped — every nested
  access is guarded (Array.isArray / typeof) so one malformed row can't 500 an endpoint.
- **Audit attribution:** enforcement decisions must log WHO/WHAT/WHY (tool, app/server,
  rule name) — an anonymous block row is an audit gap.
- Classic: hardcoded secrets, injection (SQL/command/prototype), path traversal, ReDoS,
  `eval`/dynamic `Function`, unsafe `child_process`, secrets in logs/previews.

### 🏗 Design

- Wrong layer: logic placed where it can't see what it needs (or duplicating a decision the
  right layer already makes)
- Rolling-deploy / backward-compat: old client + new server (and the reverse) — new fields
  tolerated (`?? []`), removed fields not required, strict schemas not breaking older peers
- Duplication: the same coercion/validation logic hand-copied across layers or repos when
  one source could serve
- Resilience shape: `.strict()` where tolerance is needed, missing caps on unbounded input,
  retries without backoff
- API/contract drift: response shape vs what the consumer (FE/proxy) actually reads

### 📐 Style / convention

- Violations of any `CLAUDE.md` rules in the repo (read them first if present)
- Dead code, unreachable branches, unused imports/variables
- Missing tests for new behavior (especially regression tests for bug fixes)
- `console.log` in non-debug paths; comments that explain _what_ vs _why_
- Missing type signatures where they should exist

### ⚡ Performance

- Synchronous I/O on hot paths; N+1 queries, missing batching
- Repeated work that could be cached/memoized; large structures held unnecessarily

## Step 5 — Output format

Render exactly this layout (skip empty sections):

```
🔍  PR Review  ·  <branch> → <comparison-branch>  ·  <N> commits  ·  <M> files

🎯  CORE CLAIM
  <one sentence> — refuted / survived scrutiny (how it was checked)

🐛  BUGS  (N findings)
  • file:line — description
    Fix: suggested change

🔑  SECURITY  (N findings)
🏗  DESIGN  (N findings)
📐  STYLE  (N findings)
⚡  PERFORMANCE  (N findings)

✅  PASSED
  • Liveness: new paths traced to a real call site — yes / no / n-a
  • Tests added: yes / no — <files>; inputs match the real caller: yes / no
  • CLAUDE.md conventions: matched / violated
  • Format / typecheck / lint: ran / not run

🎯  VERDICT
  Ready to push: yes / yes-with-fixes / no
  Reasoning: <one sentence>
```

## Rules

- **Do NOT auto-apply fixes.** Read-only review. Only report.
- **Do NOT modify any files.** No `Edit`, `Write`, or destructive bash.
- Cite specific file:line for every finding. No vague "consider improving error handling."
- Severity order: real bugs first, nitpicks last. Label debatable style findings "(opinion)".
- **Verdict cap for enforcement/security diffs:** a change that adds or alters a gate, auth,
  DLP, or governance path can be at most **yes-with-fixes** unless its real path was
  exercised end-to-end at least once (a green unit suite alone does not clear it) — and
  recommend the workflow `/code-review` for those diffs; single-pass self-review has a
  demonstrated ceiling.
- If part of the diff is unreadable (binary, image), note it but don't flag.
- Run `npm run typecheck` / `lint` / `test` only when invoked with `--run-checks`.

## Optional arguments

Treat arguments after the command as focus areas:

- `/review-pr security focus` → emphasize 🔑, skim the rest
- `/review-pr quick` → bugs + security only; skip style/perf
- `/review-pr <file-path>` → focus on that file

Default (no args): full review across all dimensions.

## Notes

Pre-push self-review layer using the local session. It complements — never replaces — the
cloud `node9-pr-agent` Action and, for security-critical diffs, the workflow `/code-review`
(adversarial multi-agent pass). This layer catches the obvious before push; those catch what
a single pass can't.
