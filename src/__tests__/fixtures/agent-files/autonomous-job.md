---
description: Build a feature end-to-end autonomously with a real safety net — design → build → real-input tests → adversarial review → security check → PR — then stop for human merge + QA.
---

# Autonomous job

Run a feature to a **safe, reviewed PR** without babysitting. The human's only touchpoints are
one design checkpoint (optional) and the final merge + visual QA. Everything between runs
unattended **with a real adversarial gate** — never blind trust in a green checkmark.

`$ARGUMENTS` = a design-doc path, a spec, or a plain description of the feature.

## Ground rules (non-negotiable)

- **Do NOT merge to main and do NOT deploy.** Open the PR, report, and stop. The human owns
  the irreversible step.
- **Do NOT send external messages / touch prod data** unless the task explicitly authorizes it.
- Obey the repo `CLAUDE.md` (tests, format, typecheck, lint, commit/PR conventions).

## Step 1 — Make it build-ready (the spec→design gate)

Assess the input's maturity (see `doc/roadmap/README.md`):

- If it's a **`design (build-ready)`** doc → proceed to Step 2.
- If it's a **spec / description** → do a short **code-design pass**: read the actual functions
  and files, pin the exact insertion points, data flow, edge cases, and a test plan. For a
  **security-critical** feature (auth / gate / DLP / enforcement / money / irreversible),
  **post the design and pause for approval** before building. Otherwise state the design in one
  paragraph and continue.

## Step 2 — Build

Implement the change in small, coherent commits on a feature branch (never commit straight to a
protected branch). Match surrounding code style.

## Step 3 — Test with REAL inputs (the #1 correctness gate)

- Write tests that use **the inputs the real caller actually produces** — verify the call site,
  don't invent a plausible shape. A test that's green on synthetic inputs the caller never sends
  is worse than none (it hides a dead feature).
- Each test must **fail without the change, for the right reason.**
- For anything that **gates behavior**, add **one real end-to-end exercise** against the actual
  path (gateway / hook / daemon / endpoint) — a unit test is not proof it fires in production.
  Use the `/verify` skill where it fits (run the app, observe the behavior).
- Run the repo's full gate: tests + typecheck + lint + format. All green before proceeding.

## Step 4 — Adversarial review (self-review is not enough)

- Run `/review-pr` for the fast local pass.
- For **security-critical** changes, ALSO run the workflow `/code-review` (refute-it reviewers)
  and **fix every confirmed finding**, then re-run tests. This is the step that catches what
  self-review misses. If the change touches auth/secrets/input-handling, `/security-review`
  as well.

## Step 5 — Open the PR + report (then STOP)

- Push the branch, open the PR with a clear body (what/why, tests, review results, e2e proof).
- **Update the paper trail so docs don't go stale** (hygiene is part of shipping, not a chore
  for later): set the design doc's status header (`building` → what it now is), update its row
  in `doc/roadmap/ROADMAP.md`, and if fully shipped later, the doc moves to `doc/roadmap/done/`.
- Report back to the human with:
  - what shipped + the PR link
  - the review findings and how each was resolved
  - the e2e proof (actual output, not "should work")
  - **an explicit "needs your eyes" flag** for anything visual/UX or any assumption you made
- **Do not merge. Do not deploy.** Wait for the human to QA + merge.

## Scale the rigor to the task

- Trivial/mechanical (rename, copy, CSS): Steps 2–3 + `/review-pr`, skip the design pass.
- Security-critical / irreversible: the full loop, including the design-approval pause and the
  workflow `/code-review`.

The whole point: the human gets **one design checkpoint + one merge decision**, and trusts the
result because a real adversarial gate — not a green checkmark — stands behind it.
