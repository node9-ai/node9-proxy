# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## Unreleased

### Security

- **MCP weakening tools are gated.** node9's MCP server now refuses _weakening_ tools — `node9_shield_disable` and `node9_approver_set` — over MCP **by default**, so a compromised agent can't disarm node9 through node9's own MCP server. A human runs them from the CLI; opt in with `settings.mcpAllowWeakening: true`. Every MCP tool is now explicitly classified (`readonly` / `add` / `weaken`), enforced by a test so a newly added tool can't silently default to `readonly` and bypass the gate.
  - **Operational note:** `node9 mcp-server` is **long-lived** — your agent app (Claude Code, Cursor, …) spawns it once and keeps it running. After updating node9 (or changing `mcpAllowWeakening`), **restart the agent app** (or reconnect MCP) so it re-spawns the server with the new code/config. Rebuilding node9 or restarting the node9 daemon does **not** reload a running server.

### Added

- **Posture auto-ships to the dashboard.** The daemon now pushes the posture scorecard (secrets exposure, open egress, destructive-command gate self-test) to your node9 dashboard on every cloud-sync tick (daemon start + ~5 h) and on a manual `node9 policy sync` — so a logged-in machine's posture stays current without running `node9 posture --ship`. Mirrors the existing blast/scan auto-ship: fire-and-forget, never blocks sync, same redacted payload (no file paths). Only ships when logged in (`node9 login`); opt out with `NODE9_POSTURE_DISABLE=1` (sibling of `NODE9_BLAST_DISABLE` / `NODE9_SCAN_DISABLE`).

- **Inline review prompts** (`reviewChannel` / `--ask`). On a `review` verdict, node9 now routes the approve/deny prompt to the agent's **own inline prompt** instead of node9's separate approver — no frozen session, no 60 s hook-timeout race, no terminal context-switch (resolves node9-ai/node9-proxy#209). Verified live against the agents whose hook contract supports it: **Claude Code** (`hookSpecificOutput.permissionDecision:"ask"`) and **GitHub Copilot CLI** (flat `permissionDecision:"ask"`).
  - Config: `settings.reviewChannel: "ask" | "approver"`; CLI override `--ask` / `--no-ask`. **Default is `"ask"`** for the two supported agents **except when a cloud approver is configured** — node9 never bypasses SaaS org-policy / second-party approval (matches the orchestrator's defer guard). All other agents (Codex, Antigravity, Gemini, Hermes, Cursor, OpenCode, Pi) keep node9's own approver — they either error on or fail open to `ask`, so node9 never sends them one.
  - node9 stays the decision-maker — the full evaluator waterfall runs unchanged; only the prompt _surface_ moves. The short-circuit happens before the SaaS handshake, so no orphaned dashboard/Slack approval is created. `node9 monitor` shows these as a `review` activity.
  - Taint/exfil-driven reviews are excluded from inline `ask` (forced to the routed approver — self-approval is weakest exactly where exfiltration risk is highest).

- **Richer audit on batch-shipped rows (Phase B).** `editFilePath`, `loopCount` and `transcriptPath` now ride the **batch** audit rows (previously only live `/intercept` rows carried them). Additive, optional, cheap to compute at write time — a file path is not a secret (`BlastSnapshot` already ships paths). Unlocks the dashboard's exact **file-risk badge (Tier 2)** — a precise join from a touched file to the machine's exposed credential paths — and exact file nodes in the session graph. No watermark/eid change; historical rows stay lean; review/block rows were already rich via `/intercept`.

- **Taint provenance on blocked exfil rows (Phase D2).** When taint propagation blocks a read→use exfil chain, the block row now carries `taintFromEid` (the audit eid of the originating sensitive read) and `taintSource` (its label). `appendLocalAudit` returns its eid, `TaintRecord` carries `fromEid`, and the daemon serializes the whole record so the link round-trips with no per-hop plumbing. The dashboard turns this into a **causal edge** in the session graph ("this credential read → that egress was blocked"), so a session's exfil attempt reads as one story instead of two unrelated rows.

### Changed

- **Review prompts are inline by default for Claude Code + GitHub Copilot** (see above). Existing users get this on upgrade with no re-setup; add `--no-ask` or set `"reviewChannel":"approver"` to keep node9's own approver. No change for any other agent or for cloud-approver setups.

- **GitHub Copilot CLI integration** (`node9 agents add copilot`). Adds the GitHub Copilot CLI (`copilot`, npm `@github/copilot`) — the terminal agent, distinct from the VS Code Copilot extension which stays under the `vscode` MCP target — to the protected agents at the hooks tier. node9 writes a dedicated `~/.copilot/hooks/node9.json` with PreToolUse/PostToolUse/UserPromptSubmit hooks (`node9 check/log --agent copilot`, `timeoutSec: 600`) and adds/wraps the node9 MCP server in `~/.copilot/mcp-config.json`. All verified live against Copilot CLI 1.0.60:
  - Copilot's PascalCase hook payload is byte-identical to Claude Code (`hook_event_name`/`session_id`/`cwd`/`tool_name`/`tool_input`) and its shell tool is already `bash` with `{command}` args — so node9's existing extractors, canonicalisation, shields, DLP and snapshot work unchanged. No new payload dialect.
  - Because the payload is indistinguishable from Claude, attribution is pinned via the `--agent copilot` flag node9 registers (a hand-written hook missing the flag harmlessly attributes to Claude Code — protection is identical).
  - Blocks emit Copilot's flat `{permissionDecision:"deny", permissionDecisionReason}` (exit 0), which surfaces the reason to the model. preToolUse is fail-closed (a node9 crash/timeout denies the tool).
  - `node9 init` / `detectAgents` discovers Copilot via `~/.copilot` or the `copilot` binary in PATH.
  - `node9 scan` reads Copilot session event logs (`~/.copilot/session-state/*/events.jsonl`) for offline DLP/rule/loop analysis.

- **Antigravity integration** (`node9 agents add antigravity`, alias `agy`). Adds Google Antigravity — the Gemini CLI successor (consumer/free tiers stop serving 2026-06-18) — to the set of protected agents, at the hooks tier. One setup covers both the agy CLI and the Antigravity IDE: PreToolUse/PostToolUse hooks (`node9 check/log --agent antigravity`, 600 s timeout) land in the shared `~/.gemini/config/hooks.json` and the node9 MCP entry + wrapping in `~/.gemini/config/mcp_config.json`. All protocol behaviors verified live against agy 1.0.6:
  - agy's hook payload is a third dialect — tool name/args nest under `toolCall`, the shell tool is `run_command` with PascalCase `CommandLine`/`Cwd` args, and there is no `hook_event_name`. New `canonicalToolInput` maps args to Claude vocabulary at the boundary so shields, DLP and snapshot work unchanged.
  - Blocks emit `{"decision":"deny","reason":…}` — agy silently ignores the Claude block shape and runs the tool (fail-open), so the `--agent` flag pins the response shape deterministically. The deny reason reaches the model verbatim (negotiation loop intact).
  - PostToolUse fires on non-tool steps with `toolCall: null` — `node9 log` skips them instead of writing junk audit rows.
  - `node9 init` / `detectAgents` now discriminates agy from the legacy Gemini CLI inside the shared `~/.gemini` root (settings.json vs antigravity-\*/ dirs, plus `agy`-binary PATH fallback) — fixes a silent protection gap where an agy-only machine was reported gemini-wired while agy ran unguarded.
  - `node9 scan` reads Antigravity brain transcripts (`~/.gemini/antigravity-{cli,ide}/brain/*/.system_generated/logs/transcript_full.jsonl`) for offline DLP/rule/loop analysis.
  - `node9 setup gemini` and `node9 agents list` warn about the Gemini CLI EOL; `node9 setup antigravity` offers cleanup of legacy node9 hooks left in `~/.gemini/settings.json`.

- **Pi integration** (`node9 agents add pi`). Adds Pi (https://pi.dev, `@earendil-works/pi-coding-agent`) to the set of AI coding agents Node9 protects, alongside Claude Code, Gemini, Cursor, Codex, Windsurf, VSCode, Claude Desktop, and Opencode. `node9 init` auto-detects an installed pi (via `~/.pi/agent/` or `pi` binary in PATH — covers the Bun-compiled binary case where the config dir is created lazily on first launch) and drops a CommonJS extension shim at `~/.pi/agent/extensions/node9.js`. The shim wires four pi hooks:
  - `tool_call` — blocks via return value `{ block: true, reason }` (pi's contract, not throw — distinct from Opencode)
  - `tool_result` — fire-and-forget audit log
  - `input` — prompt DLP; blocks via `{ action: "handled" }` + `ctx.ui.notify`
  - `user_bash` (`!` / `!!` prefix) — the prompt-escape side channel; synthesizes a `Bash`-shaped PreToolUse payload so the same dangerous-words and DLP rules engage, blocks by returning a synthetic failed `BashResult` (pi's `UserBashEventResult` has no `block` field by design)

  Pi tool names are normalized inside the shim (`bash`→`Bash`, `read`→`Read`, …) before the payload reaches `node9 check`, so existing PascalCase policy rules engage without edits. Pi has no MCP client, so unlike Opencode setup, no `mcp.node9` entry is written — only the extension file.

  Self-heal: `node9 init` rewrites the shim when its embedded `NODE9_SHIM_VERSION` differs from the installed node9. Design doc: `doc/roadmap/pi-integration.md`.

### Fixed

- **`chmod 777` shield false-positive on string literals (AST-aware fix).** The filesystem shield matched `chmod 777` as a raw substring, so it fired on a `node -e` / `python -c` payload that merely _mentioned_ `chmod 777` inside a regex/string literal (a detection pattern, not a run command). New `analyzeChmod777` only fires when `chmod` is a real command name (a `CallExpr` first-word in the mvdan-sh AST) **and** an open-permission token is present; the raw-regex smart rule `shield:filesystem:review-chmod-777` is suppressed for bash via `AST_FS_REGEX_RULES`. Pinned by a test using the exact `node -e` payload that misfired. Same class as the earlier AST-aware SQL-destructive fix — keyword-in-a-string is never a real action.

- **PostToolUse audit rows misattributed to "Claude Code" when shim-tagged.** `src/cli/commands/log.ts` reimplemented a subset of `detectAiAgent` and skipped its Layer-0 `meta.agent` check entirely — meaning any payload from a node9-authored shim (Pi, Opencode) carrying `hook_event_name: "PostToolUse"` was misattributed to Claude Code in `~/.node9/audit.log`, even when the shim correctly tagged `meta.agent: "Pi"` / `"Opencode"`. The block decisions on PreToolUse and UserPromptSubmit were correct (those go through `check.ts` which honors Layer 0); only the `node9 log` fire-and-forget audit path was wrong. Added the Layer-0 check ahead of the existing fingerprint chain in `log.ts`, exactly mirroring `check.ts:48-60`. Surfaces dashboards' per-agent block-rate metrics correctly for shim-wired agents. Found during Pi integration live verify; defensive empty-string / non-string `meta.agent` falls through to the existing fingerprint chain.

- **Activity-socket rebind loop.** The flight-recorder Unix socket's self-heal used `fs.watch` on `tmpdir()`, which fired inotify events for the daemon's own unlink-then-listen sequence. The watcher would observe the file gone (between unlink and listen completing), trigger another rebind, fire another inotify event, and so on — quickly hitting `EADDRINUSE` and tripping the circuit breaker, leaving the flight recorder down with the warning _"Activity socket repeatedly disappearing — run: node9 daemon restart"_ until manual intervention. Replaced with a 2 s `setInterval` polling probe that cannot self-trigger. Detection latency on real socket loss goes from ~instant to ≤ 2 s. Adds a regression test asserting zero rebind log lines during quiet operation.

---

## v1.19.3 — macOS daemon-detection hotfix

### Fixed

- **`node9 doctor` reported the daemon as not running on macOS even when it was running** (issue #162). `isDaemonRunning()` shelled out to `ss` (Linux iproute2) to verify the TCP port was bound. On macOS `ss` does not exist, so `spawnSync` returned `ENOENT` and the function always returned `false` — even when the daemon process was up and the PID file was valid. This caused `node9 daemon status` (PID-file based) and `node9 doctor` (port-probe based) to disagree on macOS, and made browser/native approvals appear unavailable.

  Fix: drop the TCP probe from the sync hot path. `isDaemonRunning()` now relies on PID-file validity + `process.kill(pid, 0)` — cross-platform and faster (no per-hook `spawnSync`). Callers needing strict HTTP-liveness should use the new `isDaemonReachable()` async helper. The orphan-adoption path in `daemon/server.ts` (rare, fires on `EADDRINUSE` without a PID file) keeps a port probe but now falls back from `ss` to `lsof` on macOS.

  Adds a regression test asserting `isDaemonRunning()` does not invoke `spawnSync` — guards against re-introducing a Linux-only binary dependency.

- **Misleading "browser dashboard" messages.** `node9 doctor` claimed _"Browser dashboard running → http://127.0.0.1:7391/"_ and the daemon banner printed _"🛡️ Node9 Guard LIVE: http://127.0.0.1:7391"_ — but the local browser dashboard was retired in the v3 browser-removal sprint and `GET /` now 404s. Updated both messages to describe what actually exists (terminal & native approvals; SSE/JSON-RPC for `node9 tail` and the MCP gateway).

- **`undo` legacy-fallback inherited `GIT_DIR` from caller env.** `buildGitEnv()`'s shadow-absent path returned `{ ...process.env }` without stripping `GIT_DIR` / `GIT_WORK_TREE`. If those happened to be set in the caller's environment (e.g. running under `git commit` inside a git worktree), the legacy fallback would inherit a worktree pointer it shouldn't use. Now explicitly deletes both before returning.

---

## v1.10.0 — Installed Skill Pinning (AST 02 + AST 07)

### Added

- **Installed Skill Pinning:** Per-plugin drift detection for marketplace-installed plugins at `~/.claude/plugins/marketplaces/<registry>/plugins/<name>/`. Each plugin gets its own pin (same model as MCP server pinning) — installing a new plugin creates a new pin silently, only changes to an already-pinned plugin trigger drift. Off by default (`policy.skillPinning.enabled: false`). Two modes:
  - **`mode: 'warn'` (default)** — `/dev/tty` notification on drift, tool call allowed (exit 0)
  - **`mode: 'block'`** — quarantine the session until the user reviews

  **Intentionally narrow default scope:** user-edited files (`CLAUDE.md`, `.cursor/rules/`, `AGENTS.md`) are **not** in the default set. Those change constantly in normal workflow, and if they're in a git repo `git status`/`git diff` is the better tool. Users who want to pin additional paths can add them via `policy.skillPinning.roots`.

  Covers **AST 02 Supply Chain Compromise** and **AST 07 Update Drift** at the installed-skill layer. Per-session memoisation in `~/.node9/skill-sessions/` so hashing runs once per session.

- **`node9 skill pin` CLI** — `list` / `update <rootKey>` / `reset`, mirroring `node9 mcp pin`.

- **`policy.skillPinning` config** — `{ enabled, mode, roots }`. `roots` extends the default (`~/.claude/skills/`) with user-specified paths.

### Security properties

- Fail-closed on corrupt `skill-pins.json` (recovery: `node9 skill pin reset`)
- Symlink-safe; size-bounded (5000 files / 50 MB per root)
- Path-traversal-safe session IDs (`[A-Za-z0-9_-]{1,128}`)
- Atomic writes, mode 0o600

---

## v1.7.0 — Steerable Redirect Recovery Menu

### Added

- **Recovery Menu in `node9 tail`:** When a stateful block rule fires with a `recoveryCommand`, the tail approver now renders an interactive STATE GUARD card instead of a plain approval card. Options:
  - **[1] Allow anyway** — override the policy for this call
  - **[2] Redirect AI** — sends a structured reason back to Claude: _"Run `<recoveryCommand>` first, then retry your original command."_ This steers the AI to fix the root cause rather than retrying blindly.
  - **[3] Deny & stop** — hard block; auto-deny on timeout

- **`terminal-redirect` decision source:** When the developer selects [2], the tail posts `{ decision: 'deny', reason: "...", source: 'terminal-redirect' }` to the daemon. The orchestrator recognises this source and uses the redirect reason as the block message sent back to the AI agent instead of the generic "user rejected" message.

- **Fail-open on daemon unreachable is intentional:** When the daemon cannot be reached, stateful block predicates are treated as unknown and the rule is downgraded to review. This is a deliberate trade-off — availability over lockout. A future `failMode: 'open' | 'closed'` field on smart rules is planned to make this configurable per-rule.

---

## v1.6.0 — Stateful Smart Rules

### Added

- **Stateful Smart Rules (`dependsOnState`):** Smart rules can now condition a `block` verdict on real session state instead of firing unconditionally. Add a `dependsOnState` array to any block rule with one or more named predicates — the block only fires if **all** predicates are satisfied at evaluation time. If any predicate is false, or the daemon is unreachable, the rule is silently downgraded to a review (fail-open). Currently supported predicate:
  - `no_test_passed_since_last_edit` — true when a file was edited since the last passing test run.

  ```json
  {
    "name": "require-tests-before-deploy",
    "tool": "Bash",
    "conditions": [{ "field": "command", "op": "matches", "value": "./deploy.sh" }],
    "verdict": "block",
    "reason": "Run tests before deploying",
    "dependsOnState": ["no_test_passed_since_last_edit"],
    "recoveryCommand": "npm test"
  }
  ```

- **`recoveryCommand` on Smart Rules:** Block rules now accept an optional `recoveryCommand` string. When the rule fires, the command is shown to the developer on `/dev/tty` as `💡 Run: npm test` and sent to the AI as a negotiation hint: _"Run `npm test` first, then retry your original command."_ Works on both stateful and plain block rules.

- **Session History tracking (daemon-side):** The daemon now tracks `lastEditAt`, `lastTestPassAt`, and `lastTestFailAt` timestamps across the session lifetime. File edits are detected from the `allow` activity events for write tools (`Edit`, `Write`, `MultiEdit`, etc.). Test results are detected from the PostToolUse `log` hook — the hook reads `tool_response.output` and classifies the run as `pass` or `fail` based on output patterns from common test runners (`vitest`, `jest`, `pytest`, `cargo test`, `go test`, `rspec`, and more).

- **`/state/check` HTTP endpoint on daemon:** `GET /state/check?predicates=no_test_passed_since_last_edit` returns a JSON map `{ "no_test_passed_since_last_edit": true }`. Called by the orchestrator before applying a stateful block; result is cached-by-call (100 ms timeout, fail-open on error).

- **HUD line 3 — Environment counts:** The status line now renders a third line showing the active Claude Code environment configuration:
  ```
  1 CLAUDE.md  |  4 rules  |  3 MCPs  |  2 hooks
  ```
  Counts are read from `~/.claude/settings.json`, `~/.claude.json`, `.mcp.json`, and `.claude/rules/` — mirroring the same sources as the claude-hud project. The line is omitted entirely when all counts are zero. The `cwd` field from Claude Code's stdin JSON is used to scope project-level counts.

---

## v1.4.0

### Added

- **Insight Line — "Always Allow" nudge:** After approving the same tool 3+ times, every approval channel (terminal, browser dashboard, native popup) now shows a 💡 hint: _"Approved N× before — 'Always Allow' creates a permanent rule."_ The counter is tracked daemon-side per tool (`insightCounts` Map) and is never reset by the suggestion threshold — only on deny. This ensures the nudge appears consistently across all channels and sessions.

- **Smart Rule Suggestions:** After 3 consecutive approvals of the same tool, the daemon generates a suggested smart rule (e.g. `allowGlob` for file reads, `allowCommand` for shell commands). The suggestion appears in the browser dashboard with a one-click "Apply Rule" button that patches your config without a restart. Suggestions are cleared on deny or config change.

- **Terminal card stamping:** Approved or denied terminal cards now stay visible in `node9 tail` history with the decision stamped on them (`✓ ALLOWED (terminal)` / `✗ DENIED (terminal)`). Previously the card was erased from the terminal buffer on resolution, leaving no trace of what was decided.

- **`node9 status` — Agent Wiring Report:** `node9 status` now includes an **Agent Wiring** section showing, per detected agent (Claude Code, Gemini CLI, Cursor): which hooks are wired (`PreToolUse`, `PostToolUse`, `BeforeTool`, `AfterTool`) and which MCP servers are currently proxied through node9. Example output:

  ```
  Agent Wiring:

  Claude Code
    ✓ PreToolUse  (node9 check)
    ✓ PostToolUse (node9 log)
    MCP proxied: none

  Gemini CLI
    ✓ BeforeTool  (node9 check)
    ✓ AfterTool   (node9 log)
    MCP proxied:
      • postgres → npx -y @modelcontextprotocol/server-postgres postgresql://...
  ```

- **Trusted-Host Allowlist (`node9 trust add/remove/list`):** Persistent per-user allowlist of known-safe network destinations. Pipe-chain exfiltration decisions are downgraded for trusted hosts only: `critical` (hard block) → `review` (approval prompt), `high` (review) → `allow`. If any sink in the pipeline is untrusted, the original decision stands. Hosts are stored in `~/.node9/trusted-hosts.json` (`0o600`) with atomic write (tmp + rename). Only the CLI can add entries — no MCP tool or API can modify the list. Supports exact FQDNs (`api.mycompany.com`) and wildcard subdomains (`*.mycompany.com`); wildcards match any subdomain at any depth (`api.mycompany.com`, `us.api.mycompany.com`, etc.) but do **not** match the bare domain (`mycompany.com`). Single-label wildcards (`*.com`, `*.io`) are rejected at add-time as too broad.
- **`node9 trust add <host>`:** Adds a host to the trusted list. Normalizes input (strips protocol, path, port, `user@`) before storing so `https://api.company.com/v1/ingest` and `api.company.com` are treated as the same entry. No-op if already present.
- **`node9 trust remove <host>`:** Removes a host from the trusted list. Exits non-zero if not found.
- **`node9 trust list`:** Displays all trusted hosts with the date they were added.
- **TTL cache for trusted-host lookups:** `isTrustedHost()` is on the hot path (called for every pipe-chain tool call). Results are cached in-process (5-second TTL) to avoid a synchronous disk read on every policy evaluation. Cache is invalidated on every write by the same process. For cross-process invalidation (e.g. `node9 trust remove` run in a CLI while the daemon is running), the cache stores the file mtime and re-reads immediately on the next call if the mtime has changed — removal takes effect on the next policy evaluation, not after the full TTL.

### Fixed

- **Browser opened twice on `node9 tail` launch:** The daemon no longer reopens the browser tab on the first `/check` request when `node9 tail` has already opened one. `tail` posts `POST /browser-opened` after launching the browser so the daemon can skip the duplicate open.

---

## v1.3.0

### Added

- **Pipe-Chain Exfiltration Detection:** The policy engine now detects shell pipelines that exfiltrate sensitive files to the network. Two risk levels: `critical` (file piped through an obfuscator such as `base64`, `xxd`, `gzip`, `openssl` before a network sink) → hard block; `high` (file piped directly to a network sink like `curl`, `wget`, `nc`, `socat`) → review. Sink targets (URLs, hostnames, IPs) are extracted from the pipeline and surfaced in the block reason and audit log.
- **Binary Provenance Check:** Absolute-path binaries (e.g. `/tmp/curl`) are classified by filesystem location before execution. Binaries in temp directories, world-writable paths, or unknown locations are flagged as `suspect` (block in strict mode, review in standard) or `unknown` (review in strict mode). System binaries (`/usr/bin`, `/bin`, `/usr/local/bin`) and managed tool binaries (nvm, volta, homebrew, pyenv, cargo) are trusted. Bare command names (`npm`, `curl`) are not checked to avoid false positives from PATH-managed tools.
- **`_classifyPath()` exported pure helper:** Extracted from `checkProvenance()` for unit testability without filesystem mocking. Takes a resolved path and optional cwd, returns `{ trustLevel, reason }`.
- **SSH multi-hop host extraction:** `extractAllSshHosts()` parses `ssh`/`scp`/`rsync` command arguments including `-J` jump hosts, `ProxyJump` config, and `user@host` patterns. Extracted hostnames are added to the token stream for dangerous-word scanning.

### Fixed

- **POSIX path semantics on Windows:** All prefix checks in provenance now use `'/'` as separator instead of `path.sep` (which is `'\\'` on Windows). `path.posix.isAbsolute` replaces `path.isAbsolute` for checking POSIX-style paths. This fixes all provenance classification tests on `windows-latest` CI.

---

## v1.2.0

### Added

- **MCP Gateway (`node9 mcp-gateway`):** Universal stdio proxy that sits between any MCP client (Claude, Cursor, Windsurf) and any upstream MCP server. Every `tools/call` passes through the full Node9 authorization engine — DLP scanner, smart rules, and human approval — before reaching the upstream. Blocked calls receive a structured JSON-RPC `-32000` error with an AI-readable explanation so the agent can reason about the block and try an alternative. Approved calls are forwarded unchanged; the gateway is transparent to both client and server. Configure in `.mcp.json`:

  ```json
  {
    "mcpServers": {
      "filesystem-node9": {
        "command": "node9",
        "args": [
          "mcp-gateway",
          "--upstream",
          "npx @modelcontextprotocol/server-filesystem /home/user"
        ]
      }
    }
  }
  ```

  Key security properties:
  - **Fail-closed:** auth engine error → deny, never pass-through
  - **Env injection stripping:** `NODE_OPTIONS`, `LD_PRELOAD`, `PYTHONPATH`, `PERL5LIB`, `RUBYLIB`, `JAVA_TOOL_OPTIONS`, `XDG_CONFIG_HOME`, and 7 more injection vectors are stripped from the upstream subprocess environment
  - **Shell-free tokenizer:** `"node /path with spaces/server.js"` is split correctly without ever spawning a shell
  - **MCP server namespacing:** `mcp__filesystem__write_file` → server name extracted and passed to the auth engine for per-server smart rules
  - **id=0 valid, object/array ids rejected** with `-32600 Invalid Request`
  - **Race condition guards:** `deferredStdinEnd` / `deferredExitCode` ensure responses are always flushed before process exit, even when the AI client disconnects mid-authorization

- **Flight Recorder — Browser Dashboard:** The browser dashboard (`localhost:7391`) is now a true fixed-viewport 3-column layout. The left column streams every tool call in real-time — appearing immediately as `● PENDING` and resolving to `✓ ALLOW`, `✗ BLOCK`, or `🛡️ DLP` as decisions arrive. The feed scrolls internally and never causes the browser page to scroll. History from the current session is replayed to new browser tabs via an in-memory ring buffer (last 100 events).
- **`node9 tail` — Terminal Flight Recorder:** New command that streams live agent activity directly to the terminal. Uses a spec-compliant SSE parser (handles TCP fragmentation), filters history floods on connect, and shows a live `● …` pending indicator for slow operations (bash, SQL, agent calls). Auto-starts the daemon if it isn't running. Supports `--history` to replay recent events on connect. Output is pipeable (`node9 tail | grep DLP`).
- **Shields Panel in Browser Dashboard:** The right sidebar now shows all available shields (postgres, github, aws, filesystem) with live enable/disable toggles. Changes take effect immediately on the next tool call — no daemon restart required. Toggle state is broadcast via SSE to keep multiple open tabs in sync.
- **Improved Pending Approval Cards:** Approval cards now show an `⚠️ Action Required` header with a live countdown timer that turns red under 15 seconds. Allow/Deny buttons have clearer labels (`✅ Allow this Action` / `🚫 Block this Action`). The deny button uses a softer outlined style to reduce accidental clicks.
- **DLP Content Scanner:** Node9 now scans every tool call argument for secrets before policy evaluation. Seven built-in patterns cover AWS Access Key IDs, GitHub tokens (`ghp_`, `gho_`, `ghs_`), Slack bot tokens (`xoxb-`), OpenAI API keys, Stripe secret keys, PEM private keys, and Bearer tokens. `block`-severity patterns hard-deny the call immediately; `review`-severity patterns route through the normal race engine. Secrets are redacted to a prefix+suffix sample in all audit logs. Configurable via `policy.dlp.enabled` and `policy.dlp.scanIgnoredTools`.
- **Shield Templates:** `node9 shield enable <service>` installs a curated rule set for a specific infrastructure service. Available shields: `postgres` (blocks `DROP TABLE`, `TRUNCATE`, `DROP COLUMN`; reviews `GRANT`/`REVOKE`), `github` (blocks `gh repo delete`; reviews remote branch deletion), `aws` (blocks S3 bucket deletion, EC2 termination; reviews IAM and RDS changes), `filesystem` (reviews `chmod 777` and writes to `/etc/`). Manage with `node9 shield enable|disable|list|status`.
- **Shadow Git Snapshots (Phase 2 — Implemented):** Node9 now takes automatic, lightweight git snapshots before every AI file edit using an isolated shadow bare repo at `~/.node9/snapshots/<hash16>/`. The user's `.git` is never touched — snapshots live in a separate hidden repository keyed by a SHA-256 hash of the project path. Run `node9 undo` to revert with a full diff preview; `--steps N` goes back multiple actions. Per-invocation `GIT_INDEX_FILE` prevents concurrent-session corruption. A `project-path.txt` sentinel inside each shadow repo detects hash collisions and directory renames and auto-recovers by reinitializing. `.git` and `.node9` directories are always excluded from snapshots (inception prevention). Performance-tuned with `core.untrackedCache` and `core.fsmonitor`. Periodic background `git gc --auto` keeps shadow repos tidy. The last 10 snapshots are tracked in `~/.node9/snapshots.json`.
- **ReDoS Protection + LRU Regex Cache:** The policy engine now validates all user-supplied regex patterns before compilation. Patterns with nested quantifiers, quantified alternations, or quantified backreferences are rejected as ReDoS vectors. A bounded LRU cache (max 500 entries) stores compiled `RegExp` objects so repeated rule evaluations never recompile the same pattern. The `notMatches` condition is now fail-closed: if the regex is invalid, the condition fails rather than silently passing.
- **Expanded DLP Patterns:** Two new `block`-severity content patterns added to the scanner: GCP service account JSON keys (detected via the `type` field unique to service account files) and NPM registry auth tokens (detected in `.npmrc` format). Total built-in patterns: 9.
- **Sensitive File Path Blocking:** The DLP engine now intercepts tool calls targeting credential files before their content is ever read. Twenty path patterns cover SSH keys, AWS credentials, GCP config, Azure credentials, kubeconfig, dotenv files, PEM/key/p12/pfx certificate files, system auth files, and common credential JSON files. Symlinks are resolved via `fs.realpathSync.native()` before matching to prevent symlink escape attacks where a safe-looking path points to a protected file.
- **`flightRecorder` setting:** New `settings.flightRecorder` flag (default `true`) controls whether the daemon records tool call activity to the flight recorder ring buffer. Can be set to `false` to disable activity recording when the browser dashboard is not in use.

### Changed

- **`node9 tail --clear` no longer streams after clearing** ⚠️ **Breaking:** Previously `--clear` wiped the ring buffer and then continued tailing live events — visually identical to plain `node9 tail`. It now clears the buffer and exits immediately. To start fresh and watch, chain the commands: `node9 tail --clear && node9 tail --history`. Scripts relying on the old streaming-after-clear behaviour must be updated.
- **Default mode is now `audit`:** Fresh installs now default to `mode: "audit"` instead of `mode: "standard"`. In audit mode every tool call is approved and logged, with a desktop notification for anything that _would_ have been blocked. This lets teams observe agent behaviour before committing to a blocking policy. Switch to `mode: "standard"` or `mode: "strict"` when you are ready to enforce.
- **Approval timeout default is now 30 seconds:** `approvalTimeoutMs` defaults to `30000` (was `0` / wait forever). Pending approval prompts now auto-deny after 30 seconds if no human responds, preventing agents from stalling indefinitely.
- **Cloud approver disabled by default:** `approvers.cloud` defaults to `false`. Cloud (Slack/SaaS) approval must be explicitly opted in via `settings.approvers.cloud: true` after running `node9 login`.
- **Hook debug logging enabled by default:** `enableHookLogDebug` defaults to `true`. Hook invocations are written to `~/.node9/hook-debug.log` on startup to aid troubleshooting. Set to `false` to suppress.
- **Config schema version field:** The generated default config now includes `"version": "1.0"` for forward-compatibility with future migration tooling.

### Fixed

- **Cursor hook setup:** `node9 addto cursor` no longer attempts to write an unsupported `hooks.json` file. A clear warning is shown explaining that MCP proxy wrapping is the only supported protection mode for Cursor.
- **Empty shields file warning:** Suppressed a spurious parse warning that appeared on first run when `~/.node9/shields.json` existed but was empty.
- **`node9 tail` crash on daemon disconnect:** An unhandled `ECONNRESET` error on the readline interface no longer crashes the process — it exits cleanly with `❌ Daemon disconnected.`
- **Orphaned daemon detection:** `node9 tail --history` and other commands that auto-start the daemon now correctly detect a running daemon even when its PID file is missing (e.g. after the file was accidentally deleted or a previous startup wrote and then cleaned it up). All three detection paths are fixed: `isDaemonRunning()` falls back to a live `ss` port check; `ensureDaemon()` in `tail` does an HTTP health probe before spawning a new process; and the EADDRINUSE handler recovers the orphaned daemon's PID via `ss` and writes the missing PID file before exiting cleanly.
- **`node9 daemon status` reports orphaned daemons:** Previously `node9 daemon status` always reported "not running" when the PID file was absent, even if the daemon was listening on port 7391. It now reports `running (no PID file — orphaned)` in that case.

---

## [0.3.0] - 2026-03-06

### Added

- **Multi-Channel Race Engine:** Node9 now fires all enabled approval channels simultaneously (Native Popup, Browser UI, Cloud/Slack, and Terminal). The first channel to receive a human signature wins and instantly cancels all other pending racers.
- **AI Negotiation Loop:** Replaced generic "Access Denied" errors with instructional feedback prompts. When blocked, Node9 injects a structured message into the LLM's context window, teaching the agent to apologize, explain its reasoning, or pivot to a safer alternative.
- **Native OS Dialogs:** Integrated sub-second, keyboard-navigable approval dialogs via `osascript` (macOS), `zenity` (Linux), and `PowerShell` (Windows).
- **Resolution Waterfall:** Implemented a strict 5-tier configuration precedence engine: `Environment Variables` > `Cloud (SaaS)` > `Project Config` > `Global Config` > `Defaults`.
- **Identity-Aware Execution:** The policy engine now distinguishes between a Human (`Terminal`) and an AI Agent (`Claude/Gemini`). Manual shell commands now benefit from "Nuclear-only" protection, while AI agents remain under "Zero Trust" restrictions.
- **Extended Hook Timeouts:** Default hook timeouts for Claude and Gemini have been increased to 10 minutes to support asynchronous Slack and remote approvals.
- **Sandbox Paths:** Added `policy.sandboxPaths` support. Any command operating strictly within defined safe zones (e.g., `/tmp/**`) is automatically allowed without human intervention.
- **Atomic File Writes:** Implemented `atomicWriteSync` for all state files (`decisions.json`, `trust.json`, `PAUSED`). This prevents JSON corruption during concurrent AI tool calls.

### Fixed

- **True Proxy Interception:** Rewrote the Proxy/MCP runner to intercept the Agent's `stdin` (requests) rather than just monitoring the Server's `stdout` (responses). Dangerous actions are now caught _before_ they reach the target server.
- **Port Conflict Resurrection:** The daemon now detects zombie PID files and `EADDRINUSE` errors, automatically clearing dead processes and resurrecting the server.
- **Credential Separation:** API keys are now strictly isolated in `~/.node9/credentials.json` and are never read from project-level config files to prevent accidental leakage to version control.

### Security

- **Waterfall Governance:** Cloud-level "Organization Policies" now act as a Master Lock, disabling local "Allow" buttons in the Native and Browser UIs when a remote manager signature is required.
- **Graceful Idle Timeout:** The background daemon now implements a 12-hour inactivity timer to automatically shut down and free system resources after use.

---

## [0.2.0] - 2026-03-01

### Added

- **Local Approval Daemon:** `node9 daemon` starts a browser-based approval UI at `http://127.0.0.1:7391`. Approve, deny, or set persistent per-tool decisions ("Always Allow" / "Always Deny") without a Slack account.
- **Persistent Decisions Panel:** The daemon browser UI shows a `📋 Persistent Decisions` panel listing every "Always Allow" / "Always Deny" decision with a **Revoke** button. Revoking a decision removes it from `~/.node9/decisions.json` and updates all open tabs instantly via SSE.
- **`GET /decisions` endpoint:** Returns the current persistent decisions map (read-only, no CSRF required).
- **`DELETE /decisions/:toolName` endpoint:** Removes a persistent decision (requires `X-Node9-Token` CSRF header).
- **Auto-start Daemon:** When a dangerous call arrives and no approval mechanism is running, Node9 automatically starts the daemon and opens the browser — no manual setup required.
- **Browser-Close Fallback:** If the browser tab is closed mid-approval, Node9 waits 2 seconds (to allow for an accidental refresh), then abandons the request and falls back to a terminal Y/N prompt, then blocks if there is no TTY. The daemon shuts down cleanly after abandonment.
- **`autoStartDaemon` Setting:** Toggle daemon auto-start from the browser UI (⚙️ Settings) or via `settings.autoStartDaemon: false` in `~/.node9/config.json`. When disabled, dangerous commands fall back directly to a terminal prompt.
- **Smart Runner — Browser-First Flow:** `node9 "rm -rf ./data"` now prefers the browser popup over a plain terminal prompt. Terminal Y/N is only shown if the daemon fails to start. This makes the full approval UI available without pre-running `node9 daemon`.
- **Terminal Prompt Timeout:** The interactive Y/N approval prompt now auto-denies after 30 seconds if no response is given, preventing agents from hanging indefinitely when a human walks away.
- **Smart Runner:** Node9 intercepts the initial command you pass to it (e.g., `node9 "rm -rf /"`) and checks it against your security policy before execution.
- **Improved Gemini CLI Integration:** Fully supports the latest Gemini CLI hook schema (array-based `BeforeTool`/`AfterTool`).
- **Verbose Policy Debugging:** Added `~/.node9/hook-debug.log` to help troubleshoot hook payloads (`NODE9_DEBUG=1`).
- **`getGlobalSettings()` API:** Reads machine-level settings from `~/.node9/config.json` independently of project config, so daemon lifecycle preferences are never overridden by a project's policy file.

### Fixed

- **Case-Insensitive Tool Matching:** Tool names like `Shell`, `shell`, and `run_shell_command` are now correctly identified and intercepted regardless of casing.
- **Robust Hook Setup:** `node9 addto gemini` now automatically detects and fixes outdated object-based hook configurations in `settings.json`.
- **Duplicate Interception:** Fixed a bug where `run_shell_command` was in the default `ignoredTools` list, preventing it from being properly inspected. Also corrected the example `node9.config.json`.
- **`node9 check` stdin Hang:** The hook no longer hangs if the AI agent opens stdin but never sends EOF. A 5-second safety timeout ensures the process exits cleanly.
- **Smart Runner Terminal Prompt:** `allowTerminalFallback` was not being passed in the smart runner path, so the Y/N prompt never appeared. Now correctly shown when no daemon is running and a TTY is available.

### Security

- **CSRF Token on Daemon:** A per-run UUID token is embedded in the browser UI and required as `X-Node9-Token` on all state-changing requests (`POST /decision`, `POST /settings`). Prevents other local processes from silently approving pending actions.
- **Credentials File Permissions:** `~/.node9/credentials.json` is now written with `0o600` (owner read/write only).
- **Daemon Error Logging:** Handler errors in `/check`, `/decision`, and `/settings` are now logged to stderr when `NODE9_DEBUG=1`, making production debugging possible without exposing errors by default.

### Changed

- `node9 addto` now supports the new array-based hook structure for Gemini CLI.
- Updated internal `GeminiSettings` interfaces to match the latest CLI specifications.

---

## [0.1.0] - 2026-02-01

### Added

- Initial release
- `node9 proxy` — MCP JSON-RPC interceptor (wraps any MCP server or shell command)
- `node9 login` — saves API key to `~/.node9/credentials.json` for Slack routing
- `node9.config.json` — project-level policy configuration (`standard` / `strict` modes, `dangerousWords`, `ignoredTools`)
- Local terminal HITL approval via `@inquirer/prompts`
- Slack remote approval via Node9 Cloud API (Pro)
