# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

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
