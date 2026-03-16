# 🛡️ Node9 Proxy

### The "Sudo" Command for AI Agents.

[![NPM Version](https://img.shields.io/npm/v/@node9/proxy.svg)](https://www.npmjs.com/package/@node9/proxy)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Node9** is the execution security layer for the Agentic Era. It encases autonomous AI Agents (Claude Code, Gemini CLI, Cursor, MCP Servers) in a deterministic security wrapper, intercepting dangerous shell commands and tool calls before they execute.

While others try to _guess_ if a prompt is malicious (Semantic Security), Node9 _governs_ the actual action (Execution Security).

---

## 💎 The "Aha!" Moment

**AIs are literal.** When you ask an agent to "Fix my disk space," it might decide to run `docker system prune -af`.

<p align="center">
  <img src="https://github.com/user-attachments/assets/afae9caa-0605-4cac-929a-c14198383169" width="100%">
</p>

**With Node9, the interaction looks like this:**

1. **🤖 AI attempts a "Nuke":** `Bash("docker system prune -af --volumes")`
2. **🛡️ Node9 Intercepts:** An OS-native popup appears immediately.
3. **🛑 User Blocks:** You click "Block" in the popup.
4. **🧠 AI Negotiates:** Node9 explains the block to the AI. The AI responds: _"I understand. I will pivot to a safer cleanup, like removing only large log files instead."_

---

## ⚡ Key Architectural Upgrades

### 🏁 The Multi-Channel Race Engine

Node9 initiates a **Concurrent Race** across all enabled channels. The first channel to receive a human signature wins and instantly cancels the others:

- **Native Popup:** OS-level dialog (Mac/Win/Linux) for sub-second keyboard dismissal.
- **Browser Dashboard:** Local web UI for deep inspection of large payloads (SQL/Code).
- **Cloud (Slack):** Remote asynchronous approval for team governance.
- **Terminal:** Classic `[Y/n]` prompt for manual proxy usage and SSH sessions.

### 🧠 AI Negotiation Loop

Node9 doesn't just "cut the wire." When a command is blocked, it injects a **Structured Negotiation Prompt** back into the AI’s context window. This teaches the AI why it was stopped and instructs it to pivot to a safer alternative or apologize to the human.

### ⏪ Shadow Git Snapshots (Auto-Undo)

Node9 takes a silent, lightweight Git snapshot before every AI file edit. If the AI hallucinates and breaks your code, run `node9 undo` to instantly revert — with a full diff preview before anything changes.

```bash
# Undo the last AI action (shows diff + asks confirmation)
node9 undo

# Go back N actions at once
node9 undo --steps 3
```

Example output:

```
⏪  Node9 Undo
    Tool:  str_replace_based_edit_tool → src/app.ts
    When:  2m ago
    Dir:   /home/user/my-project

--- src/app.ts (snapshot)
+++ src/app.ts (current)
@@ -1,4 +1,6 @@
-const x = 1;
+const x = 99;
+const y = "hello";

Revert to this snapshot? [y/N]
```

Node9 keeps the last 10 snapshots. Snapshots are only taken for file-writing tools (`write_file`, `edit_file`, `str_replace_based_edit_tool`, `create_file`) — not for read-only or shell commands.

### 🌊 The Resolution Waterfall

Security posture is resolved using a strict 5-tier waterfall:

1.  **Env Vars:** Session-level overrides (e.g., `NODE9_PAUSED=1`).
2.  **Cloud (SaaS):** Global organization "Locks" that cannot be bypassed locally.
3.  **Project Config:** Repository-specific rules (`node9.config.json`).
4.  **Global Config:** Personal UI preferences (`~/.node9/config.json`).
5.  **Defaults:** The built-in safety net.

---

## 🚀 Quick Start

```bash
npm install -g @node9/proxy

# 1. Setup protection for your favorite agent
node9 setup           # interactive menu — picks the right agent for you
node9 addto claude    # or wire directly
node9 addto gemini

# 2. Initialize your local safety net
node9 init

# 3. Verify everything is wired correctly
node9 doctor

# 4. Check your status
node9 status
```

---

## 🛠 Protection Modes

| Mode            | Target                 | How it works                                            |
| :-------------- | :--------------------- | :------------------------------------------------------ |
| **Hook Mode**   | Claude, Gemini, Cursor | `node9 addto <agent>` wires native pre-execution hooks. |
| **Proxy Mode**  | MCP Servers, Shell     | `node9 "npx <server>"` intercepts JSON-RPC traffic.     |
| **Manual Mode** | You                    | `node9 rm -rf /` protects you from your own typos.      |

---

## ⚙️ Configuration (`node9.config.json`)

Rules are **merged additive**—you cannot "un-danger" a word locally if it was defined as dangerous by a higher authority (like the Cloud).

```json
{
  "settings": {
    "mode": "standard",
    "enableUndo": true,
    "approvalTimeoutMs": 30000,
    "approvers": {
      "native": true,
      "browser": true,
      "cloud": true,
      "terminal": true
    }
  },
  "policy": {
    "sandboxPaths": ["/tmp/**", "**/test-results/**"],
    "dangerousWords": ["drop", "destroy", "purge", "push --force"],
    "ignoredTools": ["list_*", "get_*", "read_*"],
    "toolInspection": {
      "bash": "command",
      "postgres:query": "sql"
    },
    "rules": [
      { "action": "rm", "allowPaths": ["**/node_modules/**", "dist/**"] },
      { "action": "push", "blockPaths": ["**"] }
    ],
    "smartRules": [
      {
        "name": "no-delete-without-where",
        "tool": "*",
        "conditions": [
          { "field": "sql", "op": "matches", "value": "^(DELETE|UPDATE)\\s", "flags": "i" },
          { "field": "sql", "op": "notMatches", "value": "\\bWHERE\\b", "flags": "i" }
        ],
        "verdict": "review",
        "reason": "DELETE/UPDATE without WHERE — would affect every row"
      }
    ]
  }
}
```

### ⚙️ `settings` options

| Key                  | Default      | Description                                                  |
| :------------------- | :----------- | :----------------------------------------------------------- |
| `mode`               | `"standard"` | `standard` \| `strict` \| `audit`                            |
| `enableUndo`         | `true`       | Take git snapshots before every AI file edit                 |
| `approvalTimeoutMs`  | `0`          | Auto-deny after N ms if no human responds (0 = wait forever) |
| `approvers.native`   | `true`       | OS-native popup                                              |
| `approvers.browser`  | `true`       | Browser dashboard (`node9 daemon`)                           |
| `approvers.cloud`    | `true`       | Slack / SaaS approval                                        |
| `approvers.terminal` | `true`       | `[Y/n]` prompt in terminal                                   |

### 🧠 Smart Rules

Smart rules match on **raw tool arguments** using structured conditions — more powerful than `dangerousWords` or `rules`, which only see extracted tokens.

```json
{
  "name": "curl-pipe-to-shell",
  "tool": "bash",
  "conditions": [{ "field": "command", "op": "matches", "value": "curl.+\\|.*(bash|sh)" }],
  "verdict": "block",
  "reason": "curl piped to shell — remote code execution risk"
}
```

**Fields:**

| Field           | Description                                                                          |
| :-------------- | :----------------------------------------------------------------------------------- |
| `tool`          | Tool name or glob (`"bash"`, `"mcp__postgres__*"`, `"*"`)                            |
| `conditions`    | Array of conditions evaluated against the raw args object                            |
| `conditionMode` | `"all"` (AND, default) or `"any"` (OR)                                               |
| `verdict`       | `"review"` (approval prompt) \| `"block"` (hard deny) \| `"allow"` (skip all checks) |
| `reason`        | Human-readable explanation shown in the approval prompt and audit log                |

**Condition operators:**

| `op`          | Meaning                                                             |
| :------------ | :------------------------------------------------------------------ |
| `matches`     | Field value matches regex (`value` = pattern, `flags` = e.g. `"i"`) |
| `notMatches`  | Field value does not match regex                                    |
| `contains`    | Field value contains substring                                      |
| `notContains` | Field value does not contain substring                              |
| `exists`      | Field is present and non-empty                                      |
| `notExists`   | Field is absent or empty                                            |

The `field` key supports dot-notation for nested args: `"params.query.sql"`.

**Built-in default smart rule** (always active, no config needed):

```json
{
  "name": "no-delete-without-where",
  "tool": "*",
  "conditions": [
    { "field": "sql", "op": "matches", "value": "^(DELETE|UPDATE)\\s", "flags": "i" },
    { "field": "sql", "op": "notMatches", "value": "\\bWHERE\\b", "flags": "i" }
  ],
  "verdict": "review",
  "reason": "DELETE/UPDATE without WHERE clause — would affect every row in the table"
}
```

Use `node9 explain <tool> <args>` to dry-run any tool call and see exactly which smart rule (or other policy tier) would trigger.

## 🖥️ CLI Reference

| Command                       | Description                                                                           |
| :---------------------------- | :------------------------------------------------------------------------------------ |
| `node9 setup`                 | Interactive menu — detects installed agents and wires hooks for you                   |
| `node9 addto <agent>`         | Wire hooks for a specific agent (`claude`, `gemini`, `cursor`)                        |
| `node9 init`                  | Create default `~/.node9/config.json`                                                 |
| `node9 status`                | Show current protection status and active rules                                       |
| `node9 doctor`                | Health check — verifies binaries, config, credentials, and all agent hooks            |
| `node9 explain <tool> [args]` | Trace the policy waterfall for a given tool call (dry-run, no approval prompt)        |
| `node9 undo [--steps N]`      | Revert the last N AI file edits using shadow Git snapshots                            |
| `node9 check`                 | Called by agent hooks; evaluates a pending tool call and exits 0 (allow) or 1 (block) |

### `node9 doctor`

Runs a full self-test and exits 1 if any required check fails:

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

Dry-runs the policy engine and prints exactly which rule (or waterfall tier) would block or allow a given tool call — useful for debugging your config:

```bash
node9 explain bash '{"command":"rm -rf /tmp/build"}'
```

```
Policy Waterfall for: bash
──────────────────────────────────────────────
Tier 1 · Cloud Org Policy       SKIP  (no org policy loaded)
Tier 2 · Dangerous Words        BLOCK ← matched "rm -rf"
Tier 3 · Path Block             –
Tier 4 · Inline Exec            –
Tier 5 · Rule Match             –
──────────────────────────────────────────────
Verdict: BLOCK  (dangerous word: rm -rf)
```

---

## 🔧 Troubleshooting

**`node9 check` exits immediately / Claude is never blocked**
Node9 fails open by design to prevent breaking your agent. Check debug logs: `NODE9_DEBUG=1 claude`.

**Terminal prompt never appears during Claude/Gemini sessions**
Interactive agents run hooks in a "Headless" subprocess. You **must** enable `native: true` or `browser: true` in your config to see approval prompts.

**"Blocked by Organization (SaaS)"**
A corporate policy has locked this action. You must click the "Approve" button in your company's Slack channel to proceed.

---

## 🗺️ Roadmap

- [x] **Multi-Channel Race Engine** (Simultaneous Native/Browser/Cloud/Terminal)
- [x] **AI Negotiation Loop** (Instructional feedback loop to guide LLM behavior)
- [x] **Resolution Waterfall** (Cascading configuration: Env > Cloud > Project > Global)
- [x] **Native OS Dialogs** (Sub-second approval via Mac/Win/Linux system windows)
- [x] **Shadow Git Snapshots** (1-click Undo for AI hallucinations)
- [x] **Identity-Aware Execution** (Differentiates between Human vs. AI risk levels)
- [ ] **Execution Sandboxing** (Simulate dangerous commands in a virtual FS before applying)
- [ ] **Multi-Admin Quorum** (Require 2+ human signatures for high-stakes production actions)
- [ ] **SOC2 Tamper-proof Audit Trail** (Cryptographically signed, cloud-managed logs)

---

## 🏢 Enterprise & Compliance

Node9 Pro provides **Governance Locking**, **SAML/SSO**, and **VPC Deployment**.
Visit [node9.ai](https://node9.ai)
