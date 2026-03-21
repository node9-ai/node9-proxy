# 🛡️ Node9 Proxy

### The "Sudo" Command for AI Agents.

[![NPM Version](https://img.shields.io/npm/v/@node9/proxy.svg)](https://www.npmjs.com/package/@node9/proxy)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Open in HF Spaces](https://huggingface.co/datasets/huggingface/badges/resolve/main/open-in-hf-spaces-sm.svg)](https://huggingface.co/spaces/Node9ai/node9-security-demo)

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

## ⚡ Key Features

### 🏁 The Multi-Channel Race Engine

Node9 initiates a **Concurrent Race** across all enabled channels. The first channel to receive a human signature wins and instantly cancels the others:

- **Native Popup:** OS-level dialog (Mac/Win/Linux) for sub-second keyboard dismissal.
- **Browser Dashboard:** Local web UI for deep inspection of large payloads (SQL/Code).
- **Cloud (Slack):** Remote asynchronous approval for team governance.
- **Terminal:** Classic `[Y/n]` prompt for manual proxy usage and SSH sessions.

### 🧠 AI Negotiation Loop

Node9 doesn't just "cut the wire." When a command is blocked, it injects a **Structured Negotiation Prompt** back into the AI's context window. This teaches the AI why it was stopped and instructs it to pivot to a safer alternative.

### ⏪ Shadow Git Snapshots (Auto-Undo)

Node9 takes a silent, lightweight Git snapshot before every AI file edit. If the AI hallucinates and breaks your code, run `node9 undo` to instantly revert — with a full diff preview before anything changes.

```bash
# Undo the last AI action (shows diff + asks confirmation)
node9 undo

# Go back N actions at once
node9 undo --steps 3
```

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
```

---

## 🛡️ How Protection Works

Node9 has two layers of protection. You get Layer 1 automatically. Layer 2 is one command per service.

### Layer 1 — Core Protection (Always On)

Built into the binary. Zero configuration required. Protects the tools every developer uses.

| What it protects | Example blocked action                                  |
| :--------------- | :------------------------------------------------------ |
| **Git**          | `git push --force`, `git reset --hard`, `git clean -fd` |
| **Shell**        | `curl ... \| bash`, `sudo` commands                     |
| **SQL**          | `DELETE` / `UPDATE` without a `WHERE` clause            |
| **Filesystem**   | `rm -rf` targeting home directory                       |

### Layer 2 — Shields (Opt-in, Per Service)

Shields add protection for specific infrastructure and services — only relevant if you actually use them.

| Shield       | What it protects                                                              |
| :----------- | :---------------------------------------------------------------------------- |
| `postgres`   | Blocks `DROP TABLE`, `TRUNCATE`, `DROP COLUMN`; reviews `GRANT`/`REVOKE`      |
| `github`     | Blocks `gh repo delete`; reviews remote branch deletion                       |
| `aws`        | Blocks S3 bucket deletion, EC2 termination; reviews IAM changes, RDS deletion |
| `filesystem` | Reviews `chmod 777`, writes to `/etc/`                                        |

```bash
node9 shield enable postgres    # protect your database
node9 shield enable aws         # protect your cloud infrastructure
node9 shield list               # see all available shields
node9 shield status             # see what's currently active
```

---

## 🛠 Protection Modes

| Mode            | Target                 | How it works                                            |
| :-------------- | :--------------------- | :------------------------------------------------------ |
| **Hook Mode**   | Claude, Gemini, Cursor | `node9 addto <agent>` wires native pre-execution hooks. |
| **Proxy Mode**  | MCP Servers, Shell     | `node9 "npx <server>"` intercepts JSON-RPC traffic.     |
| **Manual Mode** | You                    | `node9 rm -rf /` protects you from your own typos.      |

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

| Field           | Description                                                                          |
| :-------------- | :----------------------------------------------------------------------------------- |
| `tool`          | Tool name or glob (`"bash"`, `"mcp__postgres__*"`, `"*"`)                            |
| `conditions`    | Array of conditions evaluated against the raw args object                            |
| `conditionMode` | `"all"` (AND, default) or `"any"` (OR)                                               |
| `verdict`       | `"review"` (approval prompt) \| `"block"` (hard deny) \| `"allow"` (skip all checks) |
| `reason`        | Human-readable explanation shown in the approval prompt and audit log                |

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
  }
}
```

| Key                  | Default      | Description                                                  |
| :------------------- | :----------- | :----------------------------------------------------------- |
| `mode`               | `"standard"` | `standard` \| `strict` \| `audit`                            |
| `enableUndo`         | `true`       | Take git snapshots before every AI file edit                 |
| `approvalTimeoutMs`  | `0`          | Auto-deny after N ms if no human responds (0 = wait forever) |
| `approvers.native`   | `true`       | OS-native popup                                              |
| `approvers.browser`  | `true`       | Browser dashboard (`node9 daemon`)                           |
| `approvers.cloud`    | `true`       | Slack / SaaS approval                                        |
| `approvers.terminal` | `true`       | `[Y/n]` prompt in terminal                                   |

---

## 🖥️ CLI Reference

| Command                       | Description                                                                           |
| :---------------------------- | :------------------------------------------------------------------------------------ |
| `node9 setup`                 | Interactive menu — detects installed agents and wires hooks for you                   |
| `node9 addto <agent>`         | Wire hooks for a specific agent (`claude`, `gemini`, `cursor`)                        |
| `node9 init`                  | Create default `~/.node9/config.json`                                                 |
| `node9 status`                | Show current protection status and active rules                                       |
| `node9 doctor`                | Health check — verifies binaries, config, credentials, and all agent hooks            |
| `node9 shield <cmd>`          | Manage shields (`enable`, `disable`, `list`, `status`)                                |
| `node9 explain <tool> [args]` | Trace the policy waterfall for a given tool call (dry-run, no approval prompt)        |
| `node9 undo [--steps N]`      | Revert the last N AI file edits using shadow Git snapshots                            |
| `node9 check`                 | Called by agent hooks; evaluates a pending tool call and exits 0 (allow) or 1 (block) |

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
- [x] **Shield Templates** (`node9 shield enable <service>` — one-click protection for Postgres, GitHub, AWS)
- [ ] **Content Scanner / DLP** (Detect and block secrets like AWS keys and Bearer tokens in-flight)
- [ ] **Universal MCP Gateway** (Standalone security tunnel for LangChain, CrewAI, and any agent without native hooks)
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
