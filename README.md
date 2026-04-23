<p align="center">
  <img src="https://github.com/user-attachments/assets/4aa6e45b-9aba-4953-9ce3-548226622588" width="720" alt="Node9 intercepts a dangerous git push" />
</p>

<h1 align="center">🛡️ Node9</h1>

<p align="center"><strong>Every command your AI agent runs, reviewed before it runs.</strong></p>

<p align="center">
  <a href="https://www.npmjs.com/package/node9-ai"><img src="https://img.shields.io/npm/v/node9-ai.svg" alt="npm version" /></a>
  <a href="https://www.npmjs.com/package/node9-ai"><img src="https://img.shields.io/npm/dm/node9-ai.svg" alt="monthly downloads" /></a>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache 2.0" /></a>
  <a href="https://node9.ai/docs"><img src="https://img.shields.io/badge/docs-node9.ai-blue" alt="Documentation" /></a>
  <a href="https://huggingface.co/spaces/Node9ai/node9-security-demo"><img src="https://huggingface.co/datasets/huggingface/badges/resolve/main/open-in-hf-spaces-sm.svg" alt="Try on HF Spaces" /></a>
</p>

Node9 sits between your AI agent and your system. Every shell command, file write, database query, and MCP tool call passes through Node9 first — blocked, reviewed, or logged based on your policy. Works with **Claude Code**, **Gemini CLI**, **Cursor**, **Codex**, and any **MCP server**.

- 🛑 **Block** dangerous actions (`git push --force`, `rm -rf /`, `curl|bash`, `DROP TABLE`, ...) before they run
- 👁 **Review** anything worth a human glance — OS-native popup, Slack, or browser approval
- 🔑 **Catch credential leaks** in tool arguments and Claude response text
- 🔁 **Stop agent loops** that burn tokens and money
- 🔌 **Gate MCP tools** and detect rug-pull attacks on server definitions
- 📊 **Dashboard + scan report** in your browser — see what your agents actually did

---

## Try it in 10 seconds — no install, no account

```bash
npx node9-ai scan
```

Reads your existing Claude / Gemini / Codex session history, runs the full Node9 policy engine, and shows every operation that would have been blocked or flagged.

```
🔍  Scanning your AI history  — what would node9 have caught?

  15 sessions  (8 Claude · 6 Gemini · 1 Codex)  5,470 tool calls
  2,439 bash commands  last 90 days  Apr 6, 2026 – Apr 23, 2026

  Found 168 risky operations in your history

    🛑  Would have blocked       3   operations stopped before execution
    👁   Would have flagged     162   sent to you for approval
    🔑  Credential leak          3   secret detected in tool call
    🔁  Loop detected          117   repeated tool call patterns found

  ──────────────────────────────────────────────────────────────────────
  Your Rules  ·  added in node9.config.json   2 blocked · 157 review
    🛑  block-force-push ×2  — Force push overwrites remote history
    👁   review-git-push ×154 — git push sends changes to a shared remote

  ──────────────────────────────────────────────────────────────────────
  bash-safe  ·  high-risk bash patterns    1 blocked · 1 review
    🛑  block-eval-remote  — eval of remote download (supply-chain attack)

  🌐  View in browser:  http://127.0.0.1:7391/
```

The last line opens a live dashboard in your browser with collapsible drill-downs, per-agent breakdown, and credential-leak samples:

<p align="center">
  <img src="https://github.com/user-attachments/assets/825f99d8-b487-4746-9cef-a02a9ca76c1f" width="90%" alt="Node9 browser History Audit dashboard" />
</p>

---

## Install

```bash
# macOS / Linux
brew tap node9-ai/node9 && brew install node9

# or via npm (any platform)
npm install -g node9-ai
```

```bash
node9 init       # auto-wires Claude Code, Gemini CLI, Cursor, Codex, MCP servers
node9 doctor     # verify everything is wired correctly
```

That's it — future agent sessions are protected.

---

## Shields — expert policy in one command

Each shield is a curated rule set for a service or domain. Enable only what you need.

| Shield            | What it catches                                                   | Enable                                |
| ----------------- | ----------------------------------------------------------------- | ------------------------------------- |
| `bash-safe`       | `curl \| bash`, `rm -rf /`, disk overwrite, `eval` of remote      | `node9 shield enable bash-safe`       |
| `postgres`        | `DROP TABLE`, `TRUNCATE`, `DROP COLUMN`, `DELETE` without `WHERE` | `node9 shield enable postgres`        |
| `mongodb`         | `dropDatabase`, `drop()`, `deleteMany({})`, index drops           | `node9 shield enable mongodb`         |
| `redis`           | `FLUSHALL`, `FLUSHDB`, `CONFIG SET` on a live server              | `node9 shield enable redis`           |
| `aws`             | S3 delete, EC2 terminate, IAM changes, RDS destroy                | `node9 shield enable aws`             |
| `k8s`             | namespace delete, `helm uninstall`, cluster role wipes            | `node9 shield enable k8s`             |
| `docker`          | `system prune`, `volume prune`, `rm -f` containers                | `node9 shield enable docker`          |
| `github`          | `gh repo delete`, remote branch deletion, settings changes        | `node9 shield enable github`          |
| `filesystem`      | `chmod 777`, writes under `/etc/`, `/boot/`, `/usr/`              | `node9 shield enable filesystem`      |
| `mcp-tool-gating` | unapproved MCP tools silently activating new capabilities         | `node9 shield enable mcp-tool-gating` |

```bash
node9 shield list    # show all shields + status
```

---

## Always on — no config needed

- **Git** — blocks `git push --force`, `git reset --hard`, `git clean -fd`
- **SQL** — blocks `DELETE` / `UPDATE` without `WHERE`, `DROP TABLE`, `TRUNCATE`
- **Shell** — blocks `curl | bash`, unauthorized `sudo`
- **DLP** — blocks AWS keys, GitHub tokens, Stripe keys, PEM private keys in any tool argument
- **Response DLP** — background scanner reads Claude's conversation history and alerts you if Claude _wrote_ a secret in its response text (not just executed one). Gemini / Codex coverage coming.
- **Auto-undo** — git snapshot before every AI file edit → `node9 undo` to revert
- **Skills pinning** — SHA-256 verification of installed Claude skills / plugins between sessions

---

## MCP gateway — protect any MCP server

Wrap any MCP server transparently. The agent sees the same server — Node9 intercepts every tool call.

```json
{
  "mcpServers": {
    "postgres": {
      "command": "node9",
      "args": ["mcp", "--upstream", "npx -y @modelcontextprotocol/server-postgres postgresql://..."]
    }
  }
}
```

Or just run `node9 init` — it wraps your existing MCP servers automatically.

<details>
<summary><strong>🔐 MCP tool pinning — rug-pull defense</strong></summary>

MCP servers can change their tool definitions between sessions. A compromised or malicious server could silently add, remove, or modify tools after you first trusted it — a **rug pull** attack.

Node9 pins tool definitions on first use:

1. **First connection** — gateway records a SHA-256 hash of every tool's name, description, and schema
2. **Subsequent connections** — hash is compared; if tools changed, the session is **quarantined** and every tool call is blocked until a human reviews and approves the change
3. **Corrupt pin state** — fails closed (blocks), never silently re-trusts

```bash
node9 mcp pin list                # show all pinned servers and hashes
node9 mcp pin update <serverKey>  # remove pin, re-pin on next connection
node9 mcp pin reset               # clear all pins
```

Automatic, no configuration. The gateway pins on first `tools/list` and enforces on every subsequent session.

</details>

<details>
<summary><strong>⚡ Large MCP response detection</strong></summary>

When an MCP server returns a 500KB+ response, it sits in the context window for every subsequent LLM turn — often silently doubling per-turn cost. Node9 warns you in real time with a toast and records the event in the dashboard so you can spot the offender.

</details>

---

## Observability — five views

Every tool call is recorded — command, arguments, decision, cost. See what your agent did, five ways:

| Command          | What it shows                                            | When to use                               |
| ---------------- | -------------------------------------------------------- | ----------------------------------------- |
| `node9 scan`     | Retrospective audit of existing agent history            | Before installing, or to review past risk |
| `node9 tail`     | Live stream of every tool call                           | Watching an agent work in real time       |
| `node9 report`   | Per-period summary: allowed/blocked/DLP/cost + top tools | Reviewing what happened after a session   |
| `node9 sessions` | Session history with prompt, tool trace, cost, snapshot  | Reviewing a handoff or past work          |
| `node9 dlp`      | Credential-leak findings in Claude response text         | Any time a DLP desktop alert fires        |

Plus a **live HUD** in your Claude Code statusline:

```
🛡 node9 | standard | [bash-safe] | ✅ 12 allowed  🛑 2 blocked  🚨 0 dlp | ~$0.43
📊 claude-opus-4-6 | ctx [████████░░░] 54% | 5h [██░░░░░░░░] 12% | 7d [█░░░░░░░] 7%
🗂 2 CLAUDE.md | 8 rules | 3 MCPs | 4 hooks
```

And a **browser dashboard** that auto-opens after `node9 scan` — History Audit modal with full drill-down, per-agent breakdown, loop-cost estimate, and live status strip.

---

## Reading the data — what the numbers mean

Node9 surfaces the signal. Here are the patterns worth knowing:

| Signal                                                      | Likely meaning                                                               |
| ----------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `Would have blocked` ≥ 5 in a week                          | Agent is attempting destructive ops; shields need review                     |
| Single `review-git-push` rule accounts for >50% of findings | Your own rule is firing as intended — not a risk, just supervision           |
| DLP finding in `user-prompt` tool                           | You pasted a secret into your own prompt — rotate the key                    |
| Agent Loop ×50+ on same file                                | Agent stuck in edit/test/fix cycle — check context or slow down              |
| MCP tool pin mismatch                                       | Server changed its tools — review before re-trusting                         |
| Large MCP response warning                                  | That server is inflating your context window for every subsequent turn       |
| `Response DLP` alert                                        | Claude wrote a secret in its response text — not blocked, rotate immediately |

These are starting points, not verdicts. One-off signals are normal; persistent patterns are what you act on.

---

## Python SDK — govern any Python agent

```python
from node9 import configure, protect

configure(agent_name="my-agent", policy="require_approval")

@protect("bash")
def run_command(cmd: str) -> str:
    ...
```

**[Python SDK →](https://github.com/node9-ai/node9-python)** · **[CI code review agent example →](https://github.com/node9-ai/node9-pr-agent)**

---

## Under the hood

- **Scan** reads raw agent history from `~/.claude/projects/`, `~/.gemini/tmp/`, `~/.codex/sessions/` — no API calls, fully offline
- **Runtime** wires PreToolUse hooks into Claude Code, Gemini CLI, and Codex — hooks write to `~/.node9/audit.log` atomically
- **MCP gateway** is a stdio proxy; intercepts `tools/list` + `tools/call` JSON-RPC, forwards the rest
- **Policy engine** uses [mvdan-sh](https://github.com/mvdan/sh) for bash AST analysis — defeats obfuscation via backslash escaping, variable substitution, eval of remote download
- **Shadow repo** for auto-undo lives at `~/.node9/snapshots/<hash16>/` — never touches your `.git`

---

## 📖 Full docs

Everything else — config reference, smart rules, stateful rules, trusted hosts, approval modes, Slack integration, CLI reference — is at **[node9.ai/docs](https://node9.ai/docs)**.

---

## Related projects

- **[node9-python](https://github.com/node9-ai/node9-python)** — Python SDK for governed agents
- **[node9-pr-agent](https://github.com/node9-ai/node9-pr-agent)** — GitHub Action that reviews PRs through Node9 (reference implementation of a governed agent)

---

## Enterprise

**Node9 Pro** adds governance locking, SAML/SSO, central audit export, and VPC deployment. See [node9.ai](https://node9.ai).

---

<p align="center">
  <sub>Built with ☕ and healthy paranoia.</sub>
</p>
