<p align="center">
  <img src="https://github.com/user-attachments/assets/bc165779-4200-438d-967a-20d42bbfe69e" width="720" alt="Node9 scan scorecard" />
</p>

<h1 align="center">🛡️ Node9</h1>

<p align="center"><strong>What did your AI agent actually do? Find out, and stop the dangerous stuff.</strong></p>

<p align="center">
  <a href="https://www.npmjs.com/package/node9-ai"><img src="https://img.shields.io/npm/v/node9-ai.svg" alt="npm version" /></a>
  <a href="https://www.npmjs.com/package/node9-ai"><img src="https://img.shields.io/npm/dm/node9-ai.svg" alt="monthly downloads" /></a>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache 2.0" /></a>
  <a href="https://node9.ai/docs"><img src="https://img.shields.io/badge/docs-node9.ai-blue" alt="Documentation" /></a>
  <a href="https://huggingface.co/spaces/Node9ai/node9-security-demo"><img src="https://huggingface.co/datasets/huggingface/badges/resolve/main/open-in-hf-spaces-sm.svg" alt="Try on HF Spaces" /></a>
</p>

---

## What `node9 scan` shows on a real machine

This is my own machine — 30 days while building Node9. Yes, even the founder has 14 credential leaks.

```
🛡  Node9 Scan  ·  21 sessions  ·  8,114 tool calls  ·  Apr 6 – May 1, 2026

Security Score: 25/100  ·  Critical
$3,789 AI spend  ·  62 risky operations

🔑  14   credential leak     (Bearer Token ×4, GCP API Key ×4, JWT ×2)
🛑  15   would have blocked  (force-push ×5, read-ssh ×4, read-aws ×4)
🔁  193  agent loops         (18% wasted  ·  ~$6.51)
👁  33   flagged for review  (git-destructive ×19, rm ×9, sudo ×2)

🔭  Blast radius             ssh × gcp × npm × other (5 exposures)

→  npx node9-ai scan         run this on your machine
```

Run it on yours — `npx node9-ai scan` finishes in ~10 seconds and runs entirely local. Nothing uploads. The full breakdown with every tool call, file path, and timestamp is `node9 scan` (default mode); the browser dashboard auto-opens after.

<p align="center">
  <img src="https://github.com/user-attachments/assets/825f99d8-b487-4746-9cef-a02a9ca76c1f" width="90%" alt="Node9 browser History Audit dashboard" />
</p>

---

## What Node9 does

- 🛑 **Block** dangerous AI actions before they run — `rm -rf`, `git push --force`, `DROP TABLE`, credential reads, `curl | bash`
- 🔍 **Scan** what your AI agent has already been doing — loops, leaked secrets, blocked operations across every session
- 🔭 **Map your blast radius** — every SSH key, AWS credential, and `.env` file an AI agent on this machine could reach right now

Works with **Claude Code · Cursor · Codex · Gemini CLI · any MCP server**.

---

## How is this different from gitleaks / Snyk / TruffleHog?

Those scan **repositories** for credentials. Node9 scans **AI agent session history** — what your AI ran, what it read, what credentials passed through tool calls. Different surface area.

Node9 catches things gitleaks can't:

- Credentials the AI read but never committed
- Agent edit loops that burn tokens on retries
- Dangerous shell commands the AI ran without confirmation
- Blast radius — which credential files an AI agent on this machine could reach right now

Run gitleaks for committed code. Run Node9 for AI session history.

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

| Shield            | What it catches                                                                | Enable                                |
| ----------------- | ------------------------------------------------------------------------------ | ------------------------------------- |
| `project-jail`    | Blocks reads of `~/.ssh`, `~/.aws`, `.env`, credentials via Bash and Read tool | `node9 shield enable project-jail`    |
| `bash-safe`       | `curl \| bash`, `rm -rf /`, disk overwrite, `eval` of remote                   | `node9 shield enable bash-safe`       |
| `postgres`        | `DROP TABLE`, `TRUNCATE`, `DROP COLUMN`, `DELETE` without `WHERE`              | `node9 shield enable postgres`        |
| `mongodb`         | `dropDatabase`, `drop()`, `deleteMany({})`, index drops                        | `node9 shield enable mongodb`         |
| `redis`           | `FLUSHALL`, `FLUSHDB`, `CONFIG SET` on a live server                           | `node9 shield enable redis`           |
| `aws`             | S3 delete, EC2 terminate, IAM changes, RDS destroy                             | `node9 shield enable aws`             |
| `k8s`             | namespace delete, `helm uninstall`, cluster role wipes                         | `node9 shield enable k8s`             |
| `docker`          | `system prune`, `volume prune`, `rm -f` containers                             | `node9 shield enable docker`          |
| `github`          | `gh repo delete`, remote branch deletion, settings changes                     | `node9 shield enable github`          |
| `filesystem`      | `chmod 777`, writes under `/etc/`, `/boot/`, `/usr/`                           | `node9 shield enable filesystem`      |
| `mcp-tool-gating` | unapproved MCP tools silently activating new capabilities                      | `node9 shield enable mcp-tool-gating` |

```bash
node9 shield list    # show all shields + status
```

---

## Always on — no config needed

- **Git** — blocks `git push --force`, `git reset --hard`, `git clean -fd`
- **SQL** — blocks `DELETE` / `UPDATE` without `WHERE`, `DROP TABLE`, `TRUNCATE`
- **Shell** — blocks `curl | bash`, unauthorized `sudo`
- **DLP** — blocks AWS keys, GitHub tokens, Stripe keys, PEM private keys in any tool argument, file Claude reads, or shell config (`~/.zshrc`, `~/.bashrc`)
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

| Command          | What it shows                                             | When to use                               |
| ---------------- | --------------------------------------------------------- | ----------------------------------------- |
| `node9 blast`    | What an AI agent can reach right now — files, creds, env  | First thing to run on any machine         |
| `node9 scan`     | Retrospective audit of existing agent history             | Before installing, or to review past risk |
| `node9 mask`     | Redact plaintext secrets from local session history files | After a DLP finding — cleans local disk   |
| `node9 tail`     | Live stream of every tool call                            | Watching an agent work in real time       |
| `node9 report`   | Per-period summary: allowed/blocked/DLP/cost + top tools  | Reviewing what happened after a session   |
| `node9 sessions` | Session history with prompt, tool trace, cost, snapshot   | Reviewing a handoff or past work          |
| `node9 dlp`      | Credential-leak findings in Claude response text          | Any time a DLP desktop alert fires        |

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

| Signal                                                      | Likely meaning                                                                                     |
| ----------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `Would have blocked` ≥ 5 in a week                          | Agent is attempting destructive ops; shields need review                                           |
| Single `review-git-push` rule accounts for >50% of findings | Your own rule is firing as intended — not a risk, just supervision                                 |
| DLP finding in `user-prompt` tool                           | You pasted a secret into your own prompt — rotate the key                                          |
| Agent Loop ×50+ on same file                                | Agent stuck in edit/test/fix cycle — check context or slow down                                    |
| MCP tool pin mismatch                                       | Server changed its tools — review before re-trusting                                               |
| Large MCP response warning                                  | That server is inflating your context window for every subsequent turn                             |
| `Response DLP` alert                                        | Claude wrote a secret in its response text — not blocked, rotate immediately                       |
| DLP finding in `tool-result`                                | Claude read a file containing a secret (`.env`, credentials) — rotate the key and run `node9 mask` |
| DLP finding in `[Shell]`                                    | Plaintext secret in `~/.zshrc` or `~/.bashrc` — every AI session can see it                        |

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
