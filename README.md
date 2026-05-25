<h1 align="center">🛡️ Node9</h1>
<p align="center"><strong>What did your AI agent actually do? Find out.</strong></p>
<p align="center">
  <a href="https://www.npmjs.com/package/node9-ai"><img src="https://img.shields.io/npm/v/node9-ai.svg" alt="npm version" /></a>
  <a href="https://www.npmjs.com/package/node9-ai"><img src="https://img.shields.io/npm/dm/node9-ai.svg" alt="monthly downloads" /></a>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache 2.0" /></a>
  <a href="https://node9.ai/docs"><img src="https://img.shields.io/badge/docs-node9.ai-blue" alt="Documentation" /></a>
  <a href="https://huggingface.co/spaces/Node9ai/node9-security-demo"><img src="https://huggingface.co/datasets/huggingface/badges/resolve/main/open-in-hf-spaces-sm.svg" alt="Try on HF Spaces" /></a>
</p>

Node9 sits between your AI agent and the tools it can use — **discover** what it's already been doing, **protect** against risky actions in real time, and **review** what happened over any time window.

Works with **Claude Code · Codex CLI · Gemini CLI · Cursor · Windsurf · VSCode · Claude Desktop · Opencode · Pi · any MCP server**.

## What Node9 does

- 🔍 **Discover** — scan every past AI session for credential leaks, agent loops, blocked operations, and every secret on disk an agent could reach right now
- 🛡 **Protect** — review or block risky commands before they run — `rm -rf`, `git push --force`, `DROP TABLE`, credential reads, `curl | bash`, AWS/GitHub/Stripe key leaks
- 📊 **Review** — period-windowed report (today / week / month / 90 days) — cost per agent, top tools, shields fired, blast radius

## Retrospective scan

This is my own machine — 90 days while building Node9. Score 25/100, 5 credential files an AI agent could reach right now.

```bash
npx node9-ai scan   # before installation, runs in ~10s, nothing uploads
node9 scan          # after installation, same output
```

<p align="center">
  <img src="https://github.com/user-attachments/assets/7c5b30f1-1ca1-40b4-bfd5-d6671002e98e" width="720" alt="Node9 scan scorecard" />
</p>

## Live monitoring

<p align="center">
  <img src="https://github.com/user-attachments/assets/4661da97-c174-4bae-ae54-4c52a1d69213" width="720" alt="Node9 monitor dashboard" />
</p>

`node9 monitor` opens an interactive terminal dashboard with two views:

- **`[1]` Realtime** — live activity, approvals, security alerts, current risk score
- **`[2]` Report** — period-windowed summary: cost, top tools, shields fired, blast radius

## Report

Press `[2]` in monitor for a period-windowed summary. Toggle the window with `[T]oday` · `[W]eek` · `[M]onth` · `[N]inety` — same panels as the scan above, driven by your post-install audit log.

<p align="center">
  <img src="https://github.com/user-attachments/assets/66c02a72-e477-443d-807f-d65a21d096cd" width="720" alt="Node9 monitor [2] Report" />
</p>

```bash
node9 monitor              # press [2] for Report view
node9 report --period 7d   # CLI form, no TUI
```

## Install

```bash
# macOS / Linux
brew tap node9-ai/node9 && brew install node9

# or via npm (any platform)
npm install -g node9-ai
```

```bash
node9 init       # auto-wires all detected agents + MCP servers
node9 doctor     # verify everything is wired correctly
```

Requires Node.js 18+.

## Shields — curated rule packs

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

## Always on — no config needed

- **Git** — catches `git push --force`, `git reset --hard`, `git clean -fd`
- **SQL** — catches `DELETE` / `UPDATE` without `WHERE`, `DROP TABLE`, `TRUNCATE`
- **Shell** — catches `curl | bash`, unauthorized `sudo`
- **DLP** — flags AWS keys, GitHub tokens, Stripe keys, PEM private keys in any tool argument, file contents, or shell config (`~/.zshrc`, `~/.bashrc`)
- **Response DLP** — background scanner reads Claude's conversation history and alerts you if Claude _wrote_ a secret in its response text
- **Auto-undo** — git snapshot before every AI file edit → `node9 undo` to revert
- **Skills pinning** — SHA-256 verification of installed Claude skills / plugins between sessions

## MCP gateway

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

</details>

## Other commands

Beyond the three flow commands above (`scan` / `monitor` / `report`):

| Command          | What it shows                                             | When to use                             |
| ---------------- | --------------------------------------------------------- | --------------------------------------- |
| `node9 blast`    | What an AI agent can reach right now — files, creds, env  | First thing to run on any machine       |
| `node9 tail`     | Live stream of every tool call (text-only, no TUI)        | Piping into other tools, CI, logs       |
| `node9 sessions` | Session history with prompt, tool trace, cost, snapshot   | Reviewing a handoff or past work        |
| `node9 dlp`      | Credential-leak findings in Claude response text          | Any time a DLP desktop alert fires      |
| `node9 mask`     | Redact plaintext secrets from local session history files | After a DLP finding — cleans local disk |

Plus a **live HUD** in your Claude Code statusline:

```
🛡 node9 | standard | [bash-safe] | ✅ 12 allowed  🛑 2 blocked  🚨 0 dlp | ~$0.43
📊 claude-opus-4-7 | ctx [████████░░░] 54% | 5h [██░░░░░░░░] 12% | 7d [█░░░░░░░] 7%
🗂 2 CLAUDE.md | 8 rules | 3 MCPs | 4 hooks
```

## Reading the data — what the numbers mean

Node9 surfaces the signal. Here are the patterns worth knowing:

| Signal                                         | Likely meaning                                                                                     |
| ---------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `Would have blocked` ≥ 5 in a week             | Agent is attempting high-impact ops; shields are worth reviewing                                   |
| Single `review-git-push` rule >50% of findings | Your own rule is firing as intended — not a risk, just supervision                                 |
| DLP finding in `user-prompt` tool              | You pasted a secret into your own prompt — rotate the key                                          |
| Agent Loop ×50+ on same file                   | Agent stuck in edit/test/fix cycle — check context or slow down                                    |
| MCP tool pin mismatch                          | Server changed its tools — review before re-trusting                                               |
| Large MCP response warning                     | That server is inflating your context window for every subsequent turn                             |
| `Response DLP` alert                           | Claude wrote a secret in its response text — not blocked, rotate immediately                       |
| DLP finding in `tool-result`                   | Claude read a file containing a secret (`.env`, credentials) — rotate the key and run `node9 mask` |
| DLP finding in `[Shell]`                       | Plaintext secret in `~/.zshrc` or `~/.bashrc` — every AI session can see it                        |

One-off signals are normal; persistent patterns are what you act on.

## Python SDK — govern any Python agent

```python
from node9 import configure, protect

configure(agent_name="my-agent", policy="require_approval")

@protect("bash")
def run_command(cmd: str) -> str:
    ...
```

**[Python SDK →](https://github.com/node9-ai/node9-python)** · **[CI code review agent example →](https://github.com/node9-ai/node9-pr-agent)**

## Under the hood

- **Scan** reads raw agent history from `~/.claude/projects/`, `~/.gemini/tmp/`, `~/.codex/sessions/` — no API calls, fully offline
- **Runtime** intercepts tool calls via pre-execution hooks (Claude Code, Codex, Gemini CLI, Opencode, Pi) or via the MCP gateway (Cursor, Windsurf, VSCode, Claude Desktop). All decisions land in `~/.node9/audit.log` atomically.
- **MCP gateway** is a stdio proxy; intercepts `tools/list` + `tools/call` JSON-RPC, forwards the rest
- **Policy engine** uses [mvdan-sh](https://github.com/mvdan/sh) for bash AST analysis — defeats obfuscation via backslash escaping, variable substitution, eval of remote download
- **Shadow repo** for auto-undo lives at `~/.node9/snapshots/<hash16>/` — never touches your `.git`

## Full docs

Config reference, smart rules, stateful rules, trusted hosts, approval modes, CLI reference — at **[node9.ai/docs](https://node9.ai/docs)**.

## Related projects

- **[node9-python](https://github.com/node9-ai/node9-python)** — Python SDK
- **[node9-pr-agent](https://github.com/node9-ai/node9-pr-agent)** — GitHub Action that reviews PRs through Node9

## Enterprise

**Node9 Pro** adds governance locking, SAML/SSO, central audit export, and VPC deployment. See [node9.ai](https://node9.ai).

## License

Apache-2.0

<p align="center">
  <sub>Built with ☕ and healthy paranoia.</sub>
</p>
