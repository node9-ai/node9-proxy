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

Works with **Claude Code · Codex CLI · Antigravity (agy) · GitHub Copilot CLI · Gemini CLI · Cursor · Windsurf · VSCode · Claude Desktop · Opencode · Pi · Hermes Agent · any MCP server**.

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

## Security posture scorecard

`node9 posture` grades how exposed this machine is to a compromised agent — isolation, egress, secrets on disk, supply chain, privilege — and hands you the exact command to fix each finding.

```bash
node9 posture          # scorecard with the #1 risk and a fix for every finding
node9 posture --ship   # send a redacted snapshot to your node9 dashboard (fleet view)
```

Findings are grouped by **who can fix them**: 🔒 the ones node9 reduces (just run the command) and 🧱 the ones only you can. Each carries a plain-language what / why / who and a real remediation — e.g. the "agent runs unsandboxed on the host" finding points straight at `node9 sandbox run` (below).

```text
🛡️  Node9 Posture — agent on this host        Score: 100/100  (Good)
  2 advisories below don't affect the score — OS-level exposure, yours to weigh.

  🟢 node9 is already protecting you
  ✅ Secrets        node9 DLP is blocking this
  ✅ Egress         node9 egress is approval-gating this
  ✅ Approval gate  node9 is blocking this
  ✅ Privilege      node9 is approval-gating this

  🔒 node9 reduces these — run the command, the rest is yours
  ⚠️  Isolation     Running directly on the host — no container
                   The agent runs loose on your whole machine, not in a sandbox.
                   → node9 sandbox run <agent>   — jail it: kernel egress + scoped mounts + node9 inside
                   → node9 shield enable project-jail   — or shrink the blast radius, keep host access
  ⚠️  Network exposure  4 services on 0.0.0.0 (node :3000/:4000, PostgreSQL :5432, Redis :6379)
                   Reachable from your whole network, not just this laptop.
                   → node9 shield enable postgres|redis   — node9 blocks DROP TABLE / FLUSHALL
                   → bind to 127.0.0.1 / firewall the port   (your part)

  ✅ Supply chain   no issues found
  ✅ Coverage       no issues found

  Track this across your fleet & keep it green → node9.ai
```

## Scan a repo — agent-CI security

`node9 scan-repo` checks any repo (or a local folder) for ways an AI agent wired into GitHub Actions could be **hijacked by an outsider** — injectable workflows, agent-reachable secrets, unpinned MCP servers, over-broad agent config, and poisoned instruction files. Static and parse-only: it reads only committed config, never executes repo code. No install or token needed for public repos.

```bash
npx node9-ai scan-repo <owner/repo>   # any public repo, no install
node9 scan-repo .                      # a local checkout — no network
node9 scan-repo <owner/repo> --json    # machine-readable
```

```text
🛡️  node9 scan-repo · node9-ai/agent-security-demo · ⚠️ agent-security risk found
   inspected 2 config file(s), 2 finding(s)

🔴 CRITICAL  Injectable agent workflow — untrusted input reaches a tool-using agent with secrets
   .github/workflows/vulnerable-example.yml · CI-2
     • runs with base-repo secrets (pull_request_target)
     • checks out the untrusted PR head into the workspace root
     • allowed_non_write_users: "*" — any user can trigger the agent
     • no effective actor gate

🔴 CRITICAL  Exfiltratable secrets reachable by an injectable agent
   .github/workflows/vulnerable-example.yml · CI-4
     • agent has arbitrary shell (bare Bash) → can read env and exfiltrate
```

What it checks:

| Check    | Flags                                                                        |
| -------- | ---------------------------------------------------------------------------- |
| **CI-1** | committed agent config that pre-authorizes broad tools or runs remote hooks  |
| **CI-2** | injectable agent workflows — an outsider can trigger the agent and hijack it |
| **CI-3** | unpinned / `@latest` MCP servers or inline credentials (supply chain)        |
| **CI-4** | secrets an injected agent could exfiltrate                                   |
| **CI-6** | poisoned or dangerous instructions in `CLAUDE.md` / `AGENTS.md` / skills     |

**Gate every PR** — the same engine as a GitHub Action, so a hijackable config can't get merged:

```yaml
# .github/workflows/agent-security.yml
- uses: node9-ai/agent-security-action@v1
  with:
    fail-on: high # or 'never' to just comment
```

Marketplace: **[node9 Agent Security Check](https://github.com/marketplace/actions/node9-agent-security-check)**

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

## Review prompts — approve inline, in your agent

When node9 flags an action for **review** (e.g. `git push --force`, a `DROP TABLE`), the approve/deny prompt renders **inline in the agent conversation** — no frozen session, no separate terminal, no hook-timeout race. node9 still runs the full evaluator and makes the decision; only the prompt _surface_ moves to the agent.

- **On by default** for **Claude Code** and **GitHub Copilot CLI** — the agents whose hook contract honors a native `ask`. Every other agent (Codex, Gemini, Antigravity, Hermes, Cursor, OpenCode, Pi) uses node9's own approver.
- **Control it** with `reviewChannel` in `~/.node9/config.json` (or `--no-ask` on the hook):

```jsonc
{
  "settings": {
    "reviewChannel": "ask", // "ask" = inline agent prompt (default) | "approver" = node9's own approver
  },
}
```

- **Team setups:** when a cloud/team approver is configured (`approvers.cloud: true`), reviews route to that approver instead — node9 won't let an inline self-approval bypass routed/second-party approval.

## Sandbox — run an agent in a jail

When watching isn't enough, **`node9 sandbox`** runs the agent inside a disposable container with a **kernel-enforced egress allowlist** and **scoped mounts** — while node9's hooks govern and audit every tool call _inside_ the box. The hard version of protection: the agent can only touch the folder you mount and reach the hosts you allow; everything else is dropped at the kernel.

```bash
cd ~/my-project
node9 sandbox new        # write node9.sandbox.yaml — what to mount + which hosts to allow
node9 sandbox run        # build + boot the jailed agent (your project at /workspace)
node9 sandbox tail       # watch the agent's actions live, from the host
```

- **Disposable** — the container is destroyed on exit; your project edits land on your real disk, nothing else survives.
- **Same policy** — your existing shields / egress rules / approvals apply inside the box, streamed to the same audit log and dashboard.
- **Closes the posture loop** — running it flips the Isolation / Egress findings green.

Honest scope (Phase 1): single container, **Claude first** (Codex next); the agent still holds its _own_ credentials in the box (the egress wall confines them to the allowed hosts) — _"the agent never holds a secret"_ is the credential-broker phase on the roadmap. Requires Docker.

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

- **Scan** reads raw agent history from `~/.claude/projects/`, `~/.gemini/tmp/`, `~/.gemini/antigravity-*/brain/`, `~/.copilot/session-state/`, `~/.codex/sessions/` — no API calls, fully offline
- **Runtime** intercepts tool calls via pre-execution hooks (Claude Code, Codex, Antigravity, GitHub Copilot CLI, Gemini CLI, Opencode, Pi) or via the MCP gateway (Cursor, Windsurf, VSCode, Claude Desktop). All decisions land in `~/.node9/audit.log` atomically.
- **MCP gateway** is a stdio proxy; intercepts `tools/list` + `tools/call` JSON-RPC, forwards the rest
- **Policy engine** uses [mvdan-sh](https://github.com/mvdan/sh) for bash AST analysis — defeats obfuscation via backslash escaping, variable substitution, eval of remote download
- **Shadow repo** for auto-undo lives at `~/.node9/snapshots/<hash16>/` — never touches your `.git`
- **Sandbox** generates a Dockerfile + entrypoint that seal an `ipset`/`iptables` deny-by-default egress wall, then drop to a non-root agent with node9's daemon + hooks running inside; only the agent's credential file is mounted, never your whole `~/.claude`

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
