# 🛡️ Node9 Proxy

### The "Sudo" Command for AI Agents.

[![NPM Version](https://img.shields.io/npm/v/@node9/proxy.svg)](https://www.npmjs.com/package/@node9/proxy)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Open in HF Spaces](https://huggingface.co/datasets/huggingface/badges/resolve/main/open-in-hf-spaces-sm.svg)](https://huggingface.co/spaces/Node9ai/node9-security-demo)
[![Documentation](https://img.shields.io/badge/docs-node9.ai%2Fdocs-blue)](https://node9.ai/docs)

**Node9** sits between your AI agent and your system. Every shell command, file write, and tool call passes through Node9 first — blocked, approved, or logged based on your policy. Works with Claude Code, Gemini CLI, Cursor, Codex, and any MCP server.

📖 **[Full Documentation →](https://node9.ai/docs)**

---

## The "Aha!" Moment

**AIs move fast.** Ask an agent to "ship the fix" and it might push straight to git without asking you.

<p align="center">
  <img src="https://github.com/user-attachments/assets/4aa6e45b-9aba-4953-9ce3-548226622588" width="100%">
</p>

With Node9:

1. **AI attempts:** `Bash("git push origin main")`
2. **Node9 intercepts:** OS-native popup appears instantly
3. **You block it** — one click
4. **AI pivots:** _"I'll create a PR for review instead"_

---

## Install

```bash
# macOS / Linux
brew tap node9-ai/node9 && brew install node9

# or via npm
npm install -g @node9/proxy
```

```bash
node9 setup      # auto-detects Claude Code, Gemini CLI, Cursor, Codex
node9 doctor     # verify everything is wired correctly
```

---

## Shields — one command per service

Enable expert-crafted protection for the infrastructure your agent touches:

```bash
node9 shield enable postgres   # blocks DROP TABLE, TRUNCATE, DROP COLUMN
node9 shield enable mongodb    # blocks dropDatabase, drop(), deleteMany({})
node9 shield enable redis      # blocks FLUSHALL, FLUSHDB
node9 shield enable aws        # blocks S3 delete, EC2 terminate, IAM changes
node9 shield enable k8s        # blocks namespace delete, helm uninstall
node9 shield enable docker     # blocks system prune, volume prune, rm -f
node9 shield enable github     # blocks gh repo delete, remote branch deletion
node9 shield enable bash-safe  # blocks curl|bash, base64|sh, rm -rf /
node9 shield enable filesystem # reviews chmod 777, writes to /etc/

node9 shield list              # see all shields and their status
```

---

## MCP Gateway — protect any MCP server

Wrap any MCP server transparently. The AI sees the same server — Node9 intercepts every tool call:

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

Or use `node9 setup` — it wraps existing MCP servers automatically.

### MCP Tool Pinning — rug pull defense

MCP servers can change their tool definitions between sessions. A compromised or malicious server could silently add, remove, or modify tools after initial trust — a **rug pull** attack.

Node9 defends against this by **pinning** tool definitions on first use:

1. **First connection** — the gateway records a SHA-256 hash of all tool definitions
2. **Subsequent connections** — the hash is compared; if tools changed, the session is **quarantined** and all tool calls are blocked until a human reviews and approves the change
3. **Corrupt pin state** — fails closed (blocks), never silently re-trusts

```bash
node9 mcp pin list                # show all pinned servers and hashes
node9 mcp pin update <serverKey>  # remove pin, re-pin on next connection
node9 mcp pin reset               # clear all pins (re-pin on next connection)
```

This is automatic — no configuration needed. The gateway pins on first `tools/list` and enforces on every subsequent session.

---

## Python SDK — govern any Python agent

```python
from node9 import configure

configure(agent_name="my-agent", policy="require_approval")

# Your existing agent code runs unchanged — Node9 intercepts tool calls
```

**[Python SDK →](https://github.com/node9-ai/node9-python)** · **[Governed Agent examples →](https://github.com/node9-ai/governed-agent)**

---

## What's always on (no config needed)

- **Git:** blocks `git push --force`, `git reset --hard`, `git clean -fd`
- **SQL:** blocks `DELETE`/`UPDATE` without `WHERE`, `DROP TABLE`, `TRUNCATE`
- **Shell:** blocks `curl | bash`, `sudo` commands
- **DLP:** blocks AWS keys, GitHub tokens, Stripe keys, PEM private keys in any tool call argument
- **Auto-undo:** git snapshot before every AI file edit → `node9 undo` to revert

---

## Flight Recorder & HUD

Every tool call your AI agent makes is recorded — command, arguments, result, and cost estimate. Node9 wires a live statusline into Claude Code that shows you what's happening in real time:

```
🛡 node9 | standard | [bash-safe] | ✅ 12 allowed  🛑 2 blocked  🚨 0 dlp | ~$0.43 | ⚡ no-force-push
📊 claude-opus-4-6 | ctx [████████░░░░░░░] 54% | 5h [██░░░░░░░░░░░░░] 12% | 7d [█░░░░░░░░░░░░░░] 7%
🗂 2 CLAUDE.md | 8 rules | 3 MCPs | 4 hooks
```

**Line 1 — Security state:** active mode, enabled shields, session totals (allowed / blocked / DLP hits), estimated cost, last rule that fired.

**Line 2 — Context & rate limits:** model name, context window usage, 5-hour and 7-day token rate-limit bars — so you can see when an agent is burning through quota.

**Line 3 — Environment:** how many CLAUDE.md files, rules, MCP servers, and hooks are active in the current project.

The HUD is wired automatically by `node9 setup`. Full session logs land in `~/.node9/audit.log`.

---

## 📖 Full docs

Everything else — config reference, smart rules, stateful rules, trusted hosts, approval modes, CLI reference — is at **[node9.ai/docs](https://node9.ai/docs)**.

---

## Related

- [node9-python](https://github.com/node9-ai/node9-python) — Python SDK
- [governed-agent](https://github.com/node9-ai/governed-agent) — Reference governed agents (CI code review fixer)

---

## Enterprise

Node9 Pro provides governance locking, SAML/SSO, and VPC deployment. Visit [node9.ai](https://node9.ai).
