# 🛡️ Node9 Proxy

### The "Sudo" Command for AI Agents.

[![NPM Version](https://img.shields.io/npm/v/node9-ai.svg)](https://www.npmjs.com/package/node9-ai)
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

## Try it instantly — no install needed

See what node9 would have caught in your existing Claude Code, Gemini CLI, and Codex history:

```bash
npx node9-ai scan
```

No account, no daemon, no config. Reads `~/.claude/projects/`, `~/.gemini/tmp/`, and `~/.codex/`, runs the full policy engine, and shows every operation that would have been blocked or flagged.

```
🔍  Scanning your AI history  — what would node9 have caught?

  47 risky operations found — none were blocked

    🛑  Would have blocked        2   operations stopped before execution
    👁   Would have flagged       44   sent to you for approval
    🔑  Credential leak           1   secret detected in tool call

  ──────────────────────────────────────────────────────────────────
  bash-safe  ·  12 findings  →  node9 shield enable bash-safe
    🛑  block-pipe-to-shell ×8  — Pipe-to-shell is a common supply-chain attack vector
    👁   review-eval ×4         — eval of dynamic content requires human approval

  ⚡ 47 operations ran unprotected. node9 would have caught them.
```

---

## Install

```bash
# macOS / Linux
brew tap node9-ai/node9 && brew install node9

# or via npm
npm install -g node9-ai
```

```bash
node9 init       # auto-detects Claude Code, Gemini CLI, Cursor, Codex
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

Or use `node9 init` — it wraps existing MCP servers automatically.

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

### Skills Pinning — installed-plugin drift detection

Marketplace plugins at `~/.claude/plugins/marketplaces/` come from registries, not your workspace — `git status` never sees them. Each installed plugin gets its own pin (same model as MCP server pinning): installing a new plugin creates a new pin silently; only changes to an already-pinned plugin trigger drift. Opt-in via `policy.skillPinning.enabled: true`; use `mode: 'block'` for strict enforcement. User-edited files are **not** in default scope. Extend via `policy.skillPinning.roots`.

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
- **Response DLP:** background scanner reads Claude's JSONL history hourly and alerts you if a secret appears in Claude's _response text_ (not just tool args) — see [`node9 dlp`](#node9-dlp--response-secret-scanner)
- **Auto-undo:** git snapshot before every AI file edit → `node9 undo` to revert
- **Skills Pinning:** SHA-256 verification of agent skill files between sessions; quarantines on drift (AST 02 + AST 07 — supply chain & update drift)

---

## Observability

Every tool call your AI agent makes is recorded — command, arguments, result, and cost estimate. Node9 gives you four ways to see what your agent is doing.

### Live HUD (statusline)

Node9 wires a live statusline into Claude Code that shows you what's happening in real time:

```
🛡 node9 | standard | [bash-safe] | ✅ 12 allowed  🛑 2 blocked  🚨 0 dlp | ~$0.43 | ⚡ no-force-push
📊 claude-opus-4-6 | ctx [████████░░░░░░░] 54% | 5h [██░░░░░░░░░░░░░] 12% | 7d [█░░░░░░░░░░░░░░] 7%
🗂 2 CLAUDE.md | 8 rules | 3 MCPs | 4 hooks
```

**Line 1 — Security state:** active mode, enabled shields, session totals (allowed / blocked / DLP hits), estimated cost, last rule that fired.

**Line 2 — Context & rate limits:** model name, context window usage, 5-hour and 7-day token rate-limit bars — so you can see when an agent is burning through quota.

**Line 3 — Environment:** how many CLAUDE.md files, rules, MCP servers, and hooks are active in the current project.

The HUD is wired automatically by `node9 init`. Full session logs land in `~/.node9/audit.log`.

### `node9 scan` — flags

```bash
node9 scan                # last 90 days
node9 scan --all          # all time
node9 scan --drill-down   # full commands + session IDs
```

### `node9 tail` — live stream

Stream every tool call as it happens. Useful when you send an agent off to work and want to watch what it's doing:

```bash
node9 tail          # stream tool calls for the active session
node9 tail --all    # include all projects
```

Each line shows the tool name, a summary of its arguments, and the decision (allowed / blocked / DLP hit).

At startup, `tail` prints a one-line context summary:

```
ctx: 34% (68k/200k  out 2k  · claude-sonnet-4-6)
```

This shows how full the context window is, how many output tokens were generated, and which model is running. Color-coded: cyan < 50%, yellow 50–79%, red ≥ 80%.

### `node9 report` — security dashboard

Run after a session to get a summary of what was allowed, blocked, DLP hits, cost, and daily activity:

```
$ node9 report --period 7d

  🛡 node9 Report  ·  Last 7 Days  Apr 8 – Apr 14  2,255 events
  ──────────────────────────────────────────────────────────────────────────────

  ✅ 1,746 allowed   🛑 509 blocked   🚨 70 DLP hits   23% block rate   💰 $82.91

  Top Tools                              Top Blocks
  ─────────────────────────────────────  ─────────────────────────────────────
  Bash                    ██████ 1,595   timeout                 ██████ 281
  Read                    █░░░░░   196   smart-rule-block        ██░░░░  79
  Edit                    █░░░░░   118   observe-mode-dlp-would… █░░░░░  69
  drop_resource           █░░░░░    69   persistent-deny         █░░░░░  69
  Grep                    █░░░░░    35   local-decision          █░░░░░   5

  Daily Activity
  ──────────────────────────────────────────────────────────────────────────────
  Apr 9       ██████████████████████████████  833  216 blocked
  Apr 10      █████░░░░░░░░░░░░░░░░░░░░░░░░░  145   24 blocked
  Apr 11      ██████████████████████░░░░░░░░  617  139 blocked
```

The report also includes a **Tokens** section showing a breakdown of input, output, cache-write, and cache-read tokens with a cache hit-rate percentage — useful for spotting sessions that are burning tokens without getting cache savings.

Periods: `today`, `7d` (default), `30d`, `month`. Cost data is read from `~/.claude/projects/` — no API calls, fully offline.

If the response DLP scanner found secrets during the period, the report shows a `⚠️ DLP ALERT` banner at the top and a dedicated **Response DLP** section listing each finding with the pattern name, a masked sample, and the project it came from.

### `node9 sessions` — session history

See what your AI agent did across sessions — prompt, tool calls, cost, files modified, and whether a snapshot was taken. Useful when you hand off a task and come back to review what happened:

```
$ node9 sessions --all

  📋  node9 sessions  — what your AI agent did

  7   sessions    $178.93  total    2379  tool calls    122 files modified
  avg $25.56    /session    7 of 7 sessions had snapshots

  Tool breakdown:
    Bash    ████████████████████  1165 (49%)
    Read    ███████████░░░░░░░░░   613 (26%)
    Edit    ██████░░░░░░░░░░░░░░   367 (15%)
    Other   ███░░░░░░░░░░░░░░░░░   203 (9%)
    Write   █░░░░░░░░░░░░░░░░░░░    31 (1%)

  ─── Apr 15  ~/node9
  14:47  implement delegated sessions feature       919 tools  $74.45  📸  00ac39e2
  12:47  ok, it seems you crash and we have a bug…   95 tools  $6.40   📸  5a4e7fab
```

Drill into any session for a full tool trace:

```
$ node9 sessions --detail 4812594b

  Session  4812594b-c93f-4a26-91f0-44aa2e324918
  Prompt   can you push node9-proxy to git dev?
  Project  ~/node9
  When     Apr 9, 2026, 20:49
  Cost     ~$2.06
  Snapshot ✓ taken

  Tool calls (54):
    20:49  Bash              git status && git branch -a
    20:52  Write             /home/nadav/node9/node9-proxy/.git/hooks/pre-commit
    20:56  Edit              /home/nadav/node9/node9-proxy/src/cli/commands/check.ts
    ...

  Files modified (3):
    /home/nadav/node9/node9-proxy/.git/hooks/pre-commit
    /home/nadav/node9/node9-proxy/src/cli/commands/check.ts
    /home/nadav/node9/node9-proxy/src/cli/hud.ts
```

```bash
node9 sessions              # last 7 days
node9 sessions --all        # all time
node9 sessions --days 30    # last 30 days
node9 sessions --detail <session-id>   # full tool trace (prefix match on session ID)
```

Currently works with Claude Code. Support for other agents coming as they expose session history.

### `node9 dlp` — response secret scanner

Node9's tool-call DLP blocks secrets _before_ they leave your machine. But Claude can also write secrets into its **response text** — a curl example with a real token, a config snippet with a live key — and that text bypasses tool-call interception entirely.

The **response DLP scanner** runs as a background daemon. It reads Claude's JSONL conversation history incrementally (delta scan — only new bytes since the last check), looks for secret patterns in assistant response text, and fires a desktop notification the moment it finds one.

```
⚠️  node9 DLP alert
AWS Access Key found in Claude response text.
Sample: AKIA****MPLE  — run: node9 dlp
```

```bash
node9 dlp              # show all open findings with pattern, sample, project, date
node9 dlp resolve      # acknowledge all current findings (clears the banner)
```

The `node9 dlp` command shows a guided remediation workflow:

```
🔐  node9 dlp  — secrets found in Claude response text

  ⚠️  1 open finding

  These secrets were included in Claude's response text — NOT blocked.
  Rotate each affected key immediately.

  ●  AWS Access Key ID   Apr 14, 2026
     Sample: AKIA****MPLE
     Project: ~/node9

  Next steps:
  1. Rotate any exposed keys shown above
  2. Run node9 dlp resolve to acknowledge
  3. Run node9 report for full audit history
```

Findings are never re-shown after `node9 dlp resolve`. The scanner stores resolved keys in `~/.node9/dlp-resolved.json` so only genuinely new secrets surface.

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
