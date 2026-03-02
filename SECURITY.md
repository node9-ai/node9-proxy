# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| latest  | ✅ Yes    |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Email: **security@node9.ai**

Include:

- A description of the vulnerability and its potential impact
- Steps to reproduce
- Any suggested mitigation (optional but appreciated)

You will receive an acknowledgment within 48 hours and a resolution timeline within 5 business days.

We follow responsible disclosure — we ask that you give us time to patch before publishing details publicly.

## Threat Model

node9-proxy is a **localhost-only** daemon that intercepts AI agent tool calls before they execute. The daemon binds exclusively to `127.0.0.1` and is never exposed to the network.

| Component                                  | Trust boundary                                                                 |
| ------------------------------------------ | ------------------------------------------------------------------------------ |
| Daemon HTTP server                         | localhost only (`127.0.0.1:7391`)                                              |
| Browser UI                                 | Protected by a per-session CSRF token (`x-node9-token` header)                 |
| Internal resolve endpoint (`/resolve/:id`) | Protected by a separate per-session internal token (`x-node9-internal` header) |
| Audit log                                  | Written to `~/.node9/audit.log`; secrets are redacted before storage           |
| Decisions file                             | Written to `~/.node9/decisions.json`; stores only `allow`/`deny` per tool name |

**Known limitation**: If an attacker already has local code execution on the machine running the daemon, they can bypass controls. This is by design — the daemon is a human-in-the-loop safety layer, not a sandbox.

## Scope

Reports are in scope for:

- Command injection or privilege escalation in the proxy or CLI
- Policy bypass — a dangerous tool call that passes through without triggering HITL
- Credential exposure (API keys stored or transmitted insecurely)
- Dependency vulnerabilities with a clear exploit path against Node9 users

## Out of Scope

- Vulnerabilities in the wrapped MCP servers themselves (report those upstream)
- Theoretical attacks with no practical exploit path
