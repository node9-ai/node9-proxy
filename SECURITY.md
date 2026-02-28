# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Email: **security@node9.ai**

Include:
- A description of the vulnerability and its potential impact
- Steps to reproduce
- Any suggested mitigation (optional but appreciated)

You will receive an acknowledgment within 48 hours and a resolution timeline within 5 business days.

We follow responsible disclosure — we ask that you give us time to patch before publishing details publicly.

## Scope

Reports are in scope for:
- Command injection or privilege escalation in the proxy or CLI
- Policy bypass — a dangerous tool call that passes through without triggering HITL
- Credential exposure (API keys stored or transmitted insecurely)
- Dependency vulnerabilities with a clear exploit path against Node9 users

## Out of Scope

- Vulnerabilities in the wrapped MCP servers themselves (report those upstream)
- Theoretical attacks with no practical exploit path
