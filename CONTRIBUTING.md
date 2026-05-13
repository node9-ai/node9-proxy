# Contributing to Node9 Proxy

Thanks for your interest. Node9 is a security tool, so the contribution model is deliberately scoped — we want a healthy outside contributor base, but the parts that decide what gets blocked stay tightly controlled.

Bug reports, real-world usage stories, new shields, docs, and examples are always welcome.

## Getting Started

```bash
git clone https://github.com/node9-ai/node9-proxy.git
cd node9-proxy
npm install
npm run build
```

Run the demo to verify your setup:

```bash
npm run demo
```

If anything in the steps above fails on your machine, that itself is a useful bug report — open an issue.

## How to Contribute

### Reporting Bugs

Open an issue at https://github.com/node9-ai/node9-proxy/issues with:

- Node.js version (`node --version`) and OS
- What you ran and what you expected
- Full error output (stderr, not just the summary)
- A minimal reproduction if you can — even a 3-line script helps

### Suggesting Features

Open an issue with the `enhancement` label. Describe **the use case**, not just the feature — "I was running X and got attacked by Y" is more useful than "add Z".

For anything that touches policy decisions, audit format, or the daemon protocol, please discuss in an issue **before** writing code (see [Contribution Scope](#contribution-scope) below). PRs in those areas that arrive without prior discussion will usually be closed with a request to open an issue first — saves everyone's time.

### Submitting Code

1. Fork the repo and create a branch from `main`:
   ```bash
   git checkout -b fix/short-description
   ```
2. Make your changes in `src/`.
3. Run the full local gate before pushing:
   ```bash
   npm run build
   npm test            # 455+ tests; all must pass
   npm run typecheck
   npm run lint
   npm run format:check   # run `npm run format` to auto-fix
   ```
4. **Every bug fix and every new behavior ships with a test that fails without the change.** This is non-negotiable — see [Test Rules](#test-rules).
5. Open a Pull Request against `main`. Keep PRs focused — one fix or feature per PR. Describe the use case in the PR body, not just the diff.

## Contribution Scope

Node9 makes security decisions for AI agents. A subtly weakened check is worse than no check at all, so different parts of the codebase have different contribution policies.

| Area                   | Policy                               | What it covers                                                                                                                                                                                                                    |
| ---------------------- | ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ✅ **Open**            | Send a PR directly                   | Docs, examples, new MCP/agent integrations, TUI polish, bug fixes with a failing-test regression, new user-shield definitions (`shields/`), typo fixes, dependency updates with a clear reason                                    |
| ⚠️ **Discuss first**   | Open an issue before writing code    | New detection rules in built-in shields, `src/dlp.ts`, `src/loop-detector.ts`, `src/scan-*.ts`, audit log schema, daemon SSE protocol, anything in `src/proxy/`, anything in `src/tui/dashboard/` that changes a displayed number |
| 🔒 **Maintainer-only** | Not currently accepting external PRs | `src/core.ts` (policy engine), `src/auth/`, `src/policy/`, cloud routing, release tooling, `packages/policy-engine` internals                                                                                                     |

If you're not sure which bucket your change falls in, open an issue and ask. Don't guess and find out at review time.

## Test Rules

(Mirrored from `CLAUDE.md` so external contributors see the same gate the maintainer does.)

**Every bug fix must ship with a regression test.** Write the failing test first, then fix the code. This proves you understood the bug and prevents silent regressions.

**Integration tests are required for:**

- Any command that runs as a subprocess (`check`, `log`, the proxy)
- Anything that touches stdout / stderr (protocol correctness — JSON-RPC and MCP must stay clean)
- Any file write (`audit.log`, `hook-debug.log`, snapshots)
- Any behavior that depends on `cwd` or `HOME`

Use `spawnSync` against `dist/cli.js`. See `src/__tests__/check.integration.test.ts` for the pattern. Always assert both `result.error` and `result.status` — a silent spawn failure must not pass tests.

**Unit tests with mocked `fs` / `getConfig` are not sufficient** for hook commands or the proxy. They cannot catch protocol bugs, filesystem path bugs, or exit-code bugs.

## Project Structure

```
src/
  core.ts                # Policy engine — authorizeAction(), config, cloud routing
  cli.ts                 # node9 CLI entry point
  index.ts               # SDK public API — protect() wrapper

  cli/
    commands/            # node9 <subcommand> implementations
                         #   (report, blast, audit, scan, daemon, shield, ...)
    aggregate/           # Shared aggregators (report data, used by CLI + TUI)
  audit/                 # Audit-log readers and writers
  auth/                  # Daemon auth tokens, internal IPC
  config/                # Per-project config loading, schema validation
  daemon/                # Long-lived daemon: SSE broadcaster, approval queue,
                         # scan-watermark, forensic extractor
  dlp.ts                 # Credential / secret detection rules
  loop-detector.ts       # Agent loop heuristics
  mcp-server/, mcp-gateway/   # MCP protocol server + gateway
  policy/                # Policy primitives
  proxy/                 # Stdin/stdout proxy that wraps the agent process
  scan-*.ts              # History scanners (claude/codex/gemini sessions)
  shields.ts             # Built-in + user-defined shield registry
  tui/                   # Terminal UI:
    dashboard/           #   `node9 monitor` — live + report views
    tail.ts              #   `node9 tail` — approval prompts
  utils/, ui/            # Shared helpers

shields/                 # Built-in shield definitions (YAML/TS rules)
packages/                # Internal workspaces (policy-engine, ...)
examples/
  demo.ts                # Runnable demo of the protect() SDK
src/__tests__/           # Vitest suite — 455+ tests, must stay green
```

If you're adding a new shield, look at `shields/` for the pattern — most useful first PRs land here.

## Code Style

- TypeScript strict mode — no `any` in new code
- Keep functions small and single-purpose
- **No `console.log` in hook or proxy code paths** — use `console.error`. Stdout must stay clean for JSON-RPC / MCP
- No new external dependencies without discussion first — the dependency surface is intentionally small
- Review your own diff before you push: missing `return` after `res.end()`, silent `catch {}` blocks, double event-listener registration, fall-through in route handlers. Automated checks miss these

## Security Issues

**Do not open a public issue for security vulnerabilities.** See [SECURITY.md](./SECURITY.md) for the responsible-disclosure process.

This applies to vulnerabilities in Node9 itself — bypass techniques, auth issues, audit-log tampering, etc. Detection bugs ("Node9 should have blocked X but allowed it") can go in normal issues unless the bypass technique is novel.

## Getting Help

- Open a GitHub Discussion or issue for questions
- Email `nadav@node9.ai` for anything that doesn't fit a public channel
