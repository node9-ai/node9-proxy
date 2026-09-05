# Where node9 sits among agent-security tools

Most comparisons in this space grade tools on runtime mediation: where the allow / deny decision
is computed, where it is enforced, and what evidence the tool emits. That is a fair axis and
node9 is not the strongest tool on it. This page grades on a second axis that the same
comparisons leave out: **what a tool can see before an agent ever runs**.

Every claim below about node9 is code-verified against this repository. Claims about other
tools come from their own public documentation as of September 2026; if one is wrong, open an
issue and it will be corrected.

## Two questions, two fields

| Question                                                                 | Who answers it                                                                                                                           |
| ------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------- |
| At runtime, can a mediator stop this action and prove it did?            | pipelock, CAPSEM, Signet, AgentMint, Cupcake, agentsh, Docker MCP gateway, Microsoft AGT, Invariant, **node9**                           |
| Before any run, is this repository's committed agent surface hijackable? | **node9 `scan-repo`**, and in narrow slices Snyk `mcp-scan` (MCP tool definitions) and Trail of Bits `mcp-context-protector` (MCP drift) |

The first field is crowded and well served. The second is nearly empty.

## The committed agent surface

An agent wired into a repository leaves configuration behind: hook files, workflow YAML, MCP
server pins, instruction files. That configuration decides what an outsider can make the agent
do, and it is reviewable without running anything.

| Check | What it reads                                                                                        | What it flags                                                                                                                           | Nearest alternative                     |
| ----- | ---------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| CI-1  | `.claude/settings.json` and hooks                                                                    | committed config that pre-authorizes broad tools or runs remote hooks                                                                   | none                                    |
| CI-2  | `.github/workflows/*.yml`                                                                            | an agent that an outsider can trigger with the repository's secrets in reach (`pull_request_target`, untrusted checkout, no actor gate) | none                                    |
| CI-3  | `.mcp.json`, `.cursor/mcp.json`                                                                      | unpinned or `@latest` MCP servers, inline credentials                                                                                   | Snyk `mcp-scan` (definitions, not pins) |
| CI-4  | workflow YAML                                                                                        | secrets an injected agent could exfiltrate, given the shell it has                                                                      | none                                    |
| CI-6  | `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `copilot-instructions.md`, `.windsurfrules`, `.clinerules` | poisoned or dangerous instructions, including concealed text                                                                            | none                                    |

Not built: CI-5, drift of these files over time. `mcp-context-protector` does drift for MCP tool
descriptions; nobody does it for the rest of the surface, including node9.

Runs as `npx node9-ai scan-repo <owner/repo>` on any public repository with no install and no
token, or as a GitHub Action that fails the PR. This repository runs it on itself on every pull
request.

## Runtime: what node9 is and is not

node9 gates tool calls in the agent's own hook system (Claude Code, Codex, Copilot CLI, Gemini
CLI, Antigravity, Hermes, OpenCode, Pi) or at the MCP boundary (Cursor, Windsurf, VS Code,
Claude Desktop). Shell commands are parsed as an AST, so `$(cat ~/.aws/credentials | base64)`
is a credential read, not a string that happens to contain the word `cat`.

Where the runtime tools are ahead of node9, in their own words and ours:

| Capability                                       | Strongest tool on it                      | node9 today                                                                                                                                 |
| ------------------------------------------------ | ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Offline-verifiable, signed evidence per decision | pipelock (Ed25519, hash-chained receipts) | audit log with privacy hashing; release artifacts are signed, decisions are not                                                             |
| Content scanning of HTTP and WebSocket egress    | pipelock                                  | egress is a destination gate, off by default; no wire-level content scan                                                                    |
| Kernel or container boundary                     | agentsh, pipelock containment, CAPSEM     | `node9 sandbox` is a first-phase container run                                                                                              |
| Prompt-injection detection on tool output        | pipelock, Invariant                       | observed and quarantined on hook agents, redacted in place on OpenCode and Pi; not blocked before the model sees it on Claude Code or Codex |

Where node9 is ahead: per-agent wiring across twelve agents with one `node9 doctor` that tells
you which hook is actually in place, and the repository scan above.

## How to read this page

If your risk is an agent that is already running, pick from the first field and compare
evidence models. If your risk is a repository that wires an agent into CI, there is one tool
that reads that surface, and this is it. Most teams have both risks, and node9 is the only one
of the set that tries to cover both, which is also why it is not the deepest on either.
