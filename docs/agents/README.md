# node9 per agent

One page per agent: what node9 wires into it, what that covers, and what it does not. The
"what is not covered" section is the one to read before you tell your team an agent is governed.

| Agent                       | Control model | Prompt scan | Guide                                  |
| --------------------------- | ------------- | ----------- | -------------------------------------- |
| Claude Code                 | hooks + MCP   | yes         | [claude-code.md](claude-code.md)       |
| Codex CLI                   | hooks + MCP   | yes         | [codex.md](codex.md)                   |
| GitHub Copilot CLI          | hooks + MCP   | yes         | [copilot-cli.md](copilot-cli.md)       |
| Gemini CLI                  | hooks + MCP   | no          | [gemini-cli.md](gemini-cli.md)         |
| Antigravity                 | hooks + MCP   | no          | [antigravity.md](antigravity.md)       |
| Hermes Agent                | hooks         | no          | [hermes.md](hermes.md)                 |
| OpenCode                    | plugin        | yes         | [opencode.md](opencode.md)             |
| Pi                          | extension     | yes         | [pi.md](pi.md)                         |
| Cursor                      | MCP only      | no          | [cursor.md](cursor.md)                 |
| Windsurf                    | MCP only      | no          | [windsurf.md](windsurf.md)             |
| VS Code (Copilot extension) | MCP only      | no          | [vscode.md](vscode.md)                 |
| Claude Desktop              | MCP only      | no          | [claude-desktop.md](claude-desktop.md) |

"Hooks" means node9 sees every tool call before it runs. "MCP only" means node9 sees the tools
that go through MCP servers and nothing the editor does on its own.

Every page ends with the same two commands, and they are the real check:

```bash
node9 doctor
node9 explain Bash 'cat ~/.ssh/id_rsa'
```
