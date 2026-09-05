# node9 with Codex CLI

Codex gets the same pre-tool gate as Claude Code.

| Surface           | How node9 is wired                                  | What it does                                       |
| ----------------- | --------------------------------------------------- | -------------------------------------------------- |
| Every tool call   | `PreToolUse` hook in `~/.codex/hooks.json`          | allow / review / block before the tool runs        |
| Pasted prompts    | `UserPromptSubmit` hook                             | prompt secret scan                                 |
| Every tool result | `PostToolUse` hook                                  | audit record; verified against real Codex sessions |
| MCP servers       | `mcp_servers` in `~/.codex/config.toml` are wrapped | per-tool allow / review / block                    |

Headless `codex exec` runs the same hooks. Verified with a nonce probe against the real
trusted-hooks config: both the pre and post hook fired.

## Set it up

```bash
node9 agents add codex
```

`node9 init` does this for every agent it detects on the machine. Either command is safe to
re-run; it repairs a hook that an agent update removed and leaves everything else alone.

## What is not covered

- Cost is not tracked for Codex. `node9 report` cost figures are Claude Code only today.
- Tool output is observed, not gated (same as Claude Code).

## Verify it on this machine

```bash
node9 doctor                                   # is the hook (or MCP wrap) actually in place?
node9 explain Bash 'cat ~/.ssh/id_rsa'         # shows the verdict the live hook enforces: BLOCK
```

`node9 explain` prints the exact rule that fires and where the decision came from. If `doctor`
says the agent is not wired, the guard is not running, whatever the config looks like.
