# node9 with GitHub Copilot CLI

Copilot CLI is wired on three events, which makes it one of the strongest integrations.

| Surface           | How node9 is wired                               | What it does                                |
| ----------------- | ------------------------------------------------ | ------------------------------------------- |
| Every tool call   | `PreToolUse` in `~/.copilot/hooks/node9.json`    | allow / review / block before the tool runs |
| Every tool result | `PostToolUse`                                    | audit record                                |
| Pasted prompts    | `UserPromptSubmit`                               | prompt secret scan                          |
| MCP servers       | `~/.copilot/mcp-config.json` entries are wrapped | per-tool allow / review / block             |

## Set it up

```bash
node9 agents add copilot
```

`node9 init` does this for every agent it detects on the machine. Either command is safe to
re-run; it repairs a hook that an agent update removed and leaves everything else alone.

## What is not covered

- Cost is not tracked for Copilot.
- Tool output is observed, not gated.

## Verify it on this machine

```bash
node9 doctor                                   # is the hook (or MCP wrap) actually in place?
node9 explain Bash 'cat ~/.ssh/id_rsa'         # shows the verdict the live hook enforces: BLOCK
```

`node9 explain` prints the exact rule that fires and where the decision came from. If `doctor`
says the agent is not wired, the guard is not running, whatever the config looks like.
