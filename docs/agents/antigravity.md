# node9 with Antigravity

| Surface           | How node9 is wired                                     | What it does                                |
| ----------------- | ------------------------------------------------------ | ------------------------------------------- |
| Every tool call   | `PreToolUse` hook in `~/.gemini/config/hooks.json`     | allow / review / block before the tool runs |
| Every tool result | `PostToolUse` hook                                     | audit record                                |
| MCP servers       | `~/.gemini/config/mcp_config.json` entries are wrapped | per-tool allow / review / block             |

Payload shape verified against Antigravity 1.0.6.

## Set it up

```bash
node9 agents add antigravity
```

`node9 init` does this for every agent it detects on the machine. Either command is safe to
re-run; it repairs a hook that an agent update removed and leaves everything else alone.

## What is not covered

- **No prompt scan.** There is no prompt event to hook.
- Cost is not tracked for Antigravity.

## Verify it on this machine

```bash
node9 doctor                                   # is the hook (or MCP wrap) actually in place?
node9 explain Bash 'cat ~/.ssh/id_rsa'         # shows the verdict the live hook enforces: BLOCK
```

`node9 explain` prints the exact rule that fires and where the decision came from. If `doctor`
says the agent is not wired, the guard is not running, whatever the config looks like.
