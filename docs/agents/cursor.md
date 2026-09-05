# node9 with Cursor

Cursor has no pre-execution hook, so node9 protects it through MCP only.

| Surface     | How node9 is wired                                                 | What it does                                                                           |
| ----------- | ------------------------------------------------------------------ | -------------------------------------------------------------------------------------- |
| MCP servers | `~/.cursor/mcp.json` entries are wrapped through the node9 gateway | every `tools/call` is authorized, pinned and env-scrubbed before it reaches the server |

For tools that go through MCP this is the same allow / review / block gate every other agent
gets.

## Set it up

```bash
node9 agents add cursor
```

`node9 init` does this for every agent it detects on the machine. Either command is safe to
re-run; it repairs a hook that an agent update removed and leaves everything else alone.

## What is not covered

- **Cursor's own terminal and file edits are not gated.** Nothing in Cursor exposes them to a
  hook today. If Cursor runs `cat ~/.ssh/id_rsa` in its built-in terminal, node9 does not see it.
- No prompt scan, no audit of native tool calls, no cost tracking.
- Say this plainly to your team: with Cursor, node9 governs the MCP surface, not the editor.

## Verify it on this machine

```bash
node9 doctor                                   # is the hook (or MCP wrap) actually in place?
node9 explain Bash 'cat ~/.ssh/id_rsa'         # shows the verdict the live hook enforces: BLOCK
```

`node9 explain` prints the exact rule that fires and where the decision came from. If `doctor`
says the agent is not wired, the guard is not running, whatever the config looks like.
