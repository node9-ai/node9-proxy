# node9 with OpenCode

OpenCode is protected by a node9 plugin rather than hooks or MCP.

| Surface           | How node9 is wired                                                                                 | What it does                                |
| ----------------- | -------------------------------------------------------------------------------------------------- | ------------------------------------------- |
| Every tool call   | `tool.execute.before` in the node9 plugin under the OpenCode config directory (`plugins/node9.js`) | allow / review / block before the tool runs |
| Prompts           | `chat.message`                                                                                     | prompt secret scan                          |
| Every tool result | `tool.execute.after`                                                                               | audit record, and output redaction in place |

Because the plugin can mutate tool output, secrets in a result are redacted before the model
sees them. That is stronger than the observe-only agents.

## Set it up

```bash
node9 agents add opencode
```

`node9 init` does this for every agent it detects on the machine. Either command is safe to
re-run; it repairs a hook that an agent update removed and leaves everything else alone.

## What is not covered

- MCP servers are not wrapped for OpenCode; the plugin gates tool calls directly.
- Cost is not tracked for OpenCode.

## Verify it on this machine

```bash
node9 doctor                                   # is the hook (or MCP wrap) actually in place?
node9 explain Bash 'cat ~/.ssh/id_rsa'         # shows the verdict the live hook enforces: BLOCK
```

`node9 explain` prints the exact rule that fires and where the decision came from. If `doctor`
says the agent is not wired, the guard is not running, whatever the config looks like.
