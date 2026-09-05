# node9 with Pi

Pi is protected by a node9 extension rather than hooks or MCP.

| Surface                           | How node9 is wired                               | What it does                                |
| --------------------------------- | ------------------------------------------------ | ------------------------------------------- |
| Every tool call                   | `tool_call` in `~/.pi/agent/extensions/node9.js` | allow / review / block before the tool runs |
| Prompts                           | `input`                                          | prompt secret scan                          |
| The `!` / `!!` shell side channel | `user_bash`                                      | gated like any other command                |
| Every tool result                 | `tool_result`                                    | audit record, and output redaction in place |

## Set it up

```bash
node9 agents add pi
```

`node9 init` does this for every agent it detects on the machine. Either command is safe to
re-run; it repairs a hook that an agent update removed and leaves everything else alone.

## What is not covered

- MCP servers are not wrapped for Pi.
- Cost is not tracked for Pi.

## Verify it on this machine

```bash
node9 doctor                                   # is the hook (or MCP wrap) actually in place?
node9 explain Bash 'cat ~/.ssh/id_rsa'         # shows the verdict the live hook enforces: BLOCK
```

`node9 explain` prints the exact rule that fires and where the decision came from. If `doctor`
says the agent is not wired, the guard is not running, whatever the config looks like.
