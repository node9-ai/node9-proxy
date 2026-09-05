# node9 with Hermes Agent

| Surface           | How node9 is wired                                     | What it does                                |
| ----------------- | ------------------------------------------------------ | ------------------------------------------- |
| Every tool call   | `pre_tool_call` command hook in the Hermes YAML config | allow / review / block before the tool runs |
| Every tool result | `post_tool_call` command hook                          | audit record                                |

Run `node9 status` to see the exact config path on your machine.

## Set it up

```bash
node9 agents add hermes
```

`node9 init` does this for every agent it detects on the machine. Either command is safe to
re-run; it repairs a hook that an agent update removed and leaves everything else alone.

## What is not covered

- **No prompt scan.** Hermes has no prompt event.
- **No MCP wrapping.** Hermes' MCP servers are not routed through the node9 gateway.
- Hermes sends an empty session id on the pre-tool hook, so the output-taint review gate
  does not work for Hermes. Upstream issue: NousResearch/hermes-agent#48311.
- Cost is not tracked for Hermes.

## Verify it on this machine

```bash
node9 doctor                                   # is the hook (or MCP wrap) actually in place?
node9 explain Bash 'cat ~/.ssh/id_rsa'         # shows the verdict the live hook enforces: BLOCK
```

`node9 explain` prints the exact rule that fires and where the decision came from. If `doctor`
says the agent is not wired, the guard is not running, whatever the config looks like.
