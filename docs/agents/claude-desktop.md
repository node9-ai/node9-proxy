# node9 with Claude Desktop

Claude Desktop only calls tools through MCP, so wrapping its servers covers every tool it
can use.

| Surface     | How node9 is wired                                                            | What it does                    |
| ----------- | ----------------------------------------------------------------------------- | ------------------------------- |
| MCP servers | entries in `claude_desktop_config.json` are wrapped through the node9 gateway | per-tool allow / review / block |

## Set it up

```bash
node9 agents add claudeDesktop
```

`node9 init` does this for every agent it detects on the machine. Either command is safe to
re-run; it repairs a hook that an agent update removed and leaves everything else alone.

## What is not covered

- No prompt scan and no cost tracking.
- `node9 doctor` and `node9 status` do not list Claude Desktop yet.

## Verify it on this machine

```bash
node9 doctor                                   # is the hook (or MCP wrap) actually in place?
node9 explain Bash 'cat ~/.ssh/id_rsa'         # shows the verdict the live hook enforces: BLOCK
```

`node9 explain` prints the exact rule that fires and where the decision came from. If `doctor`
says the agent is not wired, the guard is not running, whatever the config looks like.
