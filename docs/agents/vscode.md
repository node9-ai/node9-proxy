# node9 with VS Code (Copilot extension)

The VS Code Copilot extension exposes no hook, so node9 wraps its MCP servers only. This is
a different integration from the Copilot **CLI**, which has full hooks; see
[copilot-cli.md](copilot-cli.md).

| Surface     | How node9 is wired                                                 | What it does                    |
| ----------- | ------------------------------------------------------------------ | ------------------------------- |
| MCP servers | VS Code's MCP config entries are wrapped through the node9 gateway | per-tool allow / review / block |

## Set it up

```bash
node9 agents add vscode
```

`node9 init` does this for every agent it detects on the machine. Either command is safe to
re-run; it repairs a hook that an agent update removed and leaves everything else alone.

## What is not covered

- The editor's own terminal and edits are not gated.
- `node9 doctor` and `node9 status` do not list VS Code yet.

## Verify it on this machine

```bash
node9 doctor                                   # is the hook (or MCP wrap) actually in place?
node9 explain Bash 'cat ~/.ssh/id_rsa'         # shows the verdict the live hook enforces: BLOCK
```

`node9 explain` prints the exact rule that fires and where the decision came from. If `doctor`
says the agent is not wired, the guard is not running, whatever the config looks like.
