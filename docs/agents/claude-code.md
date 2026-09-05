# node9 with Claude Code

Claude Code is the most fully covered agent.

| Surface           | How node9 is wired                                                | What it does                                              |
| ----------------- | ----------------------------------------------------------------- | --------------------------------------------------------- |
| Every tool call   | `PreToolUse` hook in `~/.claude/settings.json`                    | allow / review / block before the tool runs               |
| Every tool result | `PostToolUse` hook                                                | writes the audit record                                   |
| Pasted prompts    | `UserPromptSubmit` hook                                           | secret pasted into the prompt is caught before it is sent |
| MCP servers       | entries in `~/.claude.json` are wrapped through the node9 gateway | per-tool allow / review / block                           |
| Cost              | reads `~/.claude/projects` session logs                           | per-project spend in `node9 report`                       |

The `PreToolUse` hook runs in every Claude Code permission mode, including
`--dangerously-skip-permissions`. That was verified with a standalone probe, and it is
undocumented behaviour, so treat it as a fact about today's Claude Code rather than a guarantee.

## Set it up

```bash
node9 agents add claude
```

`node9 init` does this for every agent it detects on the machine. Either command is safe to
re-run; it repairs a hook that an agent update removed and leaves everything else alone.

## What is not covered

- Tool **output** is observed, not gated. Claude Code's `PostToolUse` cannot suppress a
  result, so a secret or an injected instruction inside a tool result is recorded and the
  session is tainted for review on the next call; it is not stripped before Claude sees it.

## Verify it on this machine

```bash
node9 doctor                                   # is the hook (or MCP wrap) actually in place?
node9 explain Bash 'cat ~/.ssh/id_rsa'         # shows the verdict the live hook enforces: BLOCK
```

`node9 explain` prints the exact rule that fires and where the decision came from. If `doctor`
says the agent is not wired, the guard is not running, whatever the config looks like.
