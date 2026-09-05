# node9 with Gemini CLI

| Surface           | How node9 is wired                                    | What it does                                |
| ----------------- | ----------------------------------------------------- | ------------------------------------------- |
| Every tool call   | `BeforeTool` hook in `~/.gemini/settings.json`        | allow / review / block before the tool runs |
| Every tool result | `AfterTool` hook                                      | audit record                                |
| MCP servers       | `mcpServers` in `~/.gemini/settings.json` are wrapped | per-tool allow / review / block             |

## Set it up

```bash
node9 agents add gemini
```

`node9 init` does this for every agent it detects on the machine. Either command is safe to
re-run; it repairs a hook that an agent update removed and leaves everything else alone.

## What is not covered

- **No prompt scan.** Gemini CLI has no prompt-submit hook, so a secret pasted into the prompt
  is not caught until it shows up in a tool call.
- The session id Gemini sends drifts across resumes, so a review taint set before a resume can
  be orphaned. Within one session it works.
- Cost is not tracked for Gemini.

## Verify it on this machine

```bash
node9 doctor                                   # is the hook (or MCP wrap) actually in place?
node9 explain Bash 'cat ~/.ssh/id_rsa'         # shows the verdict the live hook enforces: BLOCK
```

`node9 explain` prints the exact rule that fires and where the decision came from. If `doctor`
says the agent is not wired, the guard is not running, whatever the config looks like.
