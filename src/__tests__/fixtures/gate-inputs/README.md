# gate-inputs — REAL captured agent payloads (do not hand-write)

Fixtures for `gate-contract.matrix.test.ts` (test-robustness-plan P0b).

Every file here was **captured from a live agent session** on a machine running
node9 (`~/.node9/hook-debug.log`, `STDIN:` lines), then sanitized — session ids,
usernames, and transcript file names are normalized; **the shape is untouched**.
That's the point: the app-permission gate once shipped dead to production while
unit tests passed on hand-written inputs the real caller never sends. A fixture
in this directory is evidence of what an agent ACTUALLY delivers to `node9 check`
on stdin.

| Fixture                | Agent       | Shape markers                                                                                                                                                     |
| ---------------------- | ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `claude-bash.json`     | Claude Code | `PreToolUse` + `transcript_path` under `.claude/` + `permission_mode`/`effort`                                                                                    |
| `claude-read.json`     | Claude Code | same envelope, `Read` tool (jail file-path surface)                                                                                                               |
| `claude-mcp-tool.json` | Claude Code | namespaced `mcp__server__tool` name (hook mode — the stdio GATEWAY forwards the BARE name instead; that path is covered by the app-permission gate tests)         |
| `gemini-shell.json`    | Gemini CLI  | `BeforeTool` + `timestamp` + transcript under `.gemini/`                                                                                                          |
| `codex-bash.json`      | Codex       | `PreToolUse` + `turn_id` + `model` + transcript under `.codex/sessions/` (note: real Codex payloads DO carry `transcript_path` — older design docs say otherwise) |

## Missing agents (visible todos in the matrix — capture, don't invent)

Copilot, Antigravity, and Hermes have no real capture on the source machine yet.
When one runs live with node9 wired, grab its payload:

```bash
grep "STDIN:" ~/.node9/hook-debug.log | tail -20   # find the new agent's line
```

Sanitize ids/usernames (see the existing fixtures for the convention), add the
file here, and move the agent from the `it.todo` rows into `MATRIX`.

## Rules

- **Never edit a fixture's shape** to make a test pass — the shape IS the test.
- **Never hand-write a new fixture.** If the gate needs a variant, mutate ONLY
  the tool arguments inside the test (see `toBlocked` in the matrix), keeping
  the captured envelope byte-identical.
