# post-tool-inputs — REAL captured `PostToolUse` payloads (do not hand-write)

Same rules as `../gate-inputs/README.md`: every file was captured from a live
agent session (a logging-only `PostToolUse` hook), then sanitized — session
ids, usernames, paths and ids are normalized; **the shape is untouched**.

They exist because `node9 log` once read `tool_response.output`, a field no
agent sends: the response-channel scan (secrets, injection, session taint, the
warning to the model) was dead on Claude Code while tests on hand-written
`{ output }` payloads passed. A test that feeds one of these fixtures proves
the scan sees what the agent actually delivers.

| Fixture            | Agent               | `tool_response` shape                                                            |
| ------------------ | ------------------- | -------------------------------------------------------------------------------- |
| `claude-bash.json` | Claude Code 2.1.259 | `{ stdout, stderr, interrupted, isImage, noOutputExpected }`                     |
| `claude-read.json` | Claude Code 2.1.259 | `{ type: "text", file: { filePath, content, numLines, startLine, totalLines } }` |

## Missing (capture, don't invent)

Claude Code Grep, Glob, Write, Edit, WebFetch and an MCP tool; Codex; Gemini;
Hermes; Antigravity. To capture: a `PostToolUse` hook that appends its stdin to
a file, one short session, then sanitize as above. Tests mutate ONLY the text
leaves inside `tool_response`, keeping the captured envelope byte-identical.
