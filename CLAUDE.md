# Node9 Proxy — Claude Code Rules

## PR Checklist (required before every commit)

Before committing or opening a PR, verify all of the following:

- [ ] New behavior has a test that **fails without the change**
- [ ] `npm test` passes (455+ tests)
- [ ] `npm run typecheck` passes
- [ ] `npm run lint` passes (catches `require()` imports, unused vars, etc.)
- [ ] `npm run format:check` passes (run `npm run format` to fix)
- [ ] No `console.log` in hook or proxy code paths — use `console.error` (stdout must stay clean for JSON-RPC / MCP)

## Test Rules

**Every bug fix must ship with a regression test.**
Write the failing test first, then fix the code. This proves you understood the bug and prevents silent regressions.

**Integration tests are required for:**

- Any command that runs as a subprocess (`check`, `log`, proxy)
- Anything that touches stdout/stderr (protocol correctness)
- Any file write (`audit.log`, `hook-debug.log`, snapshot)
- Any behavior that depends on `cwd` or `HOME`

Use `spawnSync` against `dist/cli.js` (see `src/__tests__/check.integration.test.ts` for the pattern).
Always assert `result.error` and `result.status` — a silent spawn failure must not pass tests.

**Unit tests with mocked `fs`/`getConfig` are not sufficient** for hook commands or the proxy.
They cannot catch protocol bugs, filesystem path bugs, or exit code bugs.

## Code Rules

**Audit writes must happen before config loads.**
In hook commands, `fs.appendFileSync(auditLog, ...)` must come before any `getConfig()` call. A config failure must never silently skip the audit entry.

**Validate external path inputs before filesystem use.**
Any `cwd`, `file_path`, or similar value from hook payloads must be validated (`path.isAbsolute()`) before being passed to `getConfig()`, `path.join()`, or `fs` calls. Use `payload.cwd || undefined` for empty-string guard, then `path.isAbsolute()` for traversal guard.

**No `process.chdir()` in hook commands.**
Pass `cwd` explicitly to `getConfig(cwd)` instead. `process.chdir` is process-global and races with concurrent hook invocations.

**No `getConfig()` inside catch blocks.**
If `getConfig()` caused the throw, calling it again re-throws and hides the real error. Use `process.env.NODE9_DEBUG` only, or log unconditionally to `hook-debug.log`.

**`|| undefined` not `?? undefined` for optional cwd.**
`??` only guards `null`/`undefined`. `||` also guards empty string `""` which `path.join` would silently treat as relative-to-cwd.

**Always write to `hook-debug.log` in catch blocks that guard audit trail.**
Do not gate on `NODE9_DEBUG`. Silent failures in the `log` command create audit gaps.

## Architecture Notes

- Shadow repo lives at `~/.node9/snapshots/<hash16>/` — never touch the user's `.git`
- `getConfig(cwd?)`: when `cwd` is provided, bypasses cache (per-project config, no cache pollution)
- `audit.log` is at `~/.node9/audit.log` — written by the `log` PostToolUse hook
- `hook-debug.log` is at `~/.node9/hook-debug.log` — written on errors, always (not gated on NODE9_DEBUG)
- DLP scan runs before ignored-tool fast path — a leaked credential is always caught
- `notMatchesGlob` is fail-closed: absent field returns `false`, not `true`
