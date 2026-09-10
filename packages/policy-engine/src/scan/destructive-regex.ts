// Regex-based detectors for destructive operations, privilege escalation,
// and sensitive-path reads. Used by the daemon watermark scanner today and
// reused by the upcoming canonical extractor (so the live daemon, the
// `--upload-history` backfill, and any other consumer share one source of
// truth instead of redefining the same patterns locally).
//
// Pure regex constants. No fs/path/os/process imports.

/**
 * Destructive-op regex. Word-boundary anchored so partial matches don't
 * fire (e.g. "term" inside "terminate" wouldn't match `\brm\b`). Each
 * pattern is independently provable as destructive — no fuzzy heuristics.
 */
export const DESTRUCTIVE_OP_RE =
  /\brm\s+-[rRf]+\b|\bDROP\s+(TABLE|DATABASE|COLLECTION|SCHEMA)\b|\bTRUNCATE\s+TABLE\b|\bgit\s+push\s+(--force|-f)\b|\bFLUSHALL\b|\bFLUSHDB\b|\bkubectl\s+delete\b|\bhelm\s+uninstall\b/i;

/**
 * Historical privilege-escalation regex. **No longer used by the canonical
 * detector** — scan/canonical.ts moved sudo/su, chmod, and chown all to
 * AST tokenization (analyzeShellCommand actions + allTokens) so:
 *   - Quoting bypasses (`s''udo`, `c\hmod`) don't slip past the matcher.
 *   - String literals like `echo "chmod 777 done"` or `cat /etc/sudoers`
 *     stop firing false positives — those don't put the action name in
 *     `actions`, only in `allTokens` (a Lit, not a CallExpr first-word).
 *
 * Kept as a public export for non-AST consumers that grep raw command
 * strings (smart-rule conditions that match on the literal command text)
 * and as documentation of the historical pattern set. Removing it would
 * be a breaking change for downstream package consumers.
 */
export const PRIVILEGE_ESCALATION_RE = /\bchmod\s+(0?777|\+x)\b|\bchown\s+root\b/i;

/**
 * Sensitive file paths the agent shouldn't be reading via tool calls.
 * Mirrors the blast walker's path set — same files matter, here detected
 * at tool-call-time rather than fs-walk-time.
 *
 * `\b` boundaries on names so substring noise doesn't trigger; the
 * patterns assume the proxy normalises ~ in inputs (which it does
 * via path expansion before we see them).
 */
// ⚠️ THE FIFTH CARRIER of the credential jail, and the one the 2026-09-10
// alignment first missed -- the design doc said four. This one feeds the
// canonical extractor (canonical.ts:411, gated to FILE_TOOLS), so it decides
// what the HISTORICAL scan reports, not what the live gate blocks.
//
// Two corrections, both measured:
//   `.ssh/(id_rsa|...)` named only four key filenames, so `Read ~/.ssh` (the
//   directory) and `~/.ssh/config` produced no finding at all -- the same
//   container-vs-contents bug fixed in the other carriers. Now uses the same
//   rooted anchor: a file inside matches anywhere, the directory itself only
//   when the path is rooted, so a search PATTERN is not read as a path.
//
//   `.env(\.|$|\b)` had no exemptions, so it reported `.env.example` and
//   `.env.test` as critical file reads while every other carrier allowed them.
//   Now carries the shared `.env` semantics verbatim.
//
// ⚠️ Known and NOT fixed here: canonical.ts:411 also feeds `args.pattern` into
// this regex, so `Grep {pattern: '.env'}` is reported as a file read of a
// secret. That is an input-contract bug in the caller, not in this pattern --
// see stage 5 of doc/credential-jail-architecture.md.
export const SENSITIVE_PATH_RE =
  /[\\/]\.aws(?:[\\/]|$)|^\.aws[\\/]|[\\/]\.ssh(?:[\\/]|$)|^\.ssh[\\/]|(?:^|[\\/])\.env(?![\w-])(?:[\w.-]*\.local$|(?!\.(?:example|sample|template)\b)(?!\.test$)[\w.-]*$)|\.config\/gcloud\/credentials\.db\b|\.docker\/config\.json\b|\.netrc\b|\.npmrc\b|\.node9\/credentials\.json\b/i;

/**
 * Tool names that read or grep file contents. Used to gate SENSITIVE_PATH_RE
 * to file-reading tools so the same path appearing in a Bash command doesn't
 * double-count against a Read of the same file.
 */
export const FILE_TOOLS = new Set<string>([
  'read',
  'read_file',
  'edit',
  'edit_file',
  'write',
  'write_file',
  'multiedit',
  'grep',
  'grep_search',
  'glob',
  'list_files',
]);
