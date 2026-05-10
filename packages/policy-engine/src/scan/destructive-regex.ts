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
export const SENSITIVE_PATH_RE =
  /\.aws\/(credentials|config)\b|\.ssh\/(id_rsa|id_ed25519|id_ecdsa|id_dsa)\b|\.env(\.|$|\b)|\.config\/gcloud\/credentials\.db\b|\.docker\/config\.json\b|\.netrc\b|\.npmrc\b|\.node9\/credentials\.json\b/i;

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
