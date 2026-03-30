// src/utils/cp-mv-parser.ts
// Extracts cp/mv source→destination pairs from a bash command string so the
// PostToolUse hook can propagate taint after the command completes.
//
// Scope: simple two-argument cp/mv with optional flag clusters.
// Out of scope (safe to miss — taint stays on the source):
//   - glob expansion:     cp *.txt /dest/
//   - multi-source:       cp a b c /dest/
//   - destination-first:  cp -t /dest src
//   - heredoc / process substitution
//   - shell metacharacters in paths: $VAR, $(cmd), `cmd`, {a,b}, trailing ; — returns null

export interface CpMvOp {
  src: string;
  dest: string;
  /** true for mv (source taint is cleared); false for cp (source stays tainted) */
  clearSource: boolean;
}

/**
 * Parse a bash command string for a cp or mv operation.
 * Returns null if the command is not cp/mv, uses unsupported flags, or the
 * paths cannot be reliably extracted.
 */
export function parseCpMvOp(command: string): CpMvOp | null {
  const trimmed = command.trim();

  // Tokenise on whitespace (does not handle quoted paths with spaces — those are
  // rare in AI-generated bash and adding a full shell parser is out of scope).
  const tokens = trimmed.split(/\s+/);
  if (tokens.length < 3) return null;

  const [cmd, ...rest] = tokens;
  const base = cmd.split('/').pop() ?? cmd; // strip leading path (e.g. /bin/cp)

  if (base !== 'cp' && base !== 'mv') return null;

  // Consume flag tokens (strings starting with '-').
  // Bail out on -t / --target-directory (destination-first semantics — can't
  // safely determine which arg is src vs dest without a full parser).
  const args: string[] = [];
  for (const tok of rest) {
    if (tok === '--') {
      // End-of-options marker — everything after is a positional arg.
      args.push(...rest.slice(rest.indexOf('--') + 1));
      break;
    }
    if (tok === '-t' || tok === '--target-directory') return null;
    if (tok.startsWith('--target-directory=')) return null;
    if (tok.startsWith('-') && !tok.startsWith('--')) {
      // Short flag cluster — bail if it contains 't' (same as -t above).
      if (tok.includes('t')) return null;
      continue; // skip recognised flag cluster (e.g. -rp, -rf)
    }
    if (tok.startsWith('--')) {
      // Unknown long flag — skip it (conservative: don't bail, don't treat as path)
      continue;
    }
    args.push(tok);
  }

  // After flags we need exactly two positional args: src and dest.
  // If there are more than two, it's a multi-source invocation — bail out safely.
  if (args.length !== 2) return null;

  const [src, dest] = args;
  if (!src || !dest) return null;

  // Bail out if either path contains shell metacharacters that would require
  // shell expansion to resolve. Without expansion we'd propagate taint to a
  // literal string like '$HOME/.ssh/authorized_keys' that doesn't exist as a
  // file — producing a silent false negative (the real expanded path stays clean).
  // Better to bail and leave taint on the source than to propagate to the wrong path.
  if (containsShellMetachar(src) || containsShellMetachar(dest)) return null;

  return { src, dest, clearSource: base === 'mv' };
}

/** Returns true if the token contains shell metacharacters that require expansion. */
function containsShellMetachar(token: string): boolean {
  // $VAR / ${VAR} / $(cmd) / `cmd` / {a,b} brace expansion / trailing ; command separator
  // Semicolon matters because `cp /tmp/a /tmp/b;` (no space before ;) produces a
  // single token '/tmp/b;' — the real dest is '/tmp/b' but we'd taint '/tmp/b;'
  // (non-existent) and miss the real path. Bail out; taint stays on the source.
  return /[$`{;]/.test(token);
}
