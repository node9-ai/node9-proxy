// src/mcp-cmd.ts
// ONE shell-style tokenizer + arg-quoter for the MCP gateway wrap path, shared by
// the config side (mcp-wrap: toGateway/fromGateway) AND the runtime spawn side
// (mcp-gateway: tokenize the --upstream string to spawn the child). Single source
// so the two can never drift — a mismatch would mean a wrapped server launches
// with different args than the config round-trips to.

/** Split a command line, honouring double-quotes + backslash escapes. */
export function tokenize(cmd: string): string[] {
  const tokens: string[] = [];
  let current = '';
  let inDouble = false;
  let quoted = false; // this token had an explicit quote → keep it even if empty
  let i = 0;
  while (i < cmd.length) {
    const ch = cmd[i];
    if (inDouble) {
      if (ch === '"') inDouble = false;
      else if (ch === '\\' && i + 1 < cmd.length) current += cmd[++i];
      else current += ch;
    } else if (ch === '"') {
      inDouble = true;
      quoted = true;
    } else if (ch === ' ' || ch === '\t') {
      if (current || quoted) {
        tokens.push(current);
        current = '';
        quoted = false;
      }
    } else if (ch === '\\' && i + 1 < cmd.length) {
      current += cmd[++i];
    } else {
      current += ch;
    }
    i++;
  }
  // Emit a trailing quoted-empty token ONLY if the quote was properly closed — an
  // unterminated quote (`serve "`) is malformed and must not yield a spurious ''.
  if (current || (quoted && !inDouble)) tokens.push(current);
  return tokens;
}

/** Quote a single arg so tokenize() reverses it exactly (incl. the empty string). */
export function quoteArg(s: string): string {
  if (s === '') return '""';
  if (/[\s"\\]/.test(s)) return `"${s.replace(/(["\\])/g, '\\$1')}"`;
  return s;
}
