// Control-character and terminal-escape sanitizers.
//
// node9's terminal output is the user's trust signal, and its tool names and
// previews are policy inputs, so stripping hostile control characters happens
// in a lot of places. Before this module there were NINE copies of three
// regexes spread across the proxy and the engine, each guarding one seam and
// kept in step only by comments. They are collected here so a fix reaches
// every caller at once.
//
// There are separate functions rather than one because the jobs genuinely
// differ, and flattening them corrupts output:
//
//   stripTerminalEscapes('alpha\nbeta\ttail') -> 'alpha\nbeta\ttail'
//   stripControlChars('alpha\nbeta\ttail')    -> 'alphabetatail'
//
// Pick by what the string is FOR, not by which is strictest.

/* eslint-disable no-control-regex */

/**
 * Full terminal escape sequences (CSI, OSC, Fe) plus C0 controls and DEL,
 * but NOT tab, newline or carriage return.
 *
 * For text that stays human-readable and whose whitespace a later
 * `.replace(/\s+/g, ' ')` normalizes: scan previews, project labels, anything
 * rendered as a line of prose. Removing the whitespace here instead of
 * collapsing it would run words together.
 *
 * Both the CLI's scan preview and the engine's `previewArgs` use this, and
 * they MUST agree: the preview feeds dedupe keys, so a drift between them
 * would make the same finding hash differently on the two paths. That is why
 * this lives in the engine and the CLI imports it rather than restating it.
 */
const TERMINAL_ESCAPE_RE =
  /\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-_]|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g;

/**
 * Every C0 control and DEL, whitespace included.
 *
 * For values that must be a single opaque token: tool names on their way into
 * policy evaluation and the audit record. A tool name containing a newline is
 * not a tool name, and letting one through would let a single call write two
 * audit lines.
 */
const CONTROL_CHAR_RE = /[\x00-\x1F\x7F]/g;

/* eslint-enable no-control-regex */

/** See TERMINAL_ESCAPE_RE. Keeps tab, newline and carriage return. */
export function stripTerminalEscapes(s: string): string {
  return s.replace(TERMINAL_ESCAPE_RE, '');
}

/** See CONTROL_CHAR_RE. Removes every C0 control and DEL, whitespace included. */
export function stripControlChars(s: string): string {
  return s.replace(CONTROL_CHAR_RE, '');
}

/**
 * One safe line, for any string that came from outside this process before it
 * reaches a terminal or a log file.
 *
 * node9's terminal output IS the user's trust signal: a "connected and
 * governed" line is what tells someone the machine is protected. A response
 * field carrying CR plus SGR codes can paint a line that looks exactly like
 * one of ours, and a newline in a value written to hook-debug.log forges a
 * second journal entry. So: escape sequences removed, all whitespace collapsed
 * to single spaces (one value can never become two lines), and a length cap so
 * a hostile or broken peer cannot flood the log.
 *
 * Accepts unknown because most call sites hold a caught `error` or an optional
 * response field.
 */
export function safeMessage(value: unknown, max = 300): string {
  const raw =
    typeof value === 'string'
      ? value
      : value instanceof Error
        ? value.message
        : String(value ?? '');
  const s = stripTerminalEscapes(raw).replace(/\s+/g, ' ').trim();
  return s.length > max ? s.slice(0, max - 1) + '\u2026' : s;
}
