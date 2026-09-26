// src/ci-check/lines.ts
// Where a finding points, as a 1-based line. DISPLAY ONLY: fingerprintOf() in diff.ts excludes
// `line`, so a finding keeps its identity when edits above it move it. A check that cannot
// place its finding leaves `line` undefined — the annotation then anchors at the file, which
// is honest; a wrong line is not.

/** 1-based line of a character index. */
export function lineAtIndex(content: string, index: number): number {
  let n = 1;
  for (let i = 0; i < index && i < content.length; i++) if (content.charCodeAt(i) === 10) n++;
  return n;
}

/** 1-based line of the first occurrence of `needle` at or after `from`, or undefined. */
export function lineOf(content: string, needle: string, from = 0): number | undefined {
  if (!needle) return undefined;
  const i = content.indexOf(needle, from);
  return i < 0 ? undefined : lineAtIndex(content, i);
}

/** 1-based line of the first regex match, or undefined. The regex must not be global. */
export function lineOfRe(content: string, re: RegExp): number | undefined {
  const m = re.exec(content);
  return m ? lineAtIndex(content, m.index) : undefined;
}

/** Index of a JSON string value as it appears in the source, whatever escaping the author
 *  used for it. Tries the canonical JSON escaping first, then the raw text. */
export function jsonValueIndex(content: string, value: string, from = 0): number {
  const escaped = JSON.stringify(value).slice(1, -1);
  const i = content.indexOf(escaped, from);
  return i >= 0 ? i : content.indexOf(value, from);
}

/** Only set `line` when it is known, so an unknown line stays absent rather than undefined. */
export function withLine<T extends object>(finding: T, line: number | undefined): T {
  return line ? { ...finding, line } : finding;
}
