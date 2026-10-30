// The strings a file tool is about to put on disk, by the argument names the
// tools use: a whole file (Write, create) or the new text of an edit (Edit,
// MultiEdit, str_replace). Shared by the hook-file and agent-file checks.
export function writtenTexts(args: unknown): { whole: string[]; edits: string[] } {
  const whole: string[] = [];
  const edits: string[] = [];
  if (!args || typeof args !== 'object') return { whole, edits };
  const a = args as Record<string, unknown>;
  for (const k of ['content', 'contents', 'file_text']) {
    if (typeof a[k] === 'string') whole.push(a[k] as string);
  }
  for (const k of ['new_string', 'new_str']) {
    if (typeof a[k] === 'string') edits.push(a[k] as string);
  }
  if (Array.isArray(a.edits)) {
    for (const e of a.edits) {
      if (
        e &&
        typeof e === 'object' &&
        typeof (e as Record<string, unknown>).new_string === 'string'
      )
        edits.push((e as Record<string, unknown>).new_string as string);
    }
  }
  return { whole, edits };
}
