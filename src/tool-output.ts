// src/tool-output.ts
// The text a tool returned, read from whatever shape the agent sent.
//
// Each agent and each tool has its own `tool_response` shape: Claude Code's
// Bash sends `{ stdout, stderr, ... }`, its Read sends `{ file: { content } }`,
// an MCP result sends `content[].text`, the OpenCode and Pi shims send
// `{ output }`, Codex declares the field as any JSON. The response-channel
// scan used to read one field (`output`) and so saw nothing on Claude Code.
//
// This walks every string leaf instead. No per-tool table: a tool whose shape
// was never captured is still scanned, and a new field is never missed. The
// cost is a few bytes of non-text noise (a file path, a type tag) the scanners
// ignore.
import { DLP_SCAN_LIMITS } from './dlp';

export interface ToolOutputText {
  /** Every string leaf, in document order, joined with newlines. */
  text: string;
  /** True when the bound cut the walk short: the scan is partial, not clean. */
  truncated: boolean;
  /** How many string leaves contributed at least one character. */
  fields: number;
}

const MAX_DEPTH = 8;

export function collectToolOutputText(
  toolResponse: unknown,
  opts: { maxBytes?: number } = {}
): ToolOutputText {
  const maxBytes = opts.maxBytes ?? DLP_SCAN_LIMITS.maxStringBytes;
  const parts: string[] = [];
  let size = 0;
  let fields = 0;
  let truncated = false;

  const push = (s: string): boolean => {
    if (s.length === 0) return true;
    const room = maxBytes - size;
    if (s.length > room) {
      if (room > 0) {
        parts.push(s.slice(0, room));
        fields++;
      }
      size = maxBytes;
      truncated = true;
      return false;
    }
    parts.push(s);
    fields++;
    size += s.length + 1;
    return true;
  };

  const walk = (v: unknown, depth: number): boolean => {
    if (typeof v === 'string') return push(v);
    if (depth >= MAX_DEPTH || v === null || typeof v !== 'object') return true;
    const children = Array.isArray(v) ? v : Object.values(v as Record<string, unknown>);
    for (const child of children) if (!walk(child, depth + 1)) return false;
    return true;
  };

  walk(toolResponse, 0);
  return { text: parts.join('\n'), truncated, fields };
}

/**
 * The streams a shell tool produced, for test-result detection: Claude Code's
 * Bash sends `stdout` and `stderr`; any other shape falls back to every leaf.
 */
export function shellOutputText(toolResponse: unknown): string {
  if (toolResponse && typeof toolResponse === 'object' && !Array.isArray(toolResponse)) {
    const r = toolResponse as Record<string, unknown>;
    if (typeof r.stdout === 'string' || typeof r.stderr === 'string') {
      return [r.stdout, r.stderr].filter((s): s is string => typeof s === 'string').join('\n');
    }
  }
  return collectToolOutputText(toolResponse).text;
}

/**
 * A copy of `toolResponse` with the same keys, order, arrays and nesting, and
 * every string leaf replaced by `fn(leaf)`. Non-string leaves are copied as
 * they are; a leaf past the depth cap is copied unchanged.
 *
 * This is what Claude Code's `updatedToolOutput` needs: it applies a
 * replacement only when it restates the tool's own `tool_response` shape.
 * Anything else is dropped and the original delivered; no signal reaches the
 * hook (Claude Code logs "does not match <tool>'s output shape; using original
 * output" on its side; verified on 2.1.259, where a bare string for Bash was
 * not applied). So the shape is never rebuilt, only mapped.
 */
export function mapToolOutputStrings(toolResponse: unknown, fn: (s: string) => string): unknown {
  const walk = (v: unknown, depth: number): unknown => {
    if (typeof v === 'string') return fn(v);
    if (depth >= MAX_DEPTH || v === null || typeof v !== 'object') return v;
    if (Array.isArray(v)) return v.map((x) => walk(x, depth + 1));
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) out[k] = walk(x, depth + 1);
    return out;
  };
  return walk(toolResponse, 0);
}

/**
 * Frame the leaves of a tool result that carry an injected instruction.
 *
 * Mode A wraps the one text it holds. A shaped result has many leaves, and
 * some are not content at all (Read's `type: "text"`, a file path) — framing
 * those would change fields Claude Code reads. So only the leaves `isSuspect`
 * picks are framed, each with its own header and footer; when no single leaf
 * qualifies (the signals only add up across leaves), the largest leaf is
 * framed, which is the content in every shape captured so far. Markers that
 * imitate a node9 frame are neutralised in every leaf.
 */
export function frameToolOutputLeaves(
  toolResponse: unknown,
  isSuspect: (leaf: string) => boolean,
  frame: () => { header: string; footer: string },
  neutralize: (s: string) => string
): unknown {
  // First pass: judge each leaf once (the injection scan is the costly part)
  // and remember the largest; leaves are visited in the same order both times.
  const suspect: boolean[] = [];
  let largestAt = -1;
  let largestLen = 0;
  mapToolOutputStrings(toolResponse, (s) => {
    const i = suspect.length;
    suspect.push(s.length > 0 && isSuspect(s));
    if (s.length > largestLen) {
      largestLen = s.length;
      largestAt = i;
    }
    return s;
  });
  const anySuspect = suspect.some(Boolean);
  let i = 0;
  return mapToolOutputStrings(toolResponse, (s) => {
    const at = i++;
    const pick = anySuspect ? suspect[at] : at === largestAt;
    if (!pick) return neutralize(s);
    const f = frame();
    return `${f.header}\n${neutralize(s)}\n${f.footer}`;
  });
}
