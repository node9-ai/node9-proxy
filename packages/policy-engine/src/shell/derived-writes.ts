// packages/policy-engine/src/shell/derived-writes.ts
// Which files a shell command writes FROM which files it reads, pipeline by
// pipeline (node9Firewall#415 item 2, step 6 of #416). The PostToolUse hook
// uses it to carry a file's taint across a copy: `cp K X`, `mv K X`,
// `base64 < K > X`, `cat K | gzip > X`, `dd if=K of=X`, `tee X < K`,
// `install K X`. Every write target of a pipeline derives from every read
// source of the same pipeline; statements joined by `;`, `&&`, `||` or a
// newline are separate pipelines, so `cat K; echo hi > X` pairs nothing.
//
// The reads and writes themselves come from the engine's file-access
// listing (files/protected-access.ts), the same one the gate judges, so a
// spelling the gate reads (a redirect, dd's of=, a pipe) is a spelling this
// reads too.
import mvdanSh from 'mvdan-sh';
import { collectFileAccesses } from '../files/protected-access';
import type { FileAccessContext } from '../files/paths';
import { parseShared } from './index';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const { syntax } = mvdanSh as any;

/** mvdan's operator numbers for `&&` and `||`, read off the parser. */
const SEQUENCE_OPS: ReadonlySet<number> = (() => {
  const ops = new Set<number>();
  for (const text of ['x && y', 'x || y']) {
    try {
      const f = parseShared(text);
      if (typeof f !== 'symbol') ops.add(f.Stmts[0].Cmd.Op as number);
    } catch {
      /* the parser is the source of truth; without it nothing is a sequence */
    }
  }
  return ops;
})();

export interface DerivedWrite {
  /** The file read, as the command spells it. */
  source: string;
  /** The file written from it, as the command spells it. */
  target: string;
  /** The source is gone after the command (`mv`): its record moves rather than copies. */
  move: boolean;
}

/** UTF-8 byte offset to character index for `text`; identity for ASCII. */
function offsetMapper(text: string): (byteOffset: number) => number {
  // eslint-disable-next-line no-control-regex
  if (!/[^\u0000-\u007f]/.test(text)) return (b) => b;
  const starts: number[] = [];
  let bytes = 0;
  for (let i = 0; i < text.length; i++) {
    starts.push(bytes);
    const code = text.codePointAt(i) ?? 0;
    bytes += code < 0x80 ? 1 : code < 0x800 ? 2 : code < 0x10000 ? 3 : 4;
    if (code >= 0x10000) {
      i++;
      starts.push(-1);
    }
  }
  starts.push(bytes);
  return (b) => {
    const i = starts.indexOf(b);
    return i < 0 ? -1 : i;
  };
}

/** The text of each pipeline of the command: one `cmd | cmd` chain, or one simple command. */
export function pipelineTexts(command: string): string[] {
  const f = parseShared(command);
  if (typeof f === 'symbol') return [];
  const at = offsetMapper(command);
  const out: string[] = [];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const visit = (stmt: any, depth: number): void => {
    if (!stmt || depth > 64) return;
    const cmd = stmt.Cmd;
    if (cmd && syntax.NodeType(cmd) === 'BinaryCmd' && SEQUENCE_OPS.has(cmd.Op as number)) {
      visit(cmd.X, depth + 1);
      visit(cmd.Y, depth + 1);
      return;
    }
    const s = at(stmt.Pos().Offset());
    const e = at(stmt.End().Offset());
    // A statement's end includes its own `;` or `&`.
    const text = s >= 0 && e > s ? command.slice(s, e).replace(/[\s;&]+$/, '') : '';
    if (text) out.push(text);
  };
  try {
    for (const stmt of f.Stmts ?? []) visit(stmt, 0);
  } catch {
    return [];
  }
  return out;
}

/**
 * The (source, target) pairs of a command: every write of a pipeline is
 * derived from every read of the same pipeline. A listing (`ls`) and an
 * upload (`curl -F file=@K`) are not sources: nothing is written from them.
 */
export function derivedWrites(command: string, context: FileAccessContext = {}): DerivedWrite[] {
  const out: DerivedWrite[] = [];
  const seen = new Set<string>();
  for (const text of pipelineTexts(command)) {
    let accesses;
    try {
      accesses = collectFileAccesses('Bash', { command: text }, context);
    } catch {
      continue;
    }
    const sources: Array<{ path: string; move: boolean }> = [];
    const targets: string[] = [];
    for (const a of accesses) {
      if (a.listing || a.upload) continue;
      if (a.operation === 'read') sources.push({ path: a.path, move: false });
      else if (a.operation === 'remove') sources.push({ path: a.path, move: true });
      else if (a.operation === 'write' || a.operation === 'create') targets.push(a.path);
    }
    if (sources.length === 0 || targets.length === 0) continue;
    for (const target of targets) {
      for (const src of sources) {
        if (src.path === target) continue;
        const key = `${src.path}\u0000${target}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push({ source: src.path, target, move: src.move });
      }
    }
  }
  return out;
}
