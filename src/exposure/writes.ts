// src/exposure/writes.ts
// Writes after the session read outside content (fw#318 P4, design 6).
//
// A write is how an injected instruction outlives the session: a line in
// ~/.bashrc, a step in .github/workflows, a postinstall script. After
// exposure, a write is held when it lands outside the project, on a file
// that runs code or instructs the agent, or carries a destination that
// appeared in the content read; an ordinary file inside the project is
// logged. Protected system files keep their own checks (d3801fc), which run
// before this gate. Like them, this gate is POSIX-only: on Windows the file
// accesses it judges are not prepared (prepareFileAccesses).
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  extractContentDestinations,
  isAgentInstructionPath,
  isInside,
  normalizeFilePath,
  type FileAccess,
} from '@node9/policy-engine';

export interface WriteHold {
  /** The path as judged (resolved when the host could). */
  path: string;
  why: 'outside-project' | 'agent-instruction' | 'content-destination';
  /** For content-destination: the destination found in the written content. */
  destination?: string;
}

const WRITE_OPS = new Set<FileAccess['operation']>(['write', 'create', 'remove']);
const LIFECYCLE_RE =
  /"(scripts|preinstall|install|postinstall|prepare|prepublish|prepublishOnly|prepack|postpack|publish|postpublish)"\s*:/;

/** The strings a write tool is about to put on disk. */
function writtenContent(args: unknown): string[] {
  if (!args || typeof args !== 'object' || Array.isArray(args)) return [];
  const a = args as Record<string, unknown>;
  const out: string[] = [];
  for (const k of ['content', 'new_string', 'new_str', 'file_text', 'contents']) {
    if (typeof a[k] === 'string') out.push(a[k] as string);
  }
  if (Array.isArray(a.edits)) {
    for (const e of a.edits) {
      if (
        e &&
        typeof e === 'object' &&
        typeof (e as Record<string, unknown>).new_string === 'string'
      )
        out.push((e as Record<string, unknown>).new_string as string);
    }
  }
  return out;
}

/** Does this edit or write of package.json touch its scripts? */
function packageScriptsTouched(
  args: unknown,
  absPath: string,
  shellCommand: string | null
): boolean {
  if (shellCommand !== null) return true; // a redirect or sed on package.json: unknowable, hold
  const a = (args ?? {}) as Record<string, unknown>;
  const texts = [
    ...writtenContent(args),
    ...(typeof a.old_string === 'string' ? [a.old_string as string] : []),
    ...(Array.isArray(a.edits)
      ? (a.edits as Array<Record<string, unknown>>).map((e) => String(e?.old_string ?? ''))
      : []),
  ];
  if (typeof a.content === 'string') {
    // A whole-file write: compare the scripts block with the file on disk.
    try {
      const next = JSON.parse(a.content as string) as { scripts?: unknown };
      const prev = JSON.parse(fs.readFileSync(absPath, 'utf8')) as { scripts?: unknown };
      return JSON.stringify(next.scripts ?? null) !== JSON.stringify(prev.scripts ?? null);
    } catch {
      return LIFECYCLE_RE.test(a.content as string);
    }
  }
  return texts.some((t) => LIFECYCLE_RE.test(t));
}

/**
 * Judge the writes of one call after exposure. `known` holds destinations
 * the session may send to; `inContent` the destinations read. Returns the
 * holds; an empty list means every write is logged.
 */
export function judgeWritesAfterExposure(opts: {
  accesses: readonly FileAccess[];
  args: unknown;
  shellCommand: string | null;
  cwd: string | undefined;
  inContent: ReadonlySet<string>;
  /** The one known-destination test the send rules use (org, typed, trusted, allowed). */
  isKnown: (dest: string) => boolean;
  home?: string;
}): WriteHold[] {
  const holds: WriteHold[] = [];
  const home = opts.home ?? os.homedir();
  const tmp = normalizeFilePath(os.tmpdir());
  const root = opts.cwd ? normalizeFilePath(opts.cwd, '', home) : null;
  const seen = new Set<string>();
  for (const access of opts.accesses) {
    if (!WRITE_OPS.has(access.operation)) continue;
    const p =
      access.candidates?.[0] ?? normalizeFilePath(access.path, access.cwd ?? opts.cwd ?? '', home);
    if (seen.has(p)) continue;
    seen.add(p);
    // Device files are not storage: `2>/dev/null`, `tee /dev/stderr`.
    if (p === '/dev' || p.startsWith('/dev/')) continue;
    // A protected system or startup file (d3801fc) was judged before this
    // gate: its review or block already holds the call, so no second reason.
    if (root !== null && isInside(root, p)) {
      if (
        isAgentInstructionPath(p, root) &&
        (path.basename(p) !== 'package.json' ||
          packageScriptsTouched(opts.args, p, opts.shellCommand))
      )
        holds.push({ path: p, why: 'agent-instruction' });
      continue;
    }
    // Scratch space is not the project but not persistence either. Only
    // when the project itself is elsewhere: a project under the temp dir (a
    // test, a throwaway clone) has no scratch space apart from itself.
    if (isInside(tmp, p) && !(root !== null && isInside(tmp, root))) continue;
    holds.push({ path: p, why: 'outside-project' });
  }
  // Content: a destination from the content read, written into a file inside
  // the project (a config, a script), is the same exfiltration one step later.
  const texts = opts.shellCommand !== null ? [opts.shellCommand] : writtenContent(opts.args);
  if (texts.length > 0 && opts.inContent.size > 0) {
    for (const d of extractContentDestinations(texts.join('\n'))) {
      if (opts.inContent.has(d) && !opts.isKnown(d)) {
        const target = [...seen][0] ?? '';
        if (!holds.some((h) => h.why === 'content-destination' && h.destination === d))
          holds.push({ path: target, why: 'content-destination', destination: d });
      }
    }
  }
  return holds;
}
