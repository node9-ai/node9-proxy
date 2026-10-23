// src/auth/session-script.ts
// A script the agent wrote in this session and then runs (`bash x.sh`,
// `./x.sh`, `source x.sh`) is judged from its content with the same checks
// as a typed command (fw#372 A3). Without this, every shell check could be
// stepped around by writing the command into a file first.
//
// Two halves. recordSessionWrites tells the daemon which files a call writes
// (the file tools' path, a shell command's write targets). resolveSessionScript
// asks, for a shell command that runs a script by path, whether the session
// wrote it, and reads the file as it is on disk now: that is what will run.
// Only a regular file of at most MAX_SCRIPT_BYTES is read. Every step fails
// open: no daemon, no record, an unreadable file, and the command is judged
// as it always was.
import fs from 'fs';
import os from 'os';
import path from 'path';
import { resolveShellInput, shellScriptOperands, type InspectionInput } from '@node9/policy-engine';
import { checkWritten, notifyWritten } from './daemon';
import { prepareFileAccesses, type PreparedFileAccess } from '../policy/file-access';

export const MAX_SCRIPT_BYTES = 64 * 1024;
const MAX_RECORDED_WRITES = 32;

export interface SessionScript {
  /** The script as the command named it. */
  path: string;
  /** Its absolute path on this machine. */
  resolved: string;
  /** The arguments the shell checks judge: the script's content as a command. */
  args: { command: string };
  fileAccess: PreparedFileAccess;
}

export interface SessionScriptDeps {
  checkWritten: typeof checkWritten;
  readScript: (resolved: string) => string | null;
}

/** The file's content when it is a regular file within the size cap, else null. */
export function readScriptFile(resolved: string): string | null {
  try {
    const st = fs.statSync(resolved);
    if (!st.isFile() || st.size > MAX_SCRIPT_BYTES) return null;
    return fs.readFileSync(resolved, 'utf8');
  } catch {
    return null;
  }
}

function absolute(p: string, cwd: string, home: string): string {
  const spelled = p === '~' || p.startsWith('~/') ? home + p.slice(1) : p;
  return path.resolve(cwd, spelled);
}

/**
 * The first script this shell command runs that the session wrote, with its
 * content prepared for the shell checks, or null.
 */
export async function resolveSessionScript(
  toolName: string,
  args: unknown,
  cwd: string | undefined,
  layers: InspectionInput,
  deps?: SessionScriptDeps,
  home = os.homedir()
): Promise<SessionScript | null> {
  try {
    // The daemon client is read here, not at module load: test suites that
    // replace that module wholesale must not break the import of this one.
    const d = deps ?? { checkWritten, readScript: readScriptFile };
    const shell = resolveShellInput(toolName, args, layers);
    if (shell.kind !== 'shell') return null;
    const operands = shellScriptOperands(shell.command);
    if (operands.length === 0) return null;
    const base = cwd ?? process.cwd();
    const byResolved = new Map<string, string>();
    for (const op of operands) byResolved.set(absolute(op, base, home), op);
    const { written } = await d.checkWritten([...byResolved.keys()]);
    for (const resolved of written) {
      const spelled = byResolved.get(resolved);
      if (spelled === undefined) continue;
      const content = d.readScript(resolved);
      if (content === null || content.trim() === '') continue;
      const scriptArgs = { command: content };
      return {
        path: spelled,
        resolved,
        args: scriptArgs,
        fileAccess: prepareFileAccesses('Bash', scriptArgs, base, layers, home),
      };
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * The files this call writes: a file tool's path, or a shell command's write
 * targets (redirects, tee, cp, sed -i, downloads) as the file policy already
 * resolved them. Recorded with the daemon before the call runs; a call that
 * is then denied leaves a record for a file that never changed, which costs
 * one read of that file if a script by that name is ever run.
 */
export function sessionWriteTargets(
  toolName: string,
  args: unknown,
  fileAccess: PreparedFileAccess | undefined,
  cwd: string | undefined,
  home = os.homedir()
): string[] {
  const base = cwd ?? process.cwd();
  const out = new Set<string>();
  const argsObj = args && typeof args === 'object' ? (args as Record<string, unknown>) : {};
  const named = argsObj.file_path ?? argsObj.path ?? argsObj.filename;
  if (typeof named === 'string' && named && /write|edit|create|save|append/i.test(toolName))
    out.add(absolute(named, base, home));
  for (const a of fileAccess?.accesses ?? []) {
    if (a.operation !== 'write' && a.operation !== 'create') continue;
    if (a.glob || a.recursive) continue; // a pattern names no one file
    out.add(absolute(a.path, a.cwd ?? base, home));
    if (out.size >= MAX_RECORDED_WRITES) break;
  }
  return [...out];
}

/** Fire-and-forget record of this call's writes. */
export async function recordSessionWrites(
  toolName: string,
  args: unknown,
  fileAccess: PreparedFileAccess | undefined,
  cwd: string | undefined
): Promise<void> {
  try {
    const targets = sessionWriteTargets(toolName, args, fileAccess, cwd);
    if (targets.length) await notifyWritten(targets);
  } catch {
    // Best-effort: the record is a convenience for a later run, never a gate.
  }
}
