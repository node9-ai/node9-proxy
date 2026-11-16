// src/ci-check/startup.ts
// fw#481 A9: start-up triggers committed to a repository. A Claude Code hook in a committed
// settings file and a VS Code task with `runOn: "folderOpen"` run a command the moment the
// repository is opened. The Shai-Hulud-family worm commits both, wired to a loader inside
// `.claude/` or `.vscode/` that downloads Bun and runs the payload next to itself.
//
// A start-up hook that runs a repository script is common and legitimate (38 of 775 clones), so
// nothing here alerts on a trigger alone. The worm's own markers match nothing legitimate in the
// same clones: a task cross-wired into `.claude/` (or a hook into `.vscode/`), and the Bun
// bootstrap. The scripts are hashed and matched as text; nothing is ever run or evaluated.
// Design: docs roadmap/active/scanner-a9-worm-startup-design.md.

import crypto from 'crypto';
import path from 'path';
import type { CiFinding } from './types';
import { hookScriptPath, hookCommandsOf, type TreeListing } from './agent-config';
import { lineAtIndex } from './lines';
import { SCRIPT_EXT_RE } from './instructions';

/** sha256 of the loader families read on 2026-11-16 (5,346 / 5,456 / 11,017 bytes). Data only. */
export const KNOWN_LOADER_SHA256: ReadonlySet<string> = new Set([
  '2be36c46d3f421bbd89bcb94997afb85020a672d82b64114637741411d7fc919',
  '6cb3fc3650355973b8a1ed86619a3f412fb0700f29c1c3a736cada4c2c76a9f7',
  'fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb',
]);

/** Loaders are 5-11 KB; anything larger is not judged by content (the payload is ~500 KB). */
export const MAX_LOADER_BYTES = 64 * 1024;

/** A script directly inside a `.claude/` or `.vscode/` folder (not in a subfolder): where the
 *  worm puts its loader. 11 such files in 775 clones, so reading them is cheap. */
export function isStartupScript(p: string): boolean {
  return /(^|\/)\.(claude|vscode)\/[^/]+$/.test(p) && SCRIPT_EXT_RE.test(p);
}

/** `.vscode/tasks.json`, at any depth (VS Code reads the one in the folder it opens). */
export const VSCODE_TASKS_RE = /(^|\/)\.vscode\/tasks\.json$/;

// The Bun bootstrap: it downloads Bun from the official release page, finds its own folder and
// runs a file there. All three markers, never one: a plain release download is common in
// legitimate setup scripts (8 of 3,329 agent-folder scripts in the clones).
const BUN_DOWNLOAD_RE = /oven-sh\/bun\/releases\/download/;
const OWN_DIR_RE = /import\.meta\.url|__dirname/;
const EXEC_RE = /\b(execFileSync|execSync|spawnSync|execFile|spawn)\b/;

export interface LoaderMatch {
  how: 'hash' | 'markers';
}

/** Whether a script is a worm loader: a known hash, or all three Bun-bootstrap markers. */
export function isWormLoader(
  content: string,
  known: ReadonlySet<string> = KNOWN_LOADER_SHA256
): LoaderMatch | null {
  const sha = crypto.createHash('sha256').update(content, 'utf8').digest('hex');
  if (known.has(sha)) return { how: 'hash' };
  if (BUN_DOWNLOAD_RE.test(content) && OWN_DIR_RE.test(content) && EXEC_RE.test(content))
    return { how: 'markers' };
  return null;
}

/** What scanTree learned about one start-up script it read. */
export interface StartupScriptInfo {
  /** null when the file was over MAX_LOADER_BYTES: present, not judged. */
  match: LoaderMatch | null | undefined;
}

export function inspectStartupScript(content: string): StartupScriptInfo {
  if (Buffer.byteLength(content, 'utf8') > MAX_LOADER_BYTES) return { match: undefined };
  return { match: isWormLoader(content) };
}

interface Trigger {
  kind: 'claude-hook' | 'vscode-task';
  file: string;
  line?: number;
  command: string;
  /** Repo-relative script the trigger runs, or null when it names none. */
  script: string | null;
  label?: string;
}

/** Strip `//` and `/* *\/` comments outside strings, and trailing commas: tasks.json is JSONC. */
export function stripJsonc(text: string): string {
  let out = '';
  let i = 0;
  let inStr = false;
  while (i < text.length) {
    const c = text[i];
    if (inStr) {
      out += c;
      if (c === '\\' && i + 1 < text.length) {
        out += text[i + 1];
        i += 2;
        continue;
      }
      if (c === '"') inStr = false;
      i++;
      continue;
    }
    if (c === '"') {
      inStr = true;
      out += c;
      i++;
    } else if (c === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i++;
    } else if (c === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      // Keep newlines so line numbers still point at the right place.
      const chunk = end < 0 ? text.slice(i) : text.slice(i, end + 2);
      out += chunk.replace(/[^\n]/g, ' ');
      i += chunk.length;
    } else {
      out += c;
      i++;
    }
  }
  // Trailing commas: a comma followed only by whitespace before a closing bracket.
  return out.replace(/,(\s*[}\]])/g, ' $1');
}

const asString = (v: unknown): string | null => (typeof v === 'string' ? v : null);

/** The shell line a task runs: `command` plus `args`, from the platform blocks too. */
function taskCommands(t: Record<string, unknown>): string[] {
  const out: string[] = [];
  for (const block of [t, t.linux, t.osx, t.windows]) {
    if (!block || typeof block !== 'object') continue;
    const b = block as Record<string, unknown>;
    const cmd = asString(b.command);
    if (!cmd) continue;
    const args = Array.isArray(b.args)
      ? b.args.map((a) => asString(a) ?? asString((a as { value?: unknown })?.value) ?? '')
      : [];
    out.push([cmd, ...args].filter(Boolean).join(' '));
  }
  return out;
}

/** Folder that holds the `.vscode/` (or `.claude/`) a file sits in: the workspace root. */
const workspaceOf = (file: string): string => {
  const parts = file.split('/');
  return parts.slice(0, Math.max(0, parts.length - 2)).join('/');
};

function lineOf(content: string, needle: string): number | undefined {
  const i = content.indexOf(needle);
  return i >= 0 ? lineAtIndex(content, i) : undefined;
}

/** Line of a task's `folderOpen`, searched after its label so two tasks get their own lines. */
function taskLine(content: string, label: string | undefined): number | undefined {
  const from = label ? Math.max(0, content.indexOf(JSON.stringify(label).slice(1, -1))) : 0;
  const i = content.indexOf('folderOpen', from);
  return i >= 0 ? lineAtIndex(content, i) : lineOf(content, 'folderOpen');
}

/** folderOpen tasks in a `.vscode/tasks.json`. Unparseable JSONC yields none. */
export function vscodeTaskTriggers(file: string, content: string): Trigger[] {
  let doc: { tasks?: unknown };
  try {
    doc = JSON.parse(stripJsonc(content)) as { tasks?: unknown };
  } catch {
    return [];
  }
  const root = workspaceOf(file);
  const out: Trigger[] = [];
  for (const t of Array.isArray(doc?.tasks) ? doc.tasks : []) {
    if (!t || typeof t !== 'object') continue;
    const task = t as Record<string, unknown>;
    const runOn = (task.runOptions as { runOn?: unknown } | undefined)?.runOn;
    if (runOn !== 'folderOpen') continue;
    const label = asString(task.label) ?? undefined;
    const cmds = taskCommands(task);
    const dependsOn = Array.isArray(task.dependsOn)
      ? task.dependsOn.filter((d): d is string => typeof d === 'string')
      : typeof task.dependsOn === 'string'
        ? [task.dependsOn]
        : [];
    if (!cmds.length) cmds.push(dependsOn.length ? `(runs tasks: ${dependsOn.join(', ')})` : '');
    for (const command of cmds) {
      const rel = hookScriptPath(command.replace(/\$\{workspaceFolder\}\//g, ''));
      const script = rel ? path.posix.join(root || '.', rel).replace(/^\.\//, '') : null;
      out.push({
        kind: 'vscode-task',
        file,
        line: taskLine(content, label),
        command,
        script,
        label,
      });
    }
  }
  return out;
}

/** Hook commands in a committed Claude settings file. */
export function claudeHookTriggers(file: string, content: string): Trigger[] {
  let cfg: { hooks?: Record<string, unknown[]> };
  try {
    cfg = JSON.parse(content) as { hooks?: Record<string, unknown[]> };
  } catch {
    return [];
  }
  return hookCommandsOf(cfg.hooks).map((command) => ({
    kind: 'claude-hook' as const,
    file,
    line: lineOf(content, JSON.stringify(command).slice(1, -1)),
    command,
    script: hookScriptPath(command),
  }));
}

const inFolder = (p: string, folder: '.claude' | '.vscode') =>
  new RegExp(`(^|/)\\${folder}/`).test(p);

const safe = (t: string, n: number) => t.replace(/[`\u0000-\u001f\u007f]+/g, ' ').slice(0, n); // eslint-disable-line no-control-regex

const WORM_FIX =
  'Delete the trigger, the task and the loader files (`.claude/setup.mjs`, `.vscode/setup.mjs` and the payload next to them) in one commit. Treat every machine that opened this repository in Claude Code or VS Code since the files landed as exposed: rotate the npm, GitHub and cloud tokens on it. Then check how the commit landed (`git log` on these files): a bot-authored commit means a CI token was stolen; rotate it.';

/** The A9 findings for one scan, from the triggers and the start-up scripts scanTree read. */
export function analyzeStartup(
  triggers: Trigger[],
  scripts: ReadonlyMap<string, StartupScriptInfo>,
  listing?: TreeListing
): CiFinding[] {
  const findings: CiFinding[] = [];
  const triggered = new Set<string>();
  const seen = new Set<string>();
  for (const t of triggers) {
    if (t.script) triggered.add(t.script);
    const key = `${t.file}\u0000${t.script ?? t.command}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const crossWired =
      !!t.script &&
      ((t.kind === 'vscode-task' && inFolder(t.script, '.claude')) ||
        (t.kind === 'claude-hook' && inFolder(t.script, '.vscode')));
    const info = t.script ? scripts.get(t.script) : undefined;
    const match = info?.match ?? null;
    const where =
      t.kind === 'vscode-task'
        ? `VS Code task${t.label ? ` "${safe(t.label, 60)}"` : ''} runs on folder open: \`${safe(t.command, 120)}\``
        : `Claude Code hook runs by itself in every session: \`${safe(t.command, 120)}\``;
    if (match || crossWired) {
      const signals = [where];
      if (match?.how === 'hash')
        signals.push(
          `\`${safe(t.script!, 200)}\` is a known worm loader (Shai-Hulud family, exact hash match)`
        );
      else if (match?.how === 'markers')
        signals.push(
          `\`${safe(t.script!, 200)}\` downloads Bun from the oven-sh release page and runs a file next to itself: the Shai-Hulud loader shape`
        );
      if (crossWired)
        signals.push(
          t.kind === 'vscode-task'
            ? 'a VS Code task runs a script from the `.claude/` folder: the worm wires the two together; nothing legitimate in 775 scanned repositories does this'
            : 'a Claude Code hook runs a script from the `.vscode/` folder: the worm wires the two together; nothing legitimate in 775 scanned repositories does this'
        );
      if (!match && t.script) {
        const absent = listing?.complete && !listing.paths.has(t.script);
        signals.push(
          absent
            ? `\`${safe(t.script, 200)}\` is not committed (the loader may have been deleted and the trigger left behind)`
            : `\`${safe(t.script, 200)}\` was not matched against the known loaders (not read, or too large)`
        );
      }
      findings.push({
        check: 'CI-1',
        rule: 'CI-1.worm-startup',
        locator: t.script ?? t.command,
        dimension: 'files',
        severity: match ? 'critical' : 'high',
        title: match
          ? 'Worm start-up hook: opening this repository runs a known malware loader'
          : 'Start-up trigger wired like the Shai-Hulud worm',
        file: t.file,
        ...(t.line ? { line: t.line } : {}),
        signals,
        fix: WORM_FIX,
      });
    } else if (t.kind === 'vscode-task') {
      findings.push({
        check: 'CI-1',
        rule: 'CI-1.folder-open-task',
        locator: t.label ?? t.command,
        dimension: 'files',
        severity: 'advisory',
        title: 'VS Code task runs when the folder is opened',
        file: t.file,
        ...(t.line ? { line: t.line } : {}),
        signals: [where, 'VS Code runs it after the workspace is trusted, before anyone reads it'],
        fix: 'Make sure the task only builds or watches; remove `runOn: "folderOpen"` if it does not need to start by itself.',
      });
    }
  }
  // Q2: a loader nothing runs. Inert on its own, but it is malware in the tree. When a trigger
  // already alerts, an untriggered copy (the worm commits the loader twice) is named on that
  // finding instead of being a second one.
  const untriggered = [...scripts].filter(([p, info]) => info.match && !triggered.has(p));
  const startup = findings.filter((f) => f.rule === 'CI-1.worm-startup');
  if (startup.length) {
    for (const [p] of untriggered)
      startup[0].signals.push(`another copy of the loader is committed at \`${safe(p, 200)}\``);
    return findings;
  }
  for (const [p, info] of untriggered) {
    if (!info.match) continue;
    findings.push({
      check: 'CI-1',
      rule: 'CI-1.worm-loader',
      locator: p,
      dimension: 'files',
      severity: 'medium',
      title: 'Known worm loader committed (no trigger runs it)',
      file: p,
      signals: [
        info.match.how === 'hash'
          ? 'exact hash match with a Shai-Hulud-family loader'
          : 'downloads Bun from the oven-sh release page and runs a file next to itself: the Shai-Hulud loader shape',
        'no committed hook or folder-open task runs it, so it does not start by itself',
      ],
      fix: 'Delete the file and its payload, and check how the commit landed (`git log` on the file).',
    });
  }
  return findings;
}

export type { Trigger as StartupTrigger };
