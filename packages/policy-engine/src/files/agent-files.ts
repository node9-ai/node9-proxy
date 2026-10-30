// packages/policy-engine/src/files/agent-files.ts
// Writes to the agent's own instruction and memory files (node9Firewall#413,
// part 4, `files.agent-instructions`). CLAUDE.md, AGENTS.md, GEMINI.md, the
// memory directory, the agents, commands and skills folders, and the hooks of
// the agent settings are loaded into every later session: a poisoned line
// persists (OWASP ASI06), and a rewritten hook disarms the guard itself
// (ASI10).
//
// Soft logs every write. Standard asks only when the written text carries an
// instruction to hide something, skip approvals, or read or send a secret
// (dlp/instruction-write.ts), when the hooks of a settings file change, or
// when a shell write's content cannot be seen; a plain write is recorded.
// Strict and Block all ask on every write (levels.ts).

import { checkValue, type CatalogSettings } from '../catalog';
import { reviewsEveryAgentFileWrite } from '../levels';
import type { PolicyVerdict } from '../policy';
import { scanInstructionWrite } from '../dlp/instruction-write';
import type { FileAccess, FileAccessContext } from './paths';
import { normalizeFilePath } from './paths';
import { writtenTexts } from './written-texts';

const CHECK_ID = 'files.agent-instructions';

export type AgentFileKind =
  'instructions' | 'memory' | 'agents' | 'commands' | 'skills' | 'settings';

export type AgentFileVerdict = PolicyVerdict & {
  path: string;
  operation: FileAccess['operation'];
  kind: AgentFileKind;
};

/** What the host supplies: the settings file as it is on disk now. */
export interface AgentFileHooks {
  readAgentSettings?: (absPath: string) => string | null;
}

const INSTRUCTION_NAMES = new Set([
  'claude.md',
  'claude.local.md',
  'agents.md',
  'gemini.md',
  '.cursorrules',
  '.windsurfrules',
  '.clinerules',
]);
const SETTINGS_RE =
  /\/(?:\.claude\/settings(?:\.local)?\.json|\.gemini\/settings\.json|\.codex\/hooks\.json|\.cursor\/hooks\.json)$/i;

/** The kind of agent file a normalized path is, or null. */
export function agentFileKind(p: string): AgentFileKind | null {
  const lower = p.toLowerCase();
  const base = lower.slice(lower.lastIndexOf('/') + 1);
  if (INSTRUCTION_NAMES.has(base)) return 'instructions';
  if (base === 'copilot-instructions.md' && lower.endsWith('/.github/' + base))
    return 'instructions';
  // A directory itself counts (`rm -rf .claude/commands`), hence `(?:/|$)`.
  if (/\/\.cursor\/rules(?:\/|$)/.test(lower)) return 'instructions';
  if (/\/\.claude\/projects\/[^/]+\/memory(?:\/|$)/.test(lower)) return 'memory';
  const m = /\/\.claude\/(agents|commands|skills)(?:\/|$)/.exec(lower);
  if (m) return m[1] as AgentFileKind;
  if (SETTINGS_RE.test(lower)) return 'settings';
  return null;
}

/** A hook event name of Claude Code or Gemini CLI, as settings files spell them. */
const HOOK_WORDS_RE =
  /"hooks"|\b(PreToolUse|PostToolUse|UserPromptSubmit|Notification|Stop|SubagentStop|SessionStart|SessionEnd|PreCompact|BeforeTool|AfterTool)\b|"command"\s*:/;

function stableHooks(text: string | null): string | undefined {
  if (text === null) return undefined;
  try {
    const parsed = JSON.parse(text) as { hooks?: unknown };
    return JSON.stringify(sortKeys(parsed?.hooks ?? null));
  } catch {
    return undefined;
  }
}

function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === 'object') {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v as Record<string, unknown>).sort())
      out[k] = sortKeys((v as Record<string, unknown>)[k]);
    return out;
  }
  return v;
}

/** The edits a file tool carries, in order. */
function editPairs(args: unknown): Array<{ from: string; to: string }> | null {
  if (!args || typeof args !== 'object') return null;
  const a = args as Record<string, unknown>;
  const out: Array<{ from: string; to: string }> = [];
  if (Array.isArray(a.edits)) {
    for (const e of a.edits) {
      const r = e as Record<string, unknown>;
      if (typeof r?.old_string === 'string' && typeof r?.new_string === 'string')
        out.push({ from: r.old_string, to: r.new_string });
      else return null;
    }
    return out;
  }
  for (const [f, t] of [
    ['old_string', 'new_string'],
    ['old_str', 'new_str'],
  ]) {
    if (typeof a[f] === 'string' && typeof a[t] === 'string')
      return [{ from: a[f] as string, to: a[t] as string }];
  }
  return null;
}

/**
 * Does this call change the `hooks` of an agent settings file? A whole write
 * is compared with the file on disk; an edit is applied to the file on disk
 * and compared; without the file (no reader, unreadable, not JSON) or with
 * an edit whose old text is not found, any mention of hooks in the new text
 * counts.
 */
function hooksChange(
  args: unknown,
  texts: { whole: string[]; edits: string[] },
  absPath: string,
  hooks: AgentFileHooks
): boolean {
  const current = hooks.readAgentSettings ? hooks.readAgentSettings(absPath) : null;
  const before = stableHooks(current);
  if (texts.whole.length > 0) {
    for (const t of texts.whole) {
      const after = stableHooks(t);
      if (before === undefined || after === undefined) {
        if (HOOK_WORDS_RE.test(t)) return true;
      } else if (after !== before) return true;
    }
    return false;
  }
  const pairs = editPairs(args);
  if (pairs && current !== null) {
    let text = current;
    let applied = true;
    for (const { from, to } of pairs) {
      const i = text.indexOf(from);
      if (i < 0) {
        applied = false;
        break;
      }
      text = text.slice(0, i) + to + text.slice(i + from.length);
    }
    if (applied) {
      const after = stableHooks(text);
      if (before !== undefined && after !== undefined) return after !== before;
    }
  }
  // Fallback: the edit mentions hooks on either side.
  if (pairs) return pairs.some((p) => HOOK_WORDS_RE.test(p.from) || HOOK_WORDS_RE.test(p.to));
  return texts.edits.some((t) => HOOK_WORDS_RE.test(t));
}

/**
 * The verdict for the first agent-file mutation among the accesses, or null.
 */
export function evaluateAgentFileWrite(
  args: unknown,
  accesses: FileAccess[],
  context: FileAccessContext,
  settings: CatalogSettings,
  shell: boolean,
  hooks: AgentFileHooks = {}
): AgentFileVerdict | null {
  const value = checkValue(settings, CHECK_ID);
  if (value === 'off') return null;
  const home = context.homeDirs?.[0] ?? '~';
  for (const access of accesses) {
    if (access.operation === 'read') continue;
    const candidates = access.candidates ?? [
      normalizeFilePath(access.path, access.cwd ?? context.cwd, home),
    ];
    let kind: AgentFileKind | null = null;
    let absPath = candidates[0] ?? access.path;
    for (const c of candidates) {
      kind = agentFileKind(c);
      if (kind) {
        absPath = c;
        break;
      }
    }
    if (!kind) continue;

    // What is being written, and what it says.
    const texts = shell ? { whole: [], edits: [] } : writtenTexts(args);
    const written = [...texts.whole, ...texts.edits];
    let signal: 'content' | 'hooks' | 'unseen' | null = null;
    let detail = '';
    if (kind === 'settings') {
      if (shell || access.operation === 'remove' || hooksChange(args, texts, absPath, hooks)) {
        signal = 'hooks';
        detail =
          access.operation === 'remove' ? 'the agent settings file is removed' : 'the hooks change';
      }
    } else if (access.operation === 'remove') {
      signal = 'unseen';
      detail = 'the file is removed';
    } else if (shell) {
      const command =
        args &&
        typeof args === 'object' &&
        typeof (args as { command?: unknown }).command === 'string'
          ? ((args as { command: string }).command as string)
          : '';
      const hit = command ? scanInstructionWrite(command) : null;
      if (hit) {
        signal = 'content';
        detail = hit.signals.join(', ');
      } else if (!access.append) {
        // The content is not in the command (`cp`, `mv`, a download, `tee < other`).
        signal = 'unseen';
        detail = 'the content written cannot be read from the command';
      }
    } else if (written.length > 0) {
      for (const t of written) {
        const hit = scanInstructionWrite(t);
        if (hit) {
          signal = 'content';
          detail = hit.signals.join(', ');
          break;
        }
      }
    }

    const every = reviewsEveryAgentFileWrite(settings.mode);
    const kindLabel: Record<AgentFileKind, string> = {
      instructions: 'agent instruction file',
      memory: 'agent memory file',
      agents: 'agent definition',
      commands: 'agent command',
      skills: 'agent skill',
      settings: 'agent settings',
    };
    const base = `${kindLabel[kind]} written: ${access.path}`;
    if (!signal && !every) {
      return {
        decision: 'allow',
        logged: true,
        checkId: CHECK_ID,
        ruleName: 'review-agent-file-write',
        path: access.path,
        operation: access.operation,
        kind,
        reason: base,
        ruleDescription: 'The AI writes to a file every later agent session loads as instructions.',
        blockedByLabel: `Node9 Files: ${base}`,
        tier: 2,
      };
    }
    const ruleName =
      signal === 'content'
        ? 'review-agent-file-content'
        : signal === 'hooks'
          ? 'review-agent-hooks-change'
          : 'review-agent-file-write';
    const reason = signal ? `${base} (${detail})` : base;
    const description =
      signal === 'content'
        ? 'The AI writes an instruction into a file every later agent session loads: to hide something from you, to skip approvals or the guard, or to read or send a secret. It would persist past this session; confirm it is yours.'
        : signal === 'hooks'
          ? "The AI changes the hooks in the agent's settings. Hooks are how node9 and your other checks run before each tool call; a change here can disarm them."
          : 'The AI writes to a file every later agent session loads as instructions (CLAUDE.md, AGENTS.md, memory, agents, commands). Confirm the change is yours.';
    return {
      decision: value === 'log' ? 'allow' : value,
      ...(value === 'log' ? { logged: true } : {}),
      checkId: CHECK_ID,
      ruleName,
      path: access.path,
      operation: access.operation,
      kind,
      reason,
      ruleDescription: description,
      blockedByLabel: `Node9 Files: ${reason}`,
      tier: 2,
      ...(value === 'block' ? { overridable: false } : {}),
    };
  }
  return null;
}
