// src/auth/state.ts
// Persistent state helpers: pause sessions, trust sessions, and persistent allow/deny decisions.
import fs from 'fs';
import path from 'path';
import os from 'os';
import { matchesPattern } from '../policy';
import { isShellShapedTool, resolveShellInput } from '@node9/policy-engine';
import { atomicWriteSync } from '../utils/atomic-write';
import { forecastRun } from './forecast-context';

const PAUSED_FILE = path.join(os.homedir(), '.node9', 'PAUSED');
const TRUST_FILE = path.join(os.homedir(), '.node9', 'trust.json');

interface PauseState {
  expiry: number;
  duration: string;
}
interface TrustEntry {
  tool: string;
  /** For Bash/shell tools: first 2 words of the command (e.g. "git push").
   * When present, trust only applies when the actual command starts with this pattern.
   * Absent for non-Bash tools → tool-level trust. */
  commandPattern?: string;
  expiry: number;
}
interface TrustFile {
  entries: TrustEntry[];
}

/** Extract a normalised command pattern (first 2 words) for Bash trust scoping. */
export function extractCommandPattern(toolName: string, args: unknown): string | undefined {
  const lower = toolName.toLowerCase();
  if (lower !== 'bash' && lower !== 'execute_bash' && lower !== 'shell') return undefined;
  const a = args as Record<string, unknown> | null;
  const cmd = typeof a?.['command'] === 'string' ? a['command'].trim() : '';
  if (!cmd) return undefined;
  const words = cmd.split(/\s+/);
  return words.slice(0, 2).join(' ');
}

export function checkPause(): { paused: boolean; expiresAt?: number; duration?: string } {
  // A pause is a moment, not a setting: a forecast judges as if none were on.
  if (forecastRun()) return { paused: false };
  try {
    if (!fs.existsSync(PAUSED_FILE)) return { paused: false };
    const state = JSON.parse(fs.readFileSync(PAUSED_FILE, 'utf-8')) as PauseState;
    if (state.expiry > 0 && Date.now() >= state.expiry) {
      try {
        fs.unlinkSync(PAUSED_FILE);
      } catch {}
      return { paused: false };
    }
    return { paused: true, expiresAt: state.expiry, duration: state.duration };
  } catch {
    return { paused: false };
  }
}

export function pauseNode9(durationMs: number, durationStr: string): void {
  const state: PauseState = { expiry: Date.now() + durationMs, duration: durationStr };
  atomicWriteSync(PAUSED_FILE, JSON.stringify(state, null, 2));
}

export function resumeNode9(): void {
  try {
    if (fs.existsSync(PAUSED_FILE)) fs.unlinkSync(PAUSED_FILE);
  } catch {}
}

export function getActiveTrustSession(toolName: string, args?: unknown): boolean {
  // Same for a trust session (and the read below rewrites trust.json).
  if (forecastRun()) return false;
  try {
    if (!fs.existsSync(TRUST_FILE)) return false;
    const trust = JSON.parse(fs.readFileSync(TRUST_FILE, 'utf-8')) as TrustFile;
    const now = Date.now();
    const active = trust.entries.filter((e) => e.expiry > now);
    if (active.length !== trust.entries.length) {
      // Atomic, like writeTrustSession below. A plain writeFileSync here let a
      // concurrent hook process read a truncated trust.json, whose parse failure
      // is swallowed and reported as "no active trust session".
      atomicWriteSync(TRUST_FILE, JSON.stringify({ entries: active }, null, 2));
    }
    return active.some((e) => {
      if (!(e.tool === toolName || matchesPattern(toolName, e.tool))) return false;
      if (e.commandPattern) {
        const actual = extractCommandPattern(toolName, args) ?? '';
        return actual === e.commandPattern || actual.startsWith(e.commandPattern + ' ');
      }
      return true;
    });
  } catch {
    return false;
  }
}

export function writeTrustSession(toolName: string, durationMs: number, args?: unknown): void {
  const commandPattern = extractCommandPattern(toolName, args);
  try {
    let trust: TrustFile = { entries: [] };

    // 1. Try to read existing trust state
    try {
      if (fs.existsSync(TRUST_FILE)) {
        trust = JSON.parse(fs.readFileSync(TRUST_FILE, 'utf-8')) as TrustFile;
      }
    } catch {
      // If the file is corrupt, start with a fresh object
    }

    // 2. Remove the matching (tool, commandPattern) entry and expired entries
    const now = Date.now();
    trust.entries = trust.entries.filter(
      (e) => !(e.tool === toolName && e.commandPattern === commandPattern) && e.expiry > now
    );

    // 3. Add the new time-boxed entry (commandPattern undefined for non-Bash tools)
    trust.entries.push({
      tool: toolName,
      ...(commandPattern && { commandPattern }),
      expiry: now + durationMs,
    });

    // 4. Perform the ATOMIC write
    atomicWriteSync(TRUST_FILE, JSON.stringify(trust, null, 2));
  } catch (err) {
    // Silent fail: Node9 should never crash an AI agent session due to a file error
    if (process.env.NODE9_DEBUG === '1') {
      console.error('[Node9 Trust Error]:', err);
    }
  }
}

/**
 * Tools whose argument is a shell command: a standing approval of one of them
 * is scoped to the command, never to the tool (node9Firewall#343). The
 * engine's own list (Bash and its aliases, and the MCP executors it reads as
 * a shell), so a tool the gate judges as a shell is approved as one.
 */
export const isShellTool = (toolName: string): boolean => isShellShapedTool(toolName);

/** The command a shell tool call runs, as the engine reads it; '' when the
 *  call carries none it can read. */
function shellCommandOf(toolName: string, args: unknown): string {
  const input = resolveShellInput(toolName, args);
  return input.kind === 'shell' ? input.command.trim() : '';
}

/**
 * Anything that makes a command more than ONE simple command, or makes its
 * words depend on the shell: a list, a pipe, a redirect, a substitution, a
 * variable, a group, an escape, a newline. Read from the text on purpose: a
 * quoted `;` also counts, which only makes the approval narrower.
 */
const NOT_ONE_SIMPLE_COMMAND_RE = /[;&|<>()`$\\{}\n\r]/;

/** What a standing "Always allow" covers, and how it is shown to the person. */
export interface PersistentScope {
  /** The key in decisions.json. */
  key: string;
  /** What the prompt shows after "Always allow". */
  label: string;
}

/**
 * The scope of a standing approval for this call (node9Firewall#343).
 *
 * A shell tool is never approved as a whole: one keypress on a harmless
 * command used to remove every later rule-less review of the tool, for good.
 *  - One simple command: its first two words. `Bash(npm test)` later allows
 *    `npm test -- --watch`, not `npm run build`.
 *  - Anything else: this exact text, `Bash(=<command>)`. A two-word prefix of
 *    a compound command says nothing about what the rest of it runs.
 * Another tool keeps its bare name: the tool is the scope.
 *
 * The daemon writes with this, the authorizer reads with it and `node9 tail`
 * shows its label, so the three cannot drift.
 */
export function persistentScope(toolName: string, args: unknown): PersistentScope {
  if (!isShellTool(toolName)) return { key: toolName, label: toolName };
  const command = shellCommandOf(toolName, args);
  if (!command || NOT_ONE_SIMPLE_COMMAND_RE.test(command))
    return { key: `${toolName}(=${command})`, label: 'this exact command' };
  const prefix = command.split(/\s+/).slice(0, 2).join(' ');
  return { key: `${toolName}(${prefix})`, label: `"${prefix}"` };
}

export function getPersistentDecision(toolName: string, args?: unknown): 'allow' | 'deny' | null {
  try {
    const file = path.join(os.homedir(), '.node9', 'decisions.json');
    if (!fs.existsSync(file)) return null;
    const decisions = JSON.parse(fs.readFileSync(file, 'utf-8')) as Record<string, string>;
    const whole = decisions[toolName];
    if (!isShellTool(toolName)) return whole === 'allow' || whole === 'deny' ? whole : null;
    // A tool-wide deny still applies: tightening is fine. A tool-wide ALLOW of
    // a shell tool, written before approvals were scoped, no longer does.
    if (whole === 'deny') return 'deny';
    // No readable command: nothing a stored approval could have named.
    if (!shellCommandOf(toolName, args)) return null;
    const scoped = decisions[persistentScope(toolName, args).key];
    if (scoped === 'allow' || scoped === 'deny') return scoped;
  } catch {
    /* ignore */
  }
  return null;
}
