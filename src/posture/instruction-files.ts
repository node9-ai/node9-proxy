// src/posture/instruction-files.ts
// Check — Instruction files (OWASP ASI06, node9Firewall#320 phase 1).
//
// The files an agent loads into every later session at user level: Claude
// Code's `~/.claude/CLAUDE.md`, its agents, commands and skills, the memory
// directory of each project, Codex's `~/.codex/AGENTS.md`, Gemini's
// `~/.gemini/GEMINI.md`. A line planted there persists past the session that
// wrote it. Two questions: does any of these files carry hidden or suspicious
// content now, and does node9 watch writes to them (`files.agent-instructions`).
//
// The content grading is scan-repo's (CI-6, src/ci-check/instructions.ts) on
// the user's files. Detail lines carry the file, the rule and a line number,
// never the text.

import fs from 'fs';
import os from 'os';
import path from 'path';
import { checkValue } from '@node9/policy-engine';
import { analyzeInstructionFile } from '../ci-check/instructions';
import type { CiFinding } from '../ci-check/types';
import { getConfig, catalogSettingsFrom } from '../config';
import type { CheckContext, Finding } from './types';
import { readSmallFile } from '../utils/read-small-file';

export const CATEGORY = 'Instruction files';

const MAX_FILES = 200;
const MAX_FILE_BYTES = 256 * 1024;

function listMd(dir: string, depth: number, out: string[]): void {
  if (out.length >= MAX_FILES || depth < 0) return;
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (out.length >= MAX_FILES) return;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) listMd(p, depth - 1, out);
    else if (e.isFile() && /\.md$/i.test(e.name)) out.push(p);
  }
}

/** The user-level instruction and memory files on this machine. */
export function instructionFiles(home: string): string[] {
  const out: string[] = [];
  for (const f of [
    path.join(home, '.claude', 'CLAUDE.md'),
    path.join(home, '.codex', 'AGENTS.md'),
    path.join(home, '.gemini', 'GEMINI.md'),
  ]) {
    try {
      if (fs.statSync(f).isFile()) out.push(f);
    } catch {
      /* absent */
    }
  }
  listMd(path.join(home, '.claude', 'agents'), 1, out);
  listMd(path.join(home, '.claude', 'commands'), 2, out);
  listMd(path.join(home, '.claude', 'skills'), 2, out);
  // Memory: ~/.claude/projects/<slug>/memory/*.md
  const projects = path.join(home, '.claude', 'projects');
  let slugs: fs.Dirent[] = [];
  try {
    slugs = fs.readdirSync(projects, { withFileTypes: true });
  } catch {
    /* none */
  }
  for (const s of slugs) {
    if (!s.isDirectory()) continue;
    listMd(path.join(projects, s.name, 'memory'), 1, out);
    if (out.length >= MAX_FILES) break;
  }
  return out;
}

// One open, checked on its descriptor (CodeQL js/file-system-race).
function readSmall(file: string): string | null {
  return readSmallFile(file, MAX_FILE_BYTES);
}

function display(file: string, home: string): string {
  return file.startsWith(home + path.sep) ? '~' + file.slice(home.length) : file;
}

/** A memory file is written by the agent about its work and quotes commands
 *  and paths as a matter of course; there only a high or critical rule (an
 *  instruction override, hidden characters) counts. In a file that IS an
 *  instruction (CLAUDE.md, an agent, a command, a skill) every rule above a
 *  style note counts. */
function isMemory(file: string): boolean {
  return /[\\/]\.claude[\\/]projects[\\/][^\\/]+[\\/]memory[\\/]/.test(file);
}

function counts(ci: CiFinding, memory: boolean): boolean {
  if (ci.severity === 'advisory') return false;
  return memory ? ci.severity === 'high' || ci.severity === 'critical' : true;
}

export function checkInstructionFiles(ctx: CheckContext): Finding[] {
  const home = ctx.home || os.homedir();
  const findings: Finding[] = [];

  // ── Hidden or suspicious content in a file the agent loads (high) ────────
  const detail: string[] = [];
  let worst: 'high' | 'medium' = 'medium';
  let filesHit = 0;
  for (const file of instructionFiles(home)) {
    const text = readSmall(file);
    if (text === null) continue;
    const memory = isMemory(file);
    const hits = analyzeInstructionFile(display(file, home), text).filter((h) => counts(h, memory));
    if (hits.length === 0) continue;
    filesHit++;
    for (const h of hits.slice(0, 3)) {
      if (h.severity === 'high' || h.severity === 'critical') worst = 'high';
      detail.push(`${display(file, home)}: ${h.rule}${h.line ? ` (line ${h.line})` : ''}`);
    }
  }
  if (filesHit > 0) {
    findings.push({
      category: CATEGORY,
      severity: worst,
      title: `${filesHit} instruction or memory file${filesHit === 1 ? '' : 's'} carr${filesHit === 1 ? 'ies' : 'y'} hidden or suspicious content`,
      what: 'A file the agent loads into every session holds text a reader would not see, or an instruction to fetch, obey, hide or send something.',
      why: 'It was written there by a past session, a tool, or by hand, and it stays until removed.',
      who: 'Every future session starts with that instruction already in place, before any input is read.',
      detail: detail.slice(0, 12),
      owner: 'os',
      fix: 'Open each file at the line shown and remove the text you did not write. `node9 scan-repo` grades the same shapes in a repository.',
    });
  }

  // ── Are writes to these files watched? (`files.agent-instructions`) ──────
  const config = getConfig(ctx.cwd);
  const value = checkValue(
    catalogSettingsFrom(config.settings, config.policy),
    'files.agent-instructions'
  );
  if (value === 'off') {
    findings.push({
      category: CATEGORY,
      severity: 'medium',
      title: 'Writes to instruction and memory files are not watched',
      what: 'An agent can rewrite its own instructions, memory, commands or hooks and nothing records it.',
      why: 'The check files.agent-instructions is off.',
      who: 'A poisoned line written in one session is loaded by every later one.',
      detail: [],
      owner: 'node9',
      fix: 'Set files.agent-instructions to review (the Checks page, or `checks.files.agent-instructions` in the config file).',
    });
  }

  return findings;
}
