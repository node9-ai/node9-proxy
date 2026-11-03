// src/posture/agent-permissions.ts
// Check — Agent permissions (OWASP ASI02, node9Firewall#320 phase 1).
//
// How each agent's OWN approval gate is set on this machine, read from the
// user-level files the agent loads for every session: Claude Code
// `~/.claude/settings.json`, Codex `~/.codex/config.toml`, Gemini CLI
// `~/.gemini/settings.json`. An agent that runs with its own prompts off, or
// with a broad standing allow-list, does whatever a poisoned input tells it
// unless a guard outside the agent stops the call.
//
// The grading of allow-lists and Codex autonomy settings is the one scan-repo
// applies to committed files (src/ci-check); here it reads the user's copies.
// Config inspection only: nothing runs, and detail lines carry setting names
// and tool patterns, never a secret.

import os from 'os';
import path from 'path';
import { analyzeAgentConfig } from '../ci-check/agent-config';
import { analyzeCodexConfig } from '../ci-check/codex';
import type { CiFinding } from '../ci-check/types';
import type { CheckContext, Finding, Severity } from './types';
import { readSmallFile } from '../utils/read-small-file';

export const CATEGORY = 'Agent permissions';

/** Claude Code permission modes that skip the agent's own prompt. */
const CLAUDE_NO_PROMPT_MODES = new Set(['bypassPermissions', 'dontAsk']);

const MAX_FILE_BYTES = 2 * 1024 * 1024;

// One open, checked on its descriptor (CodeQL js/file-system-race).
function readSmall(file: string): string | null {
  return readSmallFile(file, MAX_FILE_BYTES);
}

function base(agent: string, severity: Severity, title: string): Finding {
  return {
    category: CATEGORY,
    severity,
    title,
    detail: [],
    // The agent's setting is the user's to change (the "your part" tier);
    // node9's hook still judges the calls its checks know, which is why the
    // finding is partial while node9 enforces and open when it does not.
    owner: 'os',
    coverageProbe: { kind: 'gateWired' },
    who: `${agent} runs what a poisoned file, page or tool result tells it, with nothing in its own path to stop the call.`,
  };
}

const CI_SEVERITY: Record<CiFinding['severity'], Severity> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  advisory: 'advisory',
};

/** Claude Code: the permission mode and the standing allow-list. */
function claudeCode(home: string): Finding[] {
  const file = path.join(home, '.claude', 'settings.json');
  const text = readSmall(file);
  if (!text) return [];
  let cfg: {
    permissions?: { defaultMode?: unknown };
    dangerouslySkipPermissions?: unknown;
  };
  try {
    cfg = JSON.parse(text) as typeof cfg;
  } catch {
    return [];
  }
  const findings: Finding[] = [];
  const mode = typeof cfg.permissions?.defaultMode === 'string' ? cfg.permissions.defaultMode : '';
  if (CLAUDE_NO_PROMPT_MODES.has(mode) || cfg.dangerouslySkipPermissions === true) {
    const f = base('Claude Code', 'high', 'Claude Code runs without asking');
    f.what = "Claude Code's own permission prompt is switched off for every session.";
    f.why = CLAUDE_NO_PROMPT_MODES.has(mode)
      ? `~/.claude/settings.json sets permissions.defaultMode to ${mode}.`
      : '~/.claude/settings.json sets dangerouslySkipPermissions.';
    f.detail = [
      CLAUDE_NO_PROMPT_MODES.has(mode)
        ? `permissions.defaultMode = ${mode}`
        : 'dangerouslySkipPermissions = true',
    ];
    f.fix =
      'Set permissions.defaultMode to "default" (or remove it) in ~/.claude/settings.json, and keep node9 in an enforcing mode so every call is still judged.';
    findings.push(f);
  }
  // The committed-file grader, on the user's file: broad standing grants and
  // pre-approved commands that run other programs. Hook rules are left out
  // here on purpose: the user file holds node9's own hook, and the Coverage
  // check already reports the hooks.
  for (const ci of analyzeAgentConfig('.claude/settings.json', text)) {
    if (ci.rule !== 'CI-1.broad-allow' && ci.rule !== 'CI-1.exec-escape-grant') continue;
    const f = base(
      'Claude Code',
      CI_SEVERITY[ci.severity],
      ci.rule === 'CI-1.broad-allow'
        ? 'Claude Code pre-approves broad tools for every session'
        : 'Claude Code pre-approves a command that can run other programs'
    );
    f.what =
      ci.rule === 'CI-1.broad-allow'
        ? 'A standing allow-list lets the agent run whole tool families without asking.'
        : 'A pre-approved command can start any other program without a prompt.';
    f.why = 'permissions.allow in ~/.claude/settings.json grants it for every project.';
    f.detail = ci.signals.slice(0, 6);
    f.fix = ci.fix;
    findings.push(f);
  }
  return findings;
}

/** Codex: approval policy and sandbox, through the committed-file grader. */
function codex(home: string): Finding[] {
  const file = path.join(home, '.codex', 'config.toml');
  const text = readSmall(file);
  if (!text) return [];
  const findings: Finding[] = [];
  for (const ci of analyzeCodexConfig('.codex/config.toml', text)) {
    if (ci.rule !== 'CI-1.codex-unsafe-defaults') continue;
    const f = base('Codex', 'high', 'Codex runs without approval or without a sandbox');
    f.what = "Codex's own approval or sandbox is switched off for every session.";
    f.why = '~/.codex/config.toml sets it for every project.';
    f.detail = ci.signals.slice(0, 6);
    f.fix =
      'Set approval_policy = "on-request" and sandbox_mode = "workspace-write" in ~/.codex/config.toml, and keep node9 in an enforcing mode.';
    findings.push(f);
  }
  return findings;
}

/** Gemini CLI: auto-accept or a yolo approval mode in the user settings. */
function gemini(home: string): Finding[] {
  const file = path.join(home, '.gemini', 'settings.json');
  const text = readSmall(file);
  if (!text) return [];
  let cfg: Record<string, unknown>;
  try {
    cfg = JSON.parse(text) as Record<string, unknown>;
  } catch {
    return [];
  }
  const hits: string[] = [];
  const visit = (obj: Record<string, unknown>, prefix: string, depth: number): void => {
    if (depth > 2) return;
    for (const [k, v] of Object.entries(obj)) {
      const key = prefix ? `${prefix}.${k}` : k;
      if (k === 'autoAccept' && v === true) hits.push(`${key} = true`);
      else if (/approval[_-]?mode/i.test(k) && typeof v === 'string' && v.toLowerCase() === 'yolo')
        hits.push(`${key} = yolo`);
      else if (v && typeof v === 'object' && !Array.isArray(v))
        visit(v as Record<string, unknown>, key, depth + 1);
    }
  };
  visit(cfg, '', 0);
  if (hits.length === 0) return [];
  const f = base('Gemini CLI', 'high', 'Gemini CLI accepts every tool call on its own');
  f.what = "Gemini CLI's own confirmation is switched off for every session.";
  f.why = '~/.gemini/settings.json sets it.';
  f.detail = hits.slice(0, 4);
  f.fix =
    'Turn auto-accept off (or set the approval mode back to default) in ~/.gemini/settings.json, and keep node9 in an enforcing mode.';
  return [f];
}

export function checkAgentPermissions(ctx: CheckContext): Finding[] {
  const home = ctx.home || os.homedir();
  return [...claudeCode(home), ...codex(home), ...gemini(home)];
}
