// src/ci-check/agent-config.ts
// CI-1 — committed agent configs (.claude/settings.json, .cursor/…). These ship
// in the repo and apply to EVERY contributor's machine. We flag hooks that run
// remote/unpinned code and over-broad permission grants. Static, parse-only.

import path from 'path';
import type { CiFinding } from './types';
import { parseFrontmatter, allowedToolsOf } from './frontmatter';
import { SCRIPT_EXT_RE, isHookScript } from './instructions';
import { lineAtIndex, jsonValueIndex } from './lines';

interface Settings {
  permissions?: { allow?: unknown[]; deny?: unknown[] };
  hooks?: Record<string, unknown[]>;
}

function asStrings(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x) => typeof x === 'string') : [];
}

/** Walk the hooks tree and collect every hook `command` string. */
function hookCommands(hooks: Record<string, unknown[]> | undefined): string[] {
  const out: string[] = [];
  for (const groups of Object.values(hooks ?? {})) {
    for (const g of Array.isArray(groups) ? groups : []) {
      const inner = (g as { hooks?: unknown[] })?.hooks;
      for (const h of Array.isArray(inner) ? inner : []) {
        const cmd = (h as { command?: unknown })?.command;
        if (typeof cmd === 'string') out.push(cmd);
      }
    }
  }
  return out;
}

/** What a broad grant is, and how badly. ONE definition, shared by settings.json
 *  (`permissions.allow`) and a skill's or command's `allowed-tools`, so the two containers
 *  can never drift: a bare `Bash` is graded the same wherever it is written.
 *
 *  Returns null when nothing in `allow` is broad. `denySupported` is false for a skill,
 *  which has no deny list, so the "no deny narrows these" signal is not emitted there.
 *  `scope` finishes the sentence that says who is exposed. */
export function gradeBroadGrant(
  allow: string[],
  deny: string[],
  opts: { denySupported?: boolean; scope?: string } = {}
): { broad: string[]; bareShell: boolean; high: boolean; signals: string[] } | null {
  const denySupported = opts.denySupported ?? true;
  const scope = opts.scope ?? 'for everyone who opens this repo with the agent';
  const broad = allow.filter((a) =>
    /^Bash$|^Bash\(\s*\*|^Bash\(git:|^Write\(\s*\*|^Write$|^Edit$/.test(a)
  );
  if (broad.length === 0) return null;
  const hasBackstop = deny.some((d) => /Bash|Write|Edit/.test(d));
  // For an unrestricted shell only a Bash deny counts: `deny: ['Write']` does nothing to
  // limit `allow: ['Bash']`. A Bash deny narrows it but cannot make it safe, and the
  // signal says exactly that.
  const bashBackstop = deny.some((d) => /^Bash\b/.test(d));
  // Calibration (2026-09-25): only an UNRESTRICTED shell with no `deny` backstop is high —
  // any command an injected instruction names runs without a prompt, for everyone who opens
  // the repo with the agent. `Bash(git:*)`, `Write` and `Edit` are broad and worth a look
  // (git can run other programs via `-c core.pager=…` or `!` aliases), but they are the
  // everyday grant of most repos, and calling them catastrophic overclaimed → medium.
  const bareShell = broad.some((a) => /^Bash$|^Bash\(\s*\*/.test(a));
  const high = bareShell && !bashBackstop;
  const signals = [`broad allow(s): ${broad.slice(0, 5).join(', ')}`];
  if (high)
    signals.push(
      `unrestricted \`Bash\` with no \`deny\` backstop — any command an injected instruction names runs without a prompt, ${scope}`
    );
  else if (bareShell)
    signals.push(
      'a `Bash` deny list narrows the unrestricted `Bash` allow; it blocks only the commands it names'
    );
  if (broad.some((a) => /^Bash\(git:/.test(a)))
    signals.push(
      '`Bash(git:*)` pre-approves every git command; git can run other programs (`-c core.pager=…`, `!` aliases), so this is broader than it looks'
    );
  if (broad.some((a) => /^Write|^Edit$/.test(a)))
    signals.push('`Write`/`Edit` pre-approve file changes without a prompt');
  if (denySupported && !high && !bareShell && !hasBackstop)
    signals.push('no `deny` entry narrows these grants');
  return { broad, bareShell, high, signals };
}

/** Split a hook command the way a shell would, well enough to find a path: on whitespace,
 *  keeping quoted spans whole and dropping their quotes. */
function shellTokens(cmd: string): string[] {
  const out: string[] = [];
  let cur = '';
  let q: string | null = null;
  for (const ch of cmd) {
    if (q) {
      if (ch === q) q = null;
      else cur += ch;
    } else if (ch === '"' || ch === "'") q = ch;
    else if (/\s/.test(ch)) {
      if (cur) out.push(cur);
      cur = '';
    } else cur += ch;
  }
  if (cur) out.push(cur);
  return out;
}

/** The repo-relative script a hook command runs, or null when it does not name one (inline
 *  shell, npx, a binary on PATH, a URL). Strips `${CLAUDE_PROJECT_DIR}/`, `$CLAUDE_PROJECT_DIR/`,
 *  `./` and quotes. A committed config is attacker-controlled input, so the path in it is not
 *  trusted: absolute paths and anything that escapes the root after normalisation are null.
 *  Never reads the filesystem. */
export function hookScriptPath(cmd: string): string | null {
  for (const raw of shellTokens(cmd)) {
    let t = raw.replace(/^\$\{CLAUDE_PROJECT_DIR\}\/|^\$CLAUDE_PROJECT_DIR\//, '');
    if (t === raw && (t.startsWith('/') || /^[A-Za-z]:[\\/]/.test(t))) continue; // absolute
    if (/^(https?:|\$|-)/.test(t)) continue; // a URL, another variable, a flag
    t = t.replace(/^\.\//, '');
    if (!SCRIPT_EXT_RE.test(t) && !/(^|\/)\.claude\/hooks\//.test(t)) continue;
    const norm = path.posix.normalize(t);
    if (norm.startsWith('..') || norm.startsWith('/') || norm.includes('/../')) return null;
    return norm;
  }
  return null;
}

/** What the reader knew about the whole tree, so a hook can be placed in one of three states:
 *  the script it names is committed and scanned, committed but outside the paths this scan
 *  reads, or not committed at all. `complete: false` means the listing was truncated — a path
 *  missing from it is unknown, not absent, and nothing is claimed. */
export interface TreeListing {
  paths: ReadonlySet<string>;
  complete: boolean;
  /** Paths no reader lists (dependency dirs are never walked): unknown, never "missing". */
  unknown?: (p: string) => boolean;
}

/** Line of a hook command in the settings source, or undefined. */
function cmdLine(content: string, cmd: string): number | undefined {
  const i = jsonValueIndex(content, cmd);
  return i >= 0 ? lineAtIndex(content, i) : undefined;
}

export function analyzeAgentConfig(path: string, content: string, tree?: TreeListing): CiFinding[] {
  let cfg: Settings;
  try {
    cfg = JSON.parse(content) as Settings;
  } catch {
    return [];
  }
  const findings: CiFinding[] = [];

  // Hooks that fetch+run third-party code on every agent action.
  for (const cmd of hookCommands(cfg.hooks)) {
    // fetch-and-run: a `curl|wget … | sh/bash` or a bare fetch tool → remote code that CANNOT be
    // pinned; an npx invocation is remote but pinnable.
    const remoteExec = /\|\s*(sh|bash|zsh)\b/.test(cmd) || /\b(curl|wget|iwr|irm)\b/.test(cmd);
    const isNpx = /\bnpx\b/.test(cmd);
    if (!remoteExec && !isNpx) continue;
    const unpinned = /@latest\b/.test(cmd) || (isNpx && !/@\d/.test(cmd));
    // 1d: unpinnable remote-exec (curl|bash) is high regardless of pinning; an unpinned npx is
    // high; a PINNED npx is a standing supply-chain dependency → medium.
    const high = remoteExec || unpinned;
    findings.push({
      check: 'CI-1',
      rule: 'CI-1.hook-remote-code',
      // Identity is the command itself: the same hook keeps its identity when its
      // severity changes (pinned → unpinned), and two different hooks stay distinct.
      locator: cmd,
      dimension: 'toolRules',
      severity: high ? 'high' : 'medium',
      title: high
        ? 'Agent hook runs UNPINNED/remote third-party code on every action'
        : 'Agent hook runs third-party code in the agent hot path',
      file: path,
      ...(cmdLine(content, cmd) ? { line: cmdLine(content, cmd) } : {}),
      signals: [
        `hook command: \`${cmd.slice(0, 120)}\``,
        remoteExec
          ? 'fetch-and-run (curl|wget / pipe-to-shell) — unpinnable remote code execution on every contributor'
          : unpinned
            ? 'unpinned — a compromised/yanked package = code execution on every contributor'
            : 'pinned, but still a standing supply-chain dependency in the agent hot path',
      ],
      fix: 'Vendor the command as a committed local script, or pin an exact version and treat updates as security-reviewed.',
    });
  }

  // The script a hook names: three states, never two. Decided only from a complete listing.
  if (tree?.complete) {
    for (const cmd of hookCommands(cfg.hooks)) {
      const script = hookScriptPath(cmd);
      if (!script || tree.unknown?.(script)) continue;
      if (!tree.paths.has(script)) {
        findings.push({
          check: 'CI-1',
          rule: 'CI-1.hook-script-missing',
          locator: script,
          dimension: 'toolRules',
          severity: 'medium',
          title: 'Agent hook runs a script that is not committed',
          file: path,
          ...(cmdLine(content, cmd) ? { line: cmdLine(content, cmd) } : {}),
          signals: [
            `hook command: \`${cmd.slice(0, 120)}\``,
            `\`${script}\` is not in the repository — whatever lands at that path later runs before every agent action, for everyone`,
          ],
          fix: 'Commit the script the hook runs, or remove the hook.',
        });
      } else if (!isHookScript(script)) {
        findings.push({
          check: 'CI-1',
          rule: 'CI-1.hook-script-unscanned',
          locator: script,
          dimension: 'toolRules',
          severity: 'advisory',
          title: 'Agent hook runs a committed script this scan did not read',
          file: path,
          ...(cmdLine(content, cmd) ? { line: cmdLine(content, cmd) } : {}),
          signals: [
            `hook command: \`${cmd.slice(0, 120)}\``,
            `\`${script}\` is committed but outside \`.claude/hooks/\`, the paths this scan reads — its contents were not graded`,
          ],
          fix: 'Move the script under `.claude/hooks/` so it is scanned with the hook that runs it, or review it by hand.',
        });
      }
    }
  }

  // Over-broad permission grants pre-authorizing every contributor's agent.
  const allow = asStrings(cfg.permissions?.allow);
  const deny = asStrings(cfg.permissions?.deny);
  const grade = gradeBroadGrant(allow, deny);
  if (grade) {
    const { high, signals } = grade;
    // Anchor at the first broad entry: where the reviewer has to change something.
    const at = jsonValueIndex(content, grade.broad[0]);
    findings.push({
      ...(at >= 0 ? { line: lineAtIndex(content, at) } : {}),
      check: 'CI-1',
      rule: 'CI-1.broad-allow',
      // File-level: one finding per config file. Adding a SECOND broad allow makes the
      // same statement about the same file, so it must not read as a new finding.
      dimension: 'toolRules',
      severity: high ? 'high' : 'medium',
      title: high
        ? 'Committed agent config pre-authorizes broad tools with no deny backstop'
        : 'Committed agent config pre-authorizes broad tools',
      file: path,
      signals,
      fix: 'Scope the allow-list to specific read-only subcommands (e.g. `Bash(gh pr view:*)`); avoid bare `Bash`/`git:`/`Write`, or add a `deny` backstop.',
    });
  }

  return findings;
}

/** Any spelling of the Agent Skills entry file, plus Claude Code's slash commands. Only
 *  these two carry `allowed-tools` with the meaning "use without asking". A subagent's
 *  `tools:` is scope, not authorization, and a CLAUDE.md has no such field at all. */
const GRANT_CARRIER_RE = /(^|\/)[Ss][Kk][Ii][Ll][Ll]\.md$|(^|\/)\.claude\/commands\/.+\.md$/;

/** CI-1 over a skill's or slash command's frontmatter. `allowed-tools` is a
 *  pre-authorization — tools Claude may use WITHOUT asking while the skill or command is
 *  active — so it is graded by the same law as `permissions.allow` in settings.json.
 *  There is no deny list in a skill, so a bare `Bash` here is graded exactly like a
 *  settings.json with no backstop. Static, parse-only. */
export function analyzeSkillGrants(path: string, content: string): CiFinding[] {
  if (!GRANT_CARRIER_RE.test(path)) return [];
  const allow = allowedToolsOf(parseFrontmatter(content));
  if (allow.length === 0) return [];
  const grade = gradeBroadGrant(allow, [], {
    denySupported: false,
    scope:
      'whenever this skill or command is active, for everyone who opens this repo with the agent',
  });
  if (!grade) return [];
  const kind = /commands\//.test(path) ? 'slash command' : 'skill';
  const at = content.search(/^allowed-tools\s*:/m);
  return [
    {
      check: 'CI-1',
      rule: 'CI-1.skill-allowed-tools',
      ...(at >= 0 ? { line: lineAtIndex(content, at) } : {}),
      // File-level: one finding per skill or command, like CI-1.broad-allow per config file.
      dimension: 'toolRules',
      // Capped at medium (2026-09-27): a settings.json grant applies to every agent action,
      // a skill's or command's only while it runs. The signal still names the unrestricted
      // shell — the cap is on reach, not on honesty.
      severity: 'medium',
      title: grade.high
        ? `Committed ${kind} pre-authorizes an unrestricted shell while active`
        : `Committed ${kind} pre-authorizes broad tools while active`,
      file: path,
      signals: grade.signals,
      fix: 'Scope `allowed-tools` to the specific commands the skill needs (e.g. `Bash(git status:*)`); avoid a bare `Bash`, `Write` or `Edit`.',
    },
  ];
}
