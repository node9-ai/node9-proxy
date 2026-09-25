// src/ci-check/agent-config.ts
// CI-1 — committed agent configs (.claude/settings.json, .cursor/…). These ship
// in the repo and apply to EVERY contributor's machine. We flag hooks that run
// remote/unpinned code and over-broad permission grants. Static, parse-only.

import type { CiFinding } from './types';

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

export function analyzeAgentConfig(path: string, content: string): CiFinding[] {
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

  // Over-broad permission grants pre-authorizing every contributor's agent.
  const allow = asStrings(cfg.permissions?.allow);
  const deny = asStrings(cfg.permissions?.deny);
  const broad = allow.filter((a) =>
    /^Bash$|^Bash\(\s*\*|^Bash\(git:|^Write\(\s*\*|^Write$|^Edit$/.test(a)
  );
  if (broad.length > 0) {
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
        'unrestricted `Bash` with no `deny` backstop — any command an injected instruction names runs without a prompt, for everyone who opens this repo with the agent'
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
    if (!high && !bareShell && !hasBackstop) signals.push('no `deny` entry narrows these grants');
    findings.push({
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
