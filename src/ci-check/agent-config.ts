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
    // 1d: a broad allow with NO `deny` backstop covering the dangerous verbs is a standing,
    // catastrophic pre-authorization for EVERY contributor's agent → high. A `deny` that names
    // Bash/Write/Edit backstops it → medium.
    const hasBackstop = deny.some((d) => /Bash|Write|Edit/.test(d));
    findings.push({
      check: 'CI-1',
      dimension: 'toolRules',
      severity: hasBackstop ? 'medium' : 'high',
      title: hasBackstop
        ? 'Committed agent config pre-authorizes broad tools'
        : 'Committed agent config pre-authorizes broad tools with no deny backstop',
      file: path,
      signals: [
        `broad allow(s): ${broad.slice(0, 5).join(', ')}`,
        hasBackstop
          ? 'a `deny` list backstops the broad allow'
          : 'no `deny` entry covers Bash/Write/Edit — every contributor is pre-authorized for catastrophic tools',
      ],
      fix: 'Scope the allow-list to specific read-only subcommands (e.g. `Bash(gh pr view:*)`); avoid bare `Bash`/`git:`/`Write`, or add a `deny` backstop.',
    });
  }

  return findings;
}
