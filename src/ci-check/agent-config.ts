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
    const remote = /\b(npx|curl|wget|iwr|irm)\b/.test(cmd) || /\|\s*(sh|bash)\b/.test(cmd);
    if (!remote) continue;
    const unpinned = /@latest\b/.test(cmd) || (/\bnpx\b/.test(cmd) && !/@\d/.test(cmd));
    findings.push({
      check: 'CI-1',
      dimension: 'toolRules',
      severity: unpinned ? 'high' : 'medium',
      title: unpinned
        ? 'Agent hook runs UNPINNED third-party code on every action'
        : 'Agent hook runs third-party code in the agent hot path',
      file: path,
      signals: [
        `hook command: \`${cmd.slice(0, 120)}\``,
        unpinned
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
    findings.push({
      check: 'CI-1',
      dimension: 'toolRules',
      severity: 'medium',
      title: 'Committed agent config pre-authorizes broad tools',
      file: path,
      signals: [
        `broad allow(s): ${broad.slice(0, 5).join(', ')}`,
        ...(deny.length === 0 ? ['no `deny` entries to backstop it'] : []),
      ],
      fix: 'Scope the allow-list to specific read-only subcommands (e.g. `Bash(gh pr view:*)`); avoid bare `Bash`/`git:`/`Write`.',
    });
  }

  return findings;
}
