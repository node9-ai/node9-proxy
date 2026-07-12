// src/ci-check/codex.ts
// 1c-A — committed OpenAI Codex config (`.codex/config.toml`). This file was fetched by
// the surface crawler but never analyzed (a dead fetch = a coverage false-negative). It
// carries two real agent-security surfaces:
//   · MCP servers under `[mcp_servers.<name>]` — the SAME supply-chain + inline-credential
//     risk CI-3 scores for `.mcp.json`, in TOML instead of JSON (shared `analyzeMcpServers`).
//   · Autonomy settings — `sandbox_mode` / `approval_policy`. A committed
//     `sandbox_mode = "danger-full-access"` + `approval_policy = "never"` pre-authorizes
//     EVERY contributor's Codex to run arbitrary commands with full disk/network and no
//     human in the loop (analogous to CI-1's committed broad-tool pre-authorization).
// Static, parse-only, never executed. Never throws (bad TOML → []).

import { parse as parseToml } from 'smol-toml';
import { analyzeMcpServers, type McpServerSpec } from './mcp';
import type { CiFinding } from './types';

interface CodexConfig {
  mcp_servers?: Record<string, McpServerSpec>;
  sandbox_mode?: unknown;
  approval_policy?: unknown;
}

export function analyzeCodexConfig(path: string, content: string): CiFinding[] {
  let cfg: CodexConfig;
  try {
    cfg = parseToml(content) as CodexConfig;
  } catch {
    return []; // unparseable TOML — fail-open, like the JSON analyzers
  }
  const findings: CiFinding[] = [];

  // CI-3 — MCP servers (reuse the exact `.mcp.json` danger model).
  findings.push(...analyzeMcpServers(cfg.mcp_servers ?? {}, path));

  // CI-1 — autonomy settings. `danger-full-access` (arbitrary cmds, full disk/network) is
  // catastrophic → high; `never` approval alone is bounded (a sandbox may still constrain
  // it) → medium; both compound → high.
  const sandbox = typeof cfg.sandbox_mode === 'string' ? cfg.sandbox_mode : '';
  const approval = typeof cfg.approval_policy === 'string' ? cfg.approval_policy : '';
  const fullAccess = /danger-full-access/i.test(sandbox);
  const noApproval = /^never$/i.test(approval);
  if (fullAccess || noApproval) {
    const signals = [
      fullAccess
        ? 'sandbox_mode = "danger-full-access" — the agent runs arbitrary commands with full disk + network access'
        : null,
      noApproval ? 'approval_policy = "never" — no human approval for agent actions' : null,
    ].filter((s): s is string => s !== null);
    findings.push({
      check: 'CI-1',
      dimension: 'toolRules',
      severity: fullAccess ? 'high' : 'medium',
      title: fullAccess
        ? 'Codex config grants a full-access sandbox'
        : 'Codex config never requires approval',
      file: path,
      signals,
      fix: 'Commit a least-privilege Codex config: prefer `sandbox_mode = "read-only"` (or `"workspace-write"`) and `approval_policy = "on-request"`/`"on-failure"`. A repo-committed config applies to every contributor who runs Codex here.',
    });
  }

  return findings;
}
