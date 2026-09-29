// src/ci-check/mcp.ts
// CI-3 — committed .mcp.json. Flags unpinned executable servers (supply-chain)
// and inline credential values (reusing the DLP scanner). Static, parse-only.

import { explainMcp } from './explain';
import { scanText } from '@node9/policy-engine';
import { lineAtIndex } from './lines';
import type { CiFinding } from './types';
import { safeText } from './suppress';

// The WHOLE command: `npx [-y] tsx ./file.ts [plain args]`; `${CLAUDE_PLUGIN_ROOT}/` is the plugin's
// own folder, set by Claude Code. Anchored, with no shell operator, so
// `sh -c "npx evil@latest; npx tsx ./a.ts"` is not excused by its tail.
const LOCAL_RUNNER_RE =
  /^npx\s+(?:-y\s+|--yes\s+)?(?:tsx|ts-node|node)\s+(?:\.{1,2}\/|\$\{CLAUDE_PLUGIN_ROOT\}\/)?[\w@./-]+\.(?:m?[jt]s|cjs)(?:\s+[^\s;&|`$<>()]+)*$/;

export interface McpServerSpec {
  command?: string;
  args?: unknown[];
  url?: string;
  env?: Record<string, unknown>;
  disabled?: boolean;
}

export function analyzeMcp(path: string, content: string): CiFinding[] {
  let cfg: { mcpServers?: Record<string, McpServerSpec> };
  try {
    cfg = JSON.parse(content);
  } catch {
    return [];
  }
  return analyzeMcpServers(cfg.mcpServers ?? {}, path, content);
}

/** Score a normalized MCP server map. Shared by `.mcp.json` (CI-3) and Codex's
 *  `.codex/config.toml` `[mcp_servers.*]` (1c-A) — same danger model, different
 *  container: an unpinned executable server = supply-chain risk; an inline credential
 *  in `env` = an agent-reachable secret committed to the repo. */
export function analyzeMcpServers(
  servers: Record<string, McpServerSpec>,
  path: string,
  content = ''
): CiFinding[] {
  const findings: CiFinding[] = [];
  for (const [name, srv] of Object.entries(servers ?? {})) {
    if (!srv || srv.disabled) continue;
    const argv = [srv.command, ...(Array.isArray(srv.args) ? srv.args.map(String) : [])].join(' ');
    // Both CI-3 rules anchor at the server's name: `"name":` in JSON, `[mcp_servers.name]`
    // (or a dotted key) in TOML. Unknown → no line, never a wrong one.
    const esc = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const at = content.search(
      new RegExp(`"${esc}"\\s*:|^[ \\t]*\\[mcp_servers\\.(?:"${esc}"|${esc})\\]`, 'm')
    );
    const line = at >= 0 ? lineAtIndex(content, at) : undefined;

    // Unpinned executable server. A runner started on a file in the repository (`npx tsx
    // ./server.ts`) runs local code: only the runner is unversioned, not the server (§Q).
    if (
      /\bnpx\b/.test(argv) &&
      (/@latest\b/.test(argv) || !/@\d/.test(argv)) &&
      !LOCAL_RUNNER_RE.test(argv)
    ) {
      findings.push({
        check: 'CI-3',
        rule: 'CI-3.mcp-unpinned',
        locator: name,
        dimension: 'mcp',
        severity: 'medium',
        title: `MCP server "${name}" runs an unpinned executable`,
        file: path,
        ...(line ? { line } : {}),
        signals: [`\`${safeText(argv, 120)}\`: unversioned/@latest npx`],
        fix: 'Pin the MCP server package to an exact version so a PR (or a registry compromise) can’t swap the toolchain.',
        explain: explainMcp({ name, argv }),
      });
    }

    // Inline credential value in env.
    for (const [k, v] of Object.entries(srv.env ?? {})) {
      if (typeof v !== 'string') continue;
      const hit = scanText(v);
      if (hit) {
        findings.push({
          check: 'CI-3',
          rule: 'CI-3.mcp-inline-credential',
          locator: `${name}.env.${k}`,
          dimension: 'mcp',
          severity: 'high',
          title: `MCP server "${name}" has an inline credential`,
          file: path,
          ...(line ? { line } : {}),
          signals: [
            `env.${k} matches ${hit.patternName}: agent-reachable secret committed to the repo`,
          ],
          fix: 'Move the value to an env var reference (${VAR}) resolved at launch; never commit the secret.',
        });
      }
    }
  }
  return findings;
}
