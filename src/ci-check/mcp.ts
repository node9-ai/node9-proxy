// src/ci-check/mcp.ts
// CI-3 — committed .mcp.json. Flags unpinned executable servers (supply-chain)
// and inline credential values (reusing the DLP scanner). Static, parse-only.

import { scanText } from '@node9/policy-engine';
import type { CiFinding } from './types';

interface McpServer {
  command?: string;
  args?: unknown[];
  url?: string;
  env?: Record<string, unknown>;
  disabled?: boolean;
}

export function analyzeMcp(path: string, content: string): CiFinding[] {
  let cfg: { mcpServers?: Record<string, McpServer> };
  try {
    cfg = JSON.parse(content);
  } catch {
    return [];
  }
  const findings: CiFinding[] = [];
  for (const [name, srv] of Object.entries(cfg.mcpServers ?? {})) {
    if (!srv || srv.disabled) continue;
    const argv = [srv.command, ...(Array.isArray(srv.args) ? srv.args.map(String) : [])].join(' ');

    // Unpinned executable server.
    if (/\bnpx\b/.test(argv) && (/@latest\b/.test(argv) || !/@\d/.test(argv))) {
      findings.push({
        check: 'CI-3',
        dimension: 'mcp',
        severity: 'medium',
        title: `MCP server "${name}" runs an unpinned executable`,
        file: path,
        signals: [`\`${argv.slice(0, 120)}\` — unversioned/@latest npx`],
        fix: 'Pin the MCP server package to an exact version so a PR (or a registry compromise) can’t swap the toolchain.',
      });
    }

    // Inline credential value in env.
    for (const [k, v] of Object.entries(srv.env ?? {})) {
      if (typeof v !== 'string') continue;
      const hit = scanText(v);
      if (hit) {
        findings.push({
          check: 'CI-3',
          dimension: 'mcp',
          severity: 'high',
          title: `MCP server "${name}" has an inline credential`,
          file: path,
          signals: [
            `env.${k} matches ${hit.patternName} — agent-reachable secret committed to the repo`,
          ],
          fix: 'Move the value to an env var reference (${VAR}) resolved at launch; never commit the secret.',
        });
      }
    }
  }
  return findings;
}
