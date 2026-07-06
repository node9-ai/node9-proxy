// src/cli/commands/scan-repo.ts
// Registered as `node9 scan-repo <url|path>` by cli.ts.
//
// Scans a repo's AGENT-SECURITY surface (committed .claude/.mcp.json/agentic
// workflows) — from a public GitHub URL (Contents API, no clone) or a local
// path. Config-only + static: it never fetches or executes repo source.
// Read-only / classification-only, like `node9 posture`.

import type { Command } from 'commander';
import { scanRepo } from '../../ci-check';
import { renderScan, renderScanMarkdown, exitCodeFor } from '../../ci-check/render';

export function registerScanRepoCommand(program: Command): void {
  program
    .command('scan-repo <target>')
    .description("Scan a repo's agent-security surface (GitHub URL or local path)")
    .option('--json', 'emit the raw result as JSON')
    .option('--markdown', 'emit a Markdown report (for a PR comment)')
    .action(async (target: string, opts: { json?: boolean; markdown?: boolean }) => {
      const res = await scanRepo(target);
      if (opts.json) {
        console.log(JSON.stringify(res, null, 2));
      } else if (opts.markdown) {
        console.log(renderScanMarkdown(res));
      } else {
        console.log(renderScan(res));
      }
      // Non-zero when a real risk is present, so CI/scripts can gate.
      process.exitCode = exitCodeFor(res);
    });
}
