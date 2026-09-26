// src/cli/commands/scan-repo.ts
// Registered as `node9 scan-repo <url|path>` by cli.ts.
//
// Scans a repo's AGENT-SECURITY surface (committed .claude/.mcp.json/agentic
// workflows) — from a public GitHub URL (Contents API, no clone) or a local
// path. Config-only + static: it never fetches or executes repo source.
// Read-only / classification-only, like `node9 posture`.

import type { Command } from 'commander';
import chalk from 'chalk';
import { scanRepo, scanTree, type OnProgress } from '../../ci-check';
import { readGitRefTree } from '../../ci-check/fetch';
import { diffScans } from '../../ci-check/diff';
import {
  renderScan,
  renderScanMarkdown,
  exitCodeFor,
  exitCodeForSeverity,
} from '../../ci-check/render';
import type { ScanDiff } from '../../ci-check/types';

const SPIN = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

/** A best-effort stderr spinner (TTY only; suppressed under --json/--markdown so
 *  the machine-readable stdout stays clean). Returns a done() to clear it. */
function makeProgress(
  target: string,
  quiet: boolean
): { onProgress: OnProgress; done: () => void } {
  if (quiet || !process.stderr.isTTY) {
    return { onProgress: () => {}, done: () => {} };
  }
  let frame = 0;
  let last = `scanning ${target}…`;
  const timer = setInterval(() => {
    process.stderr.write(`\r${chalk.cyan(SPIN[frame++ % SPIN.length])} ${last}   `);
  }, 80);
  return {
    onProgress: (p) => {
      last = p.total > 1 ? `${p.phase} ${p.done}/${p.total}` : p.phase;
    },
    done: () => {
      clearInterval(timer);
      process.stderr.write('\r' + ' '.repeat(last.length + 6) + '\r');
    },
  };
}

export function registerScanRepoCommand(program: Command): void {
  program
    .command('scan-repo <target>')
    .description("Scan a repo's agent-security surface (GitHub URL or local path)")
    .option('--json', 'emit the raw result as JSON')
    .option('--markdown', 'emit a Markdown report (for a PR comment)')
    .option(
      '--base <ref>',
      'also scan this git ref and report what the working tree INTRODUCED (local path targets only)'
    )
    .option(
      '--fail-on-introduced',
      'exit non-zero only for findings this change introduced (requires --base)'
    )
    .action(
      async (
        target: string,
        opts: { json?: boolean; markdown?: boolean; base?: string; failOnIntroduced?: boolean }
      ) => {
        const { onProgress, done } = makeProgress(target, !!(opts.json || opts.markdown));
        let res;
        try {
          res = await scanRepo(target, onProgress);
        } finally {
          done();
        }

        // CI-5: what did THIS change introduce? A base tree that cannot be read yields a
        // null base, which `diffScans` degrades to the absolute answer — never to a
        // false "nothing new".
        let diff: ScanDiff | undefined;
        if (opts.base) {
          const baseTree = readGitRefTree(target, opts.base);
          diff = diffScans(baseTree ? scanTree(baseTree) : null, res);
          // ONE truth for every consumer (the JSON the Action reads, the renderers, the exit
          // code): the head as the gate must see it. A suppression added in the same change
          // is not honoured in the default gate either — `worst` is replaced, not just
          // `worstIntroduced` (design G.1, 2026-09-27).
          res = {
            ...res,
            findings: diff.honoured,
            worst: diff.worstAll,
            ...(res.suppressions
              ? { suppressedCount: diff.honoured.filter((f) => f.suppressed).length }
              : {}),
          };
        }

        // A pull-request runner with no --base (an older Action ref, a hand-written workflow,
        // `node9-version: latest` under an action that predates CI-5) cannot show that any
        // suppression predates the PR, so none is honoured — the file is PR-controlled
        // (review H.5, 2026-09-27). A local run, or a push event, applies the file as written.
        if (!opts.base && process.env.GITHUB_BASE_REF && res.suppressedCount) {
          const strict = diffScans(null, res);
          res = {
            ...res,
            findings: strict.honoured,
            worst: strict.worstAll,
            suppressedCount: 0,
            notes: [
              ...res.notes,
              'running on a pull request without --base: no suppression can be shown to predate it — none honoured. Pass --base <base sha> to honour suppressions that existed before this PR.',
            ],
          };
        }

        if (opts.json) {
          console.log(JSON.stringify(diff ? { ...res, diff } : res, null, 2));
        } else if (opts.markdown) {
          console.log(renderScanMarkdown(res, diff));
        } else {
          console.log(renderScan(res, diff));
        }

        // Non-zero when a real risk is present, so CI/scripts can gate. `--fail-on-introduced`
        // narrows WHICH findings are judged; it does not change the severity policy, so it
        // runs through the same exit-code law — a medium blocks (or does not) identically
        // either way. `incomplete` is carried through: a scan that could not read every
        // file still exits 3, because "nothing introduced" would then be a statement about
        // what we read rather than about the change.
        process.exitCode =
          opts.failOnIntroduced && diff
            ? exitCodeForSeverity(diff.worstIntroduced, diff.incomplete)
            : exitCodeFor(res);
      }
    );
}
