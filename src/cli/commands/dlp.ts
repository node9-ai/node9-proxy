// src/cli/commands/dlp.ts
// Registered as `node9 dlp` by cli.ts.
// Shows response-DLP findings (secrets detected in Claude response text)
// and lets the user mark them resolved.

import type { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import path from 'path';
import os from 'os';

const AUDIT_LOG = path.join(os.homedir(), '.node9', 'audit.log');
const RESOLVED_FILE = path.join(os.homedir(), '.node9', 'dlp-resolved.json');

interface DlpEntry {
  ts: string;
  source: string;
  dlpPattern?: string;
  dlpSample?: string;
  project?: string;
}

const ANSI_RE = /\x1b(?:\[[0-9;?]*[a-zA-Z]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-_])/g;
function stripAnsi(s: string): string {
  return s.replace(ANSI_RE, '');
}

function loadResolved(): Set<string> {
  try {
    const raw = JSON.parse(fs.readFileSync(RESOLVED_FILE, 'utf-8')) as string[];
    return new Set(raw);
  } catch {
    return new Set();
  }
}

function saveResolved(resolved: Set<string>): void {
  try {
    fs.writeFileSync(RESOLVED_FILE, JSON.stringify([...resolved], null, 2), { mode: 0o600 });
  } catch {}
}

function loadDlpFindings(): DlpEntry[] {
  if (!fs.existsSync(AUDIT_LOG)) return [];
  return fs
    .readFileSync(AUDIT_LOG, 'utf-8')
    .split('\n')
    .flatMap((line) => {
      if (!line.trim()) return [];
      try {
        const e = JSON.parse(line) as DlpEntry;
        return e.source === 'response-dlp' ? [e] : [];
      } catch {
        return [];
      }
    });
}

function entryKey(e: DlpEntry): string {
  return `${e.ts}:${e.dlpPattern}:${e.dlpSample}`;
}

function fmtDate(ts: string): string {
  try {
    return new Date(ts).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  } catch {
    return ts.slice(0, 10);
  }
}

export function registerDlpCommand(program: Command): void {
  const cmd = program
    .command('dlp')
    .description('Show secrets detected in Claude response text and mark them resolved');

  cmd
    .command('resolve')
    .description('Mark all current DLP findings as resolved')
    .action(() => {
      const findings = loadDlpFindings();
      if (findings.length === 0) {
        console.log(chalk.green('\n  ✅ No response-DLP findings to resolve.\n'));
        return;
      }
      const resolved = loadResolved();
      for (const e of findings) resolved.add(entryKey(e));
      saveResolved(resolved);
      console.log(
        chalk.green(
          `\n  ✅ ${findings.length} finding${findings.length !== 1 ? 's' : ''} marked as resolved.\n`
        )
      );
    });

  cmd.action(() => {
    const findings = loadDlpFindings();
    const resolved = loadResolved();
    const open = findings.filter((e) => !resolved.has(entryKey(e)));
    const resolvedCount = findings.length - open.length;

    console.log('');
    console.log(
      chalk.bold.cyan('🔐  node9 dlp') + chalk.dim('  — secrets found in Claude response text')
    );
    console.log('');

    if (open.length === 0) {
      if (resolvedCount > 0) {
        console.log(chalk.green(`  ✅ No open findings  ·  ${resolvedCount} previously resolved`));
      } else {
        console.log(
          chalk.green('  ✅ No findings — Claude has not leaked secrets in response text')
        );
      }
      console.log('');
      return;
    }

    console.log(
      chalk.bgRed.white.bold(` ⚠️  ${open.length} open finding${open.length !== 1 ? 's' : ''} `) +
        chalk.dim(resolvedCount > 0 ? `  (${resolvedCount} resolved)` : '')
    );
    console.log('');
    console.log(
      chalk.dim("  These secrets were included in Claude's response text — NOT blocked.")
    );
    console.log(chalk.dim('  Rotate each affected key immediately.\n'));

    for (const e of open) {
      console.log(
        '  ' +
          chalk.red('●') +
          '  ' +
          chalk.white(e.dlpPattern ?? 'Secret') +
          chalk.dim('  ' + fmtDate(e.ts))
      );
      if (e.dlpSample) {
        console.log('     ' + chalk.dim('Sample: ') + chalk.yellow(stripAnsi(e.dlpSample)));
      }
      if (e.project) {
        console.log('     ' + chalk.dim('Project: ') + chalk.dim(stripAnsi(e.project)));
      }
      console.log('');
    }

    console.log('  ' + chalk.bold('Next steps:'));
    console.log('  ' + chalk.cyan('1.') + ' Rotate any exposed keys shown above');
    console.log(
      '  ' + chalk.cyan('2.') + ' Run ' + chalk.white('node9 dlp resolve') + ' to acknowledge'
    );
    console.log(
      '  ' + chalk.cyan('3.') + ' Run ' + chalk.white('node9 report') + ' for full audit history'
    );
    console.log('');
  });
}
