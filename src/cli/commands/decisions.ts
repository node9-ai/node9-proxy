// src/cli/commands/decisions.ts
// `node9 decisions list / clear` — manage persistent "Always Allow" /
// "Always Deny" entries from the CLI.
//
// Replaces the local browser dashboard's decisions panel (retired in
// the v3 browser-removal sprint). Reads/writes ~/.node9/decisions.json
// directly — no daemon round-trip needed; the file is the source of
// truth and the orchestrator re-reads it on every check.

import type { Command } from 'commander';
import fs from 'fs';
import os from 'os';
import path from 'path';
import chalk from 'chalk';

const DECISIONS_FILE = path.join(os.homedir(), '.node9', 'decisions.json');

type Decision = 'allow' | 'deny';
type DecisionMap = Record<string, Decision>;

function readDecisions(): DecisionMap {
  try {
    if (!fs.existsSync(DECISIONS_FILE)) return {};
    const raw = fs.readFileSync(DECISIONS_FILE, 'utf-8');
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const out: DecisionMap = {};
    for (const [k, v] of Object.entries(parsed)) {
      if (v === 'allow' || v === 'deny') out[k] = v;
    }
    return out;
  } catch {
    return {};
  }
}

function writeDecisions(d: DecisionMap): void {
  const dir = path.dirname(DECISIONS_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  // Atomic write — same approach as the daemon. The orchestrator reads
  // the file on every authorization, so a torn write would surface as
  // a parse error and a (correctly fail-open) "no persistent decision".
  const tmp = `${DECISIONS_FILE}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(d, null, 2));
  fs.renameSync(tmp, DECISIONS_FILE);
}

export function registerDecisionsCommand(program: Command): void {
  const cmd = program
    .command('decisions')
    .description('Manage persistent "Always Allow" / "Always Deny" tool decisions');

  cmd
    .command('list')
    .description('Print every persistent decision for the current user')
    .action(() => {
      const decisions = readDecisions();
      const entries = Object.entries(decisions);
      if (entries.length === 0) {
        console.log(chalk.gray('  No persistent decisions stored.'));
        console.log(
          chalk.gray(`  File: ${DECISIONS_FILE}\n`) +
            chalk.gray('  Decisions are written when you click "Always Allow" or')
        );
        console.log(chalk.gray('  "Always Deny" in node9 tail or the native popup.'));
        return;
      }
      console.log(chalk.bold(`\nPersistent decisions  (${entries.length})\n`));
      const w = Math.max(...entries.map(([k]) => k.length));
      for (const [tool, verdict] of entries.sort()) {
        const colored = verdict === 'allow' ? chalk.green(verdict) : chalk.red(verdict);
        console.log(`  ${tool.padEnd(w)}  ${colored}`);
      }
      console.log(
        chalk.gray(`\n  Stored in ${DECISIONS_FILE}\n`) +
          chalk.gray('  Run `node9 decisions clear <tool>` to remove an entry.')
      );
    });

  cmd
    .command('clear <toolName>')
    .description('Remove a persistent decision for one tool')
    .action((toolName: string) => {
      const decisions = readDecisions();
      if (!(toolName in decisions)) {
        console.log(chalk.yellow(`  No persistent decision for "${toolName}". Nothing to clear.`));
        process.exitCode = 1;
        return;
      }
      delete decisions[toolName];
      writeDecisions(decisions);
      console.log(chalk.green(`  ✓ Cleared persistent decision for "${toolName}".`));
    });

  cmd
    .command('clear-all')
    .description('Remove every persistent decision (irreversible)')
    .action(() => {
      const decisions = readDecisions();
      const count = Object.keys(decisions).length;
      if (count === 0) {
        console.log(chalk.gray('  Nothing to clear — no persistent decisions stored.'));
        return;
      }
      writeDecisions({});
      console.log(
        chalk.green(`  ✓ Cleared ${count} persistent decision${count === 1 ? '' : 's'}.`)
      );
    });
}
