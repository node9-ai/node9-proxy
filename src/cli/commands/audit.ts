// src/cli/commands/audit.ts
// Registered as `node9 audit` by cli.ts.
import type { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import path from 'path';
import os from 'os';

function formatRelativeTime(timestamp: string): string {
  const diff = Date.now() - new Date(timestamp).getTime();
  const sec = Math.floor(diff / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hrs = Math.floor(min / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return new Date(timestamp).toLocaleDateString();
}

export function registerAuditCommand(program: Command): void {
  program
    .command('audit')
    .description('View local execution audit log')
    .option('--tail <n>', 'Number of entries to show', '20')
    .option('--tool <pattern>', 'Filter by tool name (substring match)')
    .option('--deny', 'Show only denied actions')
    .option('--json', 'Output raw JSON')
    .action((options: { tail: string; tool?: string; deny?: boolean; json?: boolean }) => {
      const logPath = path.join(os.homedir(), '.node9', 'audit.log');
      if (!fs.existsSync(logPath)) {
        console.log(
          chalk.yellow('No audit logs found. Run node9 with an agent to generate entries.')
        );
        return;
      }

      const raw = fs.readFileSync(logPath, 'utf-8');
      const lines = raw.split('\n').filter((l) => l.trim() !== '');

      let entries = lines.flatMap((line) => {
        try {
          return [JSON.parse(line)];
        } catch {
          return [];
        }
      });

      // Normalize decision field — some older entries use "allowed"/"denied"
      entries = entries.map((e) => ({
        ...e,
        decision: String(e.decision).startsWith('allow') ? 'allow' : 'deny',
      }));

      if (options.tool) entries = entries.filter((e) => String(e.tool).includes(options.tool!));
      if (options.deny) entries = entries.filter((e) => e.decision === 'deny');

      const limit = Math.max(1, parseInt(options.tail, 10) || 20);
      entries = entries.slice(-limit);

      if (options.json) {
        console.log(JSON.stringify(entries, null, 2));
        return;
      }

      if (entries.length === 0) {
        console.log(chalk.yellow('No matching audit entries.'));
        return;
      }

      console.log(
        `\n  ${chalk.bold('Node9 Audit Log')}  ${chalk.dim(`(${entries.length} entries)`)}`
      );
      console.log(chalk.dim('  ' + '─'.repeat(65)));
      console.log(
        `  ${'Time'.padEnd(12)} ${'Tool'.padEnd(18)} ${'Result'.padEnd(10)} ${'By'.padEnd(15)} Agent`
      );
      console.log(chalk.dim('  ' + '─'.repeat(65)));

      for (const e of entries) {
        const time = formatRelativeTime(String(e.ts)).padEnd(12);
        const tool = String(e.tool).slice(0, 17).padEnd(18);
        const result =
          e.decision === 'allow' ? chalk.green('ALLOW'.padEnd(10)) : chalk.red('DENY'.padEnd(10));
        const checker = String(e.checkedBy || 'unknown')
          .slice(0, 14)
          .padEnd(15);
        const agent = String(e.agent || 'unknown');
        console.log(`  ${time} ${tool} ${result} ${checker} ${agent}`);
      }

      const allowed = entries.filter((e) => e.decision === 'allow').length;
      const denied = entries.filter((e) => e.decision === 'deny').length;
      console.log(chalk.dim('  ' + '─'.repeat(65)));
      console.log(
        `  ${entries.length} entries  |  ${chalk.green(allowed + ' allowed')}  |  ${chalk.red(denied + ' denied')}\n`
      );
    });
}
