// src/cli/commands/agents.ts
// Registered as `node9 agents` by cli.ts.
import type { Command } from 'commander';
import chalk from 'chalk';
import {
  setupClaude,
  setupGemini,
  setupCursor,
  setupCodex,
  setupWindsurf,
  setupVSCode,
  teardownClaude,
  teardownGemini,
  teardownCursor,
  teardownCodex,
  teardownWindsurf,
  teardownVSCode,
  getAgentsStatus,
  type AgentName,
} from '../../setup';

const SETUP_FN: Record<AgentName, () => Promise<void> | void> = {
  claude: setupClaude,
  gemini: setupGemini,
  cursor: setupCursor,
  codex: setupCodex,
  windsurf: setupWindsurf,
  vscode: setupVSCode,
};

const TEARDOWN_FN: Record<AgentName, () => void> = {
  claude: teardownClaude,
  gemini: teardownGemini,
  cursor: teardownCursor,
  codex: teardownCodex,
  windsurf: teardownWindsurf,
  vscode: teardownVSCode,
};

const AGENT_NAMES = Object.keys(SETUP_FN) as AgentName[];

export function registerAgentsCommand(program: Command): void {
  const agents = program.command('agents').description('List and manage AI agent integrations');

  // ── list ──────────────────────────────────────────────────────────────────
  agents
    .command('list')
    .description('Show all supported agents and their Node9 status')
    .action(() => {
      const statuses = getAgentsStatus();
      const anyInstalled = statuses.some((s) => s.installed);

      console.log('');
      console.log(`  ${'Agent'.padEnd(14)}${'Installed'.padEnd(11)}${'Wired'.padEnd(8)}Mode`);
      console.log('  ' + '─'.repeat(44));

      for (const s of statuses) {
        const installed = s.installed ? chalk.green('✓') : chalk.gray('✗');
        const wired = !s.installed
          ? chalk.gray('—')
          : s.wired
            ? chalk.green('✓')
            : chalk.yellow('✗');
        const mode = s.mode ? chalk.gray(s.mode) : chalk.gray('—');
        const hint = s.installed && !s.wired ? chalk.gray(`  ← node9 agents add ${s.name}`) : '';
        // Use fixed-width columns without padEnd on colored strings (escape codes break alignment)
        console.log(`  ${s.label.padEnd(14)}${installed}          ${wired}       ${mode}${hint}`);
      }

      console.log('');

      if (!anyInstalled) {
        console.log(
          chalk.gray('  No AI agents detected. Install Claude Code, Gemini CLI, Cursor,\n') +
            chalk.gray('  Windsurf, VSCode, or Codex then run: node9 agents list\n')
        );
        return;
      }

      const unwired = statuses.filter((s) => s.installed && !s.wired);
      if (unwired.length > 0) {
        console.log(
          chalk.yellow(`  ${unwired.length} agent(s) not yet wired. Run: `) +
            chalk.white(`node9 agents add ${unwired[0].name}`) +
            '\n'
        );
      }
    });

  // ── add ───────────────────────────────────────────────────────────────────
  agents
    .command('add')
    .description('Wire Node9 into an agent')
    .argument('<agent>', `Agent to wire: ${AGENT_NAMES.join(' | ')}`)
    .action(async (agent: string) => {
      const name = agent.toLowerCase() as AgentName;
      const fn = SETUP_FN[name];
      if (!fn) {
        console.error(chalk.red(`Unknown agent: "${agent}". Supported: ${AGENT_NAMES.join(', ')}`));
        process.exit(1);
      }
      await fn();
    });

  // ── remove ────────────────────────────────────────────────────────────────
  agents
    .command('remove')
    .description('Remove Node9 from an agent')
    .argument('<agent>', `Agent to unwire: ${AGENT_NAMES.join(' | ')}`)
    .action((agent: string) => {
      const name = agent.toLowerCase() as AgentName;
      const fn = TEARDOWN_FN[name];
      if (!fn) {
        console.error(chalk.red(`Unknown agent: "${agent}". Supported: ${AGENT_NAMES.join(', ')}`));
        process.exit(1);
      }
      console.log(chalk.cyan(`\n🛡️  Node9: removing from ${name}...\n`));
      fn();
      console.log(chalk.gray('\n  Restart the agent for changes to take effect.'));
    });
}
