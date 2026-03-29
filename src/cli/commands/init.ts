// src/cli/commands/init.ts
// Registered as `node9 init` by cli.ts.
import type { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { DEFAULT_CONFIG } from '../../core';
import { setupClaude, setupGemini, setupCursor, detectAgents } from '../../setup';

export function registerInitCommand(program: Command): void {
  program
    .command('init')
    .description('Set up Node9: create config and wire all detected AI agents')
    .option('--force', 'Overwrite existing config')
    .option('-m, --mode <mode>', 'Set initial security mode (standard, strict, audit)', 'standard')
    .option('--skip-setup', 'Only create config — do not wire AI agents')
    .action(async (options: { force?: boolean; mode: string; skipSetup?: boolean }) => {
      console.log(chalk.cyan.bold('\n🛡️  Node9 Init\n'));

      // ── Step 1: Create config ──────────────────────────────────────────────
      const configPath = path.join(os.homedir(), '.node9', 'config.json');

      if (fs.existsSync(configPath) && !options.force) {
        console.log(chalk.blue(`ℹ️  Config already exists: ${configPath}`));
      } else {
        const requestedMode = options.mode.toLowerCase();
        const safeMode = ['standard', 'strict', 'audit'].includes(requestedMode)
          ? requestedMode
          : DEFAULT_CONFIG.settings.mode;

        const configToSave = {
          ...DEFAULT_CONFIG,
          settings: { ...DEFAULT_CONFIG.settings, mode: safeMode },
        };

        const dir = path.dirname(configPath);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(configPath, JSON.stringify(configToSave, null, 2));

        console.log(chalk.green(`✅ Config created: ${configPath}`));
        console.log(chalk.gray(`   Mode: ${safeMode}`));
      }

      if (options.skipSetup) return;

      // ── Step 2: Auto-detect and wire agents ────────────────────────────────
      console.log('');
      const detected = detectAgents();
      const found = (Object.keys(detected) as Array<keyof typeof detected>).filter(
        (k) => detected[k]
      );

      if (found.length === 0) {
        console.log(
          chalk.gray('No AI agents detected. Install Claude Code, Gemini CLI, or Cursor')
        );
        console.log(chalk.gray('then run: node9 addto <claude|gemini|cursor>'));
        return;
      }

      console.log(chalk.bold('Detected agents:'));
      for (const agent of found) {
        console.log(chalk.green(`  ✓ ${agent}`));
      }
      console.log('');

      for (const agent of found) {
        console.log(chalk.bold(`Wiring ${agent}...`));
        if (agent === 'claude') await setupClaude();
        else if (agent === 'gemini') await setupGemini();
        else if (agent === 'cursor') await setupCursor();
        console.log('');
      }

      console.log(chalk.green.bold('🛡️  Node9 is ready!'));
      console.log(chalk.gray('   Run: node9 daemon start'));
    });
}
