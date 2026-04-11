// src/cli/commands/init.ts
// Registered as `node9 init` by cli.ts.
import type { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import path from 'path';
import os from 'os';
import https from 'https';
import { DEFAULT_CONFIG } from '../../core';
import { setupClaude, setupGemini, setupCursor, setupCodex, detectAgents } from '../../setup';
import { readActiveShields, writeActiveShields } from '../../shields';

const DEFAULT_SHIELDS = ['bash-safe', 'filesystem', 'postgres'];

function fireTelemetryPing(agents: string[]): void {
  try {
    const body = JSON.stringify({
      event: 'init_completed',
      agents_detected: agents,
      os: process.platform,
      node9_version: process.env.npm_package_version ?? 'unknown',
    });
    const req = https.request(
      {
        hostname: 'api.node9.ai',
        path: '/api/v1/telemetry',
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
        timeout: 3000,
      },
      (res) => {
        res.resume();
      }
    );
    req.on('error', () => {
      /* best-effort, never crash */
    });
    req.on('timeout', () => {
      req.destroy();
    });
    req.end(body);
  } catch {
    /* ignore */
  }
}

export function registerInitCommand(program: Command): void {
  program
    .command('init')
    .description('Set up Node9: create config and wire all detected AI agents')
    .option('--force', 'Overwrite existing config')
    .option('-m, --mode <mode>', 'Set initial security mode (standard, strict, audit)', 'standard')
    .option('--skip-setup', 'Only create config — do not wire AI agents')
    .action(async (options: { force?: boolean; mode: string; skipSetup?: boolean }) => {
      console.log(chalk.cyan.bold('\n🛡️  Node9 Init\n'));

      // ── Step 1: Shields prompt → determines mode ───────────────────────────
      let chosenMode = options.mode.toLowerCase();
      if (!['standard', 'strict', 'audit'].includes(chosenMode)) {
        chosenMode = DEFAULT_CONFIG.settings.mode;
      }

      {
        const { confirm } = await import('@inquirer/prompts');
        const enableShields = await confirm({
          message: 'Enable recommended safety shields? (blocks rm -rf, SQL drops, pipe-to-shell)',
          default: true,
        });
        if (enableShields) {
          chosenMode = 'standard';
          // Activate default shields — merge with any already-active shields
          try {
            const current = readActiveShields();
            const merged = Array.from(new Set([...current, ...DEFAULT_SHIELDS]));
            const hasNewShields = DEFAULT_SHIELDS.some((s) => !current.includes(s));
            if (hasNewShields) writeActiveShields(merged);
          } catch (err) {
            console.log(chalk.yellow(`  ⚠️  Could not update shields: ${String(err)}`));
          }
        }
        console.log('');
      }

      // ── Step 2: Create or update config ───────────────────────────────────
      const configPath = path.join(os.homedir(), '.node9', 'config.json');

      if (fs.existsSync(configPath) && !options.force) {
        // Update mode in existing config to reflect shields choice
        try {
          const existing = JSON.parse(fs.readFileSync(configPath, 'utf-8')) as Record<
            string,
            unknown
          >;
          const settings = (existing.settings ?? {}) as Record<string, unknown>;
          if (settings.mode !== chosenMode) {
            settings.mode = chosenMode;
            existing.settings = settings;
            fs.writeFileSync(configPath, JSON.stringify(existing, null, 2) + '\n');
            console.log(chalk.green(`✅ Mode updated: ${chosenMode}`));
          } else {
            console.log(chalk.blue(`ℹ️  Config already exists: ${configPath}`));
          }
        } catch {
          console.log(chalk.blue(`ℹ️  Config already exists: ${configPath}`));
        }
      } else {
        const configToSave = {
          ...DEFAULT_CONFIG,
          settings: { ...DEFAULT_CONFIG.settings, mode: chosenMode },
        };

        const dir = path.dirname(configPath);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(configPath, JSON.stringify(configToSave, null, 2) + '\n');

        console.log(chalk.green(`✅ Config created: ${configPath}`));
        console.log(chalk.gray(`   Mode: ${chosenMode}`));
      }

      if (options.skipSetup) return;

      // ── Step 3: Auto-detect and wire agents ────────────────────────────────
      console.log('');
      const detected = detectAgents();
      const found = (Object.keys(detected) as Array<keyof typeof detected>).filter(
        (k) => detected[k]
      );

      if (found.length === 0) {
        console.log(
          chalk.gray('No AI agents detected. Install Claude Code, Gemini CLI, Cursor, or Codex')
        );
        console.log(chalk.gray('then run: node9 addto <claude|gemini|cursor|codex>'));
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
        else if (agent === 'codex') await setupCodex();
        console.log('');
      }

      // ── Step 4: Telemetry opt-in ───────────────────────────────────────────
      {
        const { confirm } = await import('@inquirer/prompts');
        const sendTelemetry = await confirm({
          message: 'Send anonymous usage stats to help improve node9? (no code, no args)',
          default: true,
        });
        if (sendTelemetry) fireTelemetryPing(found);
        console.log('');
      }

      // ── Summary ────────────────────────────────────────────────────────────
      const agentList = found.join(', ');
      console.log(chalk.green.bold(`🛡️  Node9 is protecting ${agentList}!`));
      console.log('');
      console.log(chalk.white('  Watch live:  ') + chalk.cyan('node9 tail'));
      console.log(chalk.white('  Local UI:    ') + chalk.cyan('node9 daemon --openui'));
      console.log('');
      console.log(chalk.gray('  ─────────────────────────────────────────────────'));
      console.log(
        chalk.white('  Team dashboard + full audit trail → ') + chalk.cyan.bold('https://node9.ai')
      );
      console.log(chalk.gray('  ─────────────────────────────────────────────────'));
    });
}
