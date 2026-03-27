// src/cli/commands/doctor.ts
// Registered as `node9 doctor` by cli.ts.
import type { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { execSync } from 'child_process';
import { isDaemonRunning, DAEMON_PORT, DAEMON_HOST } from '../../auth/daemon';

export function registerDoctorCommand(program: Command, version: string): void {
  program
    .command('doctor')
    .description('Check that Node9 is installed and configured correctly')
    .action(() => {
      const homeDir = os.homedir();
      let failures = 0;

      function pass(msg: string) {
        console.log(chalk.green('  ✅ ') + msg);
      }
      function fail(msg: string, hint?: string) {
        console.log(chalk.red('  ❌ ') + msg);
        if (hint) console.log(chalk.gray('       ' + hint));
        failures++;
      }
      function warn(msg: string, hint?: string) {
        console.log(chalk.yellow('  ⚠️  ') + msg);
        if (hint) console.log(chalk.gray('       ' + hint));
      }
      function section(title: string) {
        console.log('\n' + chalk.bold(title));
      }

      console.log(chalk.cyan.bold(`\n🛡️  Node9 Doctor  v${version}\n`));

      // ── Binary ───────────────────────────────────────────────────────────────
      section('Binary');
      try {
        const which = execSync('which node9', { encoding: 'utf-8', timeout: 3000 }).trim();
        pass(`node9 found at ${which}`);
      } catch {
        warn(
          'node9 not found in $PATH — hooks may not find it',
          'Run: npm install -g @node9/proxy'
        );
      }

      const nodeMajor = parseInt(process.versions.node.split('.')[0], 10);
      if (nodeMajor >= 18) {
        pass(`Node.js ${process.versions.node}`);
      } else {
        fail(
          `Node.js ${process.versions.node} (requires ≥18)`,
          'Upgrade Node.js: https://nodejs.org'
        );
      }

      try {
        const gitVersion = execSync('git --version', { encoding: 'utf-8', timeout: 3000 }).trim();
        pass(gitVersion);
      } catch {
        warn(
          'git not found — Undo Engine will be disabled',
          'Install git to enable snapshot-based undo'
        );
      }

      // ── Config ───────────────────────────────────────────────────────────────
      section('Configuration');
      const globalConfigPath = path.join(homeDir, '.node9', 'config.json');
      if (fs.existsSync(globalConfigPath)) {
        try {
          JSON.parse(fs.readFileSync(globalConfigPath, 'utf-8'));
          pass('~/.node9/config.json found and valid');
        } catch {
          fail('~/.node9/config.json is invalid JSON', 'Run: node9 init --force');
        }
      } else {
        warn('~/.node9/config.json not found (using defaults)', 'Run: node9 init');
      }

      const projectConfigPath = path.join(process.cwd(), 'node9.config.json');
      if (fs.existsSync(projectConfigPath)) {
        try {
          JSON.parse(fs.readFileSync(projectConfigPath, 'utf-8'));
          pass('node9.config.json found and valid (project)');
        } catch {
          fail(
            'node9.config.json is invalid JSON',
            'Fix the JSON or delete it and run: node9 init'
          );
        }
      }

      const credsPath = path.join(homeDir, '.node9', 'credentials.json');
      if (fs.existsSync(credsPath)) {
        pass('Cloud credentials found (~/.node9/credentials.json)');
      } else {
        warn(
          'No cloud credentials — running in local-only mode',
          'Run: node9 login <apiKey>  (or skip for local-only)'
        );
      }

      // ── Hooks ────────────────────────────────────────────────────────────────
      section('Agent Hooks');

      // Claude
      const claudeSettingsPath = path.join(homeDir, '.claude', 'settings.json');
      if (fs.existsSync(claudeSettingsPath)) {
        try {
          const cs = JSON.parse(fs.readFileSync(claudeSettingsPath, 'utf-8')) as {
            hooks?: { PreToolUse?: Array<{ hooks: Array<{ command?: string }> }> };
          };
          const hasHook = cs.hooks?.PreToolUse?.some((m) =>
            m.hooks.some((h) => h.command?.includes('node9') || h.command?.includes('cli.js'))
          );
          if (hasHook) pass('Claude Code — PreToolUse hook active');
          else
            fail(
              'Claude Code — hooks file found but node9 hook missing',
              'Run: node9 setup claude'
            );
        } catch {
          fail('Claude Code — ~/.claude/settings.json is invalid JSON');
        }
      } else {
        warn('Claude Code — not configured', 'Run: node9 setup claude');
      }

      // Gemini
      const geminiSettingsPath = path.join(homeDir, '.gemini', 'settings.json');
      if (fs.existsSync(geminiSettingsPath)) {
        try {
          const gs = JSON.parse(fs.readFileSync(geminiSettingsPath, 'utf-8')) as {
            hooks?: { BeforeTool?: Array<{ hooks: Array<{ command?: string }> }> };
          };
          const hasHook = gs.hooks?.BeforeTool?.some((m) =>
            m.hooks.some((h) => h.command?.includes('node9') || h.command?.includes('cli.js'))
          );
          if (hasHook) pass('Gemini CLI  — BeforeTool hook active');
          else
            fail(
              'Gemini CLI  — hooks file found but node9 hook missing',
              'Run: node9 setup gemini'
            );
        } catch {
          fail('Gemini CLI  — ~/.gemini/settings.json is invalid JSON');
        }
      } else {
        warn('Gemini CLI  — not configured', 'Run: node9 setup gemini  (skip if not using Gemini)');
      }

      // Cursor
      const cursorHooksPath = path.join(homeDir, '.cursor', 'hooks.json');
      if (fs.existsSync(cursorHooksPath)) {
        try {
          const cur = JSON.parse(fs.readFileSync(cursorHooksPath, 'utf-8')) as {
            hooks?: { preToolUse?: Array<{ command?: string }> };
          };
          const hasHook = cur.hooks?.preToolUse?.some(
            (h) => h.command?.includes('node9') || h.command?.includes('cli.js')
          );
          if (hasHook) pass('Cursor      — preToolUse hook active');
          else
            fail(
              'Cursor      — hooks file found but node9 hook missing',
              'Run: node9 setup cursor'
            );
        } catch {
          fail('Cursor      — ~/.cursor/hooks.json is invalid JSON');
        }
      } else {
        warn('Cursor      — not configured', 'Run: node9 setup cursor  (skip if not using Cursor)');
      }

      // ── Daemon ───────────────────────────────────────────────────────────────
      section('Daemon (optional)');
      if (isDaemonRunning()) {
        pass(`Browser dashboard running → http://${DAEMON_HOST}:${DAEMON_PORT}/`);
      } else {
        warn(
          'Daemon not running — browser approvals unavailable',
          'Run: node9 daemon --background'
        );
      }

      // ── Summary ───────────────────────────────────────────────────────────────
      console.log('');
      if (failures === 0) {
        console.log(chalk.green.bold('  All checks passed. Node9 is ready.\n'));
      } else {
        console.log(chalk.red.bold(`  ${failures} check(s) failed. See hints above.\n`));
        process.exit(1);
      }
    });
}
