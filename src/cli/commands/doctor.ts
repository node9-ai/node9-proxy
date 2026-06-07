// src/cli/commands/doctor.ts
// Registered as `node9 doctor` by cli.ts.
import type { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { execSync } from 'child_process';
import { isDaemonRunning, DAEMON_PORT, DAEMON_HOST } from '../../auth/daemon';
import { getConfig } from '../../config';

export function registerDoctorCommand(program: Command, version: string): void {
  program
    .command('doctor')
    .description('Check that Node9 is installed and configured correctly')
    .action(async () => {
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
        pass(
          `Daemon running on ${DAEMON_HOST}:${DAEMON_PORT} — terminal & native approvals enabled`
        );
      } else {
        warn(
          'Daemon not running — terminal & native approvals unavailable',
          'Run: node9 daemon --background'
        );
      }

      // ── Cloud audit shipping ──────────────────────────────────────────────────
      // The outbox shipper is what makes dashboard numbers match the local
      // report — surface its health so "cloud shows 0" is never a mystery.
      section('Cloud audit shipping');
      try {
        const { shipLagBytes, readWatermark, AUDIT_SHIP_WATERMARK } =
          await import('../../daemon/audit-shipper.js');
        const cfg = getConfig();
        const creds = fs.existsSync(path.join(os.homedir(), '.node9', 'credentials.json'));
        if (!creds) {
          warn('Not logged in — audit rows stay local', 'Run: node9 login <api-key>');
        } else if (!cfg.settings.approvers.cloud) {
          warn(
            'Cloud approvals OFF (settings.approvers.cloud=false) — nothing syncs to the dashboard',
            'Privacy mode is a valid choice; set approvers.cloud=true to sync.'
          );
        } else if (cfg.settings.shipper.enabled === false) {
          warn('Shipper disabled (settings.shipper.enabled=false) — audit rows stay local');
        } else {
          const lag = shipLagBytes();
          const wm = readWatermark(AUDIT_SHIP_WATERMARK);
          if (lag === 0) {
            pass('Audit shipping caught up — dashboard matches the local log');
          } else if (wm && lag !== null) {
            const ageMin = Math.round((Date.now() - new Date(wm.updatedAt).getTime()) / 60_000);
            if (ageMin > 5 && !isDaemonRunning()) {
              warn(
                `${Math.round(lag / 1024)} KB of audit rows not shipped (last ship ${ageMin}m ago)`,
                'The daemon ships every ~20s — start it: node9 daemon --background'
              );
            } else {
              pass(
                `Shipping in progress — ${Math.round(lag / 1024)} KB queued, last ship ${ageMin}m ago`
              );
            }
          } else {
            warn(
              'Shipper has never run on this machine — dashboard may lag the local log',
              'Start the daemon: node9 daemon --background'
            );
          }
        }
      } catch (err) {
        warn(`Shipping status unavailable: ${(err as Error).message}`);
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
