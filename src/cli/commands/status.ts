// src/cli/commands/status.ts
// Registered as `node9 status` by cli.ts.
import type { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { getCredentials, getConfig, checkPause } from '../../core';
import { isDaemonRunning, DAEMON_PORT } from '../../auth/daemon';
import { getAgentWiring } from '../../agent-wiring';
import { readSyncHealth, isPolicyStale } from '../../daemon/sync';
import {
  isDaemonServiceInstalled,
  isDaemonServiceEnabled,
  autostartAdvice,
} from '../../daemon/service';
import { agoLabel } from '../../lib/relative-time';

// Renders one agent's wiring: a header, ✓/✗ rows for each hook event, and the
// MCP-proxied server list (omitted when the agent has no MCP surface). Hook +
// MCP data come from the shared agent-wiring registry.
function printAgentSection(
  label: string,
  hookPairs: Array<{ name: string; present: boolean }>,
  wrapped: string[] | null // null = agent has no MCP surface → omit the line
): void {
  console.log(chalk.bold(`  ${label}`));
  for (const { name, present } of hookPairs) {
    if (present) {
      console.log(chalk.green(`    ✓ ${name}`));
    } else {
      console.log(chalk.red(`    ✗ ${name}`) + chalk.gray(' (not wired)'));
    }
  }
  if (wrapped === null) return;
  if (wrapped.length > 0) {
    console.log(chalk.cyan(`    MCP proxied:`));
    for (const entry of wrapped) {
      console.log(chalk.gray(`      • ${entry}`));
    }
  } else {
    console.log(chalk.gray(`    MCP proxied: none`));
  }
}

export function registerStatusCommand(program: Command): void {
  program
    .command('status')
    .description('Show current Node9 mode, policy source, and persistent decisions')
    .action(() => {
      const creds = getCredentials();
      const daemonRunning = isDaemonRunning();

      // Grab the fully resolved waterfall config!
      const mergedConfig = getConfig();
      const settings = mergedConfig.settings;

      console.log('');

      // ── Policy authority ────────────────────────────────────────────────────
      if (creds && settings.approvers.cloud) {
        console.log(chalk.green('  ● Agent mode') + chalk.gray(' — cloud team policy enforced'));
        // Policy-sync freshness: a stale/failing sync means this machine may be
        // enforcing an out-of-date cloud policy. Surfacing it is the whole point
        // of the sync-health fix (policy-sync-fix-spec.md D3).
        const health = readSyncHealth();
        if (isPolicyStale(Date.now(), health)) {
          const when = health.lastCheckedAt
            ? `last synced ${agoLabel(health.lastCheckedAt)}`
            : 'never synced';
          const fails =
            health.consecutiveFailures > 0
              ? ` · ${health.consecutiveFailures} failed attempt${
                  health.consecutiveFailures === 1 ? '' : 's'
                }${health.lastError ? ` (${health.lastError})` : ''}`
              : '';
          console.log(chalk.yellow('    ⚠ Policy sync STALE') + chalk.gray(` — ${when}${fails}`));
          console.log(chalk.gray('      the cached policy is still enforced — run: node9 doctor'));
        } else if (health.lastCheckedAt) {
          console.log(chalk.gray(`    ↳ policy synced ${agoLabel(health.lastCheckedAt)}`));
        }
      } else if (creds && !settings.approvers.cloud) {
        console.log(
          chalk.blue('  ● Privacy mode 🛡️') + chalk.gray(' — all decisions stay on this machine')
        );
      } else {
        console.log(
          chalk.yellow('  ○ Privacy mode 🛡️') + chalk.gray(' — no API key (Local rules only)')
        );
      }

      // ── Daemon & Architecture ────────────────────────────────────────────────
      console.log('');
      if (daemonRunning) {
        console.log(
          chalk.green('  ● Daemon running') + chalk.gray(` → http://127.0.0.1:${DAEMON_PORT}/`)
        );
      } else {
        console.log(chalk.gray('  ○ Daemon stopped'));
      }
      // Autostart health — same DECISION as doctor (autostartAdvice: gated on
      // cloud + installable platform), rendered compactly here to avoid drift.
      const autostart = autostartAdvice({
        installed: isDaemonServiceInstalled(),
        enabled: isDaemonServiceEnabled(),
        cloudEnabled: !!(creds && settings.approvers.cloud),
      });
      if (autostart) {
        console.log(
          chalk.yellow('    ⚠ daemon autostart not active') +
            chalk.gray(" — won't survive reboot; run: node9 doctor")
        );
      }

      if (settings.enableUndo) {
        console.log(
          chalk.magenta('  ● Undo Engine') +
            chalk.gray(`    → Auto-snapshotting Git repos on AI change`)
        );
      }

      // ── Configuration State ──────────────────────────────────────────────────
      console.log('');
      const modeLabel =
        settings.mode === 'audit'
          ? chalk.blue('audit')
          : settings.mode === 'strict'
            ? chalk.red('strict')
            : chalk.white('standard');
      console.log(`  Mode:    ${modeLabel}`);

      const projectConfig = path.join(process.cwd(), 'node9.config.json');
      const globalConfig = path.join(os.homedir(), '.node9', 'config.json');
      console.log(
        `  Local:   ${fs.existsSync(projectConfig) ? chalk.green('Active (node9.config.json)') : chalk.gray('Not present')}`
      );
      console.log(
        `  Global:  ${fs.existsSync(globalConfig) ? chalk.green('Active (~/.node9/config.json)') : chalk.gray('Not present')}`
      );

      if (mergedConfig.policy.sandboxPaths.length > 0) {
        console.log(
          `  Sandbox: ${chalk.green(`${mergedConfig.policy.sandboxPaths.length} safe zones active`)}`
        );
      }

      // ── Agent wiring ─────────────────────────────────────────────────────────
      // Sourced from the shared agent-wiring registry (src/agent-wiring.ts) so
      // status and doctor can't drift. Show every agent with a footprint on the
      // machine (config file / install dir); render its hook events + MCP surface.
      const wiring = getAgentWiring(os.homedir()).filter((a) => a.present);

      if (wiring.length > 0) {
        console.log('');
        console.log(chalk.bold('  Agent Wiring:'));
        console.log('');
        for (const a of wiring) {
          // A present-but-unparseable config must not silently vanish the
          // section — that's exactly when the user needs to see it's unwired.
          if (a.wireState === 'invalid') {
            console.error(
              chalk.yellow(
                `  ⚠️  ${a.label} config at ${a.settingsPath} is not valid ${a.configFormat} — showing as unwired.`
              )
            );
          }
          printAgentSection(
            a.label,
            a.hooks.map((h) => ({ name: h.label, present: h.wired })),
            a.mcpServers
          );
          console.log('');
        }
      }

      // ── Pause state ──────────────────────────────────────────────────────────
      const pauseState = checkPause();
      if (pauseState.paused) {
        const expiresAt = pauseState.expiresAt
          ? new Date(pauseState.expiresAt).toLocaleTimeString()
          : 'indefinitely';
        console.log('');
        console.log(
          chalk.yellow(`  ⏸  PAUSED until ${expiresAt}`) + chalk.gray(' — all tool calls allowed')
        );
      }

      console.log('');
    });
}
