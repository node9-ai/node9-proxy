// src/cli/commands/init.ts
// Registered as `node9 init` by cli.ts.
import type { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import path from 'path';
import os from 'os';
import https from 'https';
import { DEFAULT_CONFIG } from '../../core';
import {
  setupClaude,
  setupGemini,
  setupAntigravity,
  setupCopilot,
  setupCursor,
  setupCodex,
  setupWindsurf,
  setupVSCode,
  setupClaudeDesktop,
  setupOpencode,
  setupPi,
  setupHermes,
  detectAgents,
  node9Version,
} from '../../setup';
import { readActiveShields, writeActiveShields, migrateRenamedRuleKeys } from '../../shields';
import { installDaemonService, isDaemonServiceInstalled } from '../../daemon/service';
import { autoStartDaemonAndWait, isTestingMode } from '../daemon-starter';

// Three universally-applicable shields. Why these specifically:
//   - bash-safe   — blocks curl|bash, rm -rf /, eval-of-remote. Universal value.
//   - filesystem  — blocks writes to /etc, /boot, /usr, chmod 777. Universal value.
//   - project-jail — blocks reads of ~/.ssh, ~/.aws, ~/.gcloud, .env. Directly
//                    addresses the most common credential-leak finding.
//
// Domain-specific shields (postgres, mongodb, aws, k8s, github, docker, redis,
// mcp-tool-gating) are left for users to enable on demand — enabling them by
// default would create false positives for users who don't use those services.
const DEFAULT_SHIELDS = ['bash-safe', 'filesystem', 'project-jail'];

export interface TelemetryPayload {
  event: 'init_completed';
  agents_detected: string[];
  os: string;
  node9_version: string;
  first_install: boolean;
}

/**
 * Build the install-telemetry payload. Exported so the unit test can
 * pin the shape — including that `node9_version` resolves to a real
 * version string, not the literal 'unknown' (which is what the prior
 * `process.env.npm_package_version` read returned for global CLI
 * installs, since npm only populates that env var for `npm run …`).
 */
export function buildTelemetryPayload(agents: string[], firstInstall: boolean): TelemetryPayload {
  return {
    event: 'init_completed',
    agents_detected: agents,
    os: process.platform,
    node9_version: node9Version(),
    first_install: firstInstall,
  };
}

function fireTelemetryPing(agents: string[], firstInstall: boolean): void {
  try {
    const body = JSON.stringify(buildTelemetryPayload(agents, firstInstall));
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
    .option(
      '-m, --mode <mode>',
      'Initial security mode: standard | strict | audit | observe (logs would-block, never blocks)',
      'standard'
    )
    .option('--skip-setup', 'Only create config — do not wire AI agents')
    .option(
      '--recommended',
      'Non-interactive: enable bash-safe + filesystem + project-jail shields without prompting'
    )
    .action(
      async (options: {
        force?: boolean;
        mode: string;
        skipSetup?: boolean;
        recommended?: boolean;
      }) => {
        console.log(chalk.cyan.bold('\n🛡️  Node9 Init\n'));

        // ── Step 0: One-shot migrations ───────────────────────────────────────
        // Rename old rule keys in the user's shields.json overrides to their
        // current names. Silent no-op when nothing needs rewriting; logs one
        // line per migration when it does. Must run before any shield read so
        // overrides resolve correctly downstream.
        {
          const migrated = migrateRenamedRuleKeys();
          for (const m of migrated) {
            console.log(chalk.dim(`  🔧 Rule renamed: ${m.oldKey} → ${m.newKey}`));
          }
        }

        // ── Step 1: Shields prompt → determines mode ───────────────────────────
        let chosenMode = options.mode.toLowerCase();
        if (!['standard', 'strict', 'audit', 'observe'].includes(chosenMode)) {
          chosenMode = DEFAULT_CONFIG.settings.mode;
        }

        {
          // --recommended skips the prompt entirely. Useful for scripted
          // installs (`npm install -g node9-ai && node9 init --recommended`)
          // and for users who've seen the scan output and want protection
          // without making N yes/no decisions about shields they don't recognize.
          let enableShields: boolean;
          if (options.recommended) {
            enableShields = true;
            console.log(
              chalk.dim(
                '  Recommended mode: enabling bash-safe + filesystem + project-jail shields'
              )
            );
          } else {
            const { confirm } = await import('@inquirer/prompts');
            enableShields = await confirm({
              message:
                'Enable recommended safety shields? (blocks rm -rf, credential reads, pipe-to-shell)',
              default: true,
            });
          }
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
        // Captured BEFORE the create/update branch so the telemetry payload
        // can distinguish first-time installs from re-runs of `node9 init`.
        // `--force` overwrites an existing config but is still a re-install
        // (the machine has run node9 before), so it counts as `false`.
        const isFirstInstall = !fs.existsSync(configPath);

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
            chalk.gray(
              'No AI agents detected. Install one of the supported agents (Claude Code, Codex, Antigravity, Gemini CLI, GitHub Copilot CLI, Cursor, Windsurf, VSCode, Claude Desktop, Opencode, Pi, or Hermes Agent).'
            )
          );
          console.log(
            chalk.gray(
              'then run: node9 agents add <claude|codex|antigravity|gemini|copilot|cursor|windsurf|vscode|claudeDesktop|opencode|pi|hermes>'
            )
          );
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
          else if (agent === 'antigravity') await setupAntigravity();
          else if (agent === 'copilot') await setupCopilot();
          else if (agent === 'cursor') await setupCursor();
          else if (agent === 'codex') await setupCodex();
          else if (agent === 'windsurf') await setupWindsurf();
          else if (agent === 'vscode') await setupVSCode();
          else if (agent === 'claudeDesktop') await setupClaudeDesktop();
          else if (agent === 'opencode') await setupOpencode();
          else if (agent === 'pi') await setupPi();
          else if (agent === 'hermes') setupHermes();
          console.log('');
        }

        // ── Step 4: Install daemon as login service ────────────────────────────
        // Only prompt on platforms that support it and when not already installed.
        // In non-interactive environments (CI, pipes) we skip silently.
        if (
          (process.platform === 'darwin' || process.platform === 'linux') &&
          process.stdout.isTTY
        ) {
          const alreadyInstalled = isDaemonServiceInstalled();
          if (!alreadyInstalled) {
            const { confirm } = await import('@inquirer/prompts');
            const installService = await confirm({
              message: 'Install daemon as a login service? (starts automatically on login)',
              default: true,
            });
            if (installService) {
              const result = installDaemonService();
              if (result.ok) {
                console.log(
                  chalk.green(`  ✓ Daemon installed as login service (${result.platform})`)
                );
              } else {
                console.log(chalk.yellow(`  ⚠️  Could not install service: ${result.reason}`));
                console.log(chalk.gray('     You can try again later with: node9 daemon install'));
              }
            }
          } else {
            console.log(chalk.green('  ✓ Daemon login service already installed'));
          }

          // Start the daemon right now so protection is immediate — don't make
          // the user wait for next login or run node9 tail manually.
          if (!isTestingMode()) {
            process.stdout.write(chalk.dim('  Starting daemon...'));
            const started = await autoStartDaemonAndWait();
            if (started) {
              process.stdout.write(
                '\r' + chalk.green('  ✓ Daemon started — protection is active') + '\n'
              );
            } else {
              process.stdout.write(
                '\r' + chalk.dim('  Daemon will start on next login         ') + '\n'
              );
            }
          }
          console.log('');
        }

        // ── Step 5: Telemetry opt-in ───────────────────────────────────────────
        {
          const { confirm } = await import('@inquirer/prompts');
          const sendTelemetry = await confirm({
            message: 'Send anonymous usage stats to help improve node9? (no code, no args)',
            default: true,
          });
          if (sendTelemetry) fireTelemetryPing(found, isFirstInstall);
          console.log('');
        }

        // ── Summary ────────────────────────────────────────────────────────────
        const agentList = found.join(', ');
        console.log(chalk.green.bold(`🛡️  Node9 is protecting ${agentList}!`));
        console.log('');
        console.log(chalk.white('  Watch live:  ') + chalk.cyan('node9 monitor'));
        console.log('');
        console.log(chalk.gray('  ─────────────────────────────────────────────────'));
        console.log(
          chalk.white('  Team dashboard + full audit trail → ') +
            chalk.cyan.bold('https://node9.ai')
        );
        console.log(chalk.gray('  ─────────────────────────────────────────────────'));
      }
    );
}
