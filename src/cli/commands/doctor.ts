// src/cli/commands/doctor.ts
// Registered as `node9 doctor` by cli.ts.
import type { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { execSync } from 'child_process';
import { isDaemonRunning, probeDaemonHealth, DAEMON_PORT, DAEMON_HOST } from '../../auth/daemon';
import { CURRENT_BUILD, describeBuildDrift } from '../../daemon/build-id';
import { getConfig } from '../../config';
import { getAgentWiring } from '../../agent-wiring';
import { readSyncHealth, isPolicyStale } from '../../daemon/sync';
import {
  isDaemonServiceInstalled,
  isDaemonServiceEnabled,
  autostartAdvice,
} from '../../daemon/service';
import { agoLabel } from '../../lib/relative-time';
import { readStartupCause } from '../../daemon/startup-log';

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
        warn('node9 not found in $PATH — hooks may not find it', 'Run: npm install -g node9-ai');
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
      // Every supported agent comes from the shared agent-wiring registry, so
      // doctor and status can't drift (doctor used to check only 3 of them).
      section('Agent Hooks');

      // Driven purely by each agent's settings file (wireState) — deterministic
      // and machine-independent (no PATH probing). Absent agents collapse into
      // one summary line so a fresh machine isn't a wall of warnings.
      const notConfigured: string[] = [];
      for (const a of getAgentWiring(homeDir)) {
        const anyHookWired = a.hooks.some((h) => h.wired);
        if (a.isProtected) {
          // Protected via hooks OR an MCP proxy entry — name which so an
          // MCP-only agent (Cursor) reads correctly instead of "not configured".
          pass(`${a.label} — ${anyHookWired ? `${a.hookLabel} active` : 'MCP proxy active'}`);
        } else if (a.wireState === 'invalid') {
          fail(`${a.label} — settings file is invalid JSON`, a.settingsPath);
        } else if (a.wireState === 'unwired') {
          // Hook file exists but the node9 hook is missing — a real gap.
          fail(`${a.label} — settings found but node9 hook missing`, `Run: ${a.setupCommand}`);
        } else {
          notConfigured.push(a.label); // absent and not MCP-protected
        }
      }
      if (notConfigured.length > 0) {
        console.log(
          chalk.gray(
            `     · Not configured: ${notConfigured.join(', ')} — run \`node9 agents add <agent>\` if you use one`
          )
        );
      }

      // ── Daemon ───────────────────────────────────────────────────────────────
      section('Daemon (optional)');
      if (isDaemonRunning()) {
        pass(
          `Daemon running on ${DAEMON_HOST}:${DAEMON_PORT} — terminal & native approvals enabled`
        );
        // Build drift (task #18): the running daemon may predate the installed
        // build — then it is ENFORCING old code, and `systemctl restart`
        // silently no-ops because the port is held. Surface it here; the
        // takeover/restart fix lands in commit (b).
        const probe = await probeDaemonHealth();
        const drift = describeBuildDrift(
          probe.kind === 'health' ? probe.health : probe.kind === 'no-health' ? 'no-health' : null,
          CURRENT_BUILD
        );
        if (drift) {
          warn(
            drift,
            'Stop the running daemon (pid in ~/.node9/daemon.pid), then: node9 daemon --background'
          );
        }
      } else {
        warn(
          'Daemon not running — terminal & native approvals unavailable',
          'Run: node9 daemon --background'
        );
        // …and WHY, if the last start attempt left a trace. Without this the crash
        // capture in daemon-startup.log has no reader: the diagnostic exists but
        // stays undiscovered, which is most of the way back to a silent failure.
        // A detail line on the warning above — deliberately not a second warn()
        // (it isn't a second finding) and never a fail() (a dead daemon still
        // enforces cached policy, so doctor's exit code must not flip).
        const cause = readStartupCause();
        if (cause) {
          // Carry the age: the window is 24h, so without it a cause from
          // yesterday morning reads as though it just happened.
          // `detail` is optional on a recorded failure, so only append the dash when
          // there is something after it.
          const suffix = cause.detail ? ` — ${cause.detail}` : '';
          // No parentheses around the age: the label supplies its own grammar
          // ("last start attempt 5 min ago" / "start attempts failing since 5 min
          // ago"), and a fixed "(…)" reads wrong for the second.
          console.log(
            chalk.gray(
              `       ${cause.label} ${agoLabel(cause.at.toISOString())}: ${cause.kind}${suffix}`
            )
          );
        }
        // Deliberately NOT reporting "autostart is enabled but the daemon is down"
        // as a startup failure: after a clean `systemctl --user stop` or the 12h
        // idle-exit the state correctly reads 'ok', so that message would accuse a
        // failure that provably did not happen. A daemon killed at module load
        // under systemd is genuinely indistinguishable from a deliberate stop by
        // this file alone — its stack is in the journal
        // (`journalctl --user -u node9-daemon`), not here. A known gap is better
        // than a confident wrong answer.
      }
      // Autostart health — the installed-but-disabled state that silently staled
      // policy for 6 days. warn (not fail) so a still-enforcing machine's doctor
      // exit code doesn't flip red; Commit 1's `Policy sync STALE` is the "now" signal.
      const autostart = autostartAdvice({
        installed: isDaemonServiceInstalled(),
        enabled: isDaemonServiceEnabled(),
        cloudEnabled: !!getConfig().settings.approvers?.cloud,
      });
      if (autostart) warn(autostart.message, autostart.hint);

      // ── Policy sync freshness ─────────────────────────────────────────────────
      // A daemon that isn't running (or a sync that keeps failing) means this
      // machine can enforce a days-old cloud policy with no signal. Keyed off
      // lastCheckedAt (last successful contact) — NOT the cache's fetchedAt, which
      // is ambiguous under 304s (policy-sync-fix-spec.md D3).
      // Only when this machine actually enforces cloud policy (approvers.cloud) —
      // a privacy-mode user (approvers.cloud=false) intentionally never syncs, so
      // "STALE" would be a false alarm contradicting the privacy-mode-is-fine
      // message below. Mirrors status.ts's gating.
      if (
        fs.existsSync(path.join(os.homedir(), '.node9', 'credentials.json')) &&
        getConfig().settings.approvers?.cloud
      ) {
        section('Policy sync');
        const health = readSyncHealth();
        if (isPolicyStale(Date.now(), health)) {
          const when = health.lastCheckedAt
            ? `last reached the cloud ${agoLabel(health.lastCheckedAt)}`
            : 'never reached the cloud';
          const fails =
            health.consecutiveFailures > 0
              ? ` (${health.consecutiveFailures} consecutive failure${
                  health.consecutiveFailures === 1 ? '' : 's'
                }${health.lastError ? `: ${health.lastError}` : ''})`
              : '';
          warn(
            `Cloud policy is STALE — ${when}${fails}. The cached policy is still enforced, but changes from the dashboard are not reaching this machine.`,
            'Run: node9 policy sync   (and ensure the daemon autostarts: systemctl --user enable --now node9-daemon)'
          );
        } else if (health.lastCheckedAt) {
          pass(`Cloud policy fresh — last synced ${agoLabel(health.lastCheckedAt)}`);
        }
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
