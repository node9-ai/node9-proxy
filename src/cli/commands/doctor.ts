// src/cli/commands/doctor.ts
// Registered as `node9 doctor` by cli.ts.
import type { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { execSync } from 'child_process';
import { isDaemonRunning, probeDaemonHealth, DAEMON_PORT, DAEMON_HOST } from '../../auth/daemon';
import { CURRENT_BUILD, buildIdString, describeBuildDrift } from '../../daemon/build-id';
import { readRefreshStamp } from '../../daemon/refresh-stamp';
import { getConfig } from '../../config';
import { getAgentWiring } from '../../agent-wiring';
import { assessCodexTrust, codexTrustInstruction } from '../../codex-trust';
import { deadClaudeNode9Hooks } from '../../setup';
import { readSyncHealth, isPolicyStale } from '../../daemon/sync';
import {
  isDaemonServiceInstalled,
  isDaemonServiceEnabled,
  autostartAdvice,
  autostartInstallHint,
} from '../../daemon/service';
import { agoLabel } from '../../lib/relative-time';
import { readStartupCause } from '../../daemon/startup-log';
import { undoLeftoverPaths } from '../../utils/undo-leftovers';
import { locatorCommand } from '../../utils/platform-shell';
import { mcpLaunchHealth, readMcpNodeFailures, launcherState } from '../../mcp-launch-health';
import { pinsNode } from '../../node9-shim';
import { describeHookErrorPolicy, readHookErrorPolicy, recentHookErrors } from '../../hook-error';

/**
 * Did the cloud REJECT this machine's key? A 401 in the sync-health record is
 * not a network problem — the key was revoked (disconnected from the
 * dashboard, the member removed from the workspace, or `node9 logout`), and
 * every cloud channel using it fails together. doctor already had this
 * evidence and printed it as a raw "API returned 401", leaving the founder to
 * work out that it meant "this machine is disconnected" (QA 2026-08-29).
 */
function keyRejected(health: { consecutiveFailures: number; lastError?: string }): boolean {
  return health.consecutiveFailures > 0 && /\b401\b/.test(health.lastError ?? '');
}

/** Parsed JSON, or null when the file is missing or invalid. */
function readJsonFile(filePath: string): Record<string, unknown> | null {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf-8')) as Record<string, unknown>;
  } catch {
    return null;
  }
}

export function registerDoctorCommand(program: Command, version: string): void {
  program
    .command('doctor')
    .description('Check that Node9 is installed and configured correctly')
    .action(async () => {
      const homeDir = os.homedir();
      let failures = 0;
      let warnings = 0;

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
        warnings++;
      }
      function section(title: string) {
        console.log('\n' + chalk.bold(title));
      }

      console.log(chalk.cyan.bold(`\n🛡️  Node9 Doctor  v${version}\n`));

      // ── Binary ───────────────────────────────────────────────────────────────
      section('Binary');
      try {
        // `which` does not exist on Windows (founder QA 2026-08-28: doctor
        // printed a cmd error and claimed node9 was missing on a machine that
        // was literally running it). `where` may return several matches — the
        // first is what a shell would resolve.
        const found = execSync(`${locatorCommand()} node9`, {
          encoding: 'utf-8',
          timeout: 3000,
        })
          .split(/\r?\n/)[0]
          .trim();
        pass(`node9 found at ${found}`);
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
        // The undo wording that used to live here recommended git for a feature
        // that no longer exists. git is still checked on its own merits.
        warn('git not found', 'Install git — node9 reads repo state for scans and reports');
      }

      // ── Config ───────────────────────────────────────────────────────────────
      section('Configuration');
      // I3: name the policy source first — every "found and valid" line below
      // is about a file that a workspace-governed machine does NOT read for
      // policy, and doctor must not imply otherwise.
      const wsGoverned = getConfig().policySource === 'workspace';
      if (wsGoverned) {
        pass(
          'Policy source: workspace config (app.node9.ai) — local config files govern operational settings only'
        );
      }
      const globalConfigPath = path.join(homeDir, '.node9', 'config.json');
      if (fs.existsSync(globalConfigPath)) {
        try {
          JSON.parse(fs.readFileSync(globalConfigPath, 'utf-8'));
          pass(
            wsGoverned
              ? '~/.node9/config.json found and valid (policy fields ignored — workspace governs)'
              : '~/.node9/config.json found and valid'
          );
        } catch {
          fail('~/.node9/config.json is invalid JSON', 'Run: node9 init --force');
        }
      } else if (wsGoverned) {
        pass('~/.node9/config.json not present (workspace config governs)');
      } else {
        warn('~/.node9/config.json not found (using defaults)', 'Run: node9 init');
      }

      // ⚠️ A TOP-LEVEL check on purpose. The undo notice used to live inside the
      // `catch` of the git probe above, which meant it was invisible to anyone
      // who had git installed — i.e. to every user the feature ever worked for,
      // including the one whose disk it filled. A leftover store is exactly what
      // someone runs `doctor` to find, so it must not hide behind a branch.
      const undoLeftovers = undoLeftoverPaths(homeDir);
      if (undoLeftovers.length > 0) {
        warn(
          `undo removed — ${undoLeftovers.length} leftover snapshot ${
            undoLeftovers.length === 1 ? 'path' : 'paths'
          } still on disk`,
          'Remove them when ready: node9 undo --purge'
        );
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

      // node9Firewall#383: what happens when node9 itself fails on a call, and
      // how often it did. A check that did not run is a gap in what node9
      // guards, so it is a warning here even though each one is in the audit log.
      pass(describeHookErrorPolicy(readHookErrorPolicy(homeDir)));
      const notChecked = recentHookErrors(Date.now() - 7 * 24 * 60 * 60 * 1000, homeDir);
      if (notChecked.count > 0) {
        const ran = notChecked.count - notChecked.stopped;
        warn(
          `${notChecked.count} ${notChecked.count === 1 ? 'call was' : 'calls were'} not checked in the last 7 days because node9 failed` +
            ` (${ran} ran, ${notChecked.stopped} stopped)`,
          `Last: ${notChecked.last?.ts ?? ''} ${notChecked.last?.what ?? ''} · details: ~/.node9/hook-debug.log (event "hook-error")`
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
      const wiring = getAgentWiring(homeDir);
      for (const a of wiring) {
        const anyHookWired = a.hooks.some((h) => h.wired);
        if (a.isProtected && a.id === 'codex' && anyHookWired) {
          // A wired hook is not a running hook. Codex runs a hook only after
          // the user trusts it, trust is keyed to the file's content, and node9
          // rewrites that file on every init/add/self-heal. So "hook active"
          // used to be printed on machines where Codex was skipping every hook
          // — dogfound 2026-09-22 across two Windows boxes. Report what can be
          // observed, and never a tick for what cannot (codex-trust.ts).
          const t = assessCodexTrust(homeDir);
          const wrote = t.hooksWrittenAt ? agoLabel(t.hooksWrittenAt) : 'unknown';
          if (t.state === 'observed') {
            pass(
              `${a.label} — ${a.hookLabel} active and trusted (Codex activity seen ${agoLabel(
                t.lastCodexActivityAt as string
              )}, after the hooks were written)`
            );
          } else if (t.state === 'disabled') {
            fail(
              `${a.label} — hooks wired but DISABLED ([features].hooks = false in ~/.codex/config.toml)`,
              'Re-enable hooks in config.toml; until then only MCP proxy wrapping is active'
            );
          } else if (t.state === 'never-trusted') {
            fail(
              `${a.label} — hooks wired but Codex has never trusted them (no [hooks.state] in config.toml)`,
              codexTrustInstruction().trim()
            );
          } else {
            warn(
              `${a.label} — hooks written ${wrote}; no Codex activity has reached node9 since`,
              'Stale trust and "Codex not used since" look identical from here. If Codex has run since then, the hooks are NOT trusted:\n' +
                codexTrustInstruction()
            );
          }
        } else if (a.id === 'opencode' && !anyHookWired && fs.existsSync(a.settingsPath)) {
          // The file existing is not the plugin loading. A shim written before
          // #480 has only the OpenCode 1.x shape, and OpenCode 2.x refuses to
          // load it, so OpenCode 2 ran with no node9 checks while this line
          // printed a tick (issue #480). agent-wiring reads it as unwired, so
          // status agrees and the daemon's heal nudge fires.
          warn(
            `${a.label}: node9 plugin is outdated. OpenCode 2.x refuses to load it (OpenCode 1.x still runs it)`,
            `Run: ${a.setupCommand}`
          );
        } else if (a.isProtected) {
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
      // Dead node9 hooks next to a live one: Claude Code still checks every
      // call, but runs the dead entries too and prints an error each time
      // (#480). With no live PreToolUse hook left, agent-wiring already reads
      // Claude as unwired and the loop above fails it.
      const claude = wiring.find((a) => a.id === 'claude');
      const deadClaudeHooks = deadClaudeNode9Hooks(
        readJsonFile(path.join(homeDir, '.claude', 'settings.json'))
      );
      if (claude?.wireState === 'wired' && deadClaudeHooks.length > 0) {
        warn(
          `Claude Code: ${deadClaudeHooks.length} node9 hook(s) point at a file that no longer exists, so Claude Code prints an error on every tool call`,
          `Run: node9 agents add claude (it repairs or removes them). First one: ${deadClaudeHooks[0]}`
        );
      }
      if (notConfigured.length > 0) {
        console.log(
          chalk.gray(
            `     · Not configured: ${notConfigured.join(', ')} — run \`node9 agents add <agent>\` if you use one`
          )
        );
      }

      // ── MCP servers ───────────────────────────────────────────────────────────
      // node9's own MCP server and the servers it wrapped start node9 from the
      // agent's config. An entry written as the bare `node9` starts on the Node
      // the AGENT's PATH holds; under an old one node9 refuses to run, and the
      // agent says only "failed to connect". Nothing above this section can
      // see that: the entry is present, so the agent reads as protected.
      // POSIX only: the launcher these checks point to does not exist on Windows.
      if (process.platform !== 'win32') {
        const mcp = mcpLaunchHealth(homeDir);
        const failures = readMcpNodeFailures(homeDir);
        const launcher = launcherState(homeDir);
        // A node9 that is not JavaScript run by node (pnpm's wrapper, bun) has
        // no launcher to move entries to: telling its user to run heal would
        // name a fix that changes nothing.
        const canPin = pinsNode(process.execPath, process.argv[1] ?? '');
        const dependent = canPin ? mcp.pathDependent : [];
        if (mcp.total > 0 || failures) {
          section('MCP servers');
          const failedOn = failures
            ? `Node.js ${failures.version} (${failures.execPath}) is too old for node9`
            : '';
          const times = failures
            ? `${failures.partial ? 'at least ' : ''}${failures.count} time${failures.count === 1 ? '' : 's'}`
            : '';
          if (dependent.length > 0) {
            // One warning for the machine, not one per agent: the fix is one
            // command, and six agents would otherwise print six warnings.
            const n = dependent.reduce((sum, g) => sum + g.names.length, 0);
            warn(
              `${n} node9 MCP entr${n === 1 ? 'y starts' : 'ies start'} on whatever Node the agent's PATH holds`,
              [
                ...dependent.map((g) => `${g.agentLabel}: ${g.names.join(', ')}`),
                'Run: node9 heal   (moves them to ~/.node9/bin/node9, which pins the Node)',
              ].join('\n       ')
            );
          }
          if (launcher.state === 'stale' && mcp.onLauncher > 0) {
            warn(
              `The node9 launcher points at a Node or a node9 that no longer exists (${launcher.node ?? launcher.path}); MCP servers fall back to PATH's node`,
              'Run: node9 init'
            );
          }
          if (failures && (dependent.length > 0 || launcher.state === 'stale')) {
            fail(
              `node9's MCP entries failed to start ${times} in the last 7 days: ${failedOn}`,
              'Run: node9 heal   (then restart the agent)'
            );
          } else if (failures && failures.lastAt > mcp.newestConfigChange) {
            // Still failing after the last change to every config node9 reads,
            // and none of them holds an entry that depends on PATH.
            warn(
              `A node9 MCP entry failed to start ${times} in the last 7 days, last ${agoLabel(new Date(failures.lastAt).toISOString())}: ${failedOn}`,
              'No agent config node9 reads holds such an entry. A project-scoped server (.mcp.json, or a project in ~/.claude.json) may: start it through ~/.node9/bin/node9'
            );
          } else if (failures) {
            pass(
              `MCP entries failed to start on an old Node until ${agoLabel(new Date(failures.lastAt).toISOString())}; no entry depends on the agent's PATH now`
            );
          }
          const steady = mcp.onLauncher + mcp.pinnedByHand;
          if (steady > 0 && launcher.state !== 'stale') {
            const parts = [];
            if (mcp.onLauncher > 0) {
              parts.push(
                `${mcp.onLauncher} start${mcp.onLauncher === 1 ? 's' : ''} through ~/.node9/bin/node9${launcher.node ? ` (Node: ${launcher.node})` : ''}`
              );
            }
            if (mcp.pinnedByHand > 0) parts.push(`${mcp.pinnedByHand} pinned by hand`);
            pass(`node9 MCP entries: ${parts.join(', ')}`);
          }
        }
      }

      // ── Daemon ────────────────────────────────────────────────────────────────
      // "(optional)" only when this machine doesn't ship to the cloud. With
      // cloud on, the daemon carries policy sync AND the audit shipper — calling
      // it optional next to an empty dashboard is how a real outage read as
      // "all checks passed" (founder QA 2026-08-28).
      const cloudOn =
        fs.existsSync(path.join(homeDir, '.node9', 'credentials.json')) &&
        !!getConfig().settings.approvers?.cloud;
      section(cloudOn ? 'Daemon' : 'Daemon (optional)');
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
          // A hook of this build asks for a refresh by itself (`node9 daemon
          // refresh`). When that was tried and changed nothing, say why: the
          // bare restart hint would hide a cause the user has to act on.
          const refresh = readRefreshStamp(homeDir);
          const why = refresh?.build === buildIdString(CURRENT_BUILD) ? refresh.reason : undefined;
          warn(drift, why ? `Automatic refresh did not work: ${why}` : 'Run: node9 daemon restart');
        }
      } else {
        warn(
          cloudOn
            ? 'Daemon not running — approvals unavailable AND nothing ships to the dashboard until it starts (it auto-starts on agent activity)'
            : 'Daemon not running — terminal & native approvals unavailable',
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
        // A REJECTED key is checked before staleness, and independently of it:
        // being revoked is not a function of elapsed time. Nested inside the
        // stale branch (the first version of this fix), a machine disconnected
        // an hour ago still reported "Cloud policy fresh" until the staleness
        // clock — up to 15h — finally caught up.
        if (keyRejected(health)) {
          const when = health.lastCheckedAt
            ? `last reached the cloud ${agoLabel(health.lastCheckedAt)}`
            : 'never reached the cloud';
          warn(
            `This machine is DISCONNECTED — the cloud rejected its key (${when}, ` +
              `${health.consecutiveFailures} consecutive failure${health.consecutiveFailures === 1 ? '' : 's'}). ` +
              'It still enforces the cached policy, but nothing reaches or leaves the dashboard.',
            'Someone disconnected it from the dashboard, removed you from the workspace, or ran `node9 logout`. Reconnect with: node9 login'
          );
        } else if (isPolicyStale(Date.now(), health)) {
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
            // Platform-aware: this hint hardcoded systemctl and told a Windows
            // founder to run a Linux command (QA 2026-08-28).
            `Run: node9 policy sync   (then keep it fresh across reboots — ${autostartInstallHint()})`
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
          // I3: "set approvers.cloud=true" is LOCAL-FILE advice — on a
          // workspace-governed machine that file is inert for policy, so
          // point at the actual control instead.
          warn(
            'Cloud approvals OFF (settings.approvers.cloud=false) — nothing syncs to the dashboard',
            cfg.policySource === 'workspace'
              ? 'The workspace config turned this off — change it at app.node9.ai (Enforcement).'
              : 'Privacy mode is a valid choice; set approvers.cloud=true to sync.'
          );
        } else if (cfg.settings.shipper.enabled === false) {
          warn('Shipper disabled (settings.shipper.enabled=false) — audit rows stay local');
        } else {
          const lag = shipLagBytes();
          const wm = readWatermark(AUDIT_SHIP_WATERMARK);
          if (lag === 0 && isDaemonRunning()) {
            pass('Audit shipping caught up — dashboard matches the local log');
          } else if (lag === 0) {
            // Zero lag without a daemon is NOT "caught up" — nobody is
            // shipping. The claim "dashboard matches the local log" next to a
            // stopped daemon is how an empty dashboard read as healthy
            // (founder QA 2026-08-28). Say what is actually true.
            warn(
              'Nothing queued, but the daemon is not running — new activity will not reach the dashboard until it starts',
              'It auto-starts on agent activity, or run: node9 daemon --background'
            );
          } else if (wm && lag !== null) {
            const ageMin = Math.round((Date.now() - new Date(wm.updatedAt).getTime()) / 60_000);
            // STALLED is about the QUEUE, not the daemon. The old condition
            // warned only when the daemon was DOWN, so a running daemon that
            // could not ship printed "Shipping in progress" over 334 KB stuck
            // for 12 hours (founder QA 2026-08-29) — the same lie as the
            // caught-up branch above, one else-if over.
            // 15 min ≈ 45 failed 20s cycles: long enough that a laptop waking
            // from sleep mid-flush is never accused.
            const stalled = ageMin > 15;
            if (stalled) {
              const rejected = keyRejected(readSyncHealth());
              warn(
                `${Math.round(lag / 1024)} KB of audit rows NOT shipped (last ship ${ageMin}m ago)`,
                // The daemon's state decides the fix, not whether to warn.
                !isDaemonRunning()
                  ? 'The daemon ships every ~20s — start it: node9 daemon --background'
                  : rejected
                    ? "The daemon is running but the cloud rejects this machine's key — run: node9 login"
                    : 'The daemon is running but shipping is failing — see Policy sync above for the reason'
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
      // Warnings must reach the verdict line. "All checks passed" above two ⚠️
      // rows taught a founder that a machine with no daemon and no dashboard
      // data was healthy. Warnings still exit 0 — a warned machine keeps
      // enforcing — but the verdict may not contradict the findings.
      console.log('');
      if (failures > 0) {
        console.log(chalk.red.bold(`  ${failures} check(s) failed. See hints above.\n`));
        process.exit(1);
      } else if (warnings > 0) {
        console.log(
          chalk.yellow.bold(
            `  ${warnings} warning(s) — Node9 is working, but see the hints above.\n`
          )
        );
      } else {
        console.log(chalk.green.bold('  All checks passed. Node9 is ready.\n'));
      }
    });
}
