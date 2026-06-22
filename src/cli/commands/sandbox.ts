// src/cli/commands/sandbox.ts
// `node9 sandbox` — disposable jailed agent runtime (Phase 1 MVP).
// Registered by cli.ts next to posture/egress.

import type { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import path from 'path';
import { spawnSync } from 'child_process';
import { getConfig } from '../../config';
import type { SandboxAgent, SandboxConfig } from '../../sandbox/types';
import {
  loadSandboxConfig,
  scaffoldSandboxYaml,
  sandboxConfigPath,
  SANDBOX_CONFIG_FILE,
} from '../../sandbox/config';
import { compileAllowlist } from '../../sandbox/firewall';
import { renderDockerfile, renderEntrypoint, pinnedNode9Version } from '../../sandbox/templates';
import {
  agentCredentialsMount,
  buildRunArgs,
  detectEngine,
  imageContentHash,
  resolveHomePath,
  sandboxBuildDir,
  sandboxDataDir,
  writeAllowlist,
  writeBuildContext,
} from '../../sandbox/runtime';

/** Seed the mounted node9 data dir's config so the in-box daemon is terminal-only
 *  (fix #1: no native popup, no cloud approval — the box has no SaaS key). */
function seedDataDirConfig(dataDir: string, sandbox: SandboxConfig): void {
  fs.mkdirSync(dataDir, { recursive: true });
  const configPath = path.join(dataDir, 'config.json');
  const seed = {
    settings: {
      approvers: {
        terminal: sandbox.node9.approvals.terminal,
        native: false,
        browser: false,
        cloud: false,
      },
    },
  };
  fs.writeFileSync(configPath, JSON.stringify(seed, null, 2), { mode: 0o600 });
}

export function registerSandboxCommand(program: Command, version: string): void {
  // Pin the in-box node9 to the host version (single source of truth — the bundled
  // dist flattens paths, so don't resolve package.json by __dirname here).
  const node9Version = pinnedNode9Version(version);

  const cmd = program
    .command('sandbox')
    .description('Run an agent in a disposable, jailed container — governed + audited inside');

  // ── new ────────────────────────────────────────────────────────────────────
  cmd
    .command('new')
    .description(`Scaffold ${SANDBOX_CONFIG_FILE} in this project`)
    .option('--agent <agent>', 'claude (default) or codex', 'claude')
    .action((opts: { agent: string }) => {
      const agent = (opts.agent === 'codex' ? 'codex' : 'claude') as SandboxAgent;
      const p = sandboxConfigPath();
      if (fs.existsSync(p)) {
        console.log(
          chalk.yellow(`  ${SANDBOX_CONFIG_FILE} already exists — leaving it untouched.`)
        );
        return;
      }
      fs.writeFileSync(p, scaffoldSandboxYaml(agent));
      console.log(
        chalk.green(`  ✓ wrote ${SANDBOX_CONFIG_FILE}`) + chalk.dim(` (agent: ${agent})`)
      );
      console.log(
        chalk.dim('  Edit it (mounts / allow / expose), then: ') + chalk.cyan('node9 sandbox run')
      );
    });

  // ── run ────────────────────────────────────────────────────────────────────
  cmd
    .command('run [agent]')
    .description('Build (if needed) + run the agent jailed. Extra args after -- go to the agent.')
    .allowUnknownOption(true)
    .allowExcessArguments(true) // pass `-- <flags>` through to the agent (e.g. --resume)
    .action((agentArg: string | undefined, _opts: unknown, command: Command) => {
      const cwd = process.cwd();
      const sandbox = loadSandboxConfig(cwd, (agentArg as SandboxAgent) || 'claude');
      if (agentArg === 'claude' || agentArg === 'codex') sandbox.agent = agentArg;

      const engine = detectEngine(sandbox.runtime.engine);
      if (!engine.available) {
        console.error(
          chalk.red(`  ${sandbox.runtime.engine} not found.`) +
            chalk.dim(` Install it first — node9 sandbox needs a container runtime.`)
        );
        process.exit(1);
      }

      // 1. Compile the egress allowlist (sandbox + config egress; SaaS host never included).
      const node9Config = getConfig(cwd);
      const compiled = compileAllowlist({
        agent: sandbox.agent,
        sandboxAllow: sandbox.outbound.allow,
        configAllow: node9Config.policy.egress.allow,
        configDeny: node9Config.policy.egress.deny,
      });
      if (compiled.rejected.length) {
        console.log(
          chalk.yellow(`  ⚠ ignoring invalid allow hosts: ${compiled.rejected.join(', ')}`)
        );
      }
      if (compiled.denied.length) {
        console.log(chalk.dim(`  (denied: ${compiled.denied.join(', ')})`));
      }
      const allowlistPath = writeAllowlist(cwd, compiled.allow);

      // 2. Render artifacts + build context.
      const dockerfile = renderDockerfile(sandbox, node9Version);
      const entrypoint = renderEntrypoint(sandbox);
      const buildDir = writeBuildContext(cwd, dockerfile, entrypoint);
      const hash = imageContentHash(dockerfile, entrypoint);
      const image = sandbox.runtime.image;

      // 3. Build if needed.
      const hashFile = path.join(sandboxBuildDir(cwd), '.image-hash');
      const lastHash = fs.existsSync(hashFile) ? fs.readFileSync(hashFile, 'utf-8').trim() : '';
      const imageExists =
        spawnSync(sandbox.runtime.engine, ['image', 'inspect', image], { stdio: 'ignore' })
          .status === 0;
      const needBuild =
        sandbox.runtime.rebuild === 'always' ||
        !imageExists ||
        (sandbox.runtime.rebuild !== 'never' && lastHash !== hash);
      if (needBuild) {
        console.log(chalk.dim(`  building ${image} …`));
        const b = spawnSync(sandbox.runtime.engine, ['build', '-t', image, buildDir], {
          stdio: 'inherit',
        });
        if (b.status !== 0) {
          console.error(chalk.red('  build failed.'));
          process.exit(b.status ?? 1);
        }
        fs.writeFileSync(hashFile, hash);
      }

      // 4. Seed the in-box config (terminal-only approval) + run.
      const dataDir = sandboxDataDir(cwd);
      seedDataDirConfig(dataDir, sandbox);
      const passthru = command.args.slice(agentArg ? 1 : 0);
      const runArgs = buildRunArgs({
        config: sandbox,
        workspaceHostPath: resolveHomePath(sandbox.workspace.mount),
        dataHostPath: dataDir,
        allowlistHostPath: allowlistPath,
        agentArgs: passthru,
      });
      if (sandbox.node9.mountAgentCredentials) {
        const creds = agentCredentialsMount(sandbox.agent);
        if (fs.existsSync(creds.hostPath)) {
          console.log(chalk.dim(`  mounting ${creds.hostPath} (agent credentials, rw)`));
        } else {
          console.log(
            chalk.yellow(`  ⚠ ${creds.hostPath} not found — `) +
              chalk.dim(`the agent must auth via an env key in env.pass.`)
          );
        }
      }
      console.log(
        chalk.green(`  🛡️  ${sandbox.agent} jailed — ${compiled.allow.length} hosts allowed\n`)
      );
      const r = spawnSync(sandbox.runtime.engine, runArgs, { stdio: 'inherit' });
      process.exit(r.status ?? 0);
    });

  // ── tail / logs ──────────────────────────────────────────────────────────────
  cmd
    .command('tail')
    .description("Stream the sandbox's audit log (host-side)")
    .action(() => {
      const auditPath = path.join(sandboxDataDir(), 'audit.log');
      if (!fs.existsSync(auditPath)) {
        console.log(chalk.dim('  no sandbox audit yet.'));
        return;
      }
      spawnSync('tail', ['-f', auditPath], { stdio: 'inherit' });
    });

  cmd
    .command('logs')
    .description("Dump the sandbox's audit log")
    .action(() => {
      const auditPath = path.join(sandboxDataDir(), 'audit.log');
      if (!fs.existsSync(auditPath)) {
        console.log(chalk.dim('  no sandbox audit yet.'));
        return;
      }
      process.stdout.write(fs.readFileSync(auditPath, 'utf-8'));
    });

  // ── clean ─────────────────────────────────────────────────────────────────────
  cmd
    .command('clean')
    .description('Remove the sandbox image, build context, and data')
    .action(() => {
      const cwd = process.cwd();
      let sandbox: SandboxConfig | null = null;
      try {
        sandbox = loadSandboxConfig(cwd);
      } catch {
        /* no config — still clean dirs */
      }
      if (sandbox) {
        spawnSync(sandbox.runtime.engine, ['image', 'rm', '-f', sandbox.runtime.image], {
          stdio: 'ignore',
        });
      }
      fs.rmSync(path.join(cwd, '.node9', 'sandbox'), { recursive: true, force: true });
      console.log(chalk.green('  ✓ sandbox image + build + data removed.'));
    });
}
