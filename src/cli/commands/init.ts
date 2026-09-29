// Shared installation steps and the script-compatible init command.
import type { Command } from 'commander';
import fs from 'fs';
import path from 'path';
import os from 'os';
import https from 'https';
import { DEFAULT_CONFIG, RUNTIME_ONLY_CONFIG_KEYS, _resetConfigCache } from '../../config';
import { setupAgent, detectAgents, node9Version } from '../../setup';
import { getMachineId } from '../../machine-id';
import { atomicWriteSync } from '../../utils/atomic-write';
import { isTestingMode } from '../daemon-starter';
import { invalidConfig, isInteractive, isPromptCancellation, SetupError } from '../interactive';

export interface TelemetryPayload {
  event: 'init_completed';
  agents_detected: string[];
  os: string;
  node9_version: string;
  first_install: boolean;
  /**
   * The machine's durable UUID from ~/.node9/machine-id -- the SAME id login
   * binds the machine by, not a second telemetry-only one.
   *
   * Without it the ping has no identity, so the server can only count init
   * runs and `first_install` has to guess from whether a config file exists.
   * With it, a machine that runs `init` twice counts once, and an install can
   * later be recognised as the machine that logged in.
   *
   * Random, never derived from hostname or user, so it says nothing about the
   * machine by itself.
   */
  machine_id: string;
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
    machine_id: getMachineId(),
  };
}

function fireTelemetryPing(agents: string[], firstInstall: boolean): void {
  // A test run (NODE9_TESTING) is not an install: never count it.
  if (isTestingMode()) return;
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

export const TELEMETRY_PROMPT =
  'Send usage stats to help improve node9? (a random install ID, detected agents, OS and version. No code, no args.)';

export async function askTelemetry(agents: string[], firstInstall: boolean): Promise<void> {
  if (!isInteractive()) return;
  const { confirm } = await import('@inquirer/prompts');
  if (await confirm({ message: TELEMETRY_PROMPT, default: true })) {
    fireTelemetryPing(agents, firstInstall);
  }
}

export function ensureConfig(mode?: string, force = false): { firstInstall: boolean } {
  const file = path.join(os.homedir(), '.node9', 'config.json');
  const firstInstall = !fs.existsSync(file);
  if (firstInstall || force) {
    const config: Record<string, unknown> = {
      ...DEFAULT_CONFIG,
      settings: { ...DEFAULT_CONFIG.settings, mode: mode ?? DEFAULT_CONFIG.settings.mode },
    };
    for (const key of RUNTIME_ONLY_CONFIG_KEYS) delete config[key];
    atomicWriteSync(file, JSON.stringify(config, null, 2) + '\n', { mode: 0o600 });
  } else if (mode !== undefined) {
    let config;
    try {
      config = JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch {
      config = undefined;
    }
    if (!config || typeof config !== 'object' || Array.isArray(config)) throw invalidConfig();
    if (config.settings?.mode !== mode) {
      config.settings = { ...config.settings, mode };
      atomicWriteSync(file, JSON.stringify(config, null, 2) + '\n', { mode: 0o600 });
    }
  }
  _resetConfigCache();
  return { firstInstall };
}

export async function wireDetectedAgents(): Promise<string[]> {
  const detected = detectAgents();
  const found = (Object.keys(detected) as Array<keyof typeof detected>).filter((k) => detected[k]);
  const previous = process.env.NODE9_NONINTERACTIVE;
  process.env.NODE9_NONINTERACTIVE = '1';
  try {
    for (const agent of found) await setupAgent(agent);
  } finally {
    if (previous === undefined) delete process.env.NODE9_NONINTERACTIVE;
    else process.env.NODE9_NONINTERACTIVE = previous;
  }
  return found;
}

export function registerInitCommand(program: Command): void {
  program
    .command('init')
    .description('Set up Node9: create config and wire all detected AI agents')
    .option('--force', 'Overwrite existing config')
    .option('-m, --mode <mode>', 'Initial security mode: standard | strict | audit | observe')
    .option('--skip-setup', 'Only configure protection; do not wire agents or install a service')
    .option('--recommended', 'Enable recommended protection without asking any questions')
    .action(
      async (options: {
        mode?: string;
        force?: boolean;
        skipSetup?: boolean;
        recommended?: boolean;
      }) => {
        try {
          const { runLocalSetup, renderSummary } = await import('../local-setup.js');
          const summary = await runLocalSetup({ ...options, interactive: isInteractive() });
          console.log(renderSummary(summary));
        } catch (error) {
          if (error instanceof SetupError) {
            console.error(`✗ ${error.message}`);
            process.exitCode = 1;
            return;
          }
          if (!isPromptCancellation(error)) throw error;
          console.log('Setup cancelled. Run node9 setup to continue.');
          process.exitCode = 130;
        }
      }
    );
}
