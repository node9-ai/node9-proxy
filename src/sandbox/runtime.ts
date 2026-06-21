// src/sandbox/runtime.ts
// Host-side orchestration: detect the engine, build the image, run the container.
// buildRunArgs is PURE (testable); detect/build/run do the process I/O.

import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { spawnSync } from 'child_process';
import type { SandboxConfig } from './types';
import { ALLOWED_DOMAINS_PATH, RUN_AS_USER } from './templates';

/** Where the persistent node9 data (audit) lands on the host, per project. */
export function sandboxDataDir(cwd = process.cwd()): string {
  return path.join(cwd, '.node9', 'sandbox', 'data');
}

export function detectEngine(engine: 'docker' | 'podman'): {
  available: boolean;
  version?: string;
} {
  const r = spawnSync(engine, ['--version'], { encoding: 'utf-8' });
  if (r.status === 0 && typeof r.stdout === 'string') {
    return { available: true, version: r.stdout.trim() };
  }
  return { available: false };
}

/** The agent's host credential FILE → its mount point inside the box. Mount ONLY the
 *  credential file, never the whole ~/.claude / ~/.codex dir, because the full dir:
 *    (a) exposes the user's entire agent history (all projects) to the box, and
 *    (b) MASKS the box's build-time node9 hook wiring with the host's settings.json,
 *        whose hooks point at the HOST node9 path (absent in the box) — silently
 *        disabling node9 governance inside the jail.
 *  RW so the agent can refresh its token mid-run; session state goes to the box's own
 *  ephemeral ~/.claude (gone on exit). */
export function agentCredentialsMount(agent: SandboxConfig['agent']): {
  hostPath: string;
  target: string;
} {
  const rel = agent === 'codex' ? '.codex/auth.json' : '.claude/.credentials.json';
  return { hostPath: path.join(os.homedir(), rel), target: `/home/${RUN_AS_USER}/${rel}` };
}

export interface RunArgsOpts {
  config: SandboxConfig;
  /** Resolved host path of the mounted workspace. */
  workspaceHostPath: string;
  /** Host path of the persistent node9 data dir (audit). */
  dataHostPath: string;
  /** Host path of the rendered allowed-domains.txt. */
  allowlistHostPath: string;
  /** Extra args passed through to the agent (after `--`). */
  agentArgs: string[];
}

/**
 * Build the `docker run` (or `podman run`) argument array. Pure.
 * - container gets NET_ADMIN (root entrypoint seals iptables; the agent is non-root)
 * - workspace + node9 data + allowlist mounted
 * - only declared env vars passed through (NODE9_API_KEY already stripped upstream)
 * - only declared ports published (loopback by default)
 */
export function buildRunArgs(opts: RunArgsOpts): string[] {
  const { config, workspaceHostPath, dataHostPath, allowlistHostPath, agentArgs } = opts;
  const args: string[] = ['run', '--rm', '-it', '--cap-add=NET_ADMIN'];

  // Mounts
  args.push('-v', `${workspaceHostPath}:${config.workspace.target}:${config.workspace.mode}`);
  args.push('-v', `${dataHostPath}:/home/${RUN_AS_USER}/.node9`);
  args.push('-v', `${allowlistHostPath}:${ALLOWED_DOMAINS_PATH}:ro`);

  // Agent credentials — so Claude (OAuth) / Codex can authenticate in the box.
  // RW: both refresh their token + write session state. Skipped when the host dir
  // is absent (the agent must then auth via an env key in env.pass).
  if (config.node9.mountAgentCredentials) {
    const creds = agentCredentialsMount(config.agent);
    if (fs.existsSync(creds.hostPath)) {
      args.push('-v', `${creds.hostPath}:${creds.target}`);
    }
  }

  // Env pass-through (only vars that are actually set on the host).
  for (const key of config.env.pass) {
    if (process.env[key] !== undefined) args.push('-e', key);
  }

  // Published ports (explicit host:port:container; loopback by default in config).
  for (const port of config.inbound.expose) {
    args.push('-p', port);
  }

  args.push(config.runtime.image);
  if (agentArgs.length) args.push(...agentArgs);
  return args;
}

/** Content hash of the build inputs — decides whether to rebuild on `rebuild: auto`. */
export function imageContentHash(dockerfile: string, entrypoint: string): string {
  return crypto
    .createHash('sha256')
    .update(dockerfile)
    .update('\0')
    .update(entrypoint)
    .digest('hex')
    .slice(0, 16);
}

export function sandboxBuildDir(cwd = process.cwd()): string {
  return path.join(cwd, '.node9', 'sandbox', 'build');
}

/** Write the build context (Dockerfile + entrypoint.sh) and return the dir. */
export function writeBuildContext(cwd: string, dockerfile: string, entrypoint: string): string {
  const dir = sandboxBuildDir(cwd);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'Dockerfile'), dockerfile);
  fs.writeFileSync(path.join(dir, 'entrypoint.sh'), entrypoint);
  return dir;
}

/** Write the resolved allowlist for the container to mount. */
export function writeAllowlist(cwd: string, hosts: string[]): string {
  const dir = path.join(cwd, '.node9', 'sandbox');
  fs.mkdirSync(dir, { recursive: true });
  const p = path.join(dir, 'allowed-domains.txt');
  fs.writeFileSync(p, hosts.join('\n') + '\n');
  return p;
}

export function resolveHomePath(p: string): string {
  return p.startsWith('~') ? path.join(os.homedir(), p.slice(1)) : path.resolve(p);
}
