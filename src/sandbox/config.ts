// src/sandbox/config.ts
// Parse / scaffold node9.sandbox.yaml. Pure merge+validate (mergeSandboxConfig) is
// testable; load/scaffold do the fs I/O.

import fs from 'fs';
import path from 'path';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import type { SandboxAgent, SandboxConfig } from './types';

export const SANDBOX_CONFIG_FILE = 'node9.sandbox.yaml';

/** Defense in depth for fix #1: the node9 SaaS key must never be handed to the box.
 *  Stripped from env.pass during merge even if a user adds it. */
const FORBIDDEN_ENV = new Set(['NODE9_API_KEY', 'NODE9_API_URL']);

export function defaultSandboxConfig(agent: SandboxAgent): SandboxConfig {
  return {
    agent,
    workspace: { mount: '.', target: '/workspace', mode: 'rw' },
    runtime: { engine: 'docker', image: 'node9-sandbox:local', rebuild: 'auto' },
    outbound: {
      mode: 'block',
      allow:
        agent === 'codex'
          ? ['api.openai.com', 'api.github.com', 'github.com', 'registry.npmjs.org']
          : ['api.anthropic.com', 'api.github.com', 'github.com', 'registry.npmjs.org'],
    },
    inbound: { expose: [] },
    // Provider key only — NODE9_API_KEY intentionally absent (fix #1).
    env: { pass: [agent === 'codex' ? 'OPENAI_API_KEY' : 'ANTHROPIC_API_KEY'] },
    // Terminal-only approval in the MVP; cloud/native/browser off (fix #1).
    node9: {
      approvals: { terminal: true, native: false, browser: false, cloud: false },
      // Mount the agent's OAuth/creds dir so it can authenticate in the box.
      mountAgentCredentials: true,
    },
  };
}

function asStringArray(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}

/**
 * Merge a raw (parsed-YAML) object onto the defaults for the given agent.
 * Pure + validating. Unknown agent → throws. NODE9_API_KEY in env.pass → stripped.
 */
export function mergeSandboxConfig(raw: unknown, fallbackAgent: SandboxAgent): SandboxConfig {
  const r = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
  const agent = (typeof r.agent === 'string' ? r.agent : fallbackAgent) as SandboxAgent;
  if (agent !== 'claude' && agent !== 'codex') {
    throw new Error(`sandbox: unsupported agent "${String(agent)}" (use claude or codex)`);
  }
  const d = defaultSandboxConfig(agent);

  const ws = (r.workspace ?? {}) as Record<string, unknown>;
  const rt = (r.runtime ?? {}) as Record<string, unknown>;
  const out = (r.outbound ?? {}) as Record<string, unknown>;
  const inb = (r.inbound ?? {}) as Record<string, unknown>;
  const env = (r.env ?? {}) as Record<string, unknown>;
  const n9 = (r.node9 ?? {}) as Record<string, unknown>;
  const appr = (n9.approvals ?? {}) as Record<string, unknown>;

  const pass = asStringArray(env.pass).filter((k) => !FORBIDDEN_ENV.has(k));

  return {
    agent,
    workspace: {
      mount: typeof ws.mount === 'string' ? ws.mount : d.workspace.mount,
      target: typeof ws.target === 'string' ? ws.target : d.workspace.target,
      mode: ws.mode === 'ro' ? 'ro' : 'rw',
    },
    runtime: {
      engine: rt.engine === 'podman' ? 'podman' : 'docker',
      image: typeof rt.image === 'string' ? rt.image : d.runtime.image,
      rebuild: rt.rebuild === 'never' || rt.rebuild === 'always' ? rt.rebuild : d.runtime.rebuild,
    },
    outbound: { mode: 'block', allow: out.allow ? asStringArray(out.allow) : d.outbound.allow },
    inbound: { expose: inb.expose ? asStringArray(inb.expose) : d.inbound.expose },
    env: { pass: env.pass ? pass : d.env.pass },
    node9: {
      approvals: {
        terminal: appr.terminal !== false,
        native: appr.native === true,
        browser: appr.browser === true,
        cloud: appr.cloud === true,
      },
      mountAgentCredentials: n9.mountAgentCredentials !== false,
    },
  };
}

/** Render the scaffold YAML for `node9 sandbox new`. */
export function scaffoldSandboxYaml(agent: SandboxAgent): string {
  const header =
    '# node9.sandbox.yaml — sandbox TOPOLOGY (what the agent may touch).\n' +
    '# Security policy (shields / egress rules / approvers) lives in ~/.node9/config.json\n' +
    '# and applies to both native and sandbox. NODE9_API_KEY is never passed into the box.\n\n';
  return header + stringifyYaml(defaultSandboxConfig(agent));
}

export function sandboxConfigPath(cwd = process.cwd()): string {
  return path.join(cwd, SANDBOX_CONFIG_FILE);
}

/** Read + parse the project-local sandbox config, merged onto defaults. */
export function loadSandboxConfig(
  cwd = process.cwd(),
  fallbackAgent: SandboxAgent = 'claude'
): SandboxConfig {
  const p = sandboxConfigPath(cwd);
  if (!fs.existsSync(p)) {
    throw new Error(`sandbox: ${SANDBOX_CONFIG_FILE} not found — run \`node9 sandbox new\` first.`);
  }
  let raw: unknown;
  try {
    raw = parseYaml(fs.readFileSync(p, 'utf-8'));
  } catch (err) {
    throw new Error(
      `sandbox: ${SANDBOX_CONFIG_FILE} is not valid YAML — ${(err as Error).message}`
    );
  }
  return mergeSandboxConfig(raw, fallbackAgent);
}
