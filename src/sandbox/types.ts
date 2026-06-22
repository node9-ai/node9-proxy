// src/sandbox/types.ts
// Types for `node9 sandbox` (Phase 1 MVP) — the disposable jailed agent runtime.
// Topology only; security policy (shields/egress/approvers) lives in the shared
// node9 config and applies to both native and sandbox modes.

/** Agents supported by the sandbox MVP. Claude first (hooks verified to fire in a
 *  fresh container); Codex is a fast-follow gated on in-container hook-trust. */
export type SandboxAgent = 'claude' | 'codex';

export type SandboxEngine = 'docker' | 'podman';

export interface SandboxWorkspace {
  /** Host path to mount (default '.', the project dir). */
  mount: string;
  /** Mount point inside the container. */
  target: string;
  /** 'rw' (default) or 'ro'. */
  mode: 'rw' | 'ro';
}

export interface SandboxRuntime {
  engine: SandboxEngine;
  /** Local image tag. */
  image: string;
  /** 'auto' (rebuild when the content hash changes) | 'never' | 'always'. */
  rebuild: 'auto' | 'never' | 'always';
}

export interface SandboxOutbound {
  /** MVP is always 'block' (deny-by-default); kept for forward-compat. */
  mode: 'block';
  /** Hostnames the agent may reach. Merged with config policy.egress.allow. */
  allow: string[];
}

export interface SandboxInbound {
  /** Explicit "host:hostPort:containerPort" maps; loopback-only by default. */
  expose: string[];
}

export interface SandboxEnvSpec {
  /** Host env vars passed THROUGH to the agent (e.g. ANTHROPIC_API_KEY).
   *  NODE9_API_KEY must NEVER be here — the SaaS key stays on the host. */
  pass: string[];
}

export interface SandboxApprovals {
  terminal: boolean;
  native: boolean;
  browser: boolean;
  /** In-box cloud approval is OFF in the MVP (would require the SaaS key in the
   *  box). The host handles cloud sync/approval instead. */
  cloud: boolean;
}

export interface SandboxNode9 {
  approvals: SandboxApprovals;
  /** Mount the agent's host credential dir (~/.claude or ~/.codex) into the box so
   *  it can authenticate. Default true — without it, Claude (OAuth) and Codex have
   *  no way to log in inside the jail. This is a deliberate exposure of the agent's
   *  own credentials (the "vendor model key" residual): the egress wall confines
   *  that token to the provider host. Set false to instead rely on an env key
   *  passed via env.pass (e.g. ANTHROPIC_API_KEY). */
  mountAgentCredentials: boolean;
}

export interface SandboxConfig {
  agent: SandboxAgent;
  workspace: SandboxWorkspace;
  runtime: SandboxRuntime;
  outbound: SandboxOutbound;
  inbound: SandboxInbound;
  env: SandboxEnvSpec;
  node9: SandboxNode9;
}
