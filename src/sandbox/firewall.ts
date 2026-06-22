// src/sandbox/firewall.ts
// Pure egress-allowlist compiler for the sandbox kernel firewall.
//
// node9's existing egress policy (packages/policy-engine/src/egress) is
// tool/command-level. The sandbox adds KERNEL-level enforcement: this compiles a
// final hostname allowlist that the container entrypoint resolves to an ipset and
// applies with iptables deny-by-default.
//
// Security invariants (tested):
//   1. The node9 SaaS hosts are NEVER allowlisted (fix #1) — a SaaS-reachable box
//      could exfiltrate a leaked key to an allowed host. Audit ships from the HOST.
//   2. `deny` wins over `allow`.
//   3. The agent's own provider host is always included (the CLI can't work without it).
//   4. Output is deduped + sorted (deterministic image/firewall hash).

import type { SandboxAgent } from './types';

/** Provider host each agent CLI must reach to talk to its model. */
const AGENT_PROVIDER_HOST: Record<SandboxAgent, string[]> = {
  claude: ['api.anthropic.com'],
  codex: ['api.openai.com'],
};

/** node9 SaaS hosts — NEVER allowed inside the box (fix #1). The host node9 ships
 *  audit + does cloud sync; the box never calls the SaaS. */
export const NODE9_SAAS_HOSTS = ['api.node9.ai', 'app.node9.ai', 'node9.ai'];

/** Conservative hostname check — letters/digits/dot/hyphen, label-structured.
 *  Rejects empty, whitespace, schemes, paths, ports, and obvious junk so a bad
 *  allowlist entry can't smuggle shell/ipset metacharacters into the entrypoint. */
export function isValidHost(host: string): boolean {
  if (typeof host !== 'string') return false;
  const h = host.trim().toLowerCase();
  if (!h || h.length > 253) return false;
  // No scheme, path, port, userinfo, or whitespace.
  if (/[\s/:@?#\\]/.test(h)) return false;
  // label.label.tld — each label 1-63 chars, alnum + internal hyphens.
  return /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(
    h
  );
}

export interface CompileAllowlistInput {
  agent: SandboxAgent;
  /** node9.sandbox.yaml outbound.allow */
  sandboxAllow: string[];
  /** ~/.node9/config.json policy.egress.allow */
  configAllow: string[];
  /** ~/.node9/config.json policy.egress.deny (deny wins) */
  configDeny: string[];
}

export interface CompileAllowlistResult {
  allow: string[];
  /** Entries dropped for being invalid hosts (surfaced as a warning by the CLI). */
  rejected: string[];
  /** Entries dropped because they matched the SaaS denylist or config deny. */
  denied: string[];
}

/**
 * Compile the final kernel allowlist. Pure — no I/O.
 * union(sandboxAllow, configAllow, agent provider host) − deny − SaaS hosts,
 * validated, deduped, sorted.
 */
export function compileAllowlist(input: CompileAllowlistInput): CompileAllowlistResult {
  const norm = (h: string) => h.trim().toLowerCase();
  const denySet = new Set([...input.configDeny.map(norm), ...NODE9_SAAS_HOSTS.map(norm)]);

  const candidates = [
    ...AGENT_PROVIDER_HOST[input.agent],
    ...input.sandboxAllow,
    ...input.configAllow,
  ].map(norm);

  const allow = new Set<string>();
  const rejected: string[] = [];
  const denied: string[] = [];

  for (const host of candidates) {
    if (!host) continue;
    if (!isValidHost(host)) {
      if (!rejected.includes(host)) rejected.push(host);
      continue;
    }
    if (denySet.has(host)) {
      if (!denied.includes(host)) denied.push(host);
      continue;
    }
    allow.add(host);
  }

  return {
    allow: [...allow].sort(),
    rejected: rejected.sort(),
    denied: denied.sort(),
  };
}
