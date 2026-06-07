// @node9/policy-engine/egress — destination policy evaluation (GAP-5).
//
// Extraction (which host is a tool calling out to?) lives in ../shell
// (extractShellDestinations) because it needs the AST parser. This module is
// the pure POLICY layer: given the extracted destinations + the user's egress
// policy, decide allow / review / block. No I/O, no DNS — host reputation is
// out of scope; we only know what the config tells us.

import type { ShellDestination } from '../shell';

export interface EgressPolicy {
  /** Master switch. Default false — opt-in, like dlp.pii. */
  enabled: boolean;
  /** Verdict for an UNKNOWN host (not in allow, not in deny, not private). */
  mode: 'off' | 'review' | 'block';
  /** Host globs always allowed (e.g. "*.github.com", "api.openai.com"). */
  allow: string[];
  /** Host globs always blocked — wins over allow/private. */
  deny: string[];
  /** Auto-allow localhost / RFC1918 / *.local. Default true. */
  allowPrivate: boolean;
}

export interface EgressVerdict {
  verdict: 'block' | 'review';
  host: string;
  binary: string;
  reason: string;
}

// Curated default allowlist of common dev / package / API hosts so turning
// egress on doesn't bury the user in prompts for routine traffic. "*.x" matches
// the apex (x) and any subdomain (see hostMatches). User `allow` adds to this.
export const DEFAULT_EGRESS_ALLOWLIST: readonly string[] = [
  '*.github.com',
  '*.githubusercontent.com',
  '*.npmjs.org',
  'pypi.org',
  '*.pythonhosted.org',
  'crates.io',
  '*.crates.io',
  'rubygems.org',
  'proxy.golang.org',
  'sum.golang.org',
  '*.anthropic.com',
  '*.openai.com',
  '*.googleapis.com',
  '*.docker.io',
  '*.docker.com',
  'deb.debian.org',
  '*.ubuntu.com',
];

/** Glob host match: "*" = any, "*.x" = apex x + any subdomain, else exact. */
export function hostMatches(host: string, pattern: string): boolean {
  const h = host.toLowerCase();
  const p = pattern.toLowerCase().trim();
  if (!p) return false;
  if (p === '*') return true;
  if (p.startsWith('*.')) {
    const suffix = p.slice(2);
    return h === suffix || h.endsWith('.' + suffix);
  }
  return h === p;
}

function matchesAny(host: string, patterns: readonly string[]): boolean {
  for (const p of patterns) if (hostMatches(host, p)) return true;
  return false;
}

/** localhost / loopback / RFC1918 / link-local-ish — never a real exfil target. */
export function isPrivateHost(host: string): boolean {
  const h = host.toLowerCase();
  if (h === 'localhost' || h === '0.0.0.0') return true;
  if (h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.localhost')) return true;
  if (/^127\./.test(h)) return true;
  if (/^10\./.test(h)) return true;
  if (/^192\.168\./.test(h)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return true;
  return false;
}

/**
 * Evaluate extracted destinations against the egress policy. Precedence per
 * host: deny (block) > private-allow > allow/default-allow (skip) > unknown
 * (policy.mode). Returns the most severe actionable verdict across all
 * destinations — a deny or block-mode-unknown short-circuits; otherwise the
 * first review; null if everything is allowed (or policy disabled / mode off).
 * Pure.
 */
export function evaluateEgress(
  dests: readonly ShellDestination[],
  policy: EgressPolicy
): EgressVerdict | null {
  if (!policy.enabled) return null;
  let review: EgressVerdict | null = null;

  for (const d of dests) {
    // Explicit deny always wins.
    if (matchesAny(d.host, policy.deny)) {
      return {
        verdict: 'block',
        host: d.host,
        binary: d.binary,
        reason: `Egress to ${d.host} is on the deny list.`,
      };
    }
    // Private / loopback — never an exfil target when allowPrivate is on.
    if (policy.allowPrivate && isPrivateHost(d.host)) continue;
    // Known-good (user allowlist or the curated defaults).
    if (matchesAny(d.host, policy.allow) || matchesAny(d.host, DEFAULT_EGRESS_ALLOWLIST)) continue;
    // Unknown destination.
    if (policy.mode === 'block') {
      return {
        verdict: 'block',
        host: d.host,
        binary: d.binary,
        reason: `Egress to unknown host ${d.host} is blocked (egress policy: block).`,
      };
    }
    if (policy.mode === 'review' && !review) {
      review = {
        verdict: 'review',
        host: d.host,
        binary: d.binary,
        reason: `${d.binary} is sending data to an unrecognized host (${d.host}). Approve this destination?`,
      };
    }
    // mode === 'off' → unknown hosts are not actioned.
  }

  return review;
}
