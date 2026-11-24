// src/addons/policy.ts
// The workspace's approved list of add-ons (node9Firewall#376 item 6, add-ons
// plan phase 3), as policy sync delivers it in `managedConfig.addons`, and the
// verdict it gives one use of an add-on.
//
//   unapproved  what happens to an add-on nobody approved: off and log let it
//               run (the dashboard alerts admins), review asks a person,
//               block stops it.
//   mcp         { identity: approved | blocked }, no version (decision D4).
//   skills,     { name: { decision, hashes } }: approved by exact version, a
//   plugins     content hash or `v:<version>` (D3); blocked covers every one.
//
// The list is cloud-only: a local config cannot write it, and a machine with
// no list (no workspace, a plan without it, an older server) enforces nothing.

export type AddonDecision = 'approved' | 'blocked';
export type UnapprovedRule = 'off' | 'log' | 'review' | 'block';

export interface VersionedDecision {
  decision: AddonDecision;
  hashes?: string[];
}

export interface AddonPolicy {
  unapproved: UnapprovedRule;
  mcp: Record<string, AddonDecision>;
  skills: Record<string, VersionedDecision>;
  plugins: Record<string, VersionedDecision>;
}

const MAX_ENTRIES = 2000;
const MAX_HASHES = 50;
const MAX_NAME = 300;
const VERSION_ID = /^[0-9a-f]{64}$|^v:.{1,64}$/;

function isRecord(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

function decisionOf(v: unknown): AddonDecision | null {
  return v === 'approved' || v === 'blocked' ? v : null;
}

function versionedMap(raw: unknown): Record<string, VersionedDecision> {
  const out: Record<string, VersionedDecision> = {};
  if (!isRecord(raw)) return out;
  for (const [name, v] of Object.entries(raw).slice(0, MAX_ENTRIES)) {
    if (!name || name.length > MAX_NAME || !isRecord(v)) continue;
    const decision = decisionOf(v.decision);
    if (!decision) continue;
    if (decision === 'blocked') {
      out[name] = { decision };
      continue;
    }
    const hashes = Array.isArray(v.hashes)
      ? v.hashes
          .filter((h): h is string => typeof h === 'string' && VERSION_ID.test(h))
          .slice(0, MAX_HASHES)
      : [];
    out[name] = { decision, hashes };
  }
  return out;
}

/**
 * The list from a sync body or the policy cache, or undefined when there is
 * none. A malformed entry drops itself only; an unknown rule reads as `log`,
 * which enforces nothing beyond the explicit blocks.
 */
export function parseAddonPolicy(raw: unknown): AddonPolicy | undefined {
  if (!isRecord(raw)) return undefined;
  const rule = raw.unapproved;
  const mcp: Record<string, AddonDecision> = {};
  if (isRecord(raw.mcp))
    for (const [identity, d] of Object.entries(raw.mcp).slice(0, MAX_ENTRIES)) {
      const decision = decisionOf(d);
      if (identity && identity.length <= MAX_NAME && decision) mcp[identity] = decision;
    }
  return {
    unapproved: rule === 'off' || rule === 'review' || rule === 'block' ? rule : 'log',
    mcp,
    skills: versionedMap(raw.skills),
    plugins: versionedMap(raw.plugins),
  };
}

/** The list asks a machine to stop or hold something. */
export function addonPolicyEnforces(p: AddonPolicy | undefined): boolean {
  if (!p) return false;
  if (p.unapproved === 'review' || p.unapproved === 'block') return true;
  return (
    Object.values(p.mcp).includes('blocked') ||
    Object.values(p.skills).some((d) => d.decision === 'blocked') ||
    Object.values(p.plugins).some((d) => d.decision === 'blocked')
  );
}

/** What the gate does with one use of an add-on. */
export type AddonVerdict =
  | { action: 'allow' }
  | {
      action: 'block' | 'review';
      /** One sentence for the agent and the approval card. */
      reason: string;
      /** The audit rule name: `addon:<type>:<name>`. */
      ruleName: string;
    };

type Standing = 'approved' | 'blocked' | 'changed' | 'new';

function standing(d: VersionedDecision | undefined, versionId: string | undefined): Standing {
  if (!d) return 'new';
  if (d.decision === 'blocked') return 'blocked';
  return versionId !== undefined && (d.hashes ?? []).includes(versionId) ? 'approved' : 'changed';
}

const FIX = 'An admin can approve it on the Add-ons page of the node9 dashboard.';

function verdictFor(
  policy: AddonPolicy,
  s: Standing,
  what: string,
  ruleName: string
): AddonVerdict {
  if (s === 'approved') return { action: 'allow' };
  // Each reason starts with the add-on, so the line the user sees reads
  // "Node9 blocked: the skill "x" is ..." (policy/negotiation.ts).
  if (s === 'blocked')
    return { action: 'block', reason: `${what} is on your workspace's block list.`, ruleName };
  const why =
    s === 'changed'
      ? `this copy of ${what} is not the version your workspace approved`
      : `${what} is not on your workspace's approved list`;
  if (policy.unapproved === 'block') return { action: 'block', reason: `${why}. ${FIX}`, ruleName };
  if (policy.unapproved === 'review')
    return {
      action: 'review',
      reason: `${why}, so a person must approve this use.`,
      ruleName,
    };
  return { action: 'allow' };
}

/** One call to an MCP server, by its identity (`npm:<pkg>`, `url:<host>`...). */
export function mcpVerdict(policy: AddonPolicy | undefined, identity: string): AddonVerdict {
  if (!policy || !identity) return { action: 'allow' };
  const d = policy.mcp[identity];
  return verdictFor(
    policy,
    d ? (d === 'blocked' ? 'blocked' : 'approved') : 'new',
    `the MCP server "${identity}"`,
    `addon:mcp:${identity}`
  );
}

/** One load of a skill. A plugin's skill also answers to its plugin: either
 *  one blocked blocks it, either one approved at this version allows it. */
export function skillVerdict(
  policy: AddonPolicy | undefined,
  skill: { name: string; hash: string; plugin?: { key: string; versionId: string } }
): AddonVerdict {
  if (!policy) return { action: 'allow' };
  const own = standing(policy.skills[skill.name], skill.hash);
  const viaPlugin = skill.plugin
    ? standing(policy.plugins[skill.plugin.key], skill.plugin.versionId)
    : 'new';
  const s: Standing =
    own === 'blocked' || viaPlugin === 'blocked'
      ? 'blocked'
      : own === 'approved' || viaPlugin === 'approved'
        ? 'approved'
        : own === 'changed' || viaPlugin === 'changed'
          ? 'changed'
          : 'new';
  const blockedByPlugin = own !== 'blocked' && viaPlugin === 'blocked';
  return verdictFor(
    policy,
    s,
    blockedByPlugin
      ? `the plugin "${skill.plugin!.key}" (skill "${skill.name}")`
      : `the skill "${skill.name}"`,
    blockedByPlugin ? `addon:plugin:${skill.plugin!.key}` : `addon:skill:${skill.name}`
  );
}

/** The stricter of two verdicts (block over review over allow). */
export function stricter(a: AddonVerdict, b: AddonVerdict): AddonVerdict {
  const rank = (v: AddonVerdict) => (v.action === 'block' ? 2 : v.action === 'review' ? 1 : 0);
  return rank(b) > rank(a) ? b : a;
}
