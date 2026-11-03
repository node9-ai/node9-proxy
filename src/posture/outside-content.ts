// src/posture/outside-content.ts
// Check — Outside content (OWASP ASI01, node9Firewall#320 phase 1).
//
// The chain behind a goal hijack on a developer machine: a tool that brings
// outside content into the session (a web page, an issue, an email, a search
// result), and a way out for what the agent does next (an open network, or
// the hold after exposure switched off). Neither alone is a finding; both
// together are the exposure. Config inspection only: the MCP inventory the
// agents already have, the roles the user set, and node9's own settings.

import os from 'os';
import { checkValue } from '@node9/policy-engine';
import { getConfig, catalogSettingsFrom } from '../config';
import { inventoryMcp } from '../mcp-wrap';
import type { CheckContext, Finding } from './types';

export const CATEGORY = 'Outside content';

/** A server whose name says it reads from outside the machine. The role the
 *  user set on the Apps page wins; the name is the fallback when none is set. */
const SOURCE_NAME_RE =
  /web|fetch|browser|crawl|scrape|search|http|mail|gmail|outlook|slack|discord|github|gitlab|jira|linear|notion|confluence|drive|docs|sheets|calendar|rss|news|wiki/i;

export interface OutsideSource {
  server: string;
  agent: string;
  how: 'role' | 'name';
}

/** MCP servers on this machine that bring outside content. Exported for tests. */
export function outsideSources(
  home: string,
  roles: Record<string, Record<string, 'source' | 'action' | 'read'>>
): OutsideSource[] {
  const out: OutsideSource[] = [];
  const seen = new Set<string>();
  for (const e of inventoryMcp(home)) {
    if (e.state === 'node9-self') continue;
    const key = `${e.agent}:${e.name}`;
    if (seen.has(key)) continue;
    const role = roles[e.name] ?? roles[e.name.toLowerCase()];
    const roleSays = role ? Object.values(role).some((r) => r === 'source') : false;
    const roleOnlyReads = role ? Object.values(role).every((r) => r === 'read') : false;
    if (roleSays) out.push({ server: e.name, agent: e.agentLabel, how: 'role' });
    else if (!roleOnlyReads && SOURCE_NAME_RE.test(e.name))
      out.push({ server: e.name, agent: e.agentLabel, how: 'name' });
    seen.add(key);
  }
  return out;
}

export function checkOutsideContent(ctx: CheckContext): Finding[] {
  const home = ctx.home || os.homedir();
  const config = getConfig(ctx.cwd);
  const roles = (config.policy.untrustedContent?.roles ?? {}) as Record<
    string,
    Record<string, 'source' | 'action' | 'read'>
  >;
  const sources = outsideSources(home, roles);
  if (sources.length === 0) return [];

  const egress = config.policy.egress;
  const egressGated = !!egress?.enabled && (egress.mode === 'block' || egress.mode === 'review');
  const hold = checkValue(
    catalogSettingsFrom(config.settings, config.policy),
    'behavior.untrusted-content'
  );
  const holdOn = hold !== 'off';
  if (egressGated && holdOn) return [];

  const gaps: string[] = [];
  if (!egressGated) gaps.push('egress is open: a send to any host goes through');
  if (!holdOn)
    gaps.push('behavior.untrusted-content is off: no hold after outside content is read');

  return [
    {
      category: CATEGORY,
      severity: 'high',
      title: `${sources.length} MCP server${sources.length === 1 ? '' : 's'} bring${sources.length === 1 ? 's' : ''} outside content in, and the way out is open`,
      what: 'An agent here reads pages, issues or messages written by others, and what it does next is not held.',
      why: gaps.join('; ') + '.',
      who: 'One poisoned page or issue is enough: the agent reads it, then sends or deletes as it says.',
      detail: [...sources.slice(0, 8).map((s) => `${s.server} (${s.agent}, by ${s.how})`), ...gaps],
      owner: 'node9',
      fix: 'Run `node9 egress watch` (or `node9 egress lock`), keep behavior.untrusted-content on, and mark each server\'s reading tools as "Brings outside content" on the Apps page so the hold applies to them.',
    },
  ];
}
