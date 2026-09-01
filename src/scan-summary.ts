// src/scan-summary.ts
//
// Single source of truth for scan-result categorization.
// Both the terminal renderer (cli/commands/scan.ts) and the browser
// (via daemon /scan endpoint → ui.html) consume the same ScanSummary
// so the numbers and groupings stay aligned.
//
// Mental model:
//   - Top stats group by VERDICT (what Node9 would do: block/supervise).
//   - Sections group by SOURCE (who defined the rule: default/shield/user).
//   - Each rule inside a section displays its verdict badge.
//
// That separation matches the terminal's existing layout and removes the
// mixed verdict+source filters the browser was using.
//
// This module is PURE: no fs, no network. Any I/O (scanning JSONL) lives
// in cli/commands/scan.ts; this module only consumes ScanResult instances.
import type { ScanResult, SessionCost } from './cli/commands/scan';
import { SHIELDS } from './shields';

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

export type AgentId = 'claude' | 'gemini' | 'codex' | 'antigravity' | 'copilot' | 'shell';

// ── Agent display helpers ──────────────────────────────────────────────────
// Single source of truth for how each agent renders in scan/sessions output.
// Before this, every badge/label site inlined `agent === 'gemini' ? … :
// 'codex' ? … : Claude`, so any agent that wasn't gemini/codex (antigravity,
// copilot, shell) silently rendered as "[Claude]" — misattributing findings
// in the security report. Add a case here, not a 6th ternary at each site.

const AGENT_SHORT: Record<string, string> = {
  claude: 'Claude',
  gemini: 'Gemini',
  codex: 'Codex',
  antigravity: 'Agy',
  copilot: 'Copilot',
  shell: 'Shell',
};

const AGENT_LONG: Record<string, string> = {
  claude: 'Claude Code',
  gemini: 'Gemini CLI',
  codex: 'Codex',
  antigravity: 'Antigravity',
  copilot: 'GitHub Copilot',
  shell: 'Shell',
};

/** Full agent name for detail views (e.g. "GitHub Copilot"). */
export function agentDisplayName(agent: string): string {
  return AGENT_LONG[agent] ?? 'Claude Code';
}

/** Bracketed agent tag, padded to a fixed column width (default 10). */
export function agentBadgeText(agent: string, width = 10): string {
  return `[${AGENT_SHORT[agent] ?? 'Claude'}]`.padEnd(width);
}

/** chalk colour-function name for an agent's badge. */
export function agentColorName(agent: string): 'cyan' | 'blue' | 'magenta' | 'yellow' | 'green' {
  switch (agent) {
    case 'gemini':
      return 'blue';
    case 'codex':
      return 'magenta';
    case 'antigravity':
      return 'yellow';
    case 'copilot':
      return 'green';
    case 'shell':
      return 'yellow';
    default:
      return 'cyan';
  }
}

export interface AgentScanInput {
  id: AgentId;
  label: string;
  icon: string;
  scan: ScanResult;
}

// ---------------------------------------------------------------------------
// Output — the shared shape that both renderers read
// ---------------------------------------------------------------------------

export interface ScanSummary {
  stats: {
    sessions: number;
    totalToolCalls: number;
    bashCalls: number;
    totalCostUSD: number;
    firstDate: string | null;
    lastDate: string | null;
  };
  byVerdict: {
    blocked: number; // any verdict === 'block' (regardless of source)
    supervised: number; // any verdict === 'review' (regardless of source)
    leaks: number;
    loops: number;
  };
  byAgent: AgentSummary[];
  sections: Section[];
  leaks: LeakRef[];
  loops: LoopRef[];
  loopWastedUSD: number;
  /** Coverage behind loopWastedUSD — see LoopWaste. Absent dollars are not
   *  zero dollars, and a renderer needs to be able to say so. */
  loopWaste: LoopWaste;
}

export interface AgentSummary {
  id: AgentId;
  label: string;
  icon: string;
  sessions: number;
  findings: number; // findings + leaks + loops (what a user calls "issues")
  costUSD: number;
}

export type SectionSourceType = 'default' | 'shield' | 'user' | 'cloud';

export interface Section {
  id: string; // stable: 'default' | `shield:${name}` | 'user' | 'cloud'
  label: string; // display: 'Default Rules' | <shield name> | 'Your Rules' | 'Cloud Policy'
  subtitle: string;
  sourceType: SectionSourceType;
  shieldKey?: string; // shield name, for `node9 shield enable <x>` hints
  blockedCount: number;
  reviewCount: number;
  rules: RuleGroup[];
}

export interface RuleGroup {
  name: string; // post-prefix-strip display name
  verdict: 'block' | 'review';
  reason: string;
  findings: FindingRef[];
}

export interface FindingRef {
  timestamp: string;
  command: string; // preview (normalized whitespace, ready for display)
  fullCommand: string; // untruncated command for drill-down
  project: string;
  sessionId: string;
  agent: AgentId;
  toolName: string;
}

export interface LeakRef {
  patternName: string;
  redactedSample: string;
  toolName: string;
  timestamp: string;
  project: string;
  sessionId: string;
  agent: AgentId;
}

export interface LoopRef {
  toolName: string;
  commandPreview: string;
  count: number;
  timestamp: string;
  project: string;
  sessionId: string;
  agent: AgentId;
  /** See LoopFinding.kind. Optional for backwards compat (legacy data). */
  kind?: 'loop' | 'long-iteration';
}

// ---------------------------------------------------------------------------
// Constants — re-exported from @node9/policy-engine so the SaaS Report can
// compute the same loop-waste figure without copying values across packages.
// ---------------------------------------------------------------------------

// COST_PER_LOOP_ITER_USD is deliberately NOT imported or re-exported here any
// more. Loop dollars come from computeLoopWaste and the session that produced
// them; a reachable constant is how six competing loop-waste formulas grew in
// the first place — whoever needed a price multiplied by the nearest one.
export { LOOP_THRESHOLD_FOR_WASTE } from '@node9/policy-engine';
import { LOOP_THRESHOLD_FOR_WASTE } from '@node9/policy-engine';

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/**
 * Highest believable price for one tool call, in USD.
 *
 * Real rates measured across live sessions span $0.11 to $1.21. A basis above
 * this ceiling means the denominator is wrong (a session whose tool calls were
 * not counted), not that a call truly cost that much — and 40 iterations times
 * a bad basis renders a six-figure "finding". Reject instead: unknown is
 * recoverable, a fabricated headline number is not.
 */
export const MAX_PLAUSIBLE_RATE_USD = 50;

export interface LoopWaste {
  /** Dollars for the iterations we could price. Never includes a guess. */
  usd: number;
  /** Iterations priced from their own session's real cost. */
  pricedIterations: number;
  /**
   * Iterations we could not price. NOT zero dollars — the session carried no
   * usable cost (Antigravity and Copilot transcripts have no token data at
   * all). Renderers must show `usd` as a floor when this is > 0.
   */
  unpricedIterations: number;
}

/**
 * Price loop waste at the rate of the session each loop actually ran in.
 *
 * Per session, never blended. With a single average over a mixed set the
 * arithmetic is not merely imprecise, it inverts: 10 iterations at $1.015 plus
 * 10,000 at $0.001 is $20.15, while the same iterations against a blended
 * $0.504 basis reads $5,049.
 *
 * Exported for its unit test — this is the one place a count becomes money.
 */
export function computeLoopWaste(
  loops: ReadonlyArray<LoopRef>,
  perSession: ReadonlyArray<SessionCost>
): LoopWaste {
  const rate = new Map<string, number>();
  for (const s of perSession) {
    // Every rejection below must land on "unknown", never on 0. A zero basis
    // is a finite number, so it survives an isFinite guard and then prices
    // real waste at $0.00 — which reads as "nothing to see here".
    if (!(s.toolCalls > 0) || !(s.costUSD > 0)) continue;
    const r = s.costUSD / s.toolCalls;
    if (!Number.isFinite(r) || r <= 0 || r > MAX_PLAUSIBLE_RATE_USD) continue;
    rate.set(s.sessionId, r);
  }

  let usd = 0;
  let pricedIterations = 0;
  let unpricedIterations = 0;
  for (const l of loops) {
    // Long iterations are sustained work on one target, not a stuck loop.
    if (l.kind === 'long-iteration') continue;
    const wasted = Math.max(0, l.count - LOOP_THRESHOLD_FOR_WASTE);
    if (!Number.isFinite(wasted) || wasted === 0) continue;
    const r = rate.get(l.sessionId);
    if (r === undefined) {
      unpricedIterations += wasted;
      continue;
    }
    usd += wasted * r;
    pricedIterations += wasted;
  }
  return { usd, pricedIterations, unpricedIterations };
}

export function buildScanSummary(agents: AgentScanInput[]): ScanSummary {
  // Aggregate stats across all agents
  const stats = {
    sessions: 0,
    totalToolCalls: 0,
    bashCalls: 0,
    totalCostUSD: 0,
    firstDate: null as string | null,
    lastDate: null as string | null,
  };
  for (const a of agents) {
    stats.sessions += a.scan.sessions;
    stats.totalToolCalls += a.scan.totalToolCalls;
    stats.bashCalls += a.scan.bashCalls;
    stats.totalCostUSD += a.scan.totalCostUSD;
    if (a.scan.firstDate && (!stats.firstDate || a.scan.firstDate < stats.firstDate)) {
      stats.firstDate = a.scan.firstDate;
    }
    if (a.scan.lastDate && (!stats.lastDate || a.scan.lastDate > stats.lastDate)) {
      stats.lastDate = a.scan.lastDate;
    }
  }

  // Flatten findings/leaks/loops across agents, preserving agent attribution
  const allFindings = agents.flatMap((a) => a.scan.findings);
  const allLeaks: LeakRef[] = agents.flatMap((a) =>
    a.scan.dlpFindings.map((f) => ({
      patternName: f.patternName,
      redactedSample: f.redactedSample,
      toolName: f.toolName,
      timestamp: f.timestamp,
      project: f.project,
      sessionId: f.sessionId,
      agent: f.agent,
    }))
  );
  const allLoops: LoopRef[] = agents.flatMap((a) =>
    a.scan.loopFindings.map((f) => ({
      toolName: f.toolName,
      commandPreview: f.commandPreview,
      count: f.count,
      timestamp: f.timestamp,
      project: f.project,
      sessionId: f.sessionId,
      agent: f.agent,
      kind: f.kind,
    }))
  );

  // Top-line verdict counts (matches terminal's categorization)
  const byVerdict = {
    blocked: allFindings.filter((f) => f.source.rule.verdict === 'block').length,
    supervised: allFindings.filter((f) => f.source.rule.verdict === 'review').length,
    leaks: allLeaks.length,
    loops: allLoops.length,
  };

  // Per-agent summary
  const byAgent: AgentSummary[] = agents
    .map((a) => ({
      id: a.id,
      label: a.label,
      icon: a.icon,
      sessions: a.scan.sessions,
      findings: a.scan.findings.length + a.scan.dlpFindings.length + a.scan.loopFindings.length,
      costUSD: a.scan.totalCostUSD,
    }))
    .filter((s) => s.sessions > 0 || s.findings > 0);

  // Build sections — group findings by (sourceType, shieldName)
  const sections = buildSections(allFindings);

  // Loop waste, priced per session. The flat COST_PER_LOOP_ITER_USD it
  // replaced assumed ~2K Sonnet tokens for every iteration; against measured
  // rates that is 100x to 200x low, and it reported $0.24 where the same
  // iterations priced at their own sessions come to roughly $35.
  const loopWaste = computeLoopWaste(
    allLoops,
    agents.flatMap((a) => a.scan.perSession)
  );
  const loopWastedUSD = loopWaste.usd;

  return {
    stats,
    byVerdict,
    byAgent,
    sections,
    leaks: allLeaks,
    loops: allLoops,
    loopWastedUSD,
    loopWaste,
  };
}

// ---------------------------------------------------------------------------
// Section grouping
// ---------------------------------------------------------------------------

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function buildSections(findings: any[]): Section[] {
  // Map keyed by stable section id → Section draft
  const sectionMap = new Map<string, Section>();

  function ensureSection(
    id: string,
    label: string,
    subtitle: string,
    sourceType: SectionSourceType,
    shieldKey?: string
  ): Section {
    let s = sectionMap.get(id);
    if (!s) {
      s = {
        id,
        label,
        subtitle,
        sourceType,
        shieldKey,
        blockedCount: 0,
        reviewCount: 0,
        rules: [],
      };
      sectionMap.set(id, s);
    }
    return s;
  }

  // Rule grouping inside a section
  const ruleMap = new Map<string, RuleGroup>(); // sectionId + '::' + rulename → group

  for (const f of findings) {
    const src = f.source;
    const sourceType: SectionSourceType = src.sourceType;
    const shieldName: string = src.shieldName;
    const verdict = src.rule.verdict === 'block' ? 'block' : 'review';

    // Resolve section id + display label
    let sectionId: string;
    let sectionLabel: string;
    let sectionSubtitle: string;
    let shieldKey: string | undefined;

    if (sourceType === 'default') {
      sectionId = 'default';
      sectionLabel = 'Default Rules';
      sectionSubtitle = 'built-in, always on';
    } else if (sourceType === 'shield') {
      sectionId = `shield:${shieldName}`;
      sectionLabel = shieldName;
      sectionSubtitle = SHIELDS[shieldName]?.description ?? '';
      shieldKey = shieldName;
    } else if (shieldName === 'cloud') {
      sectionId = 'cloud';
      sectionLabel = 'Cloud Policy';
      sectionSubtitle = 'synced from node9 cloud';
    } else {
      sectionId = 'user';
      sectionLabel = 'Your Rules';
      sectionSubtitle = 'added in node9.config.json';
    }

    const section = ensureSection(sectionId, sectionLabel, sectionSubtitle, sourceType, shieldKey);

    // Get or create rule group
    const ruleDisplayName = (src.rule.name ?? 'unnamed').replace(/^shield:[^:]+:/, '');
    const ruleKey = sectionId + '::' + ruleDisplayName;
    let rule = ruleMap.get(ruleKey);
    if (!rule) {
      rule = {
        name: ruleDisplayName,
        verdict,
        reason: src.rule.reason ?? '',
        findings: [],
      };
      ruleMap.set(ruleKey, rule);
      section.rules.push(rule);
    }

    // Deduplicate findings within a rule group (same project + same command preview)
    const cmdPreview = previewCommand(f.input, 120);
    const fullCmd = fullCommandOf(f.input);
    const isDupe = rule.findings.some((x) => x.project === f.project && x.command === cmdPreview);
    if (!isDupe) {
      rule.findings.push({
        timestamp: f.timestamp ?? '',
        command: cmdPreview,
        fullCommand: fullCmd,
        project: f.project,
        sessionId: f.sessionId,
        agent: f.agent,
        toolName: f.toolName,
      });
    }

    // Update section counts (by verdict)
    if (verdict === 'block') section.blockedCount++;
    else section.reviewCount++;
  }

  // Sort: sections by (blocked desc, total findings desc); rules within by (block first, count desc)
  const sections = [...sectionMap.values()];
  sections.sort((a, b) => {
    const aTotal = a.blockedCount + a.reviewCount;
    const bTotal = b.blockedCount + b.reviewCount;
    if (b.blockedCount !== a.blockedCount) return b.blockedCount - a.blockedCount;
    return bTotal - aTotal;
  });
  for (const s of sections) {
    s.rules.sort((a, b) => {
      const aBlock = a.verdict === 'block' ? 1 : 0;
      const bBlock = b.verdict === 'block' ? 1 : 0;
      if (bBlock !== aBlock) return bBlock - aBlock;
      return b.findings.length - a.findings.length;
    });
  }

  return sections;
}

// ---------------------------------------------------------------------------
// Command preview helpers (kept here so both renderers compute identically)
// ---------------------------------------------------------------------------

function previewCommand(input: Record<string, unknown>, max: number): string {
  const raw = input.command ?? input.query ?? input.file_path ?? JSON.stringify(input);
  const s = String(raw).replace(/\s+/g, ' ').trim();
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

function fullCommandOf(input: Record<string, unknown>): string {
  const raw = input.command ?? input.query ?? input.file_path ?? JSON.stringify(input);
  return String(raw).replace(/\s+/g, ' ').trim();
}
