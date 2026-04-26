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
import type { ScanResult } from './cli/commands/scan';
import { SHIELDS } from './shields';

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

export type AgentId = 'claude' | 'gemini' | 'codex' | 'shell';

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
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const LOOP_THRESHOLD_FOR_WASTE = 3;
export const COST_PER_LOOP_ITER_USD = 0.006; // ~2K tokens at Sonnet pricing

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

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

  // Loop savings estimate
  const wastedIters = allLoops.reduce(
    (sum, l) => sum + Math.max(0, l.count - LOOP_THRESHOLD_FOR_WASTE),
    0
  );
  const loopWastedUSD = wastedIters * COST_PER_LOOP_ITER_USD;

  return {
    stats,
    byVerdict,
    byAgent,
    sections,
    leaks: allLeaks,
    loops: allLoops,
    loopWastedUSD,
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
