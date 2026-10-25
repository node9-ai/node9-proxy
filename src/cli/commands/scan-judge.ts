// One judgement path for `node9 scan` (fw#399, Part A of #320).
//
// Every historical tool call is judged by the live gate through the forecast
// entry (src/auth/forecast.ts), under the caller's real configuration, with
// the catalog modes and the mode of the machine. The five history parsers
// share this one class; the verdict is mapped back onto the scan's finding
// shapes so the renderers, the summary and `--json` keep working.
//
// What stays outside this path, on purpose: DLP and canary scans of prompts,
// tool results and shell configuration files (observations, not gate
// decisions), and the whole-session churn analytics (`detectLoops`).

import { DEFAULT_CONFIG, getConfig, type Config } from '../../config';
import type { SmartRule } from '@node9/policy-engine';
import { SHIELDS } from '../../shields';
import { forecastDecision, type ForecastVerdict } from '../../auth/forecast';
import { ForecastSessionState } from '../../auth/forecast-state';
import { toolRole } from '../../exposure/roles';
import { scanArgs } from '../../dlp';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { DlpFinding, Finding, RuleSource, ScanDedup, ScanResult } from './scan';

export type ScanAgent = Finding['agent'];

export interface HistoricalCall {
  agent: ScanAgent;
  toolName: string;
  input: Record<string, unknown>;
  /** ISO timestamp of the call; empty when the transcript has none. */
  timestamp: string;
  sessionId: string;
  project: string;
  /** The call's working directory when the transcript carries one. Selects
   *  the project configuration the hook would have read. */
  cwd?: string;
  /** The input with every planted decoy value replaced, when the call carried
   *  one. The gate stops at the decoy; the leaks list still names a real
   *  credential beside it (tool-result-dlp T6). */
  scrubbed?: Record<string, unknown>;
}

export interface JudgedCall {
  verdict: ForecastVerdict;
  /** A credential was found in the call's arguments (the DLP gate). */
  dlpMatched: boolean;
}

/** What the scan judged under; one per run, shown beside the findings. */
export interface ScanPolicy {
  basis: 'current';
  mode: string;
  /** Observe / audit: nothing is enforced on this machine. */
  recordOnly: boolean;
  policySource: 'local' | 'workspace';
  /** Inputs the forecast could not reproduce, with how many calls each touched. */
  unknownInputs: Record<string, number>;
}

const PREVIEW_LEN = 120;

export class HistoryJudge {
  private readonly configs = new Map<string, Config>();
  private readonly sessions = new Map<string, ForecastSessionState>();
  private readonly unknownInputs: Record<string, number> = {};
  private readonly repos = new Map<string, string | undefined>();

  /** The nearest git repository at or above `cwd` (a `.git` directory or
   *  file, so worktrees count), home-relative; undefined when none. Cached per
   *  directory: history repeats the same few cwds thousands of times. */
  repoOf(cwd: string | undefined): string | undefined {
    if (!cwd || !path.isAbsolute(cwd)) return undefined;
    if (this.repos.has(cwd)) return this.repos.get(cwd);
    let dir = cwd;
    let found: string | undefined;
    for (;;) {
      try {
        if (fs.existsSync(path.join(dir, '.git'))) {
          found = dir;
          break;
        }
      } catch {
        break;
      }
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
    const home = os.homedir();
    const label = found && found.startsWith(home) ? '~' + found.slice(home.length) : found;
    this.repos.set(cwd, label);
    return label;
  }

  /** The configuration the hook would have read for a call in `cwd`,
   *  resolved once per distinct directory. */
  configFor(cwd: string | undefined): Config {
    const key = cwd ?? '';
    let c = this.configs.get(key);
    if (!c) {
      c = cwd ? getConfig(cwd) : getConfig();
      this.configs.set(key, c);
    }
    return c;
  }

  /** The replayed state of one session, created on first use. `blind` marks
   *  a transcript that carries no tool results, so the state cannot be fed. */
  session(sessionId: string, opts: { blind?: boolean } = {}): ForecastSessionState {
    let s = this.sessions.get(sessionId);
    if (!s) {
      s = new ForecastSessionState(sessionId, opts);
      this.sessions.set(sessionId, s);
    }
    return s;
  }

  /** A tool result held a secret: the session is tainted from here on. */
  noteOutputSecret(sessionId: string, patternName: string, timestamp: string): void {
    this.session(sessionId).noteOutputSecret(patternName, clockOf(timestamp));
  }

  /** A tool that brings outside content returned something. */
  noteToolResult(sessionId: string, toolName: string, timestamp: string, cwd?: string): void {
    const policy = this.configFor(cwd).policy.untrustedContent;
    if (!policy?.enabled) return;
    if (!toolRole(toolName, policy).source) return;
    const mcp = /^mcp__([^_]+(?:_[^_]+)*)__/.exec(toolName);
    this.session(sessionId).noteOutsideContent({
      tool: toolName,
      ...(mcp && { server: mcp[1] }),
      at: clockOf(timestamp),
    });
  }

  async judge(call: HistoricalCall, result: ScanResult, dedup: ScanDedup): Promise<JudgedCall> {
    const config = this.configFor(call.cwd);
    const verdict = await forecastDecision(
      call.toolName,
      call.input,
      { agent: call.agent, sessionId: call.sessionId },
      { cwd: call.cwd, config, session: this.session(call.sessionId), at: clockOf(call.timestamp) }
    );
    for (const u of verdict.unknown) this.unknownInputs[u] = (this.unknownInputs[u] ?? 0) + 1;
    const repo = this.repoOf(call.cwd);
    const where = call.cwd ? { cwd: call.cwd, ...(repo && { repo }) } : {};

    // Credentials in the arguments: the leaks list, as before.
    let dlpMatched = false;
    for (const row of verdict.rows) {
      if (!row.dlpPattern || !/dlp/.test(row.checkedBy) || /canary/.test(row.checkedBy)) continue;
      dlpMatched = true;
      const finding: DlpFinding = {
        patternName: row.dlpPattern,
        redactedSample: row.dlpSample ?? '',
        toolName: call.toolName,
        timestamp: call.timestamp,
        project: call.project,
        sessionId: call.sessionId,
        agent: call.agent,
        ...where,
      };
      const k = `${finding.patternName}|${finding.redactedSample}|${call.project}`;
      if (!dedup.dlpKeys.has(k)) {
        dedup.dlpKeys.add(k);
        result.dlpFindings.push(finding);
      }
    }

    // The decoy gate ran first and the DLP gate never saw the arguments: a
    // real credential beside the decoy is still a leak (an observation, not a
    // second verdict; design 4.1).
    if (verdict.layer === 'canary' && call.scrubbed) {
      const m = scanArgs(call.scrubbed);
      if (m) {
        dlpMatched = true;
        const k = `${m.patternName}|${m.redactedSample}|${call.project}`;
        if (!dedup.dlpKeys.has(k)) {
          dedup.dlpKeys.add(k);
          result.dlpFindings.push({
            patternName: m.patternName,
            redactedSample: m.redactedSample,
            toolName: call.toolName,
            timestamp: call.timestamp,
            project: call.project,
            sessionId: call.sessionId,
            agent: call.agent,
            ...where,
          });
        }
      }
    }

    // Everything the gate would have stopped or recorded, except the leaks
    // and decoys above, which have their own lists.
    if (verdict.decision !== 'allow' && verdict.layer !== 'dlp' && verdict.layer !== 'canary') {
      const source = ruleSourceFor(verdict, call.toolName, config);
      // The same command in two repositories is two findings (fw#404).
      const k = `${source.rule.name ?? '<unnamed>'}|${preview(call.input)}|${call.project}|${repo ?? ''}`;
      if (!dedup.findingsKeys.has(k)) {
        dedup.findingsKeys.add(k);
        result.findings.push({
          source,
          toolName: call.toolName,
          input: call.input,
          timestamp: call.timestamp,
          project: call.project,
          sessionId: call.sessionId,
          agent: call.agent,
          checkId: verdict.checkId,
          decision: verdict.decision,
          enforced: verdict.enforced,
          ...(verdict.notEnforcedBecause && { notEnforcedBecause: verdict.notEnforcedBecause }),
          layer: verdict.layer,
          unknown: verdict.unknown,
          ...where,
        });
      }
    }
    return { verdict, dlpMatched };
  }

  policy(): ScanPolicy {
    const home = this.configFor(undefined);
    const mode = home.settings.mode ?? 'standard';
    return {
      basis: 'current',
      mode,
      recordOnly: mode === 'observe' || mode === 'audit',
      policySource: home.policySource,
      unknownInputs: { ...this.unknownInputs },
    };
  }
}

function clockOf(timestamp: string): number {
  const t = Date.parse(timestamp);
  return Number.isFinite(t) ? t : Date.now();
}

function preview(input: Record<string, unknown>): string {
  const s = typeof input.command === 'string' ? input.command : JSON.stringify(input);
  return s.replace(/\s+/g, ' ').slice(0, PREVIEW_LEN);
}

/**
 * The scan's rule source for a verdict: the shield and rule behind a
 * `shield:<name>:<rule>` name, the user's or the default rule behind a plain
 * name, or a synthetic rule named after the catalog check for the gates that
 * have no rule (PII, loops, taint-egress, the SSRF floor, ...).
 */
export function ruleSourceFor(
  verdict: ForecastVerdict,
  toolName: string,
  config: Config
): RuleSource {
  const name = verdict.ruleName;
  const ruleVerdict: SmartRule['verdict'] = verdict.decision === 'block' ? 'block' : 'review';
  const synthetic = (ruleName: string): SmartRule => ({
    name: ruleName,
    tool: toolName.toLowerCase(),
    conditions: [],
    verdict: ruleVerdict,
    reason: verdict.reason ?? verdict.label ?? '',
  });

  if (name?.startsWith('shield:')) {
    const shieldName = name.split(':')[1] ?? 'shield';
    const rule = SHIELDS[shieldName]?.smartRules.find((r) => r.name === name);
    return {
      shieldName,
      shieldLabel: shieldName,
      sourceType: 'shield',
      rule: rule ?? synthetic(name),
    };
  }
  if (name) {
    const own = config.policy.smartRules.find((r) => r.name === name);
    if (own) {
      const isDefault = DEFAULT_CONFIG.policy.smartRules.some((r) => r.name === name);
      if (isDefault)
        return {
          shieldName: 'default',
          shieldLabel: 'Default Rules',
          sourceType: 'default',
          rule: own,
        };
      const cloud = config.policySource === 'workspace';
      return {
        shieldName: cloud ? 'cloud' : 'user',
        shieldLabel: cloud ? 'Cloud Policy' : 'Your Rules',
        sourceType: 'user',
        rule: own,
      };
    }
  }
  return {
    shieldName: 'default',
    shieldLabel: 'Default Rules',
    sourceType: 'default',
    rule: synthetic(name ?? verdict.checkId ?? verdict.layer),
  };
}
