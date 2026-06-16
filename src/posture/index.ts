// src/posture/index.ts
// Orchestrates `node9 posture`: run all checks → score → assemble result.
// Phase 0 checks: secrets · egress · gate-bypass self-test.

import os from 'os';
import { checkSecrets } from './secrets';
import { checkEgress } from './egress';
import { checkGate } from './gate';
import { checkSupplyChain } from './supply-chain';
import { checkPrivilege } from './privilege';
import { checkContainment } from './containment';
import { checkInbound } from './inbound';
import { checkCoverage } from './coverage';
import { scorePosture } from './score';
import { deriveHeadline } from './headline';
import { annotateCoverage } from './enforcement';
import type { CheckContext, Finding, PostureCheck, PostureResult } from './types';

export const POSTURE_CHECKS: PostureCheck[] = [
  { category: 'Secrets', run: checkSecrets },
  { category: 'Egress', run: checkEgress },
  { category: 'Approval gate', run: checkGate },
  { category: 'Supply chain', run: checkSupplyChain },
  { category: 'Privilege', run: checkPrivilege },
  { category: 'Isolation', run: checkContainment },
  { category: 'Inbound', run: checkInbound },
  { category: 'Coverage', run: checkCoverage },
];

export interface RunPostureOptions {
  home?: string;
  cwd?: string;
  agent?: string;
}

/**
 * Run a set of checks with per-check isolation: a check that throws is recorded
 * in `erroredCategories` and never crashes the report. Exported so the
 * isolation is directly testable.
 */
export async function runChecks(
  checks: PostureCheck[],
  ctx: CheckContext
): Promise<{ findings: Finding[]; passedCategories: string[]; erroredCategories: string[] }> {
  const findings: Finding[] = [];
  const passedCategories: string[] = [];
  const erroredCategories: string[] = [];

  for (const check of checks) {
    try {
      const result = await check.run(ctx);
      if (result.length === 0) passedCategories.push(check.category);
      else findings.push(...result);
    } catch (err) {
      // One bad check (e.g. a malformed config reaching the policy engine)
      // must not nuke the whole scorecard — the report is the product.
      erroredCategories.push(check.category);
      if (process.env.NODE9_DEBUG) {
        console.error(`[posture] check "${check.category}" failed:`, (err as Error)?.message);
      }
    }
  }

  return { findings, passedCategories, erroredCategories };
}

export async function runPosture(opts: RunPostureOptions = {}): Promise<PostureResult> {
  const ctx: CheckContext = {
    home: opts.home ?? os.homedir(),
    cwd: opts.cwd ?? process.cwd(),
    agent: opts.agent,
  };

  const { findings, passedCategories, erroredCategories } = await runChecks(POSTURE_CHECKS, ctx);

  // Decide what node9 is already enforcing — at the real gating layer.
  await annotateCoverage(findings, ctx);

  const { score, tier } = scorePosture(findings, POSTURE_CHECKS.length);

  return {
    agent: opts.agent ? `${opts.agent} on this host` : 'agent on this host',
    findings,
    passedCategories,
    erroredCategories,
    headline: deriveHeadline(findings),
    score,
    tier,
    checksRun: POSTURE_CHECKS.length,
  };
}

export type { PostureResult, Finding } from './types';
