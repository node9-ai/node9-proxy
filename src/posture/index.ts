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

export async function runPosture(opts: RunPostureOptions = {}): Promise<PostureResult> {
  const ctx: CheckContext = {
    home: opts.home ?? os.homedir(),
    cwd: opts.cwd ?? process.cwd(),
    agent: opts.agent,
  };

  const findings: Finding[] = [];
  const passedCategories: string[] = [];

  for (const check of POSTURE_CHECKS) {
    const result = await check.run(ctx);
    if (result.length === 0) {
      passedCategories.push(check.category);
    } else {
      findings.push(...result);
    }
  }

  const { score, tier } = scorePosture(findings, POSTURE_CHECKS.length);

  return {
    agent: opts.agent ? `${opts.agent} on this host` : 'agent on this host',
    findings,
    passedCategories,
    score,
    tier,
    checksRun: POSTURE_CHECKS.length,
  };
}

export type { PostureResult, Finding } from './types';
