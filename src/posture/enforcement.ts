// src/posture/enforcement.ts
// Coverage-awareness: for each finding, decide whether node9 is ALREADY
// enforcing a mitigation — assessed at the LAYER THAT ACTUALLY GATES the
// action (DLP for file reads, policy for commands), not a single tier.
//
// Hard-won (see doc/roadmap/active/posture-plain-language-design.md): probing
// `evaluatePolicy` alone is wrong — it sits after DLP, so a credential read
// reads `allow` there while the real gate BLOCKS it via DLP. We mirror the
// orchestrator's layering with the PURE functions (no side effects).

import { scanFilePath } from '../dlp';
import { evaluatePolicy } from '../policy';
import { getConfig } from '../config';
import { getAgentWiring } from '../agent-wiring';
import type { CheckContext, Coverage, Finding } from './types';

interface EnforceEnv {
  /** node9 is actually enforcing (not observe/audit) AND wired into an agent. */
  enforcing: boolean;
  egressBlocking: boolean;
  egressReviewing: boolean;
}

/**
 * Egress coverage. `review` counts as COVERED (approval-gated) exactly like a
 * review-verdict command: at runtime an outbound to an unknown host routes to
 * the approval race engine, so the user gates exfil — it is NOT "logged but
 * not stopped". Only `off` / not-enforcing is open. Exported for tests.
 */
export function egressCoverage(env: EnforceEnv): Coverage {
  if (env.enforcing && env.egressBlocking) {
    return { state: 'covered', level: 'block', via: 'node9 egress' };
  }
  if (env.enforcing && env.egressReviewing) {
    return { state: 'covered', level: 'review', via: 'node9 egress' };
  }
  return { state: 'open' };
}

/** A gate verdict, normalised. 'review' counts as GATED (it prompts the user). */
type Verdict = 'block' | 'review' | 'allow';

/**
 * Pure: turn a probe outcome + environment into a Coverage. Exported for tests.
 * - block/review + enforcing → covered (review = approval-gated, still covered)
 * - any verdict but NOT enforcing → open ("node9 sees it but isn't enforcing")
 * - allow → open
 */
export function coverageFromVerdict(verdict: Verdict, env: EnforceEnv, via?: string): Coverage {
  if (!env.enforcing) return { state: 'open' };
  if (verdict === 'block') return { state: 'covered', level: 'block', via };
  if (verdict === 'review') return { state: 'covered', level: 'review', via };
  return { state: 'open' };
}

/** Shorten a rule name like `shield:project-jail:block-read-ssh` → `project-jail shield`. */
function viaFromRule(ruleName?: string): string | undefined {
  if (!ruleName) return undefined;
  const m = /^shield:([^:]+):/.exec(ruleName);
  return m ? `${m[1]} shield` : undefined;
}

/** Mutates each finding's `coverage` in place, based on its `coverageProbe`. */
export async function annotateCoverage(findings: Finding[], ctx: CheckContext): Promise<void> {
  const config = getConfig(ctx.cwd);
  const mode = config.settings.mode;
  const wired = getAgentWiring(ctx.home).some((r) => r.isProtected);
  const env: EnforceEnv = {
    enforcing: wired && mode !== 'observe' && mode !== 'audit',
    egressBlocking: config.policy.egress.enabled && config.policy.egress.mode === 'block',
    egressReviewing: config.policy.egress.enabled && config.policy.egress.mode === 'review',
  };

  for (const f of findings) {
    const probe = f.coverageProbe;
    if (!probe) continue;

    if (probe.kind === 'cantFix') {
      f.coverage = { state: 'cant-fix' };
      continue;
    }

    if (probe.kind === 'egress') {
      f.coverage = egressCoverage(env);
      continue;
    }

    if (probe.kind === 'fileRead') {
      // DLP layer — the one that actually gates the agent's Read tool.
      const verdicts = probe.paths.map((p) => scanFilePath(p)?.severity ?? null);
      if (verdicts.length === 0 || verdicts.some((v) => v === null)) {
        f.coverage = coverageFromVerdict('allow', env); // any unblocked path → open
      } else {
        const worst: Verdict = verdicts.some((v) => v === 'review') ? 'review' : 'block';
        f.coverage = coverageFromVerdict(worst, env, 'node9 DLP');
      }
      continue;
    }

    // probe.kind === 'command' — policy/AST layer (destructive, sudo).
    const verdict = await evaluatePolicy('Bash', { command: probe.command }, ctx.agent, ctx.cwd);
    f.coverage = coverageFromVerdict(
      verdict.decision as Verdict,
      env,
      viaFromRule(verdict.ruleName)
    );
  }
}
