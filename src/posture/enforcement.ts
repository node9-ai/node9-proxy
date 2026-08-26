// src/posture/enforcement.ts
// Coverage-awareness: for each finding, decide whether node9 is ALREADY
// enforcing a mitigation — assessed at the LAYER THAT ACTUALLY GATES the
// action (DLP for file reads, policy for commands), not a single tier.
//
// Hard-won (see doc/roadmap/active/posture-plain-language-design.md): probing
// `evaluatePolicy` alone is wrong — it sits after DLP, so a credential read
// reads `allow` there while the real gate BLOCKS it via DLP. We mirror the
// orchestrator's layering with the PURE functions (no side effects).

import path from 'path';
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

/** Render an absolute path as `~/…` for a fix string (twin of
 *  displayPath in secrets.ts — same `home + sep` boundary rule so a
 *  sibling dir sharing the prefix is not mis-rendered as `~foo`). */
function tildePath(p: string, home: string): string {
  if (!home) return p;
  if (p === home) return '~';
  const prefix = home.endsWith(path.sep) ? home : home + path.sep;
  return p.startsWith(prefix) ? '~' + path.sep + p.slice(prefix.length) : p;
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
      // The real gate for an agent file read is DLP ∪ the policy path
      // rules: `node9 jail add` creates `block-path-*` smartRules on
      // file_path that DLP knows nothing about, so probing DLP alone
      // reported a jail-added file as uncovered forever (N6). Mirror the
      // orchestrator: DLP answers first (it gates first at runtime); a
      // DLP-silent path falls through to the policy layer's Read verdict.
      const perPath: Array<{ path: string; verdict: Verdict; via?: string }> = [];
      for (const p of probe.paths) {
        const dlpSev = scanFilePath(p)?.severity ?? null;
        if (dlpSev) {
          perPath.push({ path: p, verdict: dlpSev as Verdict, via: 'node9 DLP' });
          continue;
        }
        const pv = await evaluatePolicy('Read', { file_path: p }, ctx.agent, ctx.cwd);
        perPath.push({ path: p, verdict: pv.decision as Verdict, via: viaFromRule(pv.ruleName) });
      }
      const uncovered = perPath.filter((x) => x.verdict !== 'block' && x.verdict !== 'review');
      if (perPath.length === 0 || uncovered.length > 0) {
        f.coverage = coverageFromVerdict('allow', env); // any ungated path → open
        // N6 fix-string honesty: the static fix says "enable
        // project-jail" — if the gate testimony says it is already
        // applied, that command is already true and the honest next step
        // is jail-adding the specific uncovered files. Rewritten HERE,
        // from the SAME per-path evaluation the coverage came from —
        // never a second judge in the finding builder.
        if (
          uncovered.length > 0 &&
          (config.policy.appliedShields ?? []).includes('project-jail') &&
          f.fix?.includes('shield enable project-jail')
        ) {
          const first = tildePath(uncovered[0].path, ctx.home || '');
          const rest = uncovered.length - 1;
          f.fix =
            `project-jail is already enabled but does not cover ${rest > 0 ? 'these files' : 'this file'}. ` +
            `Fix it now: run \`node9 jail add ${first}\`` +
            (rest > 0 ? ` (+${rest} more — see detail)` : '') +
            ' to block agent reads in-path.';
        }
      } else {
        const worst: Verdict = perPath.some((x) => x.verdict === 'review') ? 'review' : 'block';
        const vias = [...new Set(perPath.map((x) => x.via).filter((v): v is string => !!v))];
        f.coverage = coverageFromVerdict(
          worst,
          env,
          vias.length > 0 ? vias.join(' + ') : undefined
        );
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
