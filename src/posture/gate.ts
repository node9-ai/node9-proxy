// src/posture/gate.ts
// Check 3 — Destructive-command gate, with the obfuscation self-test.
//
// This is the share-magnet: it runs a corpus of destructive commands —
// a plain baseline plus obfuscated variants — through node9's OWN policy
// evaluator and reports which slip past. It tests the user's ACTUAL config
// (same `evaluatePolicy` the in-path gate calls), so the finding is real.
//
// SAFETY: these payload strings are passed ONLY to `evaluatePolicy`, which
// classifies them and returns a verdict. They are NEVER handed to a shell,
// spawn, or exec — nothing here executes. This is a dry-run classifier probe.

import { evaluatePolicy } from '../policy';
import type { CheckContext, Finding } from './types';

interface GatePayload {
  /** Short label for the technique (shown in the report). */
  technique: string;
  /** Destructive command — classifier input only, never executed. */
  command: string;
}

/**
 * One obvious baseline + several obfuscations of the same destructive intent.
 * If the baseline is caught but obfuscations slip, that's the honest message:
 * pattern heuristics are not a boundary.
 */
const PAYLOADS: GatePayload[] = [
  { technique: 'plain recursive delete', command: 'rm -rf /' },
  // base64 of "rm -rf ~" piped into a shell
  { technique: 'base64-decoded pipe to shell', command: 'echo cm0gLXJmIH4= | base64 -d | sh' },
  { technique: 'quote-split command name', command: "r''m -rf ~" },
  {
    technique: 'interpreter wrapper',
    command: 'python3 -c "import shutil,os;shutil.rmtree(os.path.expanduser(\'~\'))"',
  },
  { technique: 'find -delete', command: 'find / -delete' },
];

export async function checkGate(ctx: CheckContext): Promise<Finding[]> {
  const results = await Promise.all(
    PAYLOADS.map(async (p) => {
      const verdict = await evaluatePolicy('Bash', { command: p.command }, ctx.agent, ctx.cwd);
      return { ...p, blocked: verdict.decision === 'block' };
    })
  );

  const baseline = results[0];
  const slipped = results.filter((r) => !r.blocked);

  // The gate isn't even catching the obvious case → it's off / not enforcing.
  if (!baseline.blocked) {
    return [
      {
        category: 'Approval gate',
        severity: 'critical',
        title: 'Destructive commands are not blocked',
        what: 'Dangerous shell commands run unchecked.',
        why: 'No enforcing policy is gating Bash — even `rm -rf /` is allowed.',
        who: 'A tricked agent could wipe files or damage the machine with one command.',
        detail: [],
        fix: 'node9 enforces destructive-command blocking in-path (enforcing mode).',
      },
    ];
  }

  // Baseline caught but obfuscations slip → heuristics aren't a boundary.
  if (slipped.length > 0) {
    return [
      {
        category: 'Approval gate',
        severity: 'high',
        title: `Catches \`rm -rf\` but misses ${slipped.length} of ${results.length} obfuscations`,
        what: 'node9 blocks obvious destructive commands, but a few disguised ones slip past.',
        why: "Pattern-matching can't catch every obfuscation.",
        who: 'A cleverly-worded destructive command could still run.',
        detail: slipped.map((s) => `slips through: ${s.technique}`),
        fix: 'node9 enforces in-path — but the OS/container is the real boundary.',
      },
    ];
  }

  return [];
}
