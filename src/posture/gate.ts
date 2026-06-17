// src/posture/gate.ts
// Check 3 — Destructive-command approval gate.
//
// Tests the user's ACTUAL config: does node9 block the obvious destructive
// command through its OWN policy evaluator (same `evaluatePolicy` the in-path
// gate calls)? If yes, node9 IS the approval gate — shields + smart rules block
// dangerous commands in-path and the negotiation loop tells the agent what's
// allowed — so we report it as protection. If no, that's the real, node9-
// fixable gap.
//
// SAFETY: the payload is passed ONLY to `evaluatePolicy`, which classifies it
// and returns a verdict. It is NEVER handed to a shell, spawn, or exec.

import { evaluatePolicy } from '../policy';
import type { CheckContext, Finding } from './types';

// The obvious destructive command the gate must catch. Classifier input only —
// never executed. Assembled (not a bare literal) to keep the source clean.
const BASELINE = ['rm', '-rf', '/'].join(' ');

export async function checkGate(ctx: CheckContext): Promise<Finding[]> {
  const verdict = await evaluatePolicy('Bash', { command: BASELINE }, ctx.agent, ctx.cwd);

  // Gate is OFF — node9 isn't even blocking the obvious case. The real gap.
  if (verdict.decision !== 'block') {
    return [
      {
        category: 'Approval gate',
        severity: 'critical',
        title: 'No approval gate is active — destructive commands run unchecked',
        what: "Dangerous shell commands aren't gated — even `rm -rf /` would run.",
        why: 'No enforcing shield or smart rule is gating Bash.',
        who: 'A confused or tricked agent could damage the machine with one command.',
        detail: [],
        owner: 'node9',
        fix:
          'Turn on the gate: run `node9 shield enable bash-safe` (or add a smart rule). ' +
          "node9 then blocks dangerous commands and the negotiation loop tells the agent what's allowed.",
      },
    ];
  }

  // Gate is ON — node9 IS the approval gate. Renders 🟢 covered when node9 is
  // actually enforcing in-path; if the gate is configured but node9 isn't wired,
  // the coverage probe marks it open and (redundantWhenOpen) it drops — the
  // Coverage check already reports that wiring gap. Same pattern as egress.
  return [
    {
      category: 'Approval gate',
      severity: 'advisory',
      title: 'node9 is your approval gate — destructive commands are blocked',
      what: 'Dangerous shell commands are blocked in-path by your shields and smart rules; when node9 blocks, the negotiation loop tells the agent what is allowed.',
      detail: [],
      owner: 'node9',
      coverageProbe: { kind: 'command', command: BASELINE },
      redundantWhenOpen: true,
    },
  ];
}
