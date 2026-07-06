// src/posture/governance.ts
// Posture checks for the governed-config dimensions (Report UI v2 · P3) —
// Data · Approvals · Tool governance · Files · Cost. Each mirrors a
// PolicyStudio control and reads the SAME config the in-path gate enforces
// (config inspection only, no probing). They're plain Finding[] producers:
// the renderer + score are unchanged, driven by the generic Finding shape.

import path from 'path';
import { getConfig } from '../config';
import type { CheckContext, Finding } from './types';

/** A canonical jailed credential file — the coverage probe reads it through
 *  the real DLP/jail layer to prove Data/Files are actually enforcing. */
const jailProbePath = (home: string) => path.join(home, '.aws', 'credentials');

/** DATA — is DLP (secret/PII) scanning governed? */
export function checkData(ctx: CheckContext): Finding[] {
  const dlp = getConfig(ctx.cwd).policy.dlp;
  if (!dlp?.enabled) {
    return [
      {
        category: 'Data',
        severity: 'high',
        title: 'DLP is off — secrets in tool output are not scanned',
        what: 'node9 is not scanning tool arguments or output for secrets/PII.',
        why: 'DLP is disabled in your policy.',
        who: 'A leaked API key or credential in a command or a tool result goes unnoticed.',
        detail: [],
        owner: 'node9',
        fix: 'Enable DLP in your policy (Data tab / `policy.dlp.enabled`).',
      },
    ];
  }
  if (dlp.pii !== 'block') {
    return [
      {
        category: 'Data',
        severity: 'medium',
        title: 'PII is detect-only — SSNs / credit cards are logged, not blocked',
        what: 'DLP catches secrets, but PII (SSN / credit card) is only flagged, not blocked in-path.',
        why: "`policy.dlp.pii` is 'off' (the default).",
        who: 'A tool call carrying PII is allowed through; only the audit records it.',
        detail: [],
        owner: 'node9',
        node9Reduces: true,
        scoreWeight: 6,
        fix: "Set PII to block (Data tab / `policy.dlp.pii = 'block'`).",
      },
    ];
  }
  // DLP on + PII blocking → covered. Coverage probe renders 🟢 when enforcing.
  return [
    {
      category: 'Data',
      severity: 'advisory',
      title: 'DLP is on — secrets and PII are gated',
      detail: [],
      owner: 'node9',
      coverageProbe: { kind: 'fileRead', paths: [jailProbePath(ctx.home)] },
      redundantWhenOpen: true,
    },
  ];
}

/** APPROVALS — can a 'review' verdict actually reach a human? */
export function checkApprovalConfig(ctx: CheckContext): Finding[] {
  const s = getConfig(ctx.cwd).settings;
  // A review needs SOMEWHERE to go: an approver channel, or the inline
  // 'ask' path (the agent renders the prompt itself).
  const a = s.approvers ?? { native: false, browser: false, cloud: false, terminal: false };
  const hasChannel = a.native || a.browser || a.cloud || a.terminal || s.reviewChannel === 'ask';

  // A zero timeout auto-denies EVERY review instantly (the shipped-then-fixed
  // approvalTimeout=0 bug class) — surface it if a user set it.
  if (s.approvalTimeoutMs === 0) {
    return [
      {
        category: 'Approvals',
        severity: 'high',
        title: 'Approval timeout is 0 — every review auto-denies instantly',
        what: 'A review request is denied the moment it is raised; no human ever sees it.',
        why: '`settings.approvalTimeoutMs` is 0.',
        who: 'Legitimate actions that need a human OK are silently blocked.',
        detail: [],
        owner: 'node9',
        fix: 'Set a real approval timeout (e.g. 300000 ms) or clear it to use the default.',
      },
    ];
  }
  if (!hasChannel) {
    return [
      {
        category: 'Approvals',
        severity: 'high',
        title: 'No approver is configured — reviews have nowhere to go and auto-deny',
        what: "A 'review' verdict can't reach a human, so it times out and denies.",
        why: 'No approver channel is enabled and review routing is not set to inline `ask`.',
        who: 'Actions that should pause for a decision are blocked instead of reviewed.',
        detail: [],
        owner: 'node9',
        fix: 'Enable an approver (terminal / desktop / cloud) or set review routing to inline `ask`.',
      },
    ];
  }
  // Wired → clean pass (✅), not a ⚠️ advisory on a good state.
  return [];
}

/** TOOL GOVERNANCE — are any per-tool rules governing what agents may do? */
export function checkToolGovernance(ctx: CheckContext): Finding[] {
  const cfg = getConfig(ctx.cwd);
  const smartRules = cfg.policy.smartRules ?? [];
  const appPerms = cfg.policy.appPermissions ?? {};
  const governedApps = Object.values(appPerms).filter(
    (tools) => tools && Object.keys(tools).length > 0
  ).length;

  if (smartRules.length === 0 && governedApps === 0) {
    return [
      {
        category: 'Tool governance',
        severity: 'medium',
        title: 'No tool rules are set — every tool call is allowed by default',
        what: 'No smart rules or MCP per-tool permissions constrain what agents may run.',
        why: 'Your policy has no rules and no governed MCP apps.',
        who: 'A risky or unexpected tool call runs with nothing to catch it.',
        detail: [],
        owner: 'node9',
        node9Reduces: true,
        scoreWeight: 8,
        fix: 'Add a smart rule, enable a shield, or set MCP tool permissions in the dashboard.',
      },
    ];
  }
  // Rules present → clean pass (✅), not a ⚠️ advisory on a good state.
  return [];
}

/** FILES — the credential jail (baseline is always on; fleet paths add to it). */
export function checkFiles(ctx: CheckContext): Finding[] {
  // The built-in jail (SSH keys, ~/.aws/credentials, .env, *.pem …) is always
  // enforced by the DLP/path layer, so Files is baseline-covered. Surface it
  // as a covered dimension via the fileRead coverage probe.
  void getConfig(ctx.cwd);
  return [
    {
      category: 'Files',
      severity: 'advisory',
      title: 'Credential jail is active — sensitive paths are gated',
      detail: [],
      owner: 'node9',
      coverageProbe: { kind: 'fileRead', paths: [jailProbePath(ctx.home)] },
      redundantWhenOpen: true,
    },
  ];
}

/** COST — spend budgets (not yet a config field; an AVAILABLE hardening). */
export function checkCost(_ctx: CheckContext): Finding[] {
  // No budget field exists yet (cost governance is designed, unbuilt). Surface
  // it as a low-weight AVAILABLE opportunity, not a genuine exposure.
  return [
    {
      category: 'Cost',
      severity: 'advisory',
      title: 'No spend budget — a runaway agent’s cost is uncapped',
      what: "node9 sees per-agent spend but can't yet stop a runaway loop by dollar/token budget.",
      why: 'Budget enforcement is not configured (it ships with cost governance).',
      who: 'A looping agent can burn cost with nothing to cap it.',
      detail: [],
      owner: 'node9',
      node9Reduces: true,
      scoreWeight: 4,
      fix: 'Cost budgets are on the roadmap; loop detection caps the worst runaways today.',
    },
  ];
}
