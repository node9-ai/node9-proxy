// src/posture/egress.ts
// Check 2 — Egress / exfiltration.
//
// Reads the SAME egress-control state the in-path gate enforces
// (`config.policy.egress`). No live network probing — config inspection only.

import fs from 'fs';
import { getConfig } from '../config';
import { ALLOWED_DOMAINS_PATH } from '../sandbox/templates';
import type { CheckContext, Finding } from './types';

interface EgressConfig {
  enabled: boolean;
  mode: 'off' | 'review' | 'block';
}

/** The egress state plus the SSRF floor knobs, for the floor row. */
export interface FloorConfig extends EgressConfig {
  ssrfStrict: boolean;
  ssrfAllow: string[];
  /** Which layer governs policy here. The remediation line depends on it: the
   *  CLI command is refused on a workspace-governed machine. */
  policySource: 'workspace' | 'local';
}

/**
 * True when running INSIDE a node9 sandbox whose kernel egress wall is active.
 * The entrypoint writes the resolved allowlist to ALLOWED_DOMAINS_PATH before
 * sealing the ipset/iptables wall (deny-by-default), so the file's presence
 * marks a hard, OS-level egress block that the config-based check below is
 * blind to. Without this, in-box posture wrongly reports "Egress open" even
 * though the box is locked tighter than any host config. Exported for tests.
 */
export function sandboxEgressWallActive(): boolean {
  try {
    return fs.existsSync(ALLOWED_DOMAINS_PATH);
  } catch {
    return false;
  }
}

/**
 * Pure verdict. Always emits an Egress finding now (never null) — coverage
 * (annotateCoverage's egress probe, gated on enforcing) decides covered vs
 * open. So a locked + enforcing egress renders 🟢 covered (consistent with
 * Secrets/Privilege), not ✅ passed.
 */
export function evaluateEgressConfig(egress: EgressConfig): Finding {
  // Locked: when node9 is enforcing this becomes 🟢 covered; if node9 ISN'T
  // enforcing (not wired / observe), it surfaces as open below via coverage —
  // honest, because a lock that isn't applied protects nothing.
  if (egress.enabled && egress.mode === 'block') {
    return {
      category: 'Egress',
      severity: 'high',
      title: 'Egress is locked, but node9 is not enforcing it',
      what: 'Egress is set to block, but node9 is not applying the policy.',
      why: "node9 isn't wired in (or is in observe mode), so the lock has no effect.",
      who: 'The lock protects nothing until node9 is enforcing in-path.',
      owner: 'node9',
      detail: [],
      fix: 'Run `node9 init` and ensure node9 is in enforcing mode.',
      coverageProbe: { kind: 'egress' },
      // Open here means only "node9 isn't enforcing" — Coverage already says
      // that, so drop this row when open to avoid double-surfacing.
      redundantWhenOpen: true,
    };
  }

  // Review (watch): node9 approval-gates outbound to unknown hosts — at runtime
  // a non-allowlisted destination routes to the approval race engine, so the
  // user catches exfil. When node9 is enforcing this is 🟢 covered (level
  // 'review' → "approval-gating"); only when node9 ISN'T enforcing does it
  // surface as open (and drops, since Coverage already reports the wiring gap).
  if (egress.enabled && egress.mode === 'review') {
    return {
      category: 'Egress',
      severity: 'medium',
      title: 'Egress is in review, but node9 is not enforcing it',
      what: 'Egress is set to review (approval-gate), but node9 is not applying the policy.',
      why: "node9 isn't wired in (or is in observe mode), so the gate has no effect.",
      who: 'Nothing gates outbound until node9 is enforcing in-path.',
      owner: 'node9',
      detail: [],
      fix: 'Run `node9 init` and ensure node9 is in enforcing mode.',
      coverageProbe: { kind: 'egress' },
      // Open here means only "node9 isn't enforcing" — Coverage already says
      // that, so drop this row when open to avoid double-surfacing.
      redundantWhenOpen: true,
    };
  }

  // disabled, or enabled with mode 'off'
  return {
    category: 'Egress',
    severity: 'high',
    title: 'Egress is open',
    // Not "apart from the protected addresses node9 blocks on every machine":
    // this row has no coverage probe, so it renders on a machine where node9
    // is not in-path and blocks nothing, four lines from the Coverage row that
    // says exactly that.
    what: 'Your agent can connect to any server on the internet.',
    why: "node9 isn't restricting where its network tools (curl, wget, ssh) can reach.",
    who: 'If the agent is ever tricked, nothing stops it sending your data out.',
    owner: 'node9',
    detail: [],
    fix: 'Fix it now: run `node9 egress watch` (or `node9 egress lock` to hard-block).',
    coverageProbe: { kind: 'egress' },
  };
}

/**
 * The SSRF floor, as a posture row. It is the one protection that holds on
 * every machine whatever the config says, so it belongs in the report as a
 * WIN, stated in terms of the attack it closes rather than the mechanism.
 *
 * Deliberately NOT a gap row when the strict tier is off. Loopback and the
 * private ranges carry ordinary, wanted development traffic; flagging that on
 * every machine would be over-reporting, and the report is judged on not doing
 * it. The strict tier is mentioned inside this row instead, as a detail line.
 */
export function checkEgressFloor(egress: FloorConfig): Finding[] {
  // detail[0] is read by the covered-row renderer as the OBJECT of the
  // sentence "<via> is blocking <detail[0]>", so it has to be a noun phrase.
  // Written as a standalone sentence it rendered as
  // "ssrf floor is blocking Strict tier off: loopback…".
  const detail = [
    'the cloud instance-metadata endpoint',
    'link-local, multicast, unspecified and CGNAT (100.64/10) addresses',
    egress.ssrfStrict
      ? 'the strict tier is on: loopback and the private ranges are blocked too'
      : `the strict tier is off: loopback and the private ranges stay reachable (${
          egress.policySource === 'workspace'
            ? 'turn it on in the dashboard, Enforcement → Network'
            : '`node9 egress strict on`'
        })`,
  ];
  if (egress.ssrfAllow.length) {
    detail.push(`you exempted: ${egress.ssrfAllow.join(', ')}`);
  }
  // Named as a limit, not buried: a reader who takes this row as machine-wide
  // protection is the failure this row exists to avoid.
  detail.push('not covered: WebFetch and MCP fetch tools reach a URL without this gate');
  return [
    {
      category: 'Egress',
      severity: 'advisory',
      title: 'The cloud metadata endpoint is blocked in shell commands',
      what:
        'node9 blocks it before any egress policy is consulted, and no setting releases it. ' +
        'It sees shell commands (curl, wget, ssh); a tool that fetches a URL itself does not ' +
        'pass this gate.',
      why: "One request to that address returns this machine's cloud credentials, to anyone who can make the agent send it.",
      who: 'An agent talked into fetching that address hands over the keys and cannot, here.',
      owner: 'node9',
      detail,
      // Probed at the REAL gate rather than asserted here. The floor lives in
      // evaluatePolicy, which only runs when node9 is in-path, so a machine
      // with no hooks wired must NOT see this row under "node9 is enforcing
      // these" — it did, next to "node9 is not in-path for any agent".
      // coverageFromVerdict returns open when not enforcing, and
      // redundantWhenOpen then drops the row, because Coverage already
      // reports the wiring gap and this row would only repeat it.
      coverageProbe: {
        kind: 'command',
        command: 'curl http://169.254.169.254/latest/meta-data/',
      },
      redundantWhenOpen: true,
    },
  ];
}

export function checkEgress(ctx: CheckContext): Finding[] {
  // Inside the sandbox, egress is hard-blocked at the kernel (deny-by-default
  // ipset wall) — stricter than any node9 config and invisible to the check
  // below. Credit it as covered so in-box posture tells the truth instead of
  // over-reporting "Egress open".
  if (sandboxEgressWallActive()) {
    return [
      {
        category: 'Egress',
        severity: 'advisory',
        title: 'Egress is hard-blocked by the sandbox kernel wall',
        what: 'Outbound is deny-by-default at the kernel; only the allowlist is reachable.',
        why: 'The sandbox seals egress with an ipset/iptables wall before the agent starts.',
        who: 'Even a compromised agent can only reach the allowlisted hosts.',
        owner: 'node9',
        detail: [],
        coverage: { state: 'covered', level: 'block', via: 'sandbox egress wall' },
      },
    ];
  }

  const config = getConfig(ctx.cwd);
  const egress = config.policy.egress;
  return [
    evaluateEgressConfig({ enabled: egress.enabled, mode: egress.mode }),
    ...checkEgressFloor({
      enabled: egress.enabled,
      mode: egress.mode,
      ssrfStrict: egress.ssrfStrict === true,
      ssrfAllow: egress.ssrfAllow ?? [],
      policySource: config.policySource,
    }),
  ];
}
