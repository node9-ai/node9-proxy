// src/addons/gateway-gate.ts
// The approved list of add-ons at one MCP gateway session (node9Firewall#376
// item 6, phase 3). The gateway fronts one server, so its identity is fixed
// for the session. A review the person approved holds for the rest of the
// session: one card per server and reason, not one per call. A denial holds nothing, so
// the next call asks again. A block is never cached away.

import { mcpVerdict, stricter, type AddonPolicy, type AddonVerdict } from './policy';

export class AddonSessionGate {
  /** The rules whose review the person approved this session. */
  private approved = new Set<string>();

  constructor(readonly identity: string) {}

  /** The verdict for the next call, under the list as it is now. `also` is a
   *  verdict from outside the list (a package on the malicious list): the
   *  stricter of the two holds. An approved review covers its own rule only:
   *  approving "not on the list" does not approve "on the malicious list",
   *  which may arrive later in the same session. */
  verdict(policy: AddonPolicy | undefined, also?: AddonVerdict): AddonVerdict {
    const settle = (v: AddonVerdict): AddonVerdict =>
      v.action === 'review' && this.approved.has(v.ruleName) ? { action: 'allow' } : v;
    const own = settle(mcpVerdict(policy, this.identity));
    return also ? stricter(own, settle(also)) : own;
  }

  /** What the authorizer answered for a call judged with `v`. */
  record(v: AddonVerdict, approved: boolean): void {
    if (approved && v.action === 'review') this.approved.add(v.ruleName);
  }
}
