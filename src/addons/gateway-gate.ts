// src/addons/gateway-gate.ts
// The approved list of add-ons at one MCP gateway session (node9Firewall#376
// item 6, phase 3). The gateway fronts one server, so its identity is fixed
// for the session. A review the person approved holds for the rest of the
// session: one card per server, not one per call. A denial holds nothing, so
// the next call asks again. A block is never cached away.

import { mcpVerdict, stricter, type AddonPolicy, type AddonVerdict } from './policy';

export class AddonSessionGate {
  private reviewApproved = false;

  constructor(readonly identity: string) {}

  /** The verdict for the next call, under the list as it is now. `also` is a
   *  verdict from outside the list (a package on the malicious list): the
   *  stricter of the two holds, and an approved review covers both. */
  verdict(policy: AddonPolicy | undefined, also?: AddonVerdict): AddonVerdict {
    const own = mcpVerdict(policy, this.identity);
    const v = also ? stricter(own, also) : own;
    return v.action === 'review' && this.reviewApproved ? { action: 'allow' } : v;
  }

  /** What the authorizer answered for a call judged with `v`. */
  record(v: AddonVerdict, approved: boolean): void {
    if (approved && v.action === 'review') this.reviewApproved = true;
  }
}
