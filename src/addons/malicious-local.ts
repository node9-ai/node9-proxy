// src/addons/malicious-local.ts
// Is the package behind an MCP server on the malicious-package list, as far
// as this machine can tell without the network (node9Firewall#376 item 6,
// phase 4, check D). Two local sources: what the daemon's package check last
// stored (it knows the version an unpinned launch resolves to), and the local
// OSV index, for a record that covers every version or the pinned one. For
// the MCP gateway, which starts the server and so can refuse to.

import { normalizePyPiName } from '@node9/policy-engine';
import { entryCovers, lookupIndex } from '../supply-chain/osv-index';
import type { McpPackage } from './identity';
import { maliciousAdvisories } from './standing-file';

/** Advisory ids when the package is known malicious, else null. Never throws:
 *  an unreadable index or file reads as "not known". */
export function knownMalicious(
  identity: string,
  pkg: McpPackage | null,
  home?: string
): string[] | null {
  try {
    const stored = maliciousAdvisories(identity, home);
    if (stored) return stored;
    if (!pkg) return null;
    const name = pkg.ecosystem === 'PyPI' ? normalizePyPiName(pkg.name) : pkg.name;
    const hit = lookupIndex(pkg.ecosystem, name);
    if (hit.status !== 'hit') return null;
    // `true` only: a record for other versions says nothing about this one.
    const ids = hit.entries.filter((e) => entryCovers(e, pkg.version) === true).map((e) => e.id);
    return ids.length ? ids.slice(0, 5) : null;
  } catch {
    return null;
  }
}
