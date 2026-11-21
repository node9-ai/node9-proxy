// src/ci-check/withdrawn-guidance.ts
// Guidance a vendor published in an agent skill and later withdrew. Copies of the
// skill in other catalogs and on users' machines keep the old text: pinning never
// alerts on them, because they never change (node9Firewall#454).
//
// An entry is added only with a public vendor fix to cite. The finding says the
// guidance is stale; it never claims a live exposure.

export interface WithdrawnGuidance {
  id: string;
  vendor: string;
  /** Matches the withdrawn text. Global flag required (counted with matchAll). */
  pattern: RegExp;
  /** The day the vendor removed it from its own copy (YYYY-MM-DD). */
  withdrawn: string;
  /** Where the vendor's fix is, for the reader to compare. */
  fixSource: string;
}

export const WITHDRAWN_GUIDANCE: readonly WithdrawnGuidance[] = [
  {
    // Render's render-deploy skill told agents that private services live under
    // render-internal.com, a domain Render did not own (AIR Security, Oct 2026).
    // Render removed every mention on 2026-08-14.
    id: 'render-internal-domain',
    vendor: 'Render',
    pattern: /\brender-internal\.com\b/gi,
    withdrawn: '2026-08-14',
    fixSource: 'render-oss/skills commit 5152e543',
  },
];

export interface WithdrawnHit {
  entry: WithdrawnGuidance;
  /** 0-based index of the first match. */
  index: number;
  count: number;
}

/** Every withdrawn entry the text still carries, with its first match and count. */
export function findWithdrawnGuidance(text: string): WithdrawnHit[] {
  const hits: WithdrawnHit[] = [];
  for (const entry of WITHDRAWN_GUIDANCE) {
    let first = -1;
    let count = 0;
    for (const m of text.matchAll(entry.pattern)) {
      if (first < 0) first = m.index ?? 0;
      count++;
    }
    if (count > 0) hits.push({ entry, index: first, count });
  }
  return hits;
}
