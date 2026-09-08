// SSRF floor: addresses no agent tool call has a legitimate reason to reach.
// Design: doc/roadmap/active/ssrf-floor-design.md. Corpus: ssrf-corpus.md.
// Pure: no fs, no config, no DNS (node9 never resolves; see design section 5).
//
// The normalizer implements inet_aton semantics, because that is what curl,
// wget and the C library actually accept: 1 to 4 dot-separated components, each
// in base 0 (0x hex, leading-0 octal, else decimal), where the LAST component
// fills all remaining bytes. That is why `127.1` denotes 127.0.0.1 and
// `2852039166` denotes 169.254.169.254. Every expectation in the corpus is
// justified by that rule or by an RFC, never by what this file returns.

export type SsrfTier =
  | 'metadata'
  | 'link-local'
  | 'multicast'
  | 'unspecified'
  | 'cgnat'
  | 'private';

export interface SsrfMatch {
  tier: SsrfTier;
  /** false for tier 1: no allowlist entry exempts it. */
  overridable: boolean;
  /** 'address' when an IP literal matched, 'hostname' for the metadata name list. */
  kind: 'address' | 'hostname';
  /** The canonical address; absent for a hostname match. Never an empty string:
   *  an empty value is dropped in flight by cloud.ts and the audit shipper. */
  normalized?: string;
}

/** Longest legal DNS name. The caller does NOT reliably bound this: a URL with a
 *  261-character host reaches us intact (measured), so we bound our own input. */
export const SSRF_MAX_HOST = 253;

// ── IPv4, inet_aton ─────────────────────────────────────────────────────────

/** One component in base 0. Returns null for anything that is not a number,
 *  including a bare `0x` prefix and an invalid octal digit (`08`). */
function parseComponent(s: string): number | null {
  if (!s) return null;
  if (/^0[xX][0-9a-fA-F]+$/.test(s)) return parseInt(s.slice(2), 16);
  if (s === '0') return 0;
  if (/^0[0-7]+$/.test(s)) return parseInt(s.slice(1), 8);
  if (/^[1-9][0-9]*$/.test(s)) return Number(s);
  return null;
}

/** inet_aton: 1..4 components, the last filling the remaining bytes. */
function parseIpv4(input: string): string | null {
  let s = input;
  if (s.endsWith('.')) s = s.slice(0, -1); // one trailing root dot is legal
  if (!s) return null;
  const parts = s.split('.');
  // Count guard BEFORE radix parsing: a hex-aware parser that counts after
  // folding would accept `0x1.0x2.0x3.0x4.0x5`.
  if (parts.length > 4) return null;
  const vals: number[] = [];
  for (const p of parts) {
    const v = parseComponent(p);
    if (v === null || !Number.isFinite(v) || v < 0) return null;
    vals.push(v);
  }
  const n = vals.length;
  // Every component but the last must fit one byte.
  for (let i = 0; i < n - 1; i++) if (vals[i] > 255) return null;
  const last = vals[n - 1];
  const remainingBytes = 4 - (n - 1);
  const limit = Math.pow(256, remainingBytes);
  if (last >= limit) return null;
  let value = last;
  for (let i = 0; i < n - 1; i++) value += vals[i] * Math.pow(256, 3 - i);
  if (value > 0xffffffff) return null;
  return [(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].join('.');
}

// ── IPv6 ────────────────────────────────────────────────────────────────────

/** Expand to eight 16-bit groups, or null. Accepts a trailing dotted IPv4. */
function expandIpv6(input: string): number[] | null {
  const s = input.toLowerCase();
  if (!/^[0-9a-f:.]+$/.test(s)) return null;
  if ((s.match(/::/g) ?? []).length > 1) return null;
  let head = s;
  let tailV4: number[] | null = null;
  const lastColon = s.lastIndexOf(':');
  const afterLast = s.slice(lastColon + 1);
  if (afterLast.includes('.')) {
    const dotted = parseIpv4(afterLast);
    if (!dotted) return null;
    const o = dotted.split('.').map(Number);
    tailV4 = [(o[0] << 8) | o[1], (o[2] << 8) | o[3]];
    head = s.slice(0, lastColon + 1) + '0';
  }
  const [lhs, rhs] = head.includes('::') ? head.split('::') : [head, null];
  const toGroups = (part: string): number[] | null => {
    if (!part) return [];
    const out: number[] = [];
    for (const g of part.split(':')) {
      if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };
  const left = toGroups(lhs);
  if (left === null) return null;
  let right: number[] = [];
  if (rhs !== null) {
    const r = toGroups(rhs);
    if (r === null) return null;
    right = r;
  }
  if (tailV4) {
    // The placeholder '0' we appended stands in for the two v4 groups.
    if (rhs !== null) right = right.slice(0, -1).concat(tailV4);
    else left.splice(left.length - 1, 1, ...tailV4);
  }
  const groups =
    rhs === null ? left : left.concat(new Array(8 - left.length - right.length).fill(0), right);
  if (rhs === null && groups.length !== 8) return null;
  if (rhs !== null && left.length + right.length > 8) return null;
  if (groups.length !== 8) return null;
  return groups;
}

/** RFC 5952 compressed form: lowercase, longest zero run replaced by '::'. */
function compressIpv6(g: readonly number[]): string {
  let bestStart = -1;
  let bestLen = 0;
  let i = 0;
  while (i < 8) {
    if (g[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && g[j] === 0) j++;
    if (j - i > bestLen) {
      bestLen = j - i;
      bestStart = i;
    }
    i = j;
  }
  const hex = g.map((x) => x.toString(16));
  if (bestLen < 2) return hex.join(':');
  return hex.slice(0, bestStart).join(':') + '::' + hex.slice(bestStart + bestLen).join(':');
}

/**
 * Fold any spelling of an IP literal to one canonical address, or null when the
 * input is not an IP literal (a hostname, or malformed). Never throws.
 *
 * IPv4-mapped IPv6 folds to the IPv4 address it denotes (RFC 4291 2.5.5.2), so
 * `[::ffff:a9fe:a9fe]` and `169.254.169.254` compare equal. Brackets and a zone
 * id are stripped here: the caller does NOT strip them (measured).
 */
export function normalizeIpLiteral(host: string): string | null {
  try {
    if (typeof host !== 'string') return null;
    let s = host.trim();
    if (!s || s.length > SSRF_MAX_HOST) return null;
    if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
    const zone = s.indexOf('%');
    if (zone >= 0) s = s.slice(0, zone); // scope selector, not part of the address
    if (!s) return null;
    if (s.includes(':')) {
      const g = expandIpv6(s);
      if (!g) return null;
      // ::ffff:x.y.z.w is the IPv4 it denotes.
      const mapped = g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff;
      if (mapped) {
        return [(g[6] >> 8) & 255, g[6] & 255, (g[7] >> 8) & 255, g[7] & 255].join('.');
      }
      return compressIpv6(g);
    }
    return parseIpv4(s);
  } catch {
    return null;
  }
}

// ── Tiers ───────────────────────────────────────────────────────────────────

/** Tier 1, non-overridable: exact cloud metadata addresses. */
const METADATA_ADDRESSES = new Set([
  '169.254.169.254', // AWS / Azure / DigitalOcean / OpenStack IMDS
  '169.254.170.2', // AWS ECS task role
  '168.63.129.16', // Azure WireServer
  'fd00:ec2::254', // AWS IMDS over IPv6 (inside fc00::/7, which is NOT a tier)
]);

/** Tier 1, non-overridable: the metadata names node9 cannot resolve to an address. */
const METADATA_HOSTNAMES = new Set(['metadata.google.internal', 'metadata.goog', 'metadata']);

const v4Octets = (a: string): number[] | null => {
  const p = a.split('.');
  return p.length === 4 ? p.map(Number) : null;
};

/**
 * Classify a destination host. Returns null when it is not a protected address,
 * which means the ordinary egress policy decides. Never throws.
 *
 * Ordering is significant: the exact metadata addresses are checked before the
 * link-local range that contains them, so the reason names metadata.
 */
export function classifySsrf(host: string): SsrfMatch | null {
  try {
    if (typeof host !== 'string' || !host) return null;
    const lower = host.trim().toLowerCase().replace(/\.$/, '');
    const ip = normalizeIpLiteral(host);
    if (ip === null) {
      return METADATA_HOSTNAMES.has(lower)
        ? { tier: 'metadata', overridable: false, kind: 'hostname' }
        : null;
    }
    const hit = (tier: SsrfTier, overridable: boolean): SsrfMatch => ({
      tier,
      overridable,
      kind: 'address',
      normalized: ip,
    });
    if (METADATA_ADDRESSES.has(ip)) return hit('metadata', false);

    const o = v4Octets(ip);
    if (o) {
      if (o[0] === 0 && o[1] === 0 && o[2] === 0 && o[3] === 0) return hit('unspecified', false);
      if (o[0] === 169 && o[1] === 254) return hit('link-local', false);
      if (o[0] >= 224 && o[0] <= 239) return hit('multicast', false);
      if (o[0] === 100 && o[1] >= 64 && o[1] <= 127) return hit('cgnat', true);
      // Tier 3: off by default (egress.ssrfStrict), because a developer talks to
      // these constantly. 72 of 308 destinations measured on real history.
      if (o[0] === 127) return hit('private', true);
      if (o[0] === 10) return hit('private', true);
      if (o[0] === 192 && o[1] === 168) return hit('private', true);
      if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return hit('private', true);
      return null;
    }

    const g = expandIpv6(ip);
    if (!g) return null;
    if (g.every((x) => x === 0)) return hit('unspecified', false);
    if ((g[0] & 0xffc0) === 0xfe80) return hit('link-local', false); // fe80::/10
    if ((g[0] & 0xff00) === 0xff00) return hit('multicast', false); // ff00::/8
    if (g.slice(0, 7).every((x) => x === 0) && g[7] === 1) return hit('private', true); // ::1
    // fc00::/7 is deliberately NOT a tier: it is the IPv6 analogue of RFC1918,
    // which is out for the reason in design section 3. The one exception is the
    // AWS metadata address above, matched exactly.
    return null;
  } catch {
    return null;
  }
}

// ── The gate-facing floor ───────────────────────────────────────────────────

export interface SsrfVerdict extends SsrfMatch {
  /** The token as written in the command. */
  host: string;
  binary: string;
  reason: string;
}

export interface SsrfFloorOptions {
  /** Exempts OVERRIDABLE tiers only. A tier-1 entry here is ignored (and is
   *  rejected at config load with a reason, never silently). */
  ssrfAllow?: readonly string[];
  /** Opt-in tier 3: loopback and RFC1918. Off by default: a developer talks to
   *  those constantly (72 of 308 destinations on measured real history). */
  ssrfStrict?: boolean;
}

const TIER_REASON: Record<SsrfTier, string> = {
  metadata: 'a cloud instance-metadata endpoint, the classic credential-theft target',
  'link-local': 'a link-local address',
  multicast: 'a multicast address',
  unspecified: 'the unspecified address',
  cgnat: 'a carrier-grade NAT address',
  private: 'a loopback or private address',
};

/**
 * The floor. Returns the first protected destination, or null.
 *
 * Runs unconditionally: not gated on egress.enabled, mode, allow or allowPrivate.
 * The one thing that does switch it off is `node9 pause`, which returns before
 * every gate; that is stated as a limit rather than special-cased here.
 */
export function ssrfFloor(
  tokens: ReadonlyArray<{ token: string; binary: string }>,
  opts: SsrfFloorOptions = {}
): SsrfVerdict | null {
  const exempt = new Set(
    (opts.ssrfAllow ?? []).map((e) => normalizeIpLiteral(e) ?? e.trim().toLowerCase())
  );
  for (const { token, binary } of tokens) {
    const m = classifySsrf(token);
    if (!m) continue;
    if (m.tier === 'private' && !opts.ssrfStrict) continue;
    // An exemption applies to overridable tiers only. Tier 1 has no allow path.
    if (m.overridable && m.normalized && exempt.has(m.normalized)) continue;
    return {
      ...m,
      host: token,
      binary,
      reason:
        `Blocked: ${token} is ${TIER_REASON[m.tier]}` +
        (m.normalized && m.normalized !== token ? ` (${m.normalized})` : '') +
        (m.overridable ? '.' : '. This address cannot be allowlisted.'),
    };
  }
  return null;
}
