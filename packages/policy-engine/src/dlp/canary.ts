// Canary (decoy credential) matcher. Pure: no fs, no config, no crypto.
// Design: doc/roadmap/active/canary-design.md sections 4.1 and 10; corpus:
// canary-corpus.md section B (row ids in comments below).
//
// A canary is a random value node9 planted itself, so matching is EXACT and
// CASE-SENSITIVE containment (B30, B31): an attacker who alters the value has
// destroyed it and the exfil is already dead. Views exist only for encodings
// that preserve the value on the wire: percent-encoding (to a fixpoint, depth
// 4), base64 in both alphabets, hex, and separator insertion. View order is
// fixed and decides ties before offset does (B39, B40). Every decoding view is
// individually guarded: a decoder that throws is logged and skipped, and a hit
// requires evidence from some view (B41, B42; decision H7).

export interface CanaryValue {
  id: string;
  value: string;
  retired?: boolean;
}
export type CanaryView =
  'raw' | 'url-decoded' | 'base64-decoded' | 'hex-decoded' | 'separators-stripped';
export interface CanaryHit {
  id: string;
  view: CanaryView;
  fieldPath?: string;
  retired: boolean;
}

/** Values shorter than this are skipped by the matcher AND rejected by the registry (H12):
 *  below 16 the separators-stripped view starts to collide with ordinary text. */
export const CANARY_MIN_LENGTH = 16;

const MAX_TEXT = 100_000; // per field, same as scanArgs (B24 to B26)
const MAX_DEPTH = 6; // same as detectArgsPii (B20, B21)
const MAX_JSON_PARSE = 10_000; // same as scanArgs's JSON-in-string branch (B23)
const URL_DEPTH = 4; // percent-decode fixpoint cap (B6 to B8)
const B64_DEPTH = 3; // nested base64 in a query segment (B11)
const MIN_SEGMENT = 16;

// pipelock's canonicalizeCanaryText set: separators an exfil path inserts.
const SEPARATORS = /[./\\?&= \t\n\r:;,\-_@%+#]/g;
const stripSeparators = (s: string): string => s.replace(SEPARATORS, '');

function percentDecodeOnce(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    // Malformed sequence somewhere: decode the well-formed ones anyway.
    return s.replace(/%([0-9A-Fa-f]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)));
  }
}

/** Candidate substrings an encoding could be wrapping: the whole text, then
 *  segments between query/whitespace/quote delimiters, then each '='-split part. */
function segments(s: string, alphabet: RegExp): string[] {
  const out = new Set<string>();
  if (alphabet.test(s)) out.add(s);
  for (const seg of s.split(/[?&\s"'<>]+/)) {
    if (seg.length >= MIN_SEGMENT && alphabet.test(seg)) out.add(seg);
    for (const part of seg.split('=')) {
      if (part.length >= MIN_SEGMENT && alphabet.test(part)) out.add(part);
    }
  }
  return [...out];
}
// A decode that yields C0 control bytes (other than tab/newline) is binary noise, not text.
const looksText = (s: string): boolean => s.length > 0 && !/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(s);

/**
 * Decoders are looked up at call time so a spec can stub one to throw (B41,
 * B42) or count calls (B32). Each returns the decoded candidates for its view;
 * the raw view has no decoder and runs first.
 */
export const CANARY_DECODERS = {
  url: (s: string): string[] => {
    const out: string[] = [];
    let cur = s;
    for (let i = 0; i < URL_DEPTH; i++) {
      const d = percentDecodeOnce(cur);
      if (d === cur) break;
      out.push(d);
      cur = d;
    }
    return out;
  },
  base64: (s: string): string[] => {
    const out: string[] = [];
    let frontier = segments(s, /^[A-Za-z0-9+/\-_=]+$/);
    for (let depth = 0; depth < B64_DEPTH && frontier.length; depth++) {
      const next: string[] = [];
      for (const c of frontier) {
        const d = Buffer.from(c, 'base64').toString('utf8');
        if (!looksText(d) || d.length < CANARY_MIN_LENGTH) continue;
        out.push(d);
        next.push(...segments(d, /^[A-Za-z0-9+/\-_=]+$/));
      }
      frontier = next;
    }
    return out;
  },
  hex: (s: string): string[] => {
    const out: string[] = [];
    for (const c of segments(s, /^[0-9A-Fa-f]+$/)) {
      if (c.length % 2 !== 0 || c.length < CANARY_MIN_LENGTH * 2) continue;
      const d = Buffer.from(c, 'hex').toString('utf8');
      if (looksText(d)) out.push(d);
    }
    return out;
  },
  separators: (s: string): string[] => [stripSeparators(s)],
};

type Needle = { v: CanaryValue; raw: string; stripped: string };

function lowestOffset(
  cands: readonly string[],
  needles: readonly Needle[],
  stripped: boolean
): CanaryValue | null {
  let best: { off: number; v: CanaryValue } | null = null;
  for (const c of cands) {
    for (const n of needles) {
      const off = c.indexOf(stripped ? n.stripped : n.raw);
      if (off >= 0 && (best === null || off < best.off)) best = { off, v: n.v };
    }
  }
  return best?.v ?? null;
}

const VIEWS: ReadonlyArray<{
  view: CanaryView;
  decoder: keyof typeof CANARY_DECODERS;
  stripped: boolean;
}> = [
  { view: 'url-decoded', decoder: 'url', stripped: false },
  { view: 'base64-decoded', decoder: 'base64', stripped: false },
  { view: 'hex-decoded', decoder: 'hex', stripped: false },
  { view: 'separators-stripped', decoder: 'separators', stripped: true },
];

function prepare(values: readonly CanaryValue[]): Needle[] {
  const out: Needle[] = [];
  for (const v of values) {
    if (typeof v.value !== 'string' || v.value.length < CANARY_MIN_LENGTH) {
      console.error(
        `[node9 engine] canary ${v.id}: value shorter than ${CANARY_MIN_LENGTH}, skipped`
      );
      continue;
    }
    out.push({ v, raw: v.value, stripped: stripSeparators(v.value) });
  }
  return out;
}

function matchPrepared(
  text: string,
  needles: readonly Needle[]
): { v: CanaryValue; view: CanaryView } | null {
  if (!text || needles.length === 0) return null;
  const t = text.length > MAX_TEXT ? text.slice(0, MAX_TEXT) : text;
  // Raw first: cannot throw, and wins every tie (B3, B40).
  const raw = lowestOffset([t], needles, false);
  if (raw) return { v: raw, view: 'raw' };
  for (const { view, decoder, stripped } of VIEWS) {
    let cands: string[];
    try {
      cands = CANARY_DECODERS[decoder](t);
    } catch (e) {
      console.error(
        `[node9 engine] canary view ${view} failed, skipped:`,
        e instanceof Error ? e.message : String(e)
      );
      continue;
    }
    const hit = lowestOffset(cands, needles, stripped);
    if (hit) return { v: hit, view };
  }
  return null;
}

/** Exact containment of any registered value in any bounded view of the text. */
export function matchCanary(text: string, values: readonly CanaryValue[]): CanaryHit | null {
  if (!text || values.length === 0) return null;
  const hit = matchPrepared(text, prepare(values));
  return hit ? { id: hit.v.id, view: hit.view, retired: Boolean(hit.v.retired) } : null;
}

/** Walks string leaves (depth <= 6, per-field budget), parsing JSON-in-string leaves
 *  so escaped values are seen (B23), like scanArgs. */
export function matchCanaryArgs(args: unknown, values: readonly CanaryValue[]): CanaryHit | null {
  if (values.length === 0) return null;
  const needles = prepare(values);
  if (needles.length === 0) return null;

  const walk = (v: unknown, depth: number, fieldPath: string): CanaryHit | null => {
    if (depth > MAX_DEPTH) return null;
    if (typeof v === 'string') {
      const hit = matchPrepared(v, needles);
      if (hit) return { id: hit.v.id, view: hit.view, fieldPath, retired: Boolean(hit.v.retired) };
      if (v.length < MAX_JSON_PARSE) {
        const trimmed = v.trim();
        if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
          try {
            return walk(JSON.parse(v), depth + 1, fieldPath);
          } catch {
            /* not JSON */
          }
        }
      }
      return null;
    }
    if (typeof v === 'number' && Number.isFinite(v)) return walk(String(v), depth, fieldPath);
    if (Array.isArray(v)) {
      for (let i = 0; i < v.length; i++) {
        const h = walk(v[i], depth + 1, `${fieldPath}[${i}]`);
        if (h) return h;
      }
      return null;
    }
    if (v && typeof v === 'object') {
      for (const [k, child] of Object.entries(v as Record<string, unknown>)) {
        const h = walk(child, depth + 1, fieldPath ? `${fieldPath}.${k}` : k);
        if (h) return h;
      }
    }
    return null;
  };
  try {
    return walk(args, 0, '');
  } catch (e) {
    console.error(
      '[node9 engine] canary args walk failed:',
      e instanceof Error ? e.message : String(e)
    );
    return null;
  }
}
