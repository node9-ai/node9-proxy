import { stripInvisible } from './normalize';
import type { MnemonicBudget } from './mnemonic';

export const SECRET_VIEW_LIMITS = {
  /** A decoded text that itself decodes is followed this many layers; a deeper layer is reviewed. */
  maxDepth: 4,
  /** Nested views per parent view, and nested text per call; past either the call is reviewed. */
  maxNestedViewsPerLeaf: 64,
  maxNestedBytes: 1_048_576,
  /** Joined hostname-label text per call; past it the call is reviewed. */
  maxJoinedLabelBytes: 1_048_576,
  /** Decoded fragments are matched in batches of about this many characters. */
  batchCharacters: 65_536,
  /** Only a valid DNS name has its labels joined. */
  maxHostLength: 253,
  maxLabelLength: 63,
  maxLabels: 127,
} as const;

/**
 * Work that can grow faster than the input is charged here and reviews on
 * exhaustion. First-level decoding is proportional to the text and has no
 * budget: nothing an attacker pads can turn into an allow (fw#338, review 3).
 */
export interface SecretViewBudget extends MnemonicBudget {
  nestedBytes: number;
  joinedLabelBytes: number;
}

export function newSecretViewBudget(): SecretViewBudget {
  return { hashes: 0, nestedBytes: 0, joinedLabelBytes: 0, reasons: new Set() };
}

export interface SecretView {
  text: string;
  transforms: string[];
}

function textBytes(buf: Buffer): string | null {
  // Credentials are textual. Permissive Buffer decoding must not manufacture
  // a token by dropping invalid bytes or introducing replacement characters.
  if (buf.length < 16) return null;
  const text = buf.toString('utf8');
  // Binary control bytes are deliberately rejected by this text decoder.
  // eslint-disable-next-line no-control-regex
  if (!Buffer.from(text).equals(buf) || /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(text)) return null;
  return text;
}

function percentOnce(text: string): string {
  return text.replace(/(?:%[a-f0-9]{2})+/gi, (run) => {
    try {
      return decodeURIComponent(run);
    } catch {
      return run.replace(/%([a-f0-9]{2})/gi, (_, h: string) =>
        String.fromCharCode(parseInt(h, 16))
      );
    }
  });
}

/**
 * Line-wrapped base64 (PEM, MIME, `base64` output, an indented YAML block):
 * one or more lines of one width, optionally a shorter tail, joined without
 * their line breaks and indentation as one more region of this level. Read
 * line by line: a single regex over the text backtracks quadratically on a
 * long run with no newline (19 s on 100 KB in the pre-push check).
 */
function* wrappedBase64(text: string): Generator<string> {
  if (!text.includes('\n')) return;
  const word = /^[A-Za-z0-9+/_-]+={0,2}$/;
  let run: string[] = [];
  let width = 0;
  const flush = function* () {
    if (run.length >= 2) yield run.join('');
    run = [];
    width = 0;
  };
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    const full = line.length >= 16 && word.test(line) && !line.includes('=');
    if (full && (!run.length || line.length === width)) {
      run.push(line);
      width = line.length;
      continue;
    }
    // A tail is shorter than the width (or the closing line with padding).
    if (run.length && word.test(line) && line.length >= 2 && line.length <= width) {
      run.push(line);
      yield* flush();
      continue;
    }
    yield* flush();
    if (full) {
      run.push(line);
      width = line.length;
    }
  }
  yield* flush();
}

function* encodedRegions(text: string, budget: SecretViewBudget): Generator<[string, boolean]> {
  yield [text, false];
  for (const block of wrappedBase64(text)) yield [block, false];
  // The scheme is bounded and anchored on its left so a long alphanumeric run
  // is scanned once, not once per starting offset.
  for (const match of text.matchAll(/(?<![a-z0-9+.-])[a-z][a-z0-9+.-]{0,30}:\/\/[^\s<>"']+/gi)) {
    try {
      new URL(match[0]);
    } catch {
      continue;
    }
    // Keep original spelling; URL.hostname lowercases case-sensitive payloads.
    const parts = match[0].match(
      /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)([^?#]*)(?:\?([^#]*))?(?:#(.*))?$/i
    );
    if (!parts) continue;
    const host = parts[1].slice(parts[1].lastIndexOf('@') + 1).replace(/:\d+$/, '');
    const regions = [
      parts[1],
      ...host.split('.'),
      ...parts[2].split('/'),
      ...(parts[3] ?? '').split('&'),
      parts[4] ?? '',
    ];
    for (const region of regions) if (region) yield [region, false];
    // Join only contiguous labels sharing an encoding alphabet, and only for a
    // valid DNS name: an exfiltration tool chunks a value into real labels. This
    // is a credential-content view, not a DNS anomaly verdict or domain boundary
    // inference. No network/SSRF classification uses these reconstructed bytes.
    const labels = host.split('.');
    if (
      host.length > SECRET_VIEW_LIMITS.maxHostLength ||
      labels.length > SECRET_VIEW_LIMITS.maxLabels ||
      !labels.every((l) => l.length >= 1 && l.length <= SECRET_VIEW_LIMITS.maxLabelLength)
    )
      continue;
    for (let start = 0; start < labels.length; start++) {
      let joined = labels[start];
      for (let end = start + 1; end < Math.min(labels.length, start + 8); end++) {
        const run = labels.slice(start, end + 1);
        if (
          !run.every((s) => /^[a-f0-9]{2,}$/i.test(s)) &&
          !run.every((s) => /^[A-Z2-7]{4,}$/i.test(s))
        )
          break;
        joined += labels[end];
        if (joined.length < 16) continue;
        // Joins expand a host up to eight times; a flood of crafted hosts is
        // held for review rather than decoded without end.
        budget.joinedLabelBytes += joined.length;
        if (budget.joinedLabelBytes > SECRET_VIEW_LIMITS.maxJoinedLabelBytes) {
          budget.reasons.add('decode-labels');
          return;
        }
        yield [joined, true];
      }
    }
  }
}

function decodeBase32(raw: string): Buffer | null {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const out: number[] = [];
  let bits = 0;
  let accumulator = 0;
  for (const c of raw.toUpperCase()) {
    accumulator = (accumulator << 5) | alphabet.indexOf(c);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push(accumulator >> bits);
      accumulator &= (1 << bits) - 1;
    }
  }
  // Reject impossible final symbol counts and nonzero padding bits.
  if ([1, 3, 6].includes(raw.length % 8) || accumulator !== 0) return null;
  return Buffer.from(out);
}

function* decodedCandidates(text: string, budget: SecretViewBudget): Generator<[string, string]> {
  const stripped = stripInvisible(text);
  if (stripped !== text) yield ['invisibles', stripped];
  if (/%[a-f0-9]{2}/i.test(text)) yield ['percent', percentOnce(text)];

  // Independent candidate families keep byte-delimited hex separate from prose.
  const families: Array<[string, RegExp]> = [
    ['base64', /[A-Za-z0-9+/_-]{22,}={0,2}/g],
    ['hex', /\b(?:[a-f0-9]{2}){16,}\b/gi],
    ['hex-escaped', /(?:\\x[a-f0-9]{2}){16,}/gi],
    ['hex-delimited', /\b[a-f0-9]{2}(?:-[a-f0-9]{2}){15,}\b/gi],
    ['base32', /\b[A-Z2-7]{26,}\b/gi],
  ];
  for (const [region, joined] of encodedRegions(text, budget)) {
    if (joined) yield ['dns-labels', region];
    for (const [kind, re] of families) {
      for (const match of region.matchAll(re)) {
        const raw = match[0];
        let buf: Buffer;
        if (kind === 'base64') {
          if (/^[a-f0-9]+$/i.test(raw)) continue;
          const normalized = raw.replace(/-/g, '+').replace(/_/g, '/');
          const unpadded = normalized.replace(/=+$/, '');
          if (unpadded.length % 4 === 1 || (raw.includes('=') && raw.length % 4 !== 0)) continue;
          buf = Buffer.from(normalized, 'base64');
          if (buf.toString('base64').replace(/=+$/, '') !== unpadded) continue;
        } else if (kind === 'base32') {
          const decoded = decodeBase32(raw);
          if (!decoded) continue;
          buf = decoded;
        } else {
          buf = Buffer.from(raw.replace(/\\x|-/gi, ''), 'hex');
        }
        const decoded = textBytes(buf);
        if (decoded !== null) yield [kind, decoded];
      }
    }
  }
}

/**
 * Every decoded view of `text`, first level complete and without a count
 * limit, deeper levels within SECRET_VIEW_LIMITS. The raw text is not
 * included; the caller matches it separately. Secret-specific decoding; does
 * not change injection or exact canary views.
 */
export function secretViews(text: string, budget: SecretViewBudget): SecretView[] {
  const seen = new Set([text]);
  const out: SecretView[] = [];
  let frontier: SecretView[] = [{ text, transforms: [] }];
  for (let depth = 1; depth <= SECRET_VIEW_LIMITS.maxDepth; depth++) {
    const next: SecretView[] = [];
    for (const parent of frontier) {
      let perLeaf = 0;
      for (const [kind, decoded] of decodedCandidates(parent.text, budget)) {
        if (seen.has(decoded)) continue;
        seen.add(decoded);
        // Removing invisibles and percent-decoding only shrink their input,
        // so a chain of them costs at most depth times the window: no budget.
        // Any decoding layer under them is charged.
        const normalizing = kind === 'invisibles' || kind === 'percent';
        if (depth >= 2 && !normalizing) {
          budget.nestedBytes += Buffer.byteLength(decoded);
          if (
            ++perLeaf > SECRET_VIEW_LIMITS.maxNestedViewsPerLeaf ||
            budget.nestedBytes > SECRET_VIEW_LIMITS.maxNestedBytes
          ) {
            budget.reasons.add('decode-nested');
            return out;
          }
        }
        const view = { text: decoded, transforms: [...parent.transforms, kind] };
        out.push(view);
        next.push(view);
      }
    }
    frontier = next;
    if (!frontier.length) return out;
  }
  // Depth exhausted while a view still decodes: an uninspected layer.
  for (const view of frontier) {
    if (!decodedCandidates(view.text, budget).next().done) {
      budget.reasons.add('decode-nested');
      break;
    }
  }
  return out;
}
