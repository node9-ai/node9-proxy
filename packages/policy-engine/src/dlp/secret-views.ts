import { stripInvisible } from './normalize';

export const SECRET_VIEW_LIMITS = {
  maxDepth: 4,
  maxViewsPerLeaf: 64,
  maxViews: 256,
  maxDerivedBytes: 1_048_576,
  maxCandidates: 4096,
} as const;

export interface SecretViewBudget {
  views: number;
  bytes: number;
  candidates: number;
  reasons: Set<string>;
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

function* encodedRegions(text: string, budget: SecretViewBudget): Generator<[string, boolean]> {
  yield [text, false];
  // The scheme is bounded and anchored on its left so a long alphanumeric run
  // is scanned once, not once per starting offset.
  for (const match of text.matchAll(/(?<![a-z0-9+.-])[a-z][a-z0-9+.-]{0,30}:\/\/[^\s<>"']+/gi)) {
    if (++budget.candidates > SECRET_VIEW_LIMITS.maxCandidates) {
      budget.reasons.add('decode-candidates');
      return;
    }
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
    // Regions are substrings of text already counted; only decode attempts
    // and label joins consume the candidate budget.
    for (const region of regions) if (region) yield [region, false];
    // Join only contiguous labels sharing an encoding alphabet. This is a
    // credential-content view, not a DNS anomaly verdict or domain boundary
    // inference. No network/SSRF classification uses these reconstructed bytes.
    const labels = host.split('.');
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
        if (++budget.candidates > SECRET_VIEW_LIMITS.maxCandidates) {
          budget.reasons.add('decode-candidates');
          return;
        }
        if (joined.length >= 16 && joined.length <= 253) yield [joined, true];
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
        if (++budget.candidates > SECRET_VIEW_LIMITS.maxCandidates) {
          budget.reasons.add('decode-candidates');
          return;
        }
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

/** Secret-specific decoding; does not change injection or exact canary views. */
export function* secretViews(text: string, budget: SecretViewBudget): Generator<SecretView> {
  const seen = new Set([text]);
  const queue: SecretView[] = [{ text, transforms: [] }];
  for (let i = 0; i < queue.length; i++) {
    const view = queue[i];
    yield view;
    for (const [kind, decoded] of decodedCandidates(view.text, budget)) {
      if (seen.has(decoded)) continue;
      if (view.transforms.length >= SECRET_VIEW_LIMITS.maxDepth) {
        budget.reasons.add('decode-depth');
        continue;
      }
      const bytes = Buffer.byteLength(decoded);
      if (
        queue.length >= SECRET_VIEW_LIMITS.maxViewsPerLeaf ||
        budget.views >= SECRET_VIEW_LIMITS.maxViews ||
        budget.bytes + bytes > SECRET_VIEW_LIMITS.maxDerivedBytes
      ) {
        budget.reasons.add('decode-budget');
        return;
      }
      seen.add(decoded);
      budget.views++;
      budget.bytes += bytes;
      queue.push({ text: decoded, transforms: [...view.transforms, kind] });
    }
    if (budget.candidates > SECRET_VIEW_LIMITS.maxCandidates) return;
  }
}
