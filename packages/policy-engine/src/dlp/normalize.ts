// packages/policy-engine/src/dlp/normalize.ts
// Text views for the injection scanner. An injected instruction that hides
// behind zero-width characters, lookalike letters, or an encoding is the same
// instruction once the model reads it, so the patterns must see it the way the
// model will. Pure, bounded, no I/O.
//
// Each helper returns a VIEW of the input, never a replacement for it: the
// scanner runs on the original and on every view, and a signal that only shows
// up in a view is itself evidence (the `obfuscated` signal in injection.ts).

/** Invisible code points that split a word without changing how it reads. */
const INVISIBLE_RE = /[­͏؜᠎​-‏‪-‮⁠-⁤⁪-⁯﻿︀-️]|[\u{E0000}-\u{E007F}]/gu;

/** Remove zero-width and other invisible code points. */
export function stripInvisible(text: string): string {
  return text.replace(INVISIBLE_RE, '');
}

// Lookalike letters that render as Latin. NFKC already folds fullwidth and
// mathematical alphanumerics; this table covers the Cyrillic and Greek letters
// NFKC leaves alone because they are distinct letters, not compatibility forms.
const HOMOGLYPHS: Readonly<Record<string, string>> = {
  // Cyrillic lowercase
  а: 'a',
  е: 'e',
  о: 'o',
  р: 'p',
  с: 'c',
  у: 'y',
  х: 'x',
  і: 'i',
  ј: 'j',
  ѕ: 's',
  ԁ: 'd',
  ԛ: 'q',
  ԝ: 'w',
  һ: 'h',
  ɡ: 'g',
  ё: 'e',
  ӏ: 'l',
  ⅼ: 'l',
  // Cyrillic uppercase
  А: 'A',
  В: 'B',
  Е: 'E',
  К: 'K',
  М: 'M',
  Н: 'H',
  О: 'O',
  Р: 'P',
  С: 'C',
  Т: 'T',
  Х: 'X',
  Ѕ: 'S',
  І: 'I',
  Ј: 'J',
  Ү: 'Y',
  Ԛ: 'Q',
  Ԝ: 'W',
  // Greek lowercase
  α: 'a',
  ο: 'o',
  ν: 'v',
  ε: 'e',
  ι: 'i',
  κ: 'k',
  ρ: 'p',
  τ: 't',
  υ: 'u',
  χ: 'x',
  γ: 'y',
  // Greek uppercase
  Α: 'A',
  Β: 'B',
  Ε: 'E',
  Ζ: 'Z',
  Η: 'H',
  Ι: 'I',
  Κ: 'K',
  Μ: 'M',
  Ν: 'N',
  Ο: 'O',
  Ρ: 'P',
  Τ: 'T',
  Υ: 'Y',
  Χ: 'X',
};
const HOMOGLYPH_RE = new RegExp(`[${Object.keys(HOMOGLYPHS).join('')}]`, 'g');

/** NFKC-fold, then map lookalike Cyrillic/Greek letters onto Latin. */
export function foldHomoglyphs(text: string): string {
  return text.normalize('NFKC').replace(HOMOGLYPH_RE, (c) => HOMOGLYPHS[c] ?? c);
}

/** The scanner's normalised reading: invisibles stripped, lookalikes folded. */
export function normalizeForScan(text: string): string {
  return foldHomoglyphs(stripInvisible(text));
}

const MAX_BLOBS = 32;
const MIN_DECODED = 16;

/** True when the decoded bytes read as text (so a decoded binary is dropped). */
function looksLikeText(buf: Uint8Array): boolean {
  if (buf.length < MIN_DECODED) return false;
  let printable = 0;
  for (const b of buf) {
    if ((b >= 0x20 && b <= 0x7e) || b === 0x0a || b === 0x0d || b === 0x09) printable++;
  }
  return printable / buf.length >= 0.9;
}

const BASE64_RUN_RE = /[A-Za-z0-9+/]{32,}={0,2}|[A-Za-z0-9_-]{32,}/g;

/** Decode every base64 / base64url run of 32+ characters that decodes to text. */
export function decodeEmbeddedBase64(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(BASE64_RUN_RE)) {
    if (out.length >= MAX_BLOBS) break;
    const run = m[0];
    // A run that is only hex is a hex blob, not base64 — leave it to the hex pass.
    if (/^[0-9a-fA-F]+$/.test(run)) continue;
    const buf = Buffer.from(run, 'base64');
    if (looksLikeText(buf)) out.push(buf.toString('utf8'));
  }
  return out;
}

const HEX_RUN_RE = /\b(?:[0-9a-fA-F]{2}){24,}\b/g;
const HEX_ESCAPE_RUN_RE = /(?:\\x[0-9a-fA-F]{2}){16,}/g;

/** Decode hex runs (48+ digits) and `\xNN` escape runs that decode to text. */
export function decodeEmbeddedHex(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(HEX_RUN_RE)) {
    if (out.length >= MAX_BLOBS) break;
    const buf = Buffer.from(m[0], 'hex');
    if (looksLikeText(buf)) out.push(buf.toString('utf8'));
  }
  for (const m of text.matchAll(HEX_ESCAPE_RUN_RE)) {
    if (out.length >= MAX_BLOBS) break;
    const buf = Buffer.from(m[0].replace(/\\x/g, ''), 'hex');
    if (looksLikeText(buf)) out.push(buf.toString('utf8'));
  }
  return out;
}

export interface ScanView {
  /** Which pass produced this text. `original` is the input itself. */
  kind: 'original' | 'normalized' | 'base64' | 'hex';
  text: string;
}

/**
 * Every reading of `text` the injection patterns should run on: the input,
 * its normalised form (when it differs), and the normalised decoding of each
 * embedded base64 and hex blob. Decoding is one level deep by design: a blob
 * inside a blob is not decoded.
 */
export function scanViews(text: string): ScanView[] {
  const views: ScanView[] = [{ kind: 'original', text }];
  const normalized = normalizeForScan(text);
  if (normalized !== text) views.push({ kind: 'normalized', text: normalized });
  for (const t of decodeEmbeddedBase64(normalized)) {
    views.push({ kind: 'base64', text: normalizeForScan(t) });
  }
  for (const t of decodeEmbeddedHex(normalized)) {
    views.push({ kind: 'hex', text: normalizeForScan(t) });
  }
  return views;
}
