import { createHash } from 'node:crypto';
import { BIP39_ENGLISH } from './bip39-english';
import { BIP39_PUBLIC_VECTORS } from './bip39-public-vectors';

const indices = new Map(BIP39_ENGLISH.map((word, i) => [word, i]));
const lengths = [24, 21, 18, 15, 12];
const hash = (value: string | Buffer) => createHash('sha256').update(value).digest();

/**
 * Checksum windows per call (about 0.2 s). Every window costs a SHA-256 and a
 * bit-string build, so a megabyte of random list words would cost a million;
 * past this the call is reviewed. The counter is the phrase check's own: no
 * other decoder can drain it (fw#338, review 3).
 */
export const MAX_MNEMONIC_HASHES = 25_000;

export interface MnemonicBudget {
  hashes: number;
  reasons: Set<string>;
}

/** English BIP-39 only: full words, valid checksum, no wallet derivation or I/O. */
export function findMnemonic(
  text: string,
  budget: MnemonicBudget = { hashes: 0, reasons: new Set() }
): boolean {
  // The caller supplies bounded argument views. No case folding or word-prefix
  // expansion: neither should manufacture a different credential from prose.
  let run: string[] = [];
  let runIndex: number[] = [];
  let previousEnd = 0;
  const rejected = new Set<string>();
  const inspect = (): boolean => {
    if (run.length < 12) return false;
    // ascending[i]: how many of the steps up to word i go up the word list.
    // A window whose every step goes up is the list itself (or a slice of
    // it), not a phrase: skipped before any hashing.
    const ascending = new Array<number>(run.length).fill(0);
    for (let i = 1; i < run.length; i++)
      ascending[i] = ascending[i - 1] + (runIndex[i] > runIndex[i - 1] ? 1 : 0);
    for (let start = 0; start + 12 <= run.length; start++) {
      for (const count of lengths) {
        if (start + count > run.length) continue;
        if (ascending[start + count - 1] - ascending[start] === count - 1) continue;
        const candidate = run.slice(start, start + count);
        const sentence = candidate.join(' ');
        if (rejected.has(sentence)) continue;
        if (++budget.hashes > MAX_MNEMONIC_HASHES) {
          budget.reasons.add('mnemonic-budget');
          return false;
        }
        if (BIP39_PUBLIC_VECTORS.has(hash(sentence).toString('hex'))) {
          // Do not rediscover a shorter checksum-valid window inside a public
          // vector. Continue scanning following words for independent secrets.
          start += count - 1;
          break;
        }
        const bits = candidate
          .map((word) => indices.get(word)!.toString(2).padStart(11, '0'))
          .join('');
        const checksumBits = count / 3;
        const entropyBits = bits.slice(0, -checksumBits);
        const entropy = Buffer.from(entropyBits.match(/.{8}/g)!.map((byte) => parseInt(byte, 2)));
        const checksum = hash(entropy)[0].toString(2).padStart(8, '0').slice(0, checksumBits);
        if (bits.endsWith(checksum)) return true;
        rejected.add(sentence);
      }
    }
    return false;
  };
  for (const word of text.matchAll(/[a-zA-Z]+/g)) {
    const index = indices.get(word[0]);
    if (index === undefined || (run.length && !/^\s+$/.test(text.slice(previousEnd, word.index)))) {
      if (inspect()) return true;
      if (budget.reasons.has('mnemonic-budget')) return false;
      run = [];
      runIndex = [];
    }
    if (index !== undefined) {
      run.push(word[0]);
      runIndex.push(index);
    }
    previousEnd = word.index + word[0].length;
  }
  return inspect();
}
