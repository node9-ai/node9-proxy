import { createHash } from 'node:crypto';
import { BIP39_ENGLISH } from './bip39-english';
import { BIP39_PUBLIC_VECTORS } from './bip39-public-vectors';

const indices = new Map(BIP39_ENGLISH.map((word, i) => [word, i]));
const lengths = [24, 21, 18, 15, 12];
const hash = (value: string | Buffer) => createHash('sha256').update(value).digest();

/** English BIP-39 only: full words, valid checksum, no wallet derivation or I/O. */
export function findMnemonic(
  text: string,
  budget: { candidates: number; reasons: Set<string> } = { candidates: 0, reasons: new Set() }
): boolean {
  // The caller supplies bounded argument views. No case folding or word-prefix
  // expansion: neither should manufacture a different credential from prose.
  const words = [...text.matchAll(/[a-zA-Z]+/g)];
  let run: string[] = [];
  let previousEnd = 0;
  const rejected = new Set<string>();
  const inspect = (): boolean => {
    for (let start = 0; start + 12 <= run.length; start++) {
      for (const count of lengths) {
        if (start + count > run.length) continue;
        const candidate = run.slice(start, start + count);
        const sentence = candidate.join(' ');
        if (rejected.has(sentence)) continue;
        if (++budget.candidates > 1024) {
          budget.reasons.add('mnemonic-candidates');
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
  for (const word of words) {
    if (
      !indices.has(word[0]) ||
      (run.length && !/^\s+$/.test(text.slice(previousEnd, word.index)))
    ) {
      if (inspect()) return true;
      if (budget.reasons.has('mnemonic-candidates')) return false;
      run = [];
    }
    if (indices.has(word[0])) run.push(word[0]);
    previousEnd = word.index + word[0].length;
  }
  return inspect();
}
