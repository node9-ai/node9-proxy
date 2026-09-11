/**
 * The credential jail, across EVERY path shape -- the axis that three
 * consecutive attempts missed.
 *
 * 1. The matchers required a TRAILING separator, so the credential DIRECTORY
 *    was never jailed, only files inside it. Measured at the real gate:
 *    `grep -r TODO ~/.ssh` and `Grep {path:'~/.ssh'}` were ALLOWED while
 *    `cat ~/.ssh/id_rsa` was blocked -- one call read every key.
 *
 * 2. The obvious repair, "separator OR end-of-string", regressed harder: with
 *    `^` already allowed at the front, the bare token `.ssh` matched ITSELF, so
 *    `grep -r .ssh ~/project` -- a search for the STRING -- became a hard block.
 *    Caught by review, not by tests, because the precision cases only covered
 *    LONGER names (`.sshfoo`) and never the bare one.
 *
 * The discriminator is a separator: a real path always carries one, a search
 * pattern never does. Hence `[/\\].ssh(sep|$)` OR `^.ssh sep`, never `^…$`.
 *
 * `base64` is here too: it prints the file's bytes re-encoded and was simply
 * absent from the reader set, the same shape the set's own note records for
 * `strings`.
 */
import { describe, it, expect } from 'vitest';
import { analyzeFsOperation } from '../shell';
import { matchSensitivePath as dlpMatch } from '../dlp';

const CATCH: Array<[string, string]> = [
  ['absolute file', '/home/x/.ssh/id_rsa'],
  ['absolute directory', '/home/x/.ssh'],
  ['directory with trailing slash', '/home/x/.ssh/'],
  ['relative file', '.ssh/id_rsa'],
  ['tilde directory', '~/.ssh'],
];

const ALLOW: Array<[string, string]> = [
  ['the BARE token — a search pattern, not a path', '.ssh'],
  ['a longer name', '/home/x/.sshfoo'],
  ['no leading dot', '/home/x/sshconfig'],
];

describe('jail matchers — every path shape, both lists', () => {
  for (const [label, p] of CATCH) {
    // `cat ${p}` -- NOT `cat ${p}/k`. Appending a child collapsed all five
    // shapes into "a file inside the directory", which the pre-fix regex
    // already caught, so this half passed green against the very bug it was
    // written to pin. An instrument has to fail on the broken code first.
    it(`AST tier catches: ${label}`, () => {
      expect(analyzeFsOperation(`cat ${p}`)).not.toBeNull();
    });
    it(`DLP tier catches: ${label}`, () => {
      expect(dlpMatch(p, p), 'the Read/Grep/Glob guard reads this list').not.toBeNull();
    });
  }

  // Earned by /code-review 2026-09-10 and confirmed by A/B against shipped
  // code: an earlier anchor here turned these into hard blocks. The pattern
  // argument of a search CAN carry a separator, so "has a separator" is not
  // the discriminator -- being ROOTED is.
  it.each([
    ['a search pattern with a leading separator', 'rg /.ssh src/'],
    ['a search for a path fragment', 'grep -rn config/.ssh .'],
    ['an unrooted relative fragment', 'rg src/.aws .'],
  ])('AST tier stays quiet: %s', (_l, cmd) => {
    expect(analyzeFsOperation(cmd)).toBeNull();
  });

  // The precision floor. Without these the suite proves only loudness — and
  // their absence is exactly how the bare-token regression shipped green.
  for (const [label, p] of ALLOW) {
    it(`AST tier stays quiet: ${label}`, () => {
      expect(analyzeFsOperation(`grep -r ${p} /home/x/project`)).toBeNull();
    });
    it(`DLP tier stays quiet: ${label}`, () => {
      expect(dlpMatch(p, p)).toBeNull();
    });
  }

  it('a bare-token search is not a jailed read, end to end', () => {
    expect(analyzeFsOperation('grep -r .ssh /home/x/project')).toBeNull();
    expect(analyzeFsOperation('rg .aws src/')).toBeNull();
  });

  // ⚠️ PRE-EXISTING and out of scope: `sed -i s/.aws/x/ f.txt` blocks on
  // shipped code, because the sed expression `s/.aws/x/` carries separators on
  // both sides and reads as a path. `s#.aws#x#` with a different delimiter
  // allows. Found while writing this suite; a separate defect, not touched
  // here -- pinned so the next reader does not mistake it for a regression.
  it('⚠️ known pre-existing FP: a sed expression reads as a path', () => {
    expect(analyzeFsOperation('sed -i s/.aws/x/ f.txt')).not.toBeNull();
    expect(analyzeFsOperation('sed -i s#.aws#x# f.txt')).toBeNull();
  });

  // Two lists, one promise. They drifted apart once already; this pins them
  // together so a fix applied to one and not the other fails here.
  it('the AST tier and the DLP tier agree on every shape', () => {
    for (const [, p] of CATCH) {
      expect(analyzeFsOperation(`cat ${p}/k`.replace('//k', '/k')), `AST, ${p}`).not.toBeNull();
      expect(dlpMatch(p, p), `DLP, ${p}`).not.toBeNull();
    }
  });
});

describe('base64 is a reader', () => {
  it('catches a jailed file', () => {
    expect(analyzeFsOperation('base64 /home/x/.ssh/id_rsa')).not.toBeNull();
  });
  it('leaves an unrelated file alone', () => {
    expect(analyzeFsOperation('base64 /home/x/project/logo.png')).toBeNull();
  });
});
