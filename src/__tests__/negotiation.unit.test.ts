import { describe, it, expect } from 'vitest';
import { buildNegotiationMessage, buildReviewMessage } from '../policy/negotiation';

// Every deny message node9 hands back to an agent must tell the agent to
// surface the block to the human. Measured 2026-09-03 on the founder's
// machine: a project-jail block on a `.env` read reached the agent as a bare
// "do not retry / find an alternative" instruction, the agent quietly pivoted,
// and the human never learned node9 had acted. The better the rule, the less
// visible the product. This is a UX layer, not a security control: a hostile
// agent can ignore it; audit.log is what always knows.
const TELLS_THE_USER = /(tell|inform) the user|acknowledge the block to the user/i;

// One label per branch of buildNegotiationMessage, in source order. The
// strings mirror the `label.includes(...)` checks, so a renamed branch fails
// here rather than silently falling through to the generic fallback.
const BRANCHES: Array<[name: string, label: string]> = [
  ['dlp (secret in arguments)', 'DLP: secret detected in args'],
  ['sql delete without where', 'SQL safety: DELETE without WHERE'],
  ['sql update without where', 'SQL safety: UPDATE without WHERE'],
  ['dangerous word', 'dangerous word: "mkfs"'],
  ['path blocked / sandbox', 'path blocked: outside sandbox'],
  ['inline execution', 'inline execution via bash -c'],
  ['strict mode', 'strict mode'],
  ['policy rule default block', 'rule "git push --force" default block'],
  ['generic fallback', 'Something node9 has no template for'],
];

describe('buildNegotiationMessage tells the agent to inform the user', () => {
  for (const [name, label] of BRANCHES) {
    it(name, () => {
      const msg = buildNegotiationMessage(label, false);
      expect(msg, `branch "${name}" never asks the agent to tell the user:\n${msg}`).toMatch(
        TELLS_THE_USER
      );
    });
  }

  it('human decision', () => {
    expect(buildNegotiationMessage('user decision', true, 'not now')).toMatch(TELLS_THE_USER);
  });

  it('generic fallback with a recovery command', () => {
    expect(
      buildNegotiationMessage('egress: host not trusted', false, undefined, 'node9 trust x')
    ).toMatch(TELLS_THE_USER);
  });

  it('the dlp branch never asks the agent to repeat the credential', () => {
    const msg = buildNegotiationMessage('DLP: secret detected', false);
    expect(msg).not.toMatch(/quote|repeat|show the (key|token|secret|credential)/i);
  });
});

// MSG-1 (doc/BUGS.md): a PROTECTED FILE was told "a sensitive credential was
// found in your tool call arguments ... rotate it immediately". No credential
// was in the arguments, only a path, and on camera the agent told the user
// node9 had misfired. The message is chosen by the KIND of block now, not by
// a substring of the label, which the dashboard and telemetry also read.
describe('a protected file gets a protected-file message (MSG-1)', () => {
  const FALSE_CLAIMS = [/was found in your tool call arguments/i, /rotate/i, /compromised/i];

  it('names the file, says it is protected, and makes no credential claim', () => {
    const msg = buildNegotiationMessage(
      '🚨 Node9 DLP (Secret Detected)',
      false,
      undefined,
      undefined,
      {
        kind: 'protected-path',
        path: '/work/app/.env',
      }
    );
    expect(msg).toContain('/work/app/.env');
    expect(msg).toMatch(/protected/i);
    for (const claim of FALSE_CLAIMS) expect(msg).not.toMatch(claim);
    expect(msg).toMatch(TELLS_THE_USER);
  });

  it('without a path it still makes no credential claim', () => {
    const msg = buildNegotiationMessage('project-jail (AST): x', false, undefined, undefined, {
      kind: 'protected-path',
    });
    expect(msg).toMatch(/this file/i);
    for (const claim of FALSE_CLAIMS) expect(msg).not.toMatch(claim);
  });

  it('a REAL secret in the arguments keeps the credential text (control)', () => {
    const msg = buildNegotiationMessage('🚨 Node9 DLP (Secret Detected)', false);
    expect(msg).toMatch(/was found in your tool call arguments/);
    expect(msg).toMatch(/rotate it immediately/);
  });

  it('a human decision is still a human decision, whatever the kind', () => {
    const msg = buildNegotiationMessage('User Decision (Native)', true, 'no', undefined, {
      kind: 'protected-path',
    });
    expect(msg).toMatch(/The human user rejected this action/);
  });
});

// MSG-2: "...without a backup.. Approve to proceed" -- the rule's sentence
// already ended in a period and one more was appended.
describe('buildReviewMessage ends the reason with one period (MSG-2)', () => {
  const OUT = (body: string) =>
    `Node9 flagged this for your review: ${body} Approve to proceed, or deny to cancel.`;
  it.each([
    ['ends in a period: kept, not doubled', 'rm is permanent.', 'rm is permanent.'],
    ['ends in no punctuation: one added', 'rm is permanent', 'rm is permanent.'],
    ['trailing spaces: trimmed', 'rm is permanent.   ', 'rm is permanent.'],
    // /code-review: a trim of [.!?] turned questions into statements
    ['a question stays a question', 'Deploy to prod?', 'Deploy to prod?'],
    ['an exclamation stays', 'rm is permanent!', 'rm is permanent!'],
    ['an ellipsis stays', 'this is irreversible...', 'this is irreversible...'],
  ])('%s', (_name, reason, body) => {
    expect(buildReviewMessage(undefined, reason)).toBe(OUT(body));
  });
});
