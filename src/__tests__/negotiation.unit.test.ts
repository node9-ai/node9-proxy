import { describe, it, expect } from 'vitest';
import {
  agentFacingLabel,
  asApprovalRequest,
  buildNegotiationMessage,
  buildReviewMessage,
  isHumanDecision,
} from '../policy/negotiation';

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

// MSG-3 (node9Firewall#306): the SSRF block reached the agent as "Action
// blocked by security policy [<globe emoji> Node9 Egress (Protected Address)]".
// The label keeps its exact spelling (the catalog, the dashboard and the
// terminal key on it); only the agent's text drops the emoji.
describe('the agent-facing label has no emoji and says node9 (MSG-3)', () => {
  const PICTO = /\p{Extended_Pictographic}/u;

  it('the SSRF block text the agent reads', () => {
    const msg = buildNegotiationMessage('\u{1F310} Node9 Egress (Protected Address)', false);
    expect(msg).not.toMatch(PICTO);
    expect(msg).toContain('[node9 Egress (Protected Address)]');
  });

  it.each([
    ['\u{1F310} Node9 Egress (Protected Address)', 'node9 Egress (Protected Address)'],
    ['\u26A0\uFE0F Override block rule: Smart Rule: x', 'Override block rule: Smart Rule: x'],
    ['Node9: Eval Remote Execution', 'node9: Eval Remote Execution'],
    ['Smart Rule: review-git-push', 'Smart Rule: review-git-push'],
    ['\u{1F310}', 'Security Policy'],
  ])('%s', (label, shown) => {
    expect(agentFacingLabel(label)).toBe(shown);
  });

  it('the branch choice still reads the raw label', () => {
    const msg = buildNegotiationMessage('\u{1F6A8} Node9 DLP (Secret Detected)', false);
    expect(msg).toMatch(/was found in your tool call arguments/);
  });
});

// MSG-5 (node9Firewall#305): a softened block's approval card said "Reading
// .env files is blocked" above "Enter = Allow".
describe('a block sentence reads as a request on an approval card (MSG-5)', () => {
  it.each([
    [
      'Reading .env files is blocked by project-jail shield',
      'Reading .env files needs your approval (project-jail shield)',
    ],
    [
      'DROP TABLE is irreversible \u2014 blocked by Postgres shield',
      'DROP TABLE is irreversible. Needs your approval (Postgres shield)',
    ],
    [
      'Reading SSH private keys is blocked by project-jail shield.',
      'Reading SSH private keys needs your approval (project-jail shield)',
    ],
    ['Pushes are blocked by my rule.', 'Pushes are blocked by my rule.'],
    // A user's own sentence is not rewritten: only the builtin "<name> shield" shape.
    [
      'Prod writes is blocked by policy unless the lead signs off.',
      'Prod writes is blocked by policy unless the lead signs off.',
    ],
    ['X is blocked by .', 'X is blocked by .'],
    ['Chained read of a sensitive file', 'Chained read of a sensitive file'],
    [' is blocked by x', ' is blocked by x'],
  ])('%s', (sentence, card) => {
    expect(asApprovalRequest(sentence)).toBe(card);
  });
});

// ENG-2 (node9Firewall#304): a deny is a person's only when no rule, timeout
// or policy is named as its decider.
describe('isHumanDecision', () => {
  it.each([
    ['User Decision (Native)', 'local-decision', true],
    ['User Decision (Terminal (node9 tail))', 'local-decision', true],
    ['User Decision (Native)', undefined, true],
    ['Steered Redirect (Terminal)', 'local-decision', false],
    ['Browser Dashboard (Abandoned)', 'local-decision', false],
    ['Smart Rule: review-user-data', 'local-config', false],
    ['Smart Rule: block-userdel', 'local-config', false],
    ['Approval Timeout', 'timeout', false],
    ['Organization Policy (SaaS)', 'team-policy', false],
    ['local-decision', 'local-decision', true],
  ] as const)('%s / %s', (label, blockedBy, human) => {
    expect(isHumanDecision(label, blockedBy)).toBe(human);
  });
});
