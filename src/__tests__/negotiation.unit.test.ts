import { describe, it, expect } from 'vitest';
import { buildNegotiationMessage } from '../policy/negotiation';

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
