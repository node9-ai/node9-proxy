import { describe, it, expect } from 'vitest';
import { analyzeFsOperation } from '../shell/index';

// ─────────────────────────────────────────────────────────────────────────────
// GHSA-fc5q-39xc-vjpf: picomatch <= 4.0.7 backtracks exponentially on
// single-branch repeated extglobs (`+(*a)`) against crafted input. No patched
// version exists, and the jail compiles globs taken from the agent's own
// command (`find -name P`, `cat ~/.e*`), so the PATTERN is agent-controlled.
//
// The INPUT never is. Every picomatch call on this path matches against
// node9's own short names (`.env`, `n9-any-name`, `.ssh`) or the absolute
// protected paths, and measured on 2026-11-17 no hostile pattern took more
// than a few milliseconds against them (the 26 s blow-up needs a long run of
// one character in the input). That is why the npm audit finding is exempted
// for a limited time in scripts/audit-exemptions.json.
//
// This test is the guard on that reasoning: real jail evaluation of hostile
// commands must stay fast. If a change ever feeds agent text in as the INPUT,
// these cases become slow and the exemption must go.
//
// Not `noextglob`: an agent can run `shopt -s extglob`, and `cat .e*@(nv)`
// would then stop matching `.env`.
// ─────────────────────────────────────────────────────────────────────────────

const HOSTILE = [
  `find . -name '+(*a)+(*a)+(*a)+(*a)+(*a)+(*a)z' -exec cat {} +`,
  `find . -name '+(*e)+(*e)+(*e)+(*e)+(*e)+(*e)+(*e)z' -exec cat {} +`,
  `cat +(*e)+(*e)+(*e)+(*e)+(*e)+(*e)+(*e)z`,
  `shopt -s extglob; cat .+(*e)+(*e)+(*e)+(*e)+(*e)+(*e)z`,
  `cat ~/.ssh/+(*s)+(*s)+(*s)+(*s)+(*s)+(*s)z`,
  `cat ~/+(*/)+(*/)+(*/)+(*/)+(*/)+(*/)z/id_rsa`,
  `cat ~/.+(*s)+(*s)+(*s)+(*s)+(*s)z/id_rsa`,
  `ls -la +(*a)+(*a)+(*a)+(*a)+(*a)+(*a)+(*a)z`,
];

describe('GHSA-fc5q-39xc-vjpf guard: hostile extglobs stay fast in the jail', () => {
  it.each(HOSTILE)('%s', (command) => {
    const started = performance.now();
    analyzeFsOperation(command);
    // A ReDoS here is seconds to minutes; a normal evaluation is milliseconds.
    // The bound is loose so a slow Windows runner never flakes it.
    expect(performance.now() - started).toBeLessThan(2000);
  });

  it('still judges a plain jailed glob read as a read of .env (control)', () => {
    expect(analyzeFsOperation('cat .e*')?.verdict).toBe('block');
  });
});
