// src/__tests__/native-fail-closed.spec.ts
//
// Regression test for GAP-6 (reproduced live 2026-06-07): the native approval
// popup treated ANY zenity/osascript exit code 0 as "allow". On X11/XWayland a
// spurious exit-0 (timeout-as-0, window-manager auto-close, headless dismiss)
// would silently approve a tool call that the user never clicked Allow on —
// turning a downgraded `block` rule into an allow. See
// doc/security-coverage-gaps.md GAP-6.
//
// Fix: resolveNativeDecision() fails closed — an affirmative (exit 0 or the
// "Trust 1h" extra-button) is only honoured when the dialog was on screen
// long enough for a human to actually read and click it. Anything faster is a
// non-interactive/spurious return and resolves to 'deny'.

import { describe, it, expect } from 'vitest';
import {
  resolveNativeDecision,
  trustScopeText,
  MIN_INTERACTION_MS,
  TRUST_BUTTON,
} from '../ui/native';

describe('resolveNativeDecision — fail-closed native approval (GAP-6)', () => {
  const HUMAN = MIN_INTERACTION_MS + 50; // long enough to be a real click
  const SPURIOUS = 20; // instant exit-0 — no human could have clicked

  it('allows a genuine click: exit 0 after a human-plausible delay', () => {
    expect(resolveNativeDecision({ code: 0, output: '', elapsedMs: HUMAN, locked: false })).toBe(
      'allow'
    );
  });

  it('FAILS CLOSED on a spurious instant exit-0 (the reproduced bug)', () => {
    // Before the fix this returned 'allow' — the headless fail-open.
    expect(resolveNativeDecision({ code: 0, output: '', elapsedMs: SPURIOUS, locked: false })).toBe(
      'deny'
    );
  });

  it('denies on a non-zero exit (explicit Block / Cancel)', () => {
    expect(resolveNativeDecision({ code: 1, output: '', elapsedMs: HUMAN, locked: false })).toBe(
      'deny'
    );
  });

  it('honours the trust button only after a human-plausible delay', () => {
    expect(
      resolveNativeDecision({ code: 0, output: TRUST_BUTTON, elapsedMs: HUMAN, locked: false })
    ).toBe('always_allow');
  });

  it('FAILS CLOSED on a spurious instant trust click', () => {
    expect(
      resolveNativeDecision({ code: 0, output: TRUST_BUTTON, elapsedMs: SPURIOUS, locked: false })
    ).toBe('deny');
  });

  // node9Firewall#343: the button said "Always Allow" / "never ask again" and
  // granted one hour. It is named for what it does, and the old label no
  // longer resolves to a standing answer.
  it('the button is named for what it grants', () => {
    expect(TRUST_BUTTON).toBe('Trust 1h');
    expect(
      resolveNativeDecision({ code: 1, output: 'Always Allow', elapsedMs: HUMAN, locked: false })
    ).toBe('deny');
  });

  it('the footer says the scope and the duration', () => {
    expect(trustScopeText('Bash', 'git push')).toBe('commands starting with "git push"');
    expect(trustScopeText('Write', undefined)).toBe('Write calls');
  });

  it('a locked popup never resolves to allow', () => {
    expect(resolveNativeDecision({ code: 0, output: '', elapsedMs: HUMAN, locked: true })).toBe(
      'deny'
    );
  });
});
