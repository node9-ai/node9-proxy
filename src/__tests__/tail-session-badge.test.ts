import { describe, it, expect, vi, beforeAll } from 'vitest';

// tail.ts → ../daemon → ../daemon/ui.ts → ui.html. Vitest's default Vite
// transform can't import .html. Mock ../daemon to short-circuit the chain
// (matches the pattern in tail.test.ts).
vi.mock('../daemon', () => ({ DAEMON_PORT: 7391 }));

let sessionTag: (id: string | undefined) => string;
let agentLabel: (a: string | undefined, m?: string, s?: string) => string;
let eventsUrl: (port: number, canApprove: boolean) => string;

beforeAll(async () => {
  const mod = await import('../tui/tail.js');
  sessionTag = mod.sessionTag;
  agentLabel = mod.agentLabel;
  eventsUrl = mod.eventsUrl;
});

// Strip ANSI color codes so tests assert on visible text only.
const plain = (s: string): string => s.replace(/\x1b\[[0-9;]*m/g, '');

describe('sessionTag — session badge derivation', () => {
  it('returns the last 4 alphanumeric chars of a UUID', () => {
    expect(sessionTag('ea385d8a-0c49-4ebe-8b66-c649672cc19e')).toBe('c19e');
  });

  it('returns empty when sessionId is undefined', () => {
    expect(sessionTag(undefined)).toBe('');
  });

  it('returns empty for short / unusable values', () => {
    expect(sessionTag('')).toBe('');
    expect(sessionTag('abc')).toBe('');
  });

  it('strips non-alphanumeric before slicing (avoids "----" tags)', () => {
    expect(sessionTag('xx-yy-zz-1234')).toBe('1234');
  });

  it('handles Gemini-style UUIDs the same way as Claude', () => {
    // Gemini sessions also use UUID v4 format.
    expect(sessionTag('3745cf2a-c7e2-440a-bd57-4f3568b366f0')).toBe('66f0');
  });
});

describe('agentLabel — renders session tag inline', () => {
  it('shows [Claude·c19e] when both agent and sessionId present', () => {
    const label = plain(
      agentLabel('Claude Code', undefined, 'ea385d8a-0c49-4ebe-8b66-c649672cc19e')
    );
    expect(label).toContain('[Claude·c19e]');
  });

  it('shows [Gemini·66f0] for Gemini CLI sessions', () => {
    const label = plain(
      agentLabel('Gemini CLI', undefined, '3745cf2a-c7e2-440a-bd57-4f3568b366f0')
    );
    expect(label).toContain('[Gemini·66f0]');
  });

  it('falls back to plain [Claude] when sessionId is missing', () => {
    const label = plain(agentLabel('Claude Code'));
    expect(label).toContain('[Claude]');
    expect(label).not.toContain('·');
  });

  it('emits no badge for Terminal / unknown agents (sessionId ignored)', () => {
    // Terminal calls don't have an agent session — never show a tag.
    expect(plain(agentLabel('Terminal', undefined, 'whatever-1234'))).toBe('');
    expect(plain(agentLabel(undefined))).toBe('');
  });

  it('preserves mcp arrow alongside the session tag', () => {
    const label = plain(agentLabel('Claude Code', 'node9', 'ea385d8a-0c49-4ebe-8b66-c649672cc19e'));
    expect(label).toContain('Claude·c19e → node9');
  });

  it('two distinct sessions produce two distinct tags', () => {
    // The whole point: parallel sessions must be visually distinguishable.
    const a = plain(agentLabel('Claude Code', undefined, 'aaaaaaaa-1111-2222-3333-aaaaaaaaaaaa'));
    const b = plain(agentLabel('Claude Code', undefined, 'bbbbbbbb-1111-2222-3333-bbbbbbbbbbbb'));
    expect(a).toContain('aaaa');
    expect(b).toContain('bbbb');
    expect(a).not.toBe(b);
  });
});

describe('eventsUrl — input capability only for a real approver (round-2 F2)', () => {
  it('a TTY tail advertises capabilities=input', () => {
    expect(eventsUrl(7391, true)).toBe('http://127.0.0.1:7391/events?capabilities=input');
  });

  it('a piped/redirected tail must NOT register as an interactive approver', () => {
    // The daemon's GET /approver counts input-capable clients as reachable
    // humans; a phantom one lets a shield hard-block soften to a review
    // nobody can answer (/code-review finding #4).
    expect(eventsUrl(7391, false)).toBe('http://127.0.0.1:7391/events');
  });
});
