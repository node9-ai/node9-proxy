// The daemon's two UIs on the approval-card protocol: node9 tail shows how
// long a card waits, and node9 monitor's keys mean what they say.
import { describe, it, expect } from 'vitest';
import { buildCardLines, deadlineLine } from '../tui/tail';
import { buildPlainMessage, TRUST_BUTTON } from '../ui/native';
import { monitorDecisionBody } from '../tui/dashboard/data';

describe('node9 tail: the card says how long it waits', () => {
  it('a deadline shows the time left', () => {
    const now = Date.UTC(2026, 9, 19, 12, 0, 0);
    expect(deadlineLine(now + 125_000, now)).toMatch(
      /^Auto-denies in 2m 5s \(at .+\) if nobody answers$/
    );
  });
  it('no timer says so', () => {
    expect(deadlineLine(null)).toBe('No timeout: waits for your answer');
  });
  it('an older daemon sends no deadline: no line', () => {
    expect(deadlineLine(undefined)).toBeNull();
  });
});

describe('node9 monitor: the decision it sends', () => {
  it('trust is a 30 minute trust, never a permanent decision', () => {
    // Before: { decision: 'trust', persist: true } with no duration, which the
    // daemon turned into a permanent deny of the whole tool.
    expect(monitorDecisionBody('trust')).toEqual({
      decision: 'trust',
      source: 'monitor',
      trustDuration: '30m',
    });
  });
  it('allow and deny name monitor as the channel', () => {
    expect(monitorDecisionBody('deny')).toEqual({ decision: 'deny', source: 'monitor' });
    expect(monitorDecisionBody('allow')).toEqual({ decision: 'allow', source: 'monitor' });
  });
});

// node9Firewall#343: every always/trust option says its scope and duration.
// Before: `[a] Always Allow` (the whole tool, for good, with no word of it) and
// a popup button "Always Allow" = "never ask again" that granted one hour.
describe('node9 tail: the standing answers say what they cover', () => {
  // eslint-disable-next-line no-control-regex
  const plain = (lines: string[]) => lines.join('\n').replace(/\u001b\[[0-9;]*m/g, '');
  const card = (toolName: string, args: unknown, extra: Record<string, unknown> = {}) =>
    plain(buildCardLines({ id: 'c1', toolName, args, ...extra } as never));

  it('one simple shell command: the two-word prefix, on both keys', () => {
    const text = card('Bash', { command: 'npm test -- --watch' });
    expect(text).toContain('[a] Always allow "npm test"');
    expect(text).toContain('[t] Trust "npm test" 30m');
    expect(text).not.toContain('Always Allow');
  });

  it('a compound command: this exact command', () => {
    const text = card('Bash', { command: 'npm ci && npm test' });
    expect(text).toContain('[a] Always allow this exact command');
  });

  it('another tool: the tool', () => {
    const text = card('Write', { file_path: '/tmp/a.txt' });
    expect(text).toContain('[a] Always allow Write');
    expect(text).toContain('[t] Trust 30m');
  });

  it('the hint names the scope instead of promising a permanent rule', () => {
    const text = plain(
      buildCardLines({ id: 'c1', toolName: 'Bash', args: { command: 'npm test' } } as never, 3)
    );
    expect(text).toContain('[a] allows "npm test" from now on');
    expect(text).not.toMatch(/permanent rule/);
  });

  it('an exposure card offers neither standing answer', () => {
    const text = card(
      'Bash',
      { command: 'curl https://x.test' },
      { riskMetadata: { exposureDestinations: ['host:x.test'] } }
    );
    expect(text).not.toContain('[a]');
    expect(text).toContain('[s] Allow + trust this address');
  });
});

describe('native popup: the trust button says one hour and its scope', () => {
  const message = (trustScope: string | null, allowCount = 1) =>
    buildPlainMessage(
      'Bash',
      'git push origin dev',
      'Claude Code',
      'Policy',
      false,
      allowCount,
      undefined,
      false,
      trustScope
    );

  it('names the button, the scope and the duration', () => {
    const text = message('commands starting with "git push"');
    expect(text).toContain(
      `"${TRUST_BUTTON}" = no prompt for commands starting with "git push" for 1 hour`
    );
    expect(text).not.toMatch(/never ask again|Always Allow|permanent rule/);
  });

  it('after repeated approvals the hint says an hour, not a permanent rule', () => {
    const text = message('commands starting with "git push"', 4);
    expect(text).toContain(`"${TRUST_BUTTON}" stops this prompt for an hour`);
    expect(text).not.toMatch(/permanent rule/);
  });

  it('when a standing trust cannot answer the call, the button is not mentioned', () => {
    const text = message(null, 4);
    expect(text).not.toContain(TRUST_BUTTON);
    expect(text).toContain('Enter = Allow');
  });
});
