// Code review of the fw#318 fixes: personal data in audit arguments is masked
// leaf by leaf, so a card passed as a number cannot leave invalid JSON behind
// (the old text masking made JSON.parse throw inside the audit writer and
// sent {redacted:true} to the SaaS), and the fractional part of a number is
// never masked as a card (node9Firewall#333). Values are computed at run time.
//
// fs.appendFileSync is spied (not mocked away) so the exact JSON line is
// asserted without touching the real ~/.node9 logs.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import { appendHookDebug, appendLocalAudit, HOOK_DEBUG_LOG, LOCAL_AUDIT_LOG } from '../audit/index';
import { maskArgsForCloud } from '../auth/cloud';

const CARD = '4242'.repeat(4);
let written: Array<{ path: string; line: string }> = [];

beforeEach(() => {
  written = [];
  vi.spyOn(fs, 'existsSync').mockReturnValue(true);
  vi.spyOn(fs, 'appendFileSync').mockImplementation((p, data) => {
    written.push({ path: String(p), line: String(data) });
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

function rowIn(file: string): Record<string, unknown> {
  const e = written.find((w) => w.path === file);
  expect(e).toBeDefined();
  return JSON.parse(e!.line) as Record<string, unknown>;
}

describe('appendLocalAudit with auditHashArgs off', () => {
  it('a card passed as a number is masked and the row is written', () => {
    expect(() =>
      appendLocalAudit(
        'Write',
        { card: Number(CARD), rate: 46 / 96 },
        'allow',
        'local-policy',
        {},
        false
      )
    ).not.toThrow();
    expect(rowIn(LOCAL_AUDIT_LOG).args).toEqual({ card: '**** **** **** 4242', rate: 46 / 96 });
  });
  it('a fraction inside written content is kept as written', () => {
    const content = JSON.stringify({ catch_rate: 46 / 96 }, null, 2);
    appendLocalAudit(
      'Write',
      { file_path: 'metrics.json', content },
      'allow',
      'local-policy',
      {},
      false
    );
    expect(rowIn(LOCAL_AUDIT_LOG).args).toEqual({ file_path: 'metrics.json', content });
  });
});

describe('appendHookDebug with auditHashArgs off', () => {
  it('a card passed as a number is masked and the row is written', () => {
    expect(() => appendHookDebug('Write', { card: Number(CARD) }, {}, false)).not.toThrow();
    expect(rowIn(HOOK_DEBUG_LOG).args).toEqual({ card: '**** **** **** 4242' });
  });
});

describe('maskArgsForCloud', () => {
  it('a fraction is sent as the same number, not as {redacted:true}', () => {
    expect(maskArgsForCloud({ file_path: 'metrics.json', rate: 46 / 96 })).toEqual({
      file_path: 'metrics.json',
      rate: 46 / 96,
    });
  });
  it('a card passed as a number is sent masked, the other args intact', () => {
    expect(maskArgsForCloud({ card: Number(CARD), note: 'hi' })).toEqual({
      card: '**** **** **** 4242',
      note: 'hi',
    });
  });
  it('a circular value still ships as redacted', () => {
    const a: Record<string, unknown> = { x: 1 };
    a.self = a;
    expect(maskArgsForCloud(a)).toEqual({ redacted: true });
  });
});
