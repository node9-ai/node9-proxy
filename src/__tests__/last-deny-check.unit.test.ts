// The ran-after-block row takes its check from the last deny row the hook
// process wrote (lastDenyAudit). A review the person denies writes two deny
// rows: the check's own row (with checkId and rule) and then the person's
// decision ('local-decision', no check). The second used to replace the
// first, so the ran row carried no check and the dashboard could not place
// it under a risk (seen on a real machine 2026-11-15).
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import { appendLocalAudit, lastDenyAudit } from '../audit/index';

beforeEach(() => {
  vi.spyOn(fs, 'existsSync').mockReturnValue(true);
  vi.spyOn(fs, 'appendFileSync').mockImplementation(() => undefined);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('lastDenyAudit', () => {
  it('keeps the check of the stop when the person then denies the review', () => {
    appendLocalAudit('Bash', undefined, 'deny', 'smart-rule-block-override', {
      checkId: 'packs.bash-safe.pipe-to-shell',
      ruleName: 'shield:bash-safe:block-pipe-to-shell',
    });
    appendLocalAudit('Bash', undefined, 'deny', 'local-decision', {});
    const stop = lastDenyAudit();
    expect(stop?.checkedBy).toBe('local-decision');
    expect(stop?.checkId).toBe('packs.bash-safe.pipe-to-shell');
    expect(stop?.ruleName).toBe('shield:bash-safe:block-pipe-to-shell');
  });

  it('a later deny with its own check takes over', () => {
    appendLocalAudit('Bash', undefined, 'deny', 'smart-rule-block', {
      checkId: 'commands.curl-pipe-shell',
    });
    appendLocalAudit('Bash', undefined, 'deny', 'dlp-block', {
      checkId: 'data.credential-files',
    });
    expect(lastDenyAudit()?.checkId).toBe('data.credential-files');
  });
});
