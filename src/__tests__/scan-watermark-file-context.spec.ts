// The daemon's extractor context carries the line's cwd and the user's home,
// so the file checks resolve a path the way the gate did when the call ran
// (node9Firewall#413 review, finding 5 follow-up).
import { describe, it, expect } from 'vitest';
import os from 'os';
import { extractCanonicalFindings } from '@node9/policy-engine';
import { canonicalContextForLine } from '../daemon/scan-watermark';

describe('canonicalContextForLine', () => {
  it('passes an absolute cwd and the home directory', () => {
    const ctx = canonicalContextForLine({ cwd: '/work/proj' }, 'sess', 4);
    expect(ctx.cwd).toBe('/work/proj');
    expect(ctx.homeDirs).toEqual([os.homedir()]);
  });

  it('drops a cwd that is not absolute', () => {
    expect(canonicalContextForLine({ cwd: 'proj' }, 'sess', 4).cwd).toBeUndefined();
    expect(canonicalContextForLine({ cwd: '' }, 'sess', 4).cwd).toBeUndefined();
    expect(canonicalContextForLine({ cwd: 42 }, 'sess', 4).cwd).toBeUndefined();
  });

  // POSIX only: the file checks join and match paths on `/`, and the gate's
  // own context (src/policy/file-access.ts) passes os.homedir() the same raw
  // way, so on Windows neither side matches `C:\Users\x/.bashrc`.
  it.skipIf(process.platform === 'win32')(
    'lets the file checks see an Edit of the shell startup file by its absolute path',
    () => {
      const ctx = canonicalContextForLine({ cwd: '/work/proj' }, 'sess', 4);
      const out = extractCanonicalFindings(
        {
          toolName: 'Edit',
          args: { file_path: `${os.homedir()}/.bashrc`, old_string: 'a', new_string: 'b' },
          timestamp: '2026-10-30T10:00:00Z',
        },
        ctx
      );
      const f = out.find((x) => x.type === 'file-access');
      expect(f?.ruleName).toBe('review-shell-startup-mutation');
      expect(f?.checkId).toBe('files.shell-startup');
    }
  );

  it('resolves a relative file_path against the line cwd', () => {
    const ctx = canonicalContextForLine({ cwd: `${os.homedir()}/proj` }, 'sess', 4);
    const out = extractCanonicalFindings(
      {
        toolName: 'Write',
        args: { file_path: '../.zshrc', content: 'x' },
        timestamp: '2026-10-30T10:00:00Z',
      },
      ctx
    );
    expect(out.find((x) => x.type === 'file-access')?.ruleName).toBe(
      'review-shell-startup-mutation'
    );
  });
});
