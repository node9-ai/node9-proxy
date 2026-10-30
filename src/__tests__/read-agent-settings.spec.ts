// readAgentSettings: the settings file as it is on disk, for the hooks
// comparison of files.agent-instructions (node9Firewall#413 part 4). Type and
// size come from the open descriptor (CodeQL js/file-system-race), and a FIFO
// at the path must not hang the gate.
import { describe, it, expect, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { readAgentSettings } from '../policy';

describe('readAgentSettings', () => {
  const dirs: string[] = [];
  const tmp = (): string => {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-settings-'));
    dirs.push(d);
    return d;
  };
  afterEach(() => {
    for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  });

  it('returns a regular file as text', () => {
    const f = path.join(tmp(), 'settings.json');
    fs.writeFileSync(f, '{"hooks":{}}');
    expect(readAgentSettings(f)).toBe('{"hooks":{}}');
  });

  it('returns null for a missing path, a directory, and a file over the cap', () => {
    const d = tmp();
    expect(readAgentSettings(path.join(d, 'absent.json'))).toBeNull();
    expect(readAgentSettings(d)).toBeNull();
    const big = path.join(d, 'big.json');
    fs.writeFileSync(big, 'x'.repeat(256 * 1024 + 1));
    expect(readAgentSettings(big)).toBeNull();
    const atCap = path.join(d, 'cap.json');
    fs.writeFileSync(atCap, 'x'.repeat(256 * 1024));
    expect(readAgentSettings(atCap)).toHaveLength(256 * 1024);
  });

  it.skipIf(process.platform === 'win32')(
    'returns null for a FIFO at the path, without blocking on open',
    () => {
      const fifo = path.join(tmp(), 'settings.json');
      const mk = spawnSync('mkfifo', [fifo]);
      expect(mk.error).toBeUndefined();
      expect(mk.status).toBe(0);
      const start = Date.now();
      expect(readAgentSettings(fifo)).toBeNull();
      expect(Date.now() - start).toBeLessThan(2000);
    },
    10000
  );
});
