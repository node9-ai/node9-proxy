// fw#406 review: Ctrl-C during a scan flushes the cache index, so the next run
// reuses what the interrupted one judged. Runs the built CLI as a subprocess.
import { describe, it, expect } from 'vitest';
import { spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

describe.skipIf(!fs.existsSync(CLI) || process.platform === 'win32')('scan interrupt', () => {
  it('SIGINT mid-scan exits 130 and leaves a usable index', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-int-'));
    const proj = path.join(home, '.claude', 'projects', '-tmp-proj');
    fs.mkdirSync(proj, { recursive: true });
    const now = Date.now();
    // Enough files that the scan is still running when the signal arrives.
    for (let i = 0; i < 400; i++) {
      const lines = Array.from({ length: 30 }, (_, k) =>
        JSON.stringify({
          type: 'assistant',
          timestamp: new Date(now - 3600_000 + k * 1000).toISOString(),
          message: {
            content: [
              {
                type: 'tool_use',
                id: `u${i}-${k}`,
                name: 'Bash',
                input: { command: `ls dir${i}/${k}` },
              },
            ],
          },
        })
      );
      fs.writeFileSync(path.join(proj, `s${i}.jsonl`), lines.join('\n') + '\n');
    }
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      HOME: home,
      TMPDIR: home,
      NODE9_NO_AUTO_DAEMON: '1',
      NODE9_TESTING: '1',
    };
    const child = spawn(process.execPath, [CLI, 'scan', '--json', '--days', '2'], { env });
    const index = path.join(home, '.node9', 'scan-cache', 'index.json');
    await new Promise<void>((resolve) => {
      const t = setInterval(() => {
        if (fs.existsSync(index)) {
          clearInterval(t);
          resolve();
        }
      }, 50);
    });
    child.kill('SIGINT');
    const code = await new Promise<number | null>((resolve) => child.on('exit', (c) => resolve(c)));
    expect(code).toBe(130);
    const idx = JSON.parse(fs.readFileSync(index, 'utf8')) as { files: Record<string, unknown> };
    expect(Object.keys(idx.files).length).toBeGreaterThanOrEqual(25);
    fs.rmSync(home, { recursive: true, force: true });
  }, 120_000);
});
