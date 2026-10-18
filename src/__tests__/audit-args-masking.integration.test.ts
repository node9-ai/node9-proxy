/**
 * Integration cover for personal-data masking in audit.log (second code review
 * of the fw#318 fixes, finding 4). CLAUDE.md requires an integration test for
 * anything that writes audit.log; the unit spec spies on fs, this runs the
 * real built CLI (`node9 log`, the PostToolUse hook that writes the row of
 * every executed call; dist/cli.js) under an isolated HOME and reads
 * the row back from disk.
 *
 * With auditHashArgs off the row carries the arguments. A card and an IBAN
 * that begin a line inside written content (finding 1) and a card after
 * "1." (finding 2) must reach the file masked, and the row must stay valid
 * JSON. The PII gate is off so the row is the call's own, not a PII row. Card and IBAN values are assembled at run time.
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const CARD = ['4242', '4242', '4242', '4242'].join('');

/** ISO 13616 check digits for a country and BBAN. */
function ibanOf(country: string, bban: string): string {
  const digits = [...`${bban}${country}00`].map((c) => parseInt(c, 36).toString()).join('');
  let rem = 0;
  for (const d of digits) rem = (rem * 10 + Number(d)) % 97;
  return `${country}${String(98 - rem).padStart(2, '0')}${bban}`;
}
const IBAN = ibanOf('GB', 'NODE' + '000000' + '12345678');

let home: string;

beforeAll(() => {
  if (!fs.existsSync(CLI)) throw new Error(`dist/cli.js not found at ${CLI}: run npm run build`);
});

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-audit-mask-'));
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  fs.writeFileSync(
    path.join(home, '.node9', 'config.json'),
    JSON.stringify({
      settings: {
        mode: 'audit',
        auditHashArgs: false,
        autoStartDaemon: false,
        approvers: { native: false, browser: false, cloud: false, terminal: false },
      },
      policy: { dlp: { enabled: true, pii: 'off', scanIgnoredTools: false } },
    })
  );
});

afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

function runLog(payload: object) {
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, USERPROFILE: home };
  delete env.NODE9_API_KEY;
  delete env.NODE9_API_URL;
  return spawnSync(process.execPath, [CLI, 'log'], {
    encoding: 'utf-8',
    input: JSON.stringify(payload),
    timeout: 60000,
    cwd: home,
    env: { ...env, NODE9_NO_AUTO_DAEMON: '1', NODE9_TESTING: '1' },
  });
}

describe('audit.log arguments are masked on disk (node9 log)', () => {
  it('a card and an IBAN that begin a line, and a card after "1.", are masked', () => {
    const content = ['name,card', 'alice,x', CARD, 'bob', IBAN, `ref 1.${CARD}`, ''].join('\n');
    const r = runLog({
      hook_event_name: 'PostToolUse',
      session_id: 'audit-mask-1',
      cwd: home,
      tool_name: 'Write',
      tool_input: { file_path: path.join(home, 'out.csv'), content },
      tool_response: { type: 'create', filePath: path.join(home, 'out.csv') },
    });
    expect(r.error).toBeUndefined();
    expect(r.status).toBe(0);

    const text = fs.readFileSync(path.join(home, '.node9', 'audit.log'), 'utf-8');
    expect(text).not.toContain(CARD);
    expect(text).not.toContain(IBAN);
    const rows = text
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l) as { tool: string; args?: { content?: string } });
    const row = rows.find((x) => x.tool === 'Write' && typeof x.args?.content === 'string');
    expect(row).toBeDefined();
    expect(row!.args!.content).toBe(
      [
        'name,card',
        'alice,x',
        '**** **** **** 4242',
        'bob',
        `${IBAN.slice(0, 4)} **** **** ${IBAN.slice(-4)}`,
        'ref 1.**** **** **** 4242',
        '',
      ].join('\n')
    );
  });
});
