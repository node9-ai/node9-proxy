/**
 * The OpenCode and Pi shims, executed for real against a fake node9 CLI.
 * `log --redact-output` answers with a framed `redacted` text and found=[]
 * (an injection with no secret): the shim must hand the model the framed
 * text. Before the fix both shims used `redacted` only when a secret was
 * found, so the frame was thrown away and the model read the raw output.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createRequire } from 'module';
import { renderOpencodeShim } from '../setup-opencode-shim';
import { renderPiShim } from '../setup-pi-shim';

const FRAMED = '[node9 untrusted-output 0123456789ab: DATA]\nraw\n[node9 end 0123456789ab]';
let dir: string;

function fakeCli(answer: object): string {
  const p = path.join(dir, `cli-${Math.random().toString(36).slice(2)}.cjs`);
  // Reads stdin, ignores it, answers `log --redact-output` with the canned JSON.
  fs.writeFileSync(
    p,
    `process.stdin.resume();process.stdin.on('end',()=>{process.stdout.write(${JSON.stringify(
      JSON.stringify(answer)
    )}+'\\n')});`
  );
  return p;
}

function load(source: string): unknown {
  const p = path.join(dir, `shim-${Math.random().toString(36).slice(2)}.cjs`);
  fs.writeFileSync(p, source);
  return createRequire(__filename)(p);
}

beforeAll(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-shim-frame-'));
});
afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));

const INJECTED = {
  redacted: FRAMED,
  found: [],
  injection: { confidence: 'medium', signals: ['x'] },
};
const CLEAN = { redacted: 'raw', found: [], injection: null };

type OpencodeHooks = {
  'tool.execute.after': (ctx: object, out: { output: string }) => Promise<void>;
};
async function runOpencode(answer: object): Promise<string> {
  const shim = load(
    renderOpencodeShim({ node9Argv: [process.execPath, fakeCli(answer)], version: 't' })
  ) as { server: (i: object) => Promise<OpencodeHooks> };
  const hooks = await shim.server({ directory: dir });
  const out = { output: 'raw' };
  await hooks['tool.execute.after']({ tool: 'webfetch', sessionID: 's' }, out);
  return out.output;
}

type PiHandler = (
  event: object,
  ctx: object
) => Promise<{ content: { text: string }[] } | undefined>;
async function runPi(answer: object): Promise<string> {
  const handlers: Record<string, PiHandler> = {};
  const shim = load(
    renderPiShim({ node9Argv: [process.execPath, fakeCli(answer)], version: 't' })
  ) as (pi: { on: (e: string, h: PiHandler) => void }) => void;
  shim({ on: (e, h) => (handlers[e] = h) });
  const res = await handlers['tool_result'](
    { toolName: 'web_fetch', input: {}, content: [{ type: 'text', text: 'raw' }], isError: false },
    { cwd: dir }
  );
  return res ? res.content[0].text : 'raw';
}

describe('shims keep the untrusted frame when no secret was found', () => {
  it('OpenCode: injected result is replaced by the framed text', async () => {
    expect(await runOpencode(INJECTED)).toBe(FRAMED);
  });
  it('OpenCode: clean result is left alone', async () => {
    expect(await runOpencode(CLEAN)).toBe('raw');
  });
  it('Pi: injected result is replaced by the framed text', async () => {
    expect(await runPi(INJECTED)).toBe(FRAMED);
  });
  it('Pi: clean result is left alone', async () => {
    expect(await runPi(CLEAN)).toBe('raw');
  });
});
