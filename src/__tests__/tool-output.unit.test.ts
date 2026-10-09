// collectToolOutputText / shellOutputText (src/tool-output.ts): the text a tool
// returned, read from whatever shape the agent sent. Shapes come from the REAL
// captures in fixtures/post-tool-inputs/, never hand-written.
import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { collectToolOutputText, shellOutputText } from '../tool-output';

const FX = path.join(__dirname, 'fixtures', 'post-tool-inputs');
const fixture = (name: string) =>
  JSON.parse(fs.readFileSync(path.join(FX, name), 'utf8')) as { tool_response: unknown };

describe('collectToolOutputText', () => {
  it('Claude Code Bash: stdout then stderr', () => {
    const tr = fixture('claude-bash.json').tool_response as Record<string, unknown>;
    const r = collectToolOutputText({ ...tr, stdout: 'out-line', stderr: 'err-line' });
    expect(r.text).toBe('out-line\nerr-line');
    expect(r.truncated).toBe(false);
  });
  it('Claude Code Read: the file content is in the text', () => {
    const r = collectToolOutputText(fixture('claude-read.json').tool_response);
    expect(r.text).toContain('line one\noriginal-file-text-7781');
    expect(r.text).toContain('/home/user/node9/sample.txt'); // a path leaf is harmless noise
  });
  it('the shims’ { output } and a bare string still work', () => {
    expect(collectToolOutputText({ output: 'hello' }).text).toBe('hello');
    expect(collectToolOutputText('hello').text).toBe('hello');
  });
  it('an MCP-style result: every content[].text, in order', () => {
    const r = collectToolOutputText({
      content: [
        { type: 'text', text: 'first' },
        { type: 'image', data: 'AAAA', mimeType: 'image/png' },
        { type: 'text', text: 'second' },
      ],
      isError: false,
    });
    // Type tags are string leaves too: harmless noise the scanners ignore.
    expect(r.text.split('\n')).toEqual([
      'text',
      'first',
      'image',
      'AAAA',
      'image/png',
      'text',
      'second',
    ]);
  });
  it('nothing: null, undefined, numbers, empty strings', () => {
    for (const v of [null, undefined, 7, '', { a: 1, b: [true] }]) {
      expect(collectToolOutputText(v)).toEqual({ text: '', truncated: false, fields: 0 });
    }
  });
  it('bound: a leaf past the cap is cut and the result says so; two leaves under it are kept', () => {
    const big = collectToolOutputText({ stdout: 'x'.repeat(300_000) });
    expect(big.text.length).toBe(100_000);
    expect(big.truncated).toBe(true);
    const two = collectToolOutputText({ stdout: 'a'.repeat(60_000), stderr: 'b'.repeat(30_000) });
    expect(two.truncated).toBe(false);
    expect(two.text.length).toBe(90_001);
    // A leaf the bound dropped entirely is not a contributing field.
    const dropped = collectToolOutputText({ a: 'x'.repeat(100_000), b: 'never' });
    expect(dropped.fields).toBe(1);
    expect(dropped.truncated).toBe(true);
  });
  it('depth cap: a leaf nested deeper than 8 levels is skipped, not crashed on', () => {
    let v: unknown = 'deep';
    for (let i = 0; i < 12; i++) v = { v };
    expect(collectToolOutputText(v).text).toBe('');
    expect(collectToolOutputText({ a: { b: 'near' } }).text).toBe('near');
  });
});

describe('shellOutputText', () => {
  it('Claude Code Bash: stdout and stderr joined', () => {
    const tr = fixture('claude-bash.json').tool_response as Record<string, unknown>;
    expect(shellOutputText({ ...tr, stdout: '3 passed', stderr: '' })).toBe('3 passed\n');
  });
  it('any other shape: every leaf', () => {
    expect(shellOutputText({ output: '3 passed' })).toBe('3 passed');
    expect(shellOutputText('3 passed')).toBe('3 passed');
  });
});
