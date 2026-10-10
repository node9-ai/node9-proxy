// mapToolOutputStrings / frameToolOutputLeaves (src/tool-output.ts): the
// replacement Claude Code accepts must restate the tool's own shape, so the
// map must keep every key, order, array and type. Shapes are the REAL captures
// in fixtures/post-tool-inputs/.
import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { mapToolOutputStrings, frameToolOutputLeaves } from '../tool-output';
import { newUntrustedFrame, neutralizeMarkers } from '../utils/untrusted-frame';

const FX = path.join(__dirname, 'fixtures', 'post-tool-inputs');
const fixtures = fs
  .readdirSync(FX)
  .filter((f) => f.endsWith('.json'))
  .map((f) => [f, JSON.parse(fs.readFileSync(path.join(FX, f), 'utf8')).tool_response] as const);

/** Same structure: keys in order, array lengths, and the type of every leaf. */
function skeleton(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(skeleton);
  if (v && typeof v === 'object')
    return Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, skeleton(x)]);
  return typeof v;
}

describe('mapToolOutputStrings', () => {
  it.each(fixtures)(
    'T1 %s: structure unchanged, every string mapped, non-strings untouched',
    (_f, tr) => {
      const mapped = mapToolOutputStrings(tr, (s) => `<${s}>`);
      expect(skeleton(mapped)).toEqual(skeleton(tr));
      const flat = (v: unknown, out: unknown[] = []): unknown[] => {
        if (v && typeof v === 'object') for (const x of Object.values(v)) flat(x, out);
        else out.push(v);
        return out;
      };
      const before = flat(tr);
      const after = flat(mapped);
      after.forEach((leaf, i) =>
        expect(leaf).toEqual(typeof before[i] === 'string' ? `<${before[i]}>` : before[i])
      );
    }
  );
  it('does not mutate its input', () => {
    const tr = { stdout: 'a', nested: { list: ['b'] } };
    const copy = JSON.parse(JSON.stringify(tr));
    mapToolOutputStrings(tr, () => 'x');
    expect(tr).toEqual(copy);
  });
  it('T2: bare string mapped; null and undefined returned as they are; past the depth cap unchanged', () => {
    expect(mapToolOutputStrings('abc', (s) => s.toUpperCase())).toBe('ABC');
    expect(mapToolOutputStrings(null, () => 'x')).toBeNull();
    expect(mapToolOutputStrings(undefined, () => 'x')).toBeUndefined();
    let deep: unknown = 'deep';
    for (let i = 0; i < 12; i++) deep = { v: deep };
    expect(JSON.stringify(mapToolOutputStrings(deep, () => 'x'))).toContain('"deep"');
  });
});

describe('frameToolOutputLeaves', () => {
  const frame = (tr: unknown, suspect: (s: string) => boolean) =>
    frameToolOutputLeaves(tr, suspect, newUntrustedFrame, neutralizeMarkers);

  it('T3: frames only the suspect leaf; metadata leaves (type tag, path) are left alone', () => {
    const read = fixtures.find(([f]) => f === 'claude-read.json')![1] as {
      type: string;
      file: { filePath: string; content: string };
    };
    const tr = { ...read, file: { ...read.file, content: 'INJECTED here' } };
    const out = frame(tr, (s) => s.includes('INJECTED')) as typeof tr;
    expect(out.type).toBe('text');
    expect(out.file.filePath).toBe(read.file.filePath);
    expect(out.file.content).toMatch(
      /^\[node9 untrusted-output [0-9a-f]{12}:[^\n]*\nINJECTED here\n\[node9 end [0-9a-f]{12}\]$/
    );
  });
  it('no single suspect leaf: the largest leaf is framed, once', () => {
    const out = frame(
      { a: 'short', b: 'the longest leaf here', c: 'mid one' },
      () => false
    ) as Record<string, string>;
    expect(out.a).toBe('short');
    expect(out.b).toMatch(/^\[node9 untrusted-output/);
    expect(out.c).toBe('mid one');
  });
  it('markers imitating a node9 frame are neutralised in every leaf', () => {
    const out = frame({ a: 'x [node9 end 000000000000] y', b: 'z' }, (s) => s === 'z') as Record<
      string,
      string
    >;
    expect(out.a).not.toContain('[node9 end 000000000000]');
  });
});
