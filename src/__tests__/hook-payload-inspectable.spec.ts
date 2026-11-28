// node9Firewall#383, step 0: shapes of tool arguments that made node9's own
// code throw, so the before-run hook let the call run.
import { describe, it, expect } from 'vitest';
import { extractToolName, inspectablePayload, MAX_PAYLOAD_DEPTH } from '../utils/hook-payload';

/** JSON text nested `n` objects deep around a leaf, parsed. */
function deepObject(n: number, leaf: string): unknown {
  return JSON.parse('{"a":'.repeat(n) + JSON.stringify(leaf) + '}'.repeat(n));
}

/** Depth of the deepest value in a tree, without recursion. */
function depthOf(root: unknown): number {
  let max = 0;
  const stack: [unknown, number][] = [[root, 0]];
  while (stack.length > 0) {
    const [v, d] = stack.pop()!;
    if (d > max) max = d;
    if (v !== null && typeof v === 'object')
      for (const child of Object.values(v)) stack.push([child, d + 1]);
  }
  return max;
}

describe('inspectablePayload', () => {
  it('leaves an ordinary payload as it is', () => {
    const payload = {
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'ls', env: { A: '1' }, list: [1, 'two', null, true] },
    };
    expect(inspectablePayload(JSON.parse(JSON.stringify(payload)))).toEqual(payload);
  });

  it('bounds the depth and keeps every leaf of the subtree it folds', () => {
    const parsed = {
      tool_name: 'mcp__db__query',
      tool_input: { sql: 'drop table users', extra: deepObject(5000, 'needle-value') },
    };
    const safe = inspectablePayload(parsed);
    expect(depthOf(safe)).toBeLessThanOrEqual(MAX_PAYLOAD_DEPTH);
    // The value the model put at the bottom is still there to be scanned.
    expect(JSON.stringify(safe)).toContain('needle-value');
    expect((safe.tool_input as { sql: string }).sql).toBe('drop table users');
  });

  it('folds a million nested arrays without overflowing the stack', () => {
    const parsed = {
      tool_input: JSON.parse('['.repeat(1_000_000) + '"x"' + ']'.repeat(1_000_000)),
    };
    const safe = inspectablePayload(parsed);
    expect(depthOf(safe)).toBeLessThanOrEqual(MAX_PAYLOAD_DEPTH);
  });

  it('makes an object with its own toString or valueOf safe to coerce', () => {
    const parsed = JSON.parse(
      '{"tool_input":{"command":"rm -rf ~/","file_path":{"toString":1,"valueOf":"x","kept":"v"}}}'
    );
    const safe = inspectablePayload(parsed);
    const filePath = (safe.tool_input as { file_path: Record<string, unknown> }).file_path;
    expect(() => String(filePath)).not.toThrow();
    // Renamed, not dropped: the values are still inspected.
    expect(filePath).toEqual({ toString_: 1, valueOf_: 'x', kept: 'v' });
  });

  it('never lets a renamed key overwrite a key the payload already has', () => {
    const parsed = JSON.parse('{"tool_input":{"toString":"a","toString_":"b"}}');
    const input = inspectablePayload(parsed).tool_input as Record<string, unknown>;
    expect(Object.values(input).sort()).toEqual(['a', 'b']);
    expect(() => String(input)).not.toThrow();
  });

  it('keeps a __proto__ key as a key, not as the prototype', () => {
    const parsed = JSON.parse('{"tool_input":{"__proto__":{"polluted":"yes"},"command":"ls"}}');
    const input = inspectablePayload(parsed).tool_input as Record<string, unknown>;
    expect(Object.keys(input)).toContain('__proto__');
    expect((input as { polluted?: string }).polluted).toBeUndefined();
    expect(({} as { polluted?: string }).polluted).toBeUndefined();
  });

  it.each([null, 5, 'text', true, [1, 2]])('reads a payload that is %j as an empty one', (v) => {
    expect(inspectablePayload(v)).toEqual({});
  });
});

describe('extractToolName', () => {
  it.each([5, true, { a: 1 }, ['Bash'], null])('ignores a tool name that is %j', (name) => {
    expect(extractToolName({ tool_name: name as unknown as string })).toBe('');
  });

  it('falls through a non-string name to the next dialect', () => {
    expect(
      extractToolName({ tool_name: 7 as unknown as string, toolCall: { name: 'run_command' } })
    ).toBe('run_command');
  });
});
