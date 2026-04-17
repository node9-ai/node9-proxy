// src/__tests__/sessions.spec.ts
// Unit tests for the sessions command parser functions.
// Uses in-memory fixture data — no fs mocking needed for the pure functions.

import { describe, it, expect } from 'vitest';
import {
  encodeProjectPath,
  parseHistoryLines,
  parseSessionLines,
  auditEntriesInWindow,
} from '../cli/commands/sessions.js';

// ---------------------------------------------------------------------------
// encodeProjectPath
// ---------------------------------------------------------------------------

describe('encodeProjectPath', () => {
  it('converts leading slash to dash', () => {
    expect(encodeProjectPath('/home/user/project')).toBe('-home-user-project');
  });

  it('handles nested paths', () => {
    expect(encodeProjectPath('/home/nadav/node9/node9-proxy')).toBe(
      '-home-nadav-node9-node9-proxy'
    );
  });

  it('handles root path', () => {
    expect(encodeProjectPath('/')).toBe('-');
  });
});

// ---------------------------------------------------------------------------
// parseHistoryLines
// ---------------------------------------------------------------------------

describe('parseHistoryLines', () => {
  it('parses valid entries', () => {
    const lines = [
      JSON.stringify({
        display: 'fix the bug',
        timestamp: '2026-04-17T10:32:00.000Z',
        project: '/home/nadav/node9',
        sessionId: 'abc-123',
      }),
      JSON.stringify({
        display: 'add tests',
        timestamp: '2026-04-16T09:00:00.000Z',
        project: '/home/nadav/node9',
        sessionId: 'def-456',
      }),
    ];

    const result = parseHistoryLines(lines);
    expect(result).toHaveLength(2);
    expect(result[0].display).toBe('fix the bug');
    expect(result[0].sessionId).toBe('abc-123');
    expect(result[1].sessionId).toBe('def-456');
  });

  it('skips blank lines', () => {
    const lines = [
      '',
      '   ',
      JSON.stringify({ display: 'hi', timestamp: 't', project: '/p', sessionId: 's1' }),
    ];
    expect(parseHistoryLines(lines)).toHaveLength(1);
  });

  it('skips malformed JSON', () => {
    const lines = [
      '{bad json',
      JSON.stringify({ display: 'ok', timestamp: 't', project: '/p', sessionId: 's1' }),
    ];
    expect(parseHistoryLines(lines)).toHaveLength(1);
  });

  it('skips entries missing required fields', () => {
    const lines = [
      JSON.stringify({ display: 'no project', timestamp: 't', sessionId: 's1' }), // missing project
      JSON.stringify({ display: 'full', timestamp: 't', project: '/p', sessionId: 's1' }),
    ];
    expect(parseHistoryLines(lines)).toHaveLength(1);
  });

  it('accepts numeric (Unix ms) timestamp from Claude Code', () => {
    const ms = 1775732878798;
    const lines = [
      JSON.stringify({ display: 'prompt', timestamp: ms, project: '/p', sessionId: 's1' }),
    ];
    const result = parseHistoryLines(lines);
    expect(result).toHaveLength(1);
    expect(result[0].timestamp).toBe(new Date(ms).toISOString());
  });

  it('returns empty array for empty input', () => {
    expect(parseHistoryLines([])).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// parseSessionLines
// ---------------------------------------------------------------------------

function makeAssistantLine(opts: {
  timestamp?: string;
  model?: string;
  toolCalls?: Array<{ name: string; input: Record<string, unknown> }>;
  usage?: {
    input_tokens?: number;
    output_tokens?: number;
    cache_creation_input_tokens?: number;
    cache_read_input_tokens?: number;
  };
}): string {
  return JSON.stringify({
    type: 'assistant',
    timestamp: opts.timestamp ?? '2026-04-17T10:32:00.000Z',
    message: {
      model: opts.model ?? 'claude-sonnet-4-6',
      content: (opts.toolCalls ?? []).map((tc) => ({
        type: 'tool_use',
        name: tc.name,
        input: tc.input,
      })),
      usage: opts.usage ?? { input_tokens: 100, output_tokens: 200 },
    },
  });
}

describe('parseSessionLines', () => {
  it('extracts tool calls from assistant entries', () => {
    const lines = [
      makeAssistantLine({
        toolCalls: [
          { name: 'Read', input: { file_path: '/src/foo.ts' } },
          { name: 'Bash', input: { command: 'npm test' } },
        ],
      }),
    ];

    const result = parseSessionLines(lines);
    expect(result.toolCalls).toHaveLength(2);
    expect(result.toolCalls[0].tool).toBe('Read');
    expect(result.toolCalls[0].input.file_path).toBe('/src/foo.ts');
    expect(result.toolCalls[1].tool).toBe('Bash');
  });

  it('accumulates cost for known model', () => {
    const lines = [
      makeAssistantLine({
        model: 'claude-sonnet-4-6',
        usage: { input_tokens: 1000, output_tokens: 500 },
        toolCalls: [],
      }),
    ];
    const result = parseSessionLines(lines);
    // 1000 * 3e-6 + 500 * 15e-6 = 0.003 + 0.0075 = 0.0105
    expect(result.costUSD).toBeCloseTo(0.0105, 6);
  });

  it('accumulates cost with cache tokens', () => {
    const lines = [
      makeAssistantLine({
        model: 'claude-sonnet-4-6',
        usage: {
          input_tokens: 0,
          output_tokens: 0,
          cache_creation_input_tokens: 1000,
          cache_read_input_tokens: 2000,
        },
        toolCalls: [],
      }),
    ];
    const result = parseSessionLines(lines);
    // 1000 * 3.75e-6 + 2000 * 0.3e-6 = 0.00375 + 0.0006 = 0.00435
    expect(result.costUSD).toBeCloseTo(0.00435, 6);
  });

  it('returns zero cost for unknown model', () => {
    const lines = [
      makeAssistantLine({
        model: 'gpt-99-ultra',
        usage: { input_tokens: 9999, output_tokens: 9999 },
        toolCalls: [],
      }),
    ];
    expect(parseSessionLines(lines).costUSD).toBe(0);
  });

  it('detects snapshot entry', () => {
    const lines = [
      JSON.stringify({ type: 'file-history-snapshot', timestamp: '2026-04-17T10:34:00.000Z' }),
    ];
    const result = parseSessionLines(lines);
    expect(result.hasSnapshot).toBe(true);
  });

  it('hasSnapshot is false when no snapshot entry', () => {
    const lines = [makeAssistantLine({ toolCalls: [] })];
    expect(parseSessionLines(lines).hasSnapshot).toBe(false);
  });

  it('collects modified files from Write and Edit tools', () => {
    const lines = [
      makeAssistantLine({
        toolCalls: [
          { name: 'Write', input: { file_path: '/src/foo.ts' } },
          { name: 'Edit', input: { file_path: '/src/bar.ts' } },
          { name: 'Read', input: { file_path: '/src/baz.ts' } }, // should not be in modifiedFiles
        ],
      }),
    ];
    const result = parseSessionLines(lines);
    expect(result.modifiedFiles).toContain('/src/foo.ts');
    expect(result.modifiedFiles).toContain('/src/bar.ts');
    expect(result.modifiedFiles).not.toContain('/src/baz.ts');
  });

  it('deduplicates modified files', () => {
    const lines = [
      makeAssistantLine({
        toolCalls: [
          { name: 'Edit', input: { file_path: '/src/foo.ts' } },
          { name: 'Edit', input: { file_path: '/src/foo.ts' } }, // same file twice
        ],
      }),
    ];
    const result = parseSessionLines(lines);
    expect(result.modifiedFiles.filter((f) => f === '/src/foo.ts')).toHaveLength(1);
  });

  it('accumulates across multiple assistant entries', () => {
    const lines = [
      makeAssistantLine({
        model: 'claude-sonnet-4-6',
        usage: { input_tokens: 100, output_tokens: 0 },
        toolCalls: [{ name: 'Read', input: { file_path: '/a.ts' } }],
      }),
      makeAssistantLine({
        model: 'claude-sonnet-4-6',
        usage: { input_tokens: 200, output_tokens: 0 },
        toolCalls: [{ name: 'Write', input: { file_path: '/b.ts' } }],
      }),
    ];
    const result = parseSessionLines(lines);
    expect(result.toolCalls).toHaveLength(2);
    // 300 * 3e-6 = 0.0009
    expect(result.costUSD).toBeCloseTo(0.0009, 6);
  });

  it('skips non-assistant entries for tool calls', () => {
    const lines = [
      JSON.stringify({
        type: 'user',
        timestamp: '2026-04-17T10:31:00.000Z',
        message: { role: 'user', content: [{ type: 'text', text: 'do something' }] },
      }),
      makeAssistantLine({ toolCalls: [{ name: 'Bash', input: { command: 'ls' } }] }),
    ];
    const result = parseSessionLines(lines);
    expect(result.toolCalls).toHaveLength(1);
    expect(result.toolCalls[0].tool).toBe('Bash');
  });

  it('handles empty input gracefully', () => {
    const result = parseSessionLines([]);
    expect(result.toolCalls).toHaveLength(0);
    expect(result.costUSD).toBe(0);
    expect(result.hasSnapshot).toBe(false);
    expect(result.modifiedFiles).toHaveLength(0);
  });

  it('skips malformed JSON lines', () => {
    const lines = [
      '{invalid',
      makeAssistantLine({ toolCalls: [{ name: 'Read', input: { file_path: '/x.ts' } }] }),
    ];
    const result = parseSessionLines(lines);
    expect(result.toolCalls).toHaveLength(1);
  });

  it('handles assistant entry with no content array', () => {
    const lines = [
      JSON.stringify({
        type: 'assistant',
        timestamp: '2026-04-17T10:32:00.000Z',
        message: { model: 'claude-sonnet-4-6' },
      }),
    ];
    const result = parseSessionLines(lines);
    expect(result.toolCalls).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// auditEntriesInWindow
// ---------------------------------------------------------------------------

function makeAuditEntry(opts: {
  ts: string;
  tool?: string;
  decision?: string;
  checkedBy?: string;
  args?: Record<string, unknown>;
  argsHash?: string;
}) {
  return {
    ts: opts.ts,
    tool: opts.tool ?? 'Bash',
    decision: opts.decision ?? 'deny',
    checkedBy: opts.checkedBy,
    args: opts.args,
    argsHash: opts.argsHash,
  };
}

describe('auditEntriesInWindow', () => {
  const entries = [
    makeAuditEntry({ ts: '2026-04-17T10:00:00.000Z', decision: 'deny', checkedBy: 'rule-a' }),
    makeAuditEntry({ ts: '2026-04-17T10:30:00.000Z', decision: 'block', checkedBy: 'rule-b' }),
    makeAuditEntry({ ts: '2026-04-17T11:00:00.000Z', decision: 'review', checkedBy: 'rule-c' }),
    makeAuditEntry({ ts: '2026-04-17T12:00:00.000Z', decision: 'deny', checkedBy: 'rule-d' }),
  ];

  it('returns entries within the window (inclusive)', () => {
    const result = auditEntriesInWindow(
      entries,
      '2026-04-17T10:00:00.000Z',
      '2026-04-17T11:00:00.000Z'
    );
    expect(result).toHaveLength(3);
    expect(result.map((e) => e.checkedBy)).toEqual(['rule-a', 'rule-b', 'rule-c']);
  });

  it('excludes entries outside the window', () => {
    const result = auditEntriesInWindow(
      entries,
      '2026-04-17T10:30:00.000Z',
      '2026-04-17T10:59:00.000Z'
    );
    expect(result).toHaveLength(1);
    expect(result[0].checkedBy).toBe('rule-b');
  });

  it('returns empty array when no entries match', () => {
    const result = auditEntriesInWindow(
      entries,
      '2026-04-17T13:00:00.000Z',
      '2026-04-17T14:00:00.000Z'
    );
    expect(result).toHaveLength(0);
  });

  it('preserves args when present', () => {
    const withArgs = [
      makeAuditEntry({
        ts: '2026-04-17T10:00:00.000Z',
        args: { command: 'git push origin main' },
      }),
    ];
    const result = auditEntriesInWindow(
      withArgs,
      '2026-04-17T09:00:00.000Z',
      '2026-04-17T11:00:00.000Z'
    );
    expect(result[0].args).toEqual({ command: 'git push origin main' });
  });

  it('preserves argsHash when args not present', () => {
    const hashOnly = [makeAuditEntry({ ts: '2026-04-17T10:00:00.000Z', argsHash: 'abc123' })];
    const result = auditEntriesInWindow(
      hashOnly,
      '2026-04-17T09:00:00.000Z',
      '2026-04-17T11:00:00.000Z'
    );
    expect(result[0].argsHash).toBe('abc123');
    expect(result[0].args).toBeUndefined();
  });

  it('returns empty array for empty input', () => {
    expect(
      auditEntriesInWindow([], '2026-04-17T10:00:00.000Z', '2026-04-17T11:00:00.000Z')
    ).toHaveLength(0);
  });
});
