/**
 * Unit test: every node9 MCP tool is explicitly classified in TOOL_CAPABILITY.
 * An unclassified tool would default to 'readonly' and BYPASS the weakening gate —
 * this test fails the build instead, forcing a conscious classification when a new
 * tool is added (closes the fail-open-for-unclassified gap).
 */
import { describe, it, expect } from 'vitest';
import { TOOLS, TOOL_CAPABILITY } from '../mcp-server';

describe('MCP tool capability classification', () => {
  it('every tool in TOOLS is explicitly classified in TOOL_CAPABILITY', () => {
    const unclassified = TOOLS.map((t) => t.name).filter((name) => !(name in TOOL_CAPABILITY));
    expect(unclassified).toEqual([]);
  });

  it('no TOOL_CAPABILITY entry references a tool that no longer exists', () => {
    const toolNames = new Set(TOOLS.map((t) => t.name));
    const orphans = Object.keys(TOOL_CAPABILITY).filter((name) => !toolNames.has(name));
    expect(orphans).toEqual([]);
  });

  it('the weakening tools are exactly shield_disable + approver_set', () => {
    const weaken = Object.entries(TOOL_CAPABILITY)
      .filter(([, cap]) => cap === 'weaken')
      .map(([name]) => name)
      .sort();
    expect(weaken).toEqual(['node9_approver_set', 'node9_shield_disable']);
  });
});
