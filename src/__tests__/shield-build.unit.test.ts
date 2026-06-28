// Pure builder for `node9 shield create` — turns inline flags into a
// ShieldDefinition. No I/O. The path-rule generator (pathRules) is the exact
// primitive `jail add` will reuse.

import { describe, it, expect } from 'vitest';
import safeRegex from 'safe-regex2';
import { toolRule, pathRules, buildShield } from '../shields/build';
import { validateShieldDefinition } from '@node9/policy-engine';

describe('toolRule', () => {
  it('blocks/reviews a whole tool via empty conditions (match-all)', () => {
    const r = toolRule('send_email', 'review');
    expect(r.tool).toBe('send_email');
    expect(r.conditions).toEqual([]); // empty conditions ⇒ evaluateSmartConditions returns true
    expect(r.verdict).toBe('review');
    expect(r.reason).toBeTruthy();
    expect(r.name).toMatch(/review/);
  });

  it('slugs odd tool names into the rule name', () => {
    const r = toolRule('mcp__gmail__send_email', 'block');
    expect(r.name).toBe('block-mcp-gmail-send-email');
  });
});

describe('pathRules', () => {
  it('emits two rules — bash command + any-tool file_path — for one path', () => {
    const rules = pathRules('~/.gmail-mcp', 'block');
    expect(rules).toHaveLength(2);
    const bash = rules.find((r) => r.tool === 'bash')!;
    const anytool = rules.find((r) => r.tool === '*')!;
    expect(bash.conditions[0].field).toBe('command');
    expect(anytool.conditions[0].field).toBe('file_path');
    for (const r of rules) {
      expect(r.verdict).toBe('block');
      expect(r.conditions[0].op).toBe('matches');
    }
  });

  it('the generated regex matches the path but not look-alikes, and is ReDoS-safe', () => {
    const [bash] = pathRules('~/.gmail-mcp', 'block');
    const pattern = bash.conditions[0].value!;
    expect(safeRegex(pattern)).toBe(true);
    const re = new RegExp(pattern);
    expect(re.test('cat ~/.gmail-mcp/credentials.json')).toBe(true);
    expect(re.test('/home/nadav/.gmail-mcp/creds')).toBe(true);
    expect(re.test('cat ~/.gmail-mcp')).toBe(true); // the dir itself
    expect(re.test('cat ~/.gmail-mcphost/x')).toBe(false); // not a prefix match
    expect(re.test('echo gmailmcp')).toBe(false);
  });

  it('handles a multi-segment path', () => {
    const [bash] = pathRules('~/.aws/credentials', 'review');
    const re = new RegExp(bash.conditions[0].value!);
    expect(re.test('cat ~/.aws/credentials')).toBe(true);
    expect(re.test('cat /home/u/.aws/credentials')).toBe(true);
    expect(re.test('cat ~/.aws/config')).toBe(false);
  });
});

describe('buildShield', () => {
  it('assembles a complete, valid ShieldDefinition from inline inputs', () => {
    const def = buildShield({
      name: 'my-gmail',
      description: 'Protect Gmail MCP creds + gate sends',
      blockPaths: ['~/.gmail-mcp'],
      reviewTools: ['send_email'],
    });
    expect(def.name).toBe('my-gmail');
    expect(def.aliases).toEqual([]);
    expect(def.dangerousWords).toEqual([]);
    // 2 path rules + 1 tool rule
    expect(def.smartRules).toHaveLength(3);
    // must pass the engine validator (what installShield runs)
    const v = validateShieldDefinition(def);
    expect('ok' in v).toBe(true);
  });

  it('defaults a description when none is given', () => {
    const def = buildShield({ name: 'x', blockTools: ['rm'] });
    expect(typeof def.description).toBe('string');
    expect(def.description.length).toBeGreaterThan(0);
  });

  it('produces no rules when no tools/paths are supplied (caller rejects that)', () => {
    const def = buildShield({ name: 'empty' });
    expect(def.smartRules).toEqual([]);
  });
});
