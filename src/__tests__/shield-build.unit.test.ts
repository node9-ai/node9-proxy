// Pure builder for `node9 shield create` — turns inline flags into a
// ShieldDefinition. No I/O. The path-rule generator (pathRules) is the exact
// primitive `jail add` will reuse.

import { describe, it, expect } from 'vitest';
import safeRegex from 'safe-regex2';
import { toolRule, pathRules, pathMatchesFragment, buildShield } from '../shields/build';
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
  it('emits four rules — bash command + any-tool file_path/path/pattern — for one path', () => {
    // Task #20: one rule per arg field the file tools actually send. The
    // engine resolves condition fields by exact name (missing = fail), so a
    // lone file_path rule can never match Grep {pattern, path} or Glob
    // {pattern} — that gap made the jail engine-invisible to file tools.
    const rules = pathRules('~/.gmail-mcp', 'block');
    expect(rules).toHaveLength(4);
    const bash = rules.find((r) => r.tool === 'bash')!;
    expect(bash.conditions[0].field).toBe('command');
    const anytoolFields = rules.filter((r) => r.tool === '*').map((r) => r.conditions[0].field);
    expect(anytoolFields.sort()).toEqual(['file_path', 'path', 'pattern']);
    // The historical `-anytool` name stays on the file_path rule — the
    // rule→shield attribution maps key on rule names.
    expect(rules.find((r) => r.conditions[0].field === 'file_path')!.name).toBe(
      'block-path-gmail-mcp-anytool'
    );
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

describe('pathMatchesFragment (task #20 — the guard-side half of the one matcher)', () => {
  it('agrees with the shield rule regex on hits and misses', () => {
    // tilde-stored path vs absolute candidate — the exact prod shape
    expect(pathMatchesFragment('/home/u/.gmail-mcp/creds.json', '~/.gmail-mcp')).toBe(true);
    expect(pathMatchesFragment('/tmp/x/.secrets/key.txt', '/tmp/x/.secrets')).toBe(true);
    // the dir itself and a glob over it (Glob {pattern: '<dir>/*'})
    expect(pathMatchesFragment('/tmp/x/.secrets', '/tmp/x/.secrets')).toBe(true);
    expect(pathMatchesFragment('/tmp/x/.secrets/*', '/tmp/x/.secrets')).toBe(true);
    // no prefix-matching, no substring noise
    expect(pathMatchesFragment('/home/u/.gmail-mcphost/x', '~/.gmail-mcp')).toBe(false);
    expect(pathMatchesFragment('/tmp/other/file.txt', '/tmp/x/.secrets')).toBe(false);
  });

  it('is false for empty candidate or a too-broad path (no usable fragment)', () => {
    expect(pathMatchesFragment('', '~/.gmail-mcp')).toBe(false);
    expect(pathMatchesFragment('/anything', '~')).toBe(false);
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
    // 4 path rules (bash + file_path/path/pattern, task #20) + 1 tool rule
    expect(def.smartRules).toHaveLength(5);
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
