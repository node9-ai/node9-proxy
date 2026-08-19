// Pure builder for `node9 shield create` — turns inline flags into a
// ShieldDefinition. No I/O. The path-rule generator (pathRules) is the exact
// primitive `jail add` will reuse.

import { describe, it, expect } from 'vitest';
import safeRegex from 'safe-regex2';
import { toolRule, pathRules, pathMatchesFragment, buildShield } from '../shields/build';
import { validateShieldDefinition, validateRegex } from '@node9/policy-engine';

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

// ── Windows paths (the 2026-08-19 CI red — a real product bug) ───────────────
// Root cause chain: pathToRegexFragment did not strip `C:\Users\<name>\`, so a
// Windows-profile path produced a >100-char fragment; the engine's
// MAX_REGEX_LENGTH cap made getCompiledRegex return null, which `matches` reads
// as NO MATCH — so `jail add` printed "reads now BLOCK" while the gate ALLOWED.
// Every row here asserts BOTH halves: the fragment survives engine validation,
// and it actually matches the shapes agents send.
describe('pathToRegexFragment — Windows shapes must survive the engine', () => {
  const WIN_USER = 'C:\\Users\\jonathan.smith\\AppData\\Roaming\\gmail-mcp\\credentials';
  const WIN_TEMP =
    'C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\node9-jail-gauntlet-Ab12Cd\\.secrets';

  it('a Windows profile path yields a fragment the ENGINE accepts (validateRegex null)', () => {
    for (const p of [WIN_USER, WIN_TEMP]) {
      const [rule] = pathRules(p, 'block');
      expect(rule, `no rules generated for ${p}`).toBeDefined();
      const frag = rule.conditions[0].value as string;
      // The engine is the arbiter: a fragment it rejects is a DEAD rule that
      // silently allows. This is the exact Windows-CI failure, pinned.
      expect(validateRegex(frag), `engine rejected fragment for ${p}`).toBeNull();
    }
  });

  it('strips the drive+profile prefix like it already strips /home and /Users', () => {
    const [rule] = pathRules(WIN_USER, 'block');
    const frag = rule.conditions[0].value as string;
    // Portable tail: must not pin the drive letter or the username…
    expect(frag).not.toContain('jonathan');
    expect(frag).not.toContain('C:');
    // …and must still pin the distinctive tail.
    expect(frag).toContain('gmail-mcp');
  });

  it('the fragment matches the candidate in BOTH slash forms', () => {
    for (const candidate of [
      'C:\\Users\\jonathan.smith\\AppData\\Roaming\\gmail-mcp\\credentials\\oauth.json',
      'C:/Users/jonathan.smith/AppData/Roaming/gmail-mcp/credentials/oauth.json',
    ]) {
      expect(pathMatchesFragment(candidate, WIN_USER), candidate).toBe(true);
    }
  });

  it('a jailed home path still matches when the agent writes it tilde-style', () => {
    // The strip exists so C:\Users\x\.aws and ~/.aws denote the same jail.
    expect(pathMatchesFragment('cat ~/AppData/Roaming/gmail-mcp/credentials', WIN_USER)).toBe(true);
  });

  it('does not over-strip: a non-profile drive path keeps its distinctive tail', () => {
    const [rule] = pathRules('D:\\data\\secrets', 'block');
    const frag = rule.conditions[0].value as string;
    expect(validateRegex(frag)).toBeNull();
    expect(pathMatchesFragment('type D:\\data\\secrets\\key.txt', 'D:\\data\\secrets')).toBe(true);
    // Precision: an unrelated path must not match.
    expect(pathMatchesFragment('type D:\\other\\file.txt', 'D:\\data\\secrets')).toBe(false);
  });

  it('a deep-but-legitimate path survives the engine cap (the 256 half of the fix)', () => {
    // The Windows-prefix strip alone fixes SHORT profile paths; this row exists
    // so the length-cap raise is load-bearing on its own: a stripped fragment
    // in the 100–256 range must be a LIVE rule, not a silent allow. Mutation
    // W-1 (cap back to 100) must turn exactly this row red.
    const deep = '~/work/acme/services/billing/config/credentials/gcp-service-accounts';
    const [rule] = pathRules(deep, 'block');
    const frag = rule.conditions[0].value as string;
    expect(frag.length).toBeGreaterThan(100); // guards the row itself from rotting
    expect(validateRegex(frag)).toBeNull();
    expect(
      pathMatchesFragment(
        '/home/u/work/acme/services/billing/config/credentials/gcp-service-accounts/key.json',
        deep
      )
    ).toBe(true);
  });

  it('AGREEMENT: the fast-path guard and the engine can never disagree', () => {
    // task #20 invariant, now for real: pathMatchesFragment must compile through
    // the SAME capped pipeline as the engine. A fragment the engine would
    // reject must therefore be a NO-match here too — never a guard-only match.
    const monster = 'C:\\Users\\u\\' + Array.from({ length: 40 }, (_, i) => `dir${i}`).join('\\');
    const [rule] = pathRules(monster, 'block');
    if (rule) {
      const frag = rule.conditions[0].value as string;
      if (validateRegex(frag) !== null) {
        // Engine rejects it → the guard MUST NOT claim a match.
        expect(pathMatchesFragment(monster + '\\x.txt', monster)).toBe(false);
      }
    }
  });
});
