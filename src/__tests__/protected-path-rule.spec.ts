// MSG-1: which smart-rule blocks are about a PROTECTED FILE. The predicate
// decides the message the agent reads, so it is pinned against the rule names
// the REAL builders generate, not against strings copied here: a builder that
// renames its rules turns a row red instead of silently falling back to the
// generic "Action blocked by security policy [Smart Rule: block-path-...]".
import { describe, it, expect } from 'vitest';
import { isProtectedPathRule } from '../auth/orchestrator';
import { pathRules } from '../shields/build';
import { AST_FS_REGEX_RULES } from '@node9/policy-engine';

describe('isProtectedPathRule', () => {
  // `node9 jail add` installs the user-jail shield's rules under their bare
  // names (measured at the real hook: ruleName `block-path-<slug>-anytool`).
  const userJail = pathRules('/home/u/vault', 'block').map((r) => r.name);
  // A managed jail's rules arrive prefixed `org:` (config/index.ts).
  const orgJail = pathRules('/srv/secrets', 'block').map((r) => `org:${r.name}`);
  // The shipped project-jail read blocks, from the engine's own table.
  const projectJail = [...AST_FS_REGEX_RULES].filter((r) =>
    r.startsWith('shield:project-jail:block-read-')
  );

  it('the fixtures are not empty (guards a vacuous pass)', () => {
    expect(userJail.length).toBeGreaterThan(0);
    expect(orgJail.length).toBeGreaterThan(0);
    expect(projectJail.length).toBeGreaterThanOrEqual(3); // ssh, aws, env
  });

  it.each([...userJail, ...orgJail, ...projectJail])('%s is a protected-path rule', (name) => {
    expect(isProtectedPathRule(name)).toBe(true);
  });

  it.each([
    'block-rm-rf-home',
    'review-drop-truncate-shell',
    'shield:filesystem:review-chmod-777',
    'shield:project-jail:review-read-credentials', // a review, not a block
    ...pathRules('/home/u/vault', 'review').map((r) => r.name),
    undefined,
    '',
  ])('%s is not', (name) => {
    expect(isProtectedPathRule(name)).toBe(false);
  });
});
