// The `engines.node` field is a promise to a user whose install either works
// or does not. It said ">=18" from the first commit of package.json in
// February 2026 and was never revisited, so it aged into a claim nobody
// checked: Node 18 reached end of life in April 2025, the CI matrix tests 20
// and 22, and the source uses `fetch`, `AbortSignal.timeout` and
// `structuredClone`, none of which exist before 17.
//
// This file makes the declaration checkable rather than aspirational: the
// lowest Node the CI actually runs must satisfy what the manifest promises.
import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';

const root = path.resolve(__dirname, '../..');
const readJson = (p: string) => JSON.parse(fs.readFileSync(path.join(root, p), 'utf8'));

/** The `node:` matrix line of the CI workflow, e.g. `node: [20, 22]`. */
function ciNodeVersions(): number[] {
  const yml = fs.readFileSync(path.join(root, '.github/workflows/ci.yml'), 'utf8');
  const m = /^\s*node:\s*\[([^\]]+)\]/m.exec(yml);
  expect(m, 'the CI workflow no longer declares a node matrix').not.toBeNull();
  return m![1].split(',').map((s) => Number(s.trim()));
}

/** The major from a `>=N` range. Only that shape is used here, deliberately. */
function declaredMinimum(range: string): number {
  const m = /^>=\s*(\d+)/.exec(range.trim());
  expect(m, `engines.node is "${range}", which this check cannot read`).not.toBeNull();
  return Number(m![1]);
}

describe('engines.node is a promise the CI keeps', () => {
  const manifests = ['package.json', 'packages/policy-engine/package.json'];

  it('the instrument can see the matrix at all', () => {
    // Without this, a workflow rename turns every row below into a vacuous
    // pass, which is the same class of mistake the declaration itself was.
    const versions = ciNodeVersions();
    expect(versions.length).toBeGreaterThan(0);
    expect(versions.every((v) => Number.isInteger(v) && v > 0)).toBe(true);
  });

  it.each(manifests)('%s promises no more than CI proves', (file) => {
    const declared = declaredMinimum(readJson(file).engines.node);
    const lowestTested = Math.min(...ciNodeVersions());
    expect(
      lowestTested,
      `${file} promises Node >=${declared} but the lowest version CI runs is ${lowestTested}`
    ).toBeLessThanOrEqual(declared);
  });

  it.each(manifests)('%s does not promise a runtime the source cannot use', (file) => {
    // structuredClone landed in 17, global fetch and AbortSignal.timeout in 18.
    // A lower promise is a lie the first time someone takes it up.
    expect(declaredMinimum(readJson(file).engines.node)).toBeGreaterThanOrEqual(18);
  });

  it('the two manifests agree with each other', () => {
    const [a, b] = manifests.map((f) => declaredMinimum(readJson(f).engines.node));
    expect(a).toBe(b);
  });
});
