// src/ci-check/yaml-strict.ts
// `yaml`'s parse() with its default duplicate-key check, in linear time (§L). The library
// compares every key of a map with every other: 32,000 keys took 17 s, and a committed workflow
// or SKILL.md frontmatter is the PR author's text. Here the document is parsed without that
// check and every map is walked once with a Set — the same rule (a scalar key repeated in one
// map is an error; non-scalar keys never collide), the same result, the same failure.

import { parseDocument, visit, isScalar } from 'yaml';

/** Same value as `parse(text)`, and throws where it throws. Never prints warnings. */
export function parseYamlStrict(text: string): unknown {
  const doc = parseDocument(text, { uniqueKeys: false });
  if (doc.errors.length) throw doc.errors[0];
  visit(doc, {
    Map(_, map) {
      const seen = new Set<unknown>();
      for (const item of map.items) {
        if (!isScalar(item.key)) continue;
        const k = item.key.value;
        if (seen.has(k)) throw new Error(`Map keys must be unique: ${String(k).slice(0, 60)}`);
        seen.add(k);
      }
    },
  });
  return doc.toJS();
}
