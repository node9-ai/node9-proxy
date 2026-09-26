// src/ci-check/frontmatter.ts
// The YAML block between the leading `---` fences of a markdown file, and the one field
// the scanner grades from it. Parsed with the same `yaml` package workflows.ts uses —
// never a hand-rolled key scanner, which would mis-read a quoted or multi-line value.
// Static, parse-only, never executed.

import { parse as parseYaml } from 'yaml';

/** The frontmatter as an object, or null when the file has none or it does not parse.
 *  A malformed block is null, not a throw: the caller is a scanner and must keep going. */
export function parseFrontmatter(content: string): Record<string, unknown> | null {
  // Tolerate a BOM and leading blank lines; the opening fence must then be the first line.
  const text = content.replace(/^﻿/, '').replace(/^\s*\n/, '');
  if (!/^---[ \t]*\r?\n/.test(text)) return null;
  const close = /\r?\n---[ \t]*(\r?\n|$)/.exec(text.slice(3));
  if (!close) return null;
  const block = text.slice(3, 3 + close.index);
  try {
    const parsed: unknown = parseYaml(block);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    // Real frontmatter is often not strict YAML — `moltis-org/moltis` writes
    // `argument-hint: ["a"] ["b"] ["c"]`, three flow sequences on one line, and strict
    // parsing throws on the whole block. The grant sits on its own well-formed line and
    // must not be lost with it. Fall back to the shapes a grant line can take: a scalar
    // on the key's line, or a `- item` list on the lines below it. Nothing else is read.
    return salvageTopLevel(block);
  }
}

/** Top-level `key: scalar` lines and `key:` + `  - item` lists, read line by line. Used
 *  only when strict YAML parsing fails; it deliberately understands nothing nested. */
function salvageTopLevel(block: string): Record<string, unknown> | null {
  const out: Record<string, unknown> = {};
  const lines = block.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const m = /^([A-Za-z0-9_-]+):[ \t]*(.*)$/.exec(lines[i]);
    if (!m) continue;
    const [, key, rest] = m;
    if (rest.trim()) {
      out[key] = rest.trim();
      continue;
    }
    const items: string[] = [];
    while (i + 1 < lines.length && /^[ \t]+-[ \t]+/.test(lines[i + 1])) {
      items.push(lines[++i].replace(/^[ \t]+-[ \t]+/, '').trim());
    }
    if (items.length) out[key] = items;
  }
  return Object.keys(out).length ? out : null;
}

/** Split a grant string on commas or whitespace, but never inside parentheses, so
 *  `Bash(git status:*)` stays one token. Empty tokens are dropped. */
function splitGrants(value: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let cur = '';
  for (const ch of value) {
    if (ch === '(') depth++;
    else if (ch === ')') depth = Math.max(0, depth - 1);
    if (depth === 0 && (ch === ',' || /\s/.test(ch))) {
      if (cur) out.push(cur);
      cur = '';
      continue;
    }
    cur += ch;
  }
  if (cur) out.push(cur);
  return out;
}

/** `allowed-tools` as a normalised list. The Agent Skills spec writes it space-separated;
 *  real files also use comma-separated strings and YAML lists (all three shapes measured
 *  on 2026-09-26). Empty when the field is absent, malformed, or not a string/list. */
export function allowedToolsOf(fm: Record<string, unknown> | null): string[] {
  const raw = fm?.['allowed-tools'];
  if (typeof raw === 'string') return splitGrants(raw);
  if (Array.isArray(raw)) {
    return raw
      .filter((x): x is string => typeof x === 'string')
      .map((x) => x.trim())
      .filter(Boolean);
  }
  return [];
}
