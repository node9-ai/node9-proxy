#!/usr/bin/env node
// Verify that CANONICAL_EXTRACTOR_HASH in the engine matches the hash of
// the detector-source files. If the source changed without a hash bump,
// the daemon won't trigger its watermark migration on user upgrade and
// findings already in the SaaS stay frozen with the old detector's
// verdicts — silent corruption, hard to diagnose later.
//
// Run modes:
//   node scripts/check-extractor-version.mjs         → check (CI gate)
//   node scripts/check-extractor-version.mjs --bump  → write the new hash
//                                                       into canonical.ts
//
// Bumping the HASH alone is fine for purely cosmetic edits. If the
// edits change detector OUTPUT, also bump CANONICAL_EXTRACTOR_VERSION
// (a string like 'canonical-v2'). The hash check ensures the bump is a
// conscious act, not a forgotten one.

import { createHash } from 'crypto';
import { readFileSync, writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

// Detector-source files. Adding a new file here means future canonical-
// extractor changes there are also gated by this check.
const SOURCES = [
  'packages/policy-engine/src/scan/canonical.ts',
  'packages/policy-engine/src/scan/pii.ts',
  'packages/policy-engine/src/scan/destructive-regex.ts',
];

const VERSION_FILE = path.join(ROOT, 'packages/policy-engine/src/scan/canonical.ts');
const HASH_LINE_RE = /export const CANONICAL_EXTRACTOR_HASH = '([^']*)';/;

function computeHash() {
  const h = createHash('sha256');
  for (const rel of SOURCES) {
    const abs = path.join(ROOT, rel);
    const src = readFileSync(abs, 'utf8');
    // Strip the hash declaration line itself before hashing — otherwise
    // every bump would invalidate its own hash. Also strip the version
    // constant's value so cosmetic version-string-only edits (e.g.
    // canonical-v1 → canonical-v2) don't trip the hash check by
    // themselves; the version bump is a separate decision logged in the
    // commit. Detector output is what we're hashing.
    const stripped = src
      .replace(HASH_LINE_RE, "export const CANONICAL_EXTRACTOR_HASH = '';")
      .replace(/CANONICAL_EXTRACTOR_VERSION = '[^']*';/, "CANONICAL_EXTRACTOR_VERSION = '';");
    h.update(stripped);
    h.update('\0'); // file separator so concatenation tricks fail
  }
  return h.digest('hex').slice(0, 16);
}

function readEmbeddedHash() {
  const src = readFileSync(VERSION_FILE, 'utf8');
  const m = HASH_LINE_RE.exec(src);
  if (!m) {
    console.error('error: CANONICAL_EXTRACTOR_HASH constant not found in canonical.ts');
    process.exit(2);
  }
  return m[1];
}

function writeEmbeddedHash(newHash) {
  const src = readFileSync(VERSION_FILE, 'utf8');
  if (!HASH_LINE_RE.test(src)) {
    console.error('error: CANONICAL_EXTRACTOR_HASH constant not found in canonical.ts');
    process.exit(2);
  }
  const next = src.replace(HASH_LINE_RE, `export const CANONICAL_EXTRACTOR_HASH = '${newHash}';`);
  writeFileSync(VERSION_FILE, next, 'utf8');
}

const mode = process.argv[2];

if (mode === '--bump') {
  const fresh = computeHash();
  writeEmbeddedHash(fresh);
  console.log(`✓ CANONICAL_EXTRACTOR_HASH bumped to '${fresh}'.`);
  console.log(
    '  If your edit changed detector OUTPUT, also bump CANONICAL_EXTRACTOR_VERSION\n' +
      '  (e.g. canonical-v1 → canonical-v2). The hash bump alone preserves the\n' +
      '  current version string.'
  );
  process.exit(0);
}

const expected = readEmbeddedHash();
const actual = computeHash();

if (expected === '__PLACEHOLDER__') {
  // First-time setup — embed the hash without complaint.
  writeEmbeddedHash(actual);
  console.log(`✓ Initialized CANONICAL_EXTRACTOR_HASH to '${actual}'.`);
  process.exit(0);
}

if (expected === actual) {
  console.log(`✓ CANONICAL_EXTRACTOR_HASH matches: '${actual}'.`);
  process.exit(0);
}

console.error('✗ CANONICAL_EXTRACTOR_HASH mismatch.');
console.error(`  embedded: ${expected}`);
console.error(`  computed: ${actual}`);
console.error('');
console.error('Detector source has changed. To resolve:');
console.error('  1. If the change preserves detector output (cosmetic, refactor):');
console.error('       npm run bump-extractor-version');
console.error('  2. If the change alters detector output (new finding type, new');
console.error('     severity classification, dedupe rule change, etc.):');
console.error("       a. bump CANONICAL_EXTRACTOR_VERSION in canonical.ts (e.g. 'canonical-v2')");
console.error('       b. npm run bump-extractor-version');
console.error('     Daemons on user machines will detect the version change on');
console.error('     next start and re-scan history through the new pipeline.');
process.exit(1);
