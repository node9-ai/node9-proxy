#!/usr/bin/env node
// Copies src/shields/builtin/*.json → dist/shields/builtin/
// tsup only bundles JS/TS; JSON assets must be copied separately.
const fs = require('fs');
const path = require('path');

const SRC = path.join(__dirname, '..', 'src', 'shields', 'builtin');
const DST = path.join(__dirname, '..', 'dist', 'shields', 'builtin');

fs.mkdirSync(DST, { recursive: true });

const files = fs.readdirSync(SRC).filter((f) => f.endsWith('.json'));
for (const file of files) {
  fs.copyFileSync(path.join(SRC, file), path.join(DST, file));
  process.stdout.write(`  copied ${file}\n`);
}
process.stdout.write(`[copy-shield-assets] ${files.length} file(s) → dist/shields/builtin/\n`);
