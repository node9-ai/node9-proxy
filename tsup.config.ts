import { defineConfig } from 'tsup';

// Four builds:
//   1) sdk: cjs + esm, the @node9/proxy SDK exports.
//   2) cli: cjs only (it relies on __dirname / require). `bin: dist/cli.js`
//      is a tiny dispatcher (src/cli-entry.ts) that loads dist/cli-hook.js
//      for the `check` / `log` hooks and dist/cli-main.js for everything
//      else, so the per-tool-call hooks never load the full CLI. Code the
//      two share is duplicated in both: esbuild cannot code-split cjs.
//   3) dashboard: esm only, loaded at runtime via dynamic import
//      because ink@7 + react@19 are ESM with top-level await — they
//      can't be require()'d from a cjs bundle. Marked as runtime
//      externals so the dashboard.mjs imports them at load time.
//   4) scan-ink: esm only, same constraint as dashboard. Hosts the
//      Ink-based `node9 scan` panel scorecard (in active migration).
//      See scan-redesign plan.
export default defineConfig([
  {
    entry: { index: 'src/index.ts' },
    format: ['cjs', 'esm'],
    dts: true,
    clean: true,
    splitting: false,
    external: ['ink', 'react', 'react/jsx-runtime'],
  },
  {
    entry: {
      cli: 'src/cli-entry.ts',
      'cli-hook': 'src/cli-hook.ts',
      'cli-main': 'src/cli.ts',
    },
    format: ['cjs'],
    dts: false,
    splitting: false,
    // Never bundle ink/react — the cli's dynamic-import path expects them
    // at load time, not inlined.
    external: ['ink', 'react', 'react/jsx-runtime'],
  },
  {
    entry: { dashboard: 'src/tui/dashboard/index.ts' },
    format: ['esm'],
    dts: false,
    splitting: false,
    outExtension: () => ({ js: '.mjs' }),
    external: ['ink', 'react', 'react/jsx-runtime'],
  },
  {
    entry: { 'scan-ink': 'src/cli/render/ink/StaticScorecard.tsx' },
    format: ['esm'],
    dts: false,
    splitting: false,
    outExtension: () => ({ js: '.mjs' }),
    external: ['ink', 'react', 'react/jsx-runtime'],
  },
]);
// Note: tsup's tree-shaking naturally excludes devDependencies (vitest,
// coverage tooling, etc.) since no src/ file imports them. No explicit
// `external` entry needed beyond ink/react above.
