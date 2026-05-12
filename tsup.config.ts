import { defineConfig } from 'tsup';

// Three builds:
//   1) cli + sdk: cjs + esm, main bundles consumed by `bin: dist/cli.js`
//      and the @node9/proxy SDK exports.
//   2) dashboard: esm only, loaded at runtime via dynamic import
//      because ink@7 + react@19 are ESM with top-level await — they
//      can't be require()'d from a cjs bundle. Marked as runtime
//      externals so the dashboard.mjs imports them at load time.
//   3) scan-ink: esm only, same constraint as dashboard. Hosts the
//      Ink-based `node9 scan` panel scorecard (in active migration).
//      See scan-redesign plan.
export default defineConfig([
  {
    entry: {
      index: 'src/index.ts',
      cli: 'src/cli.ts',
    },
    format: ['cjs', 'esm'],
    dts: true,
    clean: true,
    splitting: false,
    // Even in the cjs+esm bundles, never bundle ink/react — the cli's
    // dynamic-import path expects them at load time, not inlined.
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
