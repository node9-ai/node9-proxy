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
      // The full CLI; `dist/cli.js` (the binary) is the launcher below.
      'cli-main': 'src/cli.ts',
    },
    format: ['cjs', 'esm'],
    dts: true,
    clean: true,
    splitting: false,
    // __filename in the ESM builds: the engine loads mvdan-sh lazily (fw#425).
    shims: true,
    // Even in the cjs+esm bundles, never bundle ink/react — the cli's
    // dynamic-import path expects them at load time, not inlined.
    external: ['ink', 'react', 'react/jsx-runtime'],
  },
  {
    // fw#425: `cli` is the dependency-free launcher behind `bin.node9` (compile
    // cache, then dispatch); `hook` holds only `check` and `log`, the two
    // commands every agent tool call runs. CJS only: both are entry points.
    entry: { cli: 'src/launch.ts', hook: 'src/hook-entry.ts' },
    format: ['cjs'],
    dts: false,
    splitting: false,
    shims: true,
    external: ['ink', 'react', 'react/jsx-runtime'],
  },
  {
    entry: { dashboard: 'src/tui/dashboard/index.ts' },
    format: ['esm'],
    dts: false,
    splitting: false,
    // __filename in the ESM builds: the engine loads mvdan-sh lazily (fw#425).
    shims: true,
    outExtension: () => ({ js: '.mjs' }),
    external: ['ink', 'react', 'react/jsx-runtime'],
  },
  {
    entry: { 'scan-ink': 'src/cli/render/ink/StaticScorecard.tsx' },
    format: ['esm'],
    dts: false,
    splitting: false,
    // __filename in the ESM builds: the engine loads mvdan-sh lazily (fw#425).
    shims: true,
    outExtension: () => ({ js: '.mjs' }),
    external: ['ink', 'react', 'react/jsx-runtime'],
  },
]);
// Note: tsup's tree-shaking naturally excludes devDependencies (vitest,
// coverage tooling, etc.) since no src/ file imports them. No explicit
// `external` entry needed beyond ink/react above.
