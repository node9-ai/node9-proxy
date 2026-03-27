import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts', // The SDK
    cli: 'src/cli.ts', // The Binary
  },
  format: ['cjs', 'esm'],
  dts: true,
  clean: true,
  splitting: false,
  esbuildOptions(options) {
    options.loader = { ...options.loader, '.html': 'text' };
  },
  // Coverage and test tooling (@vitest/coverage-v8, @rolldown/*, etc.) are devDependencies
  // and are never imported by any src/ file, so tsup's tree-shaking naturally excludes them
  // from the production bundle. No explicit `external` entry is needed.
});
