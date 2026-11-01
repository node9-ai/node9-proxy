import { defineConfig } from 'tsup';

// Mirrors the parent proxy's tsup config so build output is consistent.
// The engine has no CLI binary — only the index.
export default defineConfig({
  entry: {
    index: 'src/index.ts',
  },
  format: ['cjs', 'esm'],
  dts: true,
  clean: true,
  splitting: false,
  // __filename in the ESM build: shell/mvdan.ts loads the parser lazily (fw#425).
  shims: true,
});
