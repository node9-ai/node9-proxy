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
});
