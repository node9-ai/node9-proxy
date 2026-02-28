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
});
