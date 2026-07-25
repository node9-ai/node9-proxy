import tseslint from 'typescript-eslint';

export default tseslint.config(
  ...tseslint.configs.recommended,
  {
    rules: {
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      'no-control-regex': 'warn',
    },
  },
  {
    ignores: [
      'dist/**',
      'node_modules/**',
      'coverage/**',
      'scripts/**',
      // Claude Code worktrees (parallel agent sessions) are full repo copies —
      // linting them from the parent repo trips "multiple TSConfigRootDirs"
      // and duplicates every finding. They lint themselves from inside.
      '.claude/worktrees/**',
      // The policy-engine workspace has its own build output. Lint runs
      // from inside the package; the parent shouldn't reach into dist/.
      'packages/**/dist/**',
      'packages/**/node_modules/**',
    ],
  }
);
