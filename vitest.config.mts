import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    env: { NODE9_TESTING: '1' },
    clearMocks: true,
    // Integration tests spawn child processes via spawnSync (runCheck / runDoctor).
    // On slow CI runners those can take 10-15s. The default 5s vitest timeout fires
    // before the child process completes, causing false timeouts. 30s is generous
    // enough for any CI machine while still catching genuinely hanging tests.
    testTimeout: 30000,
    // Claude Code worktrees (parallel agent sessions) are full repo copies
    // inside the repo — without this, `npm test` runs THEIR suites too
    // (~3x the tests) and their in-progress failures gate OUR commits.
    exclude: ['**/node_modules/**', '**/dist/**', '.claude/worktrees/**'],
  },
  coverage: {
    provider: 'v8',
    include: ['src/**/*.ts'],
    exclude: [
      'src/**/__tests__/**',
      'src/**/*.d.ts',
      'src/daemon/ui.ts',
      // Barrel file — no executable code, 0% is correct
      'src/core.ts',
      // OS-native UI — spawns zenity/osascript, untestable in CI
      'src/ui/native.ts',
    ],
    reporter: ['text', 'html', 'json-summary'],
    reportsDirectory: './coverage',
    all: true,
    thresholds: {
      // Floors raised on 2026-03-28 after adding auth/state, timeout-racer, and
      // unknown-ID tests. CI blocks any regression below these numbers.
      // Target: 80% across the board.
      statements: 70,
      branches: 60,
      functions: 70,
      lines: 71,
    },
  },
});
