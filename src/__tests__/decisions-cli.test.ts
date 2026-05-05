// Unit tests for the new `node9 decisions` CLI commands. Each test
// runs against an isolated tmpdir-backed HOME so reads/writes don't
// touch the real ~/.node9/decisions.json.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

// Stub HOME before importing the module so the const captures the
// tmpdir path. afterEach restores.
let tmpHome: string;
let originalHome: string | undefined;
let registerDecisionsCommand: typeof import('../cli/commands/decisions.js').registerDecisionsCommand;

beforeEach(async () => {
  tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-decisions-test-'));
  originalHome = process.env.HOME;
  process.env.HOME = tmpHome;
  // Force re-import so the module-level DECISIONS_FILE rebinds.
  // Vitest caches modules; resetModules clears the cache.
  await import('vitest').then(({ vi }) => vi.resetModules());
  ({ registerDecisionsCommand } = await import('../cli/commands/decisions.js'));
});

afterEach(() => {
  if (originalHome !== undefined) process.env.HOME = originalHome;
  else delete process.env.HOME;
  try {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  } catch {
    // best effort
  }
});

// Tiny shim — we only need the .command(name).description(...).action(fn) chain.
function makeFakeProgram() {
  const subActions = new Map<string, (...args: unknown[]) => void>();
  function fakeCommand() {
    const node = {
      command(sub: string) {
        const subNode = {
          description() {
            return subNode;
          },
          action(fn: (...args: unknown[]) => void) {
            // Strip the leading "decisions " parent name + arg placeholder.
            const key = sub.split(' ')[0];
            subActions.set(key, fn);
            return subNode;
          },
        };
        return subNode;
      },
      description() {
        return node;
      },
    };
    return node;
  }
  return {
    program: {
      command(name: string) {
        if (name === 'decisions') return fakeCommand();
        throw new Error(`unexpected top-level command: ${name}`);
      },
    },
    runSub(name: string, ...args: unknown[]) {
      const fn = subActions.get(name);
      if (!fn) throw new Error(`subcommand not registered: ${name}`);
      fn(...args);
    },
  };
}

function decisionsFile(): string {
  return path.join(tmpHome, '.node9', 'decisions.json');
}

describe('node9 decisions', () => {
  it('list with no decisions prints an empty hint (no crash)', () => {
    const { program, runSub } = makeFakeProgram();
    registerDecisionsCommand(program as never);
    // Should not throw — relevant signal: handles missing file gracefully.
    expect(() => runSub('list')).not.toThrow();
  });

  it('list reads decisions.json and prints all entries', () => {
    const dir = path.dirname(decisionsFile());
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(decisionsFile(), JSON.stringify({ Bash: 'allow', Write: 'deny' }));
    const logs: string[] = [];
    const orig = console.log;
    console.log = (...a: unknown[]) => logs.push(a.join(' '));
    try {
      const { program, runSub } = makeFakeProgram();
      registerDecisionsCommand(program as never);
      runSub('list');
    } finally {
      console.log = orig;
    }
    const out = logs.join('\n');
    expect(out).toContain('Bash');
    expect(out).toContain('Write');
    expect(out).toContain('allow');
    expect(out).toContain('deny');
  });

  it('clear removes one tool and leaves others intact', () => {
    const dir = path.dirname(decisionsFile());
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      decisionsFile(),
      JSON.stringify({ Bash: 'allow', Write: 'deny', Read: 'allow' })
    );
    const { program, runSub } = makeFakeProgram();
    registerDecisionsCommand(program as never);
    runSub('clear', 'Write');
    const after = JSON.parse(fs.readFileSync(decisionsFile(), 'utf-8'));
    expect(after).toEqual({ Bash: 'allow', Read: 'allow' });
  });

  it('clear with unknown tool exits non-zero (no file mutation)', () => {
    const dir = path.dirname(decisionsFile());
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(decisionsFile(), JSON.stringify({ Bash: 'allow' }));
    const before = fs.readFileSync(decisionsFile(), 'utf-8');
    const { program, runSub } = makeFakeProgram();
    registerDecisionsCommand(program as never);
    runSub('clear', 'NotAToolThatExists');
    expect(process.exitCode).toBe(1);
    process.exitCode = 0; // reset so it doesn't leak to the next test
    expect(fs.readFileSync(decisionsFile(), 'utf-8')).toBe(before);
  });

  it('clear-all empties the decisions file', () => {
    const dir = path.dirname(decisionsFile());
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(decisionsFile(), JSON.stringify({ Bash: 'allow', Write: 'deny' }));
    const { program, runSub } = makeFakeProgram();
    registerDecisionsCommand(program as never);
    runSub('clear-all');
    const after = JSON.parse(fs.readFileSync(decisionsFile(), 'utf-8'));
    expect(after).toEqual({});
  });

  it('drops invalid verdicts on read (e.g. corrupted file)', () => {
    const dir = path.dirname(decisionsFile());
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      decisionsFile(),
      JSON.stringify({ Bash: 'allow', Junk: 'maybe', Write: 'deny' })
    );
    const logs: string[] = [];
    const orig = console.log;
    console.log = (...a: unknown[]) => logs.push(a.join(' '));
    try {
      const { program, runSub } = makeFakeProgram();
      registerDecisionsCommand(program as never);
      runSub('list');
    } finally {
      console.log = orig;
    }
    const out = logs.join('\n');
    expect(out).toContain('Bash');
    expect(out).toContain('Write');
    expect(out).not.toContain('Junk');
  });
});
