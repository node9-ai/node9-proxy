// The credential jail must see a read however the file name reaches the
// reader. Found 2026-11-02 in the Claude desktop app: at Standard,
//   for f in .env fe/.env be/.env; do sed -E 's/=.+/=<set>/' "$f"; done
// read three .env files and was allowed. The jail read the reader's operands
// as written; the structural file-access walk, which already resolves loop
// variables, globs, $PWD and find -exec, was not consulted.
// Design: docs/roadmap/active/jail-indirect-reads-code-design.md.
//
// Rows assert at evaluatePolicy, the layer that gates.

import { describe, it, expect } from 'vitest';
import { evaluatePolicy, type PolicyConfig } from './index';
import { analyzeFsOperation } from '../shell/index';
import projectJail from '../shields/builtin/project-jail.json';
import type { SmartRule } from '../types';

const config: PolicyConfig = {
  policy: {
    sandboxPaths: [],
    dangerousWords: [],
    ignoredTools: [],
    smartRules: projectJail.smartRules as SmartRule[],
    toolInspection: { bash: 'command', shell: 'command', run_shell_command: 'command' },
    dlp: { enabled: false, scanIgnoredTools: false },
  },
  settings: { mode: 'standard' },
} as unknown as PolicyConfig;

async function G(command: string): Promise<string> {
  const v = await evaluatePolicy(config, 'Bash', { command }, { agent: 'claude' }, {});
  return String(v.decision);
}

describe('step 1: names the file-access walk already resolves', () => {
  it.each([
    ['the founder case', `for f in .env fe/.env be/.env; do sed -E 's/=.+/=<set>/' "$f"; done`],
    ['a loop over one name', 'for f in .env; do cat "$f"; done'],
    ['a loop whose second item is jailed', 'for f in a .env; do cat "$f"; done'],
    ['a loop over a glob', 'for f in .e*; do cat "$f"; done'],
    ['a glob', 'cat .e*'],
    ['a one-character glob', 'cat .en?'],
    ['a bracket glob', 'cat .en[v]'],
    ['$PWD', 'cat "$PWD/.env"'],
    ['find -exec', 'find . -name .env -exec cat {} \;'],
  ])('blocks %s', async (_name, command) => {
    expect(await G(command)).toBe('block');
  });

  it('covers .ssh and .aws the same way', async () => {
    expect(await G('for f in ~/.ssh/id_rsa; do cat "$f"; done')).toBe('block');
    expect(await G('for f in ~/.aws/*; do cat "$f"; done')).toBe('block');
    expect(await G('cat ~/.ssh/id_*')).toBe('block');
  });
});

describe('the exemptions and everyday commands stay allowed', () => {
  it.each([
    'for f in .env.example; do cat "$f"; done',
    'for f in .env.test; do cat "$f"; done',
    'for f in src/*.ts; do wc -l "$f"; done',
    'cat *',
    'cat *.json',
    'ls .env',
    'ls -la .e*',
    'find . -name .env',
    'grep -r TODO .',
    'cat package.json',
  ])('allows %s', async (command) => {
    expect(await G(command)).not.toBe('block');
  });
});

describe('step 2: shapes the file-access walk learns', () => {
  it.each([
    ['set --', 'set -- .env; cat "$1"'],
    ['set -- with two names', 'set -- a .env; cat "$2"'],
    ['an array element', 'arr=(.env); cat "${arr[0]}"'],
    ['an array expansion', 'arr=(a .env); cat "${arr[@]}"'],
    ['a here-string into while read', 'while read f; do cat "$f"; done <<< .env'],
    ['a heredoc into while read', 'while read -r f; do cat "$f"; done <<EOF\na\n.env\nEOF'],
    ['echo piped into while read', 'echo .env | while read f; do cat "$f"; done'],
    ['echo piped into xargs', 'echo .env | xargs cat'],
    ['printf piped into xargs -I', "printf '.env\\n' | xargs -I{} cat {}"],
    ['xargs with options', 'echo a .env | xargs -n 1 -r cat'],
    ['diff', 'diff .env /dev/null'],
    ['comm', 'comm .env .env.example'],
    ['an ANSI-C quoted name', "cat $'\\x2eenv'"],
    ['an ANSI-C quoted name in a loop', 'for f in $\'\\x2eenv\'; do cat "$f"; done'],
    ['a sourced .env printed by env', 'source .env; env'],
    ['a dot-sourced .env printed by printenv', '. ./.env && printenv'],
  ])('blocks %s', async (_name, command) => {
    expect(await G(command)).toBe('block');
  });

  it.each([
    // Loading .env to run the app is everyday work; only printing it is a read.
    'source .env && npm run dev',
    'set -a; . ./.env; set +a; node server.js',
    'echo src/a.ts | xargs wc -l',
    'set -- a b; echo "$1"',
    'while read l; do echo "$l"; done <<< hello',
    'diff a.txt b.txt',
  ])('allows %s', async (command) => {
    expect(await G(command)).not.toBe('block');
  });
});

// Decision b1: names that come from a listing at run time cannot be known
// before the command runs. A reader fed by a listing that can include a
// jailed file is `data.credential-files-unknown`: logged at Standard, asked
// at Strict. A listing that cannot reach a jailed name is not flagged.
describe('step 3: names node9 cannot know', () => {
  const at = (mode: string) => ({ ...config, settings: { mode } }) as unknown as PolicyConfig;
  async function D(command: string, mode = 'standard') {
    return evaluatePolicy(at(mode), 'Bash', { command }, { agent: 'claude' }, {});
  }

  it.each([
    'find . | xargs cat',
    'find . -type f -print0 | xargs -0 cat',
    'ls -A | while read f; do cat "$f"; done',
    'cat $(find . -type f)',
    'for f in $(find ~/.ssh -type f); do cat "$f"; done',
    'fd -H . | xargs grep -l KEY',
  ])('%s: logged at Standard, asked at Strict', async (command) => {
    const standard = await D(command);
    expect(standard.decision).toBe('allow');
    expect(JSON.stringify(standard)).toContain('data.credential-files-unknown');
    const strict = await D(command, 'strict');
    expect(strict.decision).toBe('review');
    expect(strict.checkId).toBe('data.credential-files-unknown');
  });

  it.each([
    "find . -name '*.ts' | xargs grep TODO",
    'find src -type f -name "*.json" | xargs cat',
    'ls | while read f; do cat "$f"; done',
    'find . -type d | xargs ls',
    'git ls-files | xargs wc -l',
    'find . | xargs echo',
  ])('%s: not flagged', async (command) => {
    const strict = await D(command, 'strict');
    expect(strict.checkId ?? '').not.toBe('data.credential-files-unknown');
    expect(JSON.stringify(await D(command))).not.toContain('data.credential-files-unknown');
  });
});

// Independent review, 2026-11-02 (before release).
describe('review: shapes the first build still missed', () => {
  it.each([
    ['source, then echo of a variable', 'source .env; echo $OPENAI_API_KEY'],
    ['dot-source, then export -p', '. .env; export -p'],
    ['source, then declare -px', 'source .env; declare -px'],
    ['source of $PWD/.env, then env', '. "$PWD/.env"; env'],
    ["printf '%s\\n' into xargs", "printf '%s\\n' .env | xargs cat"],
    ["printf '%s\\n' of a key into xargs", "printf '%s\\n' ~/.ssh/id_rsa | xargs cat"],
    ['a glob in the directory part', 'cat ~/.ss?/id_rsa'],
    ['a bracket glob in the directory part', 'cat ~/.[s]sh/id_rsa'],
    ['find -name .env into xargs', 'find . -name .env | xargs cat'],
    [
      'find -name .e* into a read loop',
      'find . -name ".e*" | while read -r f; do sed -n 1p "$f"; done',
    ],
    ['find -name .env -print0 into xargs -0', 'find . -name .env -print0 | xargs -0 cat'],
    ['a negated bracket glob', 'cat .[!a]nv'],
    ['a for loop over "$@"', 'set -- .env; for f; do cat "$f"; done'],
    ['a here-string into xargs', 'xargs cat <<< .env'],
    ['printf with \\0 into xargs -0', "printf '.env\\0' | xargs -0 cat"],
    ['a one-character suffix glob', 'cat .env.?'],
  ])('blocks %s', async (_name, command) => {
    expect(await G(command)).toBe('block');
  });

  it('a find that excludes a pattern still counts as a listing', async () => {
    const strict = { ...config, settings: { mode: 'strict' } } as unknown as PolicyConfig;
    const v = await evaluatePolicy(
      strict,
      'Bash',
      { command: "find . -not -name '*.ts' | xargs cat" },
      { agent: 'claude' },
      {}
    );
    expect(v.checkId).toBe('data.credential-files-unknown');
  });

  it('a short xargs -I command cannot blow up into a slow check', async () => {
    const items = Array.from({ length: 64 }, (_, i) => `item${i}`.padEnd(40, 'x')).join(' ');
    const command = `echo ${items} | xargs -I X cat ${'X'.repeat(1000)}`;
    const started = Date.now();
    analyzeFsOperation(command);
    expect(Date.now() - started).toBeLessThan(1000);
  });
});
