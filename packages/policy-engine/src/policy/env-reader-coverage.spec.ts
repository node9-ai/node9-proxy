// The credential jail must cover every command that READS, not the fourteen
// someone happened to list.
//
// HOW THIS WAS FOUND, because the shape recurs. `shield:project-jail:block-read-env`
// exists twice under ONE name: as a regex rule in project-jail.json naming 36
// reader commands, and as `SENSITIVE_PATH_RULES` inside `analyzeFsOperation`
// knowing 14. The regex rule is additionally suppressed for bash
// (`AST_FS_REGEX_RULES`), so for every AI agent the AST tier is the only gate
// and the 22-reader delta was ungated:
//
//   grep egrep fgrep rg ag ack awk gawk sed cut tr jq yq
//   od xxd hexdump strings sort uniq tac nl dd
//
// Measured before this change, all `allow`: `strings .env`, `xxd .env`,
// `grep -i secret .env`, `sed -n 1,10p .env`, `jq . .env`, `sort .env`.
// A reviewer who greps the rule NAME sees a rule that exists and moves on —
// a shared name is not a shared implementation.
//
// Second defect, same cause: the AST rule's suffix list is hand-written and
// anchored with `$`, so `.env.prod` and `.env.ci` were never covered either.
//
// Rows assert at `evaluatePolicy` — the layer that actually gates. Asserting at
// `evaluateSmartConditions` would test a layer that is suppressed downstream.

import { describe, it, expect } from 'vitest';
import { evaluatePolicy, type PolicyConfig } from './index';
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

// The 22 readers the AST tier did not know. Each is a real way to read a file:
// `strings` and `xxd` dump contents, `jq`/`yq` parse them, `sort`/`uniq`/`tac`/
// `nl` echo them, `sed`/`awk`/`cut`/`tr` transform them to stdout.
const UNGATED_READERS = [
  ['grep', 'grep -i secret .env'],
  ['egrep', 'egrep KEY .env'],
  ['fgrep', 'fgrep KEY .env'],
  ['rg', 'rg API_KEY .env'],
  ['ag', 'ag KEY .env'],
  ['ack', 'ack KEY .env'],
  ['awk', "awk '{print}' .env"],
  ['gawk', "gawk '{print}' .env"],
  ['sed', 'sed -n 1,10p .env'],
  ['cut', 'cut -d= -f2 .env'],
  ['tr', 'tr a b .env'],
  ['jq', 'jq . .env'],
  ['yq', 'yq . .env'],
  ['od', 'od -c .env'],
  ['xxd', 'xxd .env'],
  ['hexdump', 'hexdump -C .env'],
  ['strings', 'strings .env'],
  ['sort', 'sort .env'],
  ['uniq', 'uniq .env'],
  ['tac', 'tac .env'],
  ['nl', 'nl .env'],
] as const;

describe('every reader the shield claims to cover is actually gated', () => {
  it.each(UNGATED_READERS)('blocks `%s` reading a .env', async (_name, command) => {
    expect(await G(command)).toBe('block');
  });

  it('covers the same readers for .ssh and .aws, not only .env', async () => {
    // The reader set is shared by all SENSITIVE_PATH_RULES, so widening it must
    // widen every rule that depends on it — not just the one under repair.
    expect(await G('strings ~/.ssh/id_rsa')).toBe('block');
    expect(await G('xxd ~/.aws/credentials')).toBe('block');
    expect(await G('strings ~/.npmrc')).toBe('review');
  });
});

describe('the suffix list was hand-written, so it was incomplete', () => {
  it.each([
    ['.env.prod', 'cat .env.prod'],
    ['.env.ci', 'cat .env.ci'],
    ['.env.test.local', 'cat .env.test.local'],
    ['.env.local.bak', 'cat .env.local.bak'],
    ['already-listed .env.local', 'cat .env.local'],
    ['already-listed .env.production.local', 'cat .env.production.local'],
  ])('blocks %s', async (_name, command) => {
    expect(await G(command)).toBe('block');
  });

  it('an unlisted suffix is caught through a NEWLY covered reader too', async () => {
    // Crosses both defects at once: a reader from the 22-delta reading a suffix
    // from outside the hand-written list. Passing either fix alone leaves this
    // red, so it cannot go green for half a reason.
    expect(await G('strings .env.prod')).toBe('block');
  });
});

describe('the documented non-matches stay allowed', () => {
  // shell/index.ts states these as INTENTIONAL non-matches and
  // shields.test.ts:983-995 pins them. Widening the suffix match is exactly the
  // change that would quietly eat them, so they are re-asserted at the gate.
  it.each([
    ['.env.example', 'cat .env.example'],
    ['.env.sample', 'cat .env.sample'],
    ['.env.template', 'cat .env.template'],
    ['.env.test', 'cat .env.test'],
    ['.envrc', 'cat .envrc'],
  ])('allows %s (committed fixture, not a secret)', async (_name, command) => {
    expect(await G(command)).toBe('allow');
  });

  it('a template read through a newly covered reader is still allowed', async () => {
    expect(await G('grep DATABASE_URL .env.example')).toBe('allow');
  });
});

describe('widening the reader set must not invent false positives', () => {
  it.each([
    ['.environment is not .env', 'cat .environment'],
    ['a name that merely starts with env', 'cat env.js'],
    ['vite-env.d.ts — hyphen, not dot', 'cat src/vite-env.d.ts'],
    ['next-env.d.ts', 'cat next-env.d.ts'],
    ['a directory called environments', 'cat config/environments/prod.yml'],
    ['printenv is not a file read', 'printenv'],
    ['env as a command, not a path', 'env | grep PATH'],
    ['listing is not reading', 'ls -la .env'],
    ['echoing the name is not reading', 'echo .env'],
    ['docker consumes it, the agent never sees it', 'docker run --env-file .env img'],
    ['git add is not a read', 'git add .env'],
    ['npm add, where `dd` hides inside `add`', 'npm add dotenv'],
    ['excluding it is the opposite of reading it', 'grep -r TODO --exclude=.env .'],
  ])('allows: %s', async (_name, command) => {
    expect(await G(command)).toBe('allow');
  });

  it('a .env named inside a commit message is data, not a read', async () => {
    expect(await G('git commit -m "update .env handling"')).toBe('allow');
    expect(await G('git commit -m "run cat .env to see"')).toBe('allow');
  });

  it('a .env named inside a JSON string argument is data, not a read', async () => {
    // The exact false positive AST_FS_REGEX_RULES suppression exists to kill.
    // If someone "fixes" this by un-suppressing the regex rule, this goes red.
    expect(await G('echo \'{"command":"cat .env"}\'')).toBe('allow');
  });

  it('a read of an unrelated file does not become a read of .env', async () => {
    // `.*?` in the regex rule spans command boundaries; the AST tier resolves
    // per call, and must keep doing so as the reader set grows.
    expect(await G('cat README.md; echo .env')).toBe('allow');
    expect(await G('head -5 CHANGELOG.md; touch .env.bak')).toBe('allow');
  });

  it('the newly added readers stay silent on ordinary work', async () => {
    // 22 new reader names is 22 new chances to fire on a normal command.
    expect(await G('grep -rn TODO src/')).toBe('allow');
    expect(await G('sort package.json')).toBe('allow');
    expect(await G('jq .version package.json')).toBe('allow');
    expect(await G('strings dist/cli.js')).toBe('allow');
    expect(await G('sed -i s/a/b/ README.md')).toBe('allow');
    expect(await G('git log | head -20')).toBe('allow');
    expect(await G('npm run type-check')).toBe('allow');
  });
});

describe('the prescreen and the reader set are one list, not two', () => {
  it('every reader passes the prescreen that guards the AST tier', async () => {
    // ⭐ The half-applied widening this repo keeps shipping: FS_OP_PRESCREEN_RE
    // is a fast-path that returns BEFORE the AST parse. Adding a reader to
    // FS_READ_TOOLS while leaving the prescreen at fourteen names produces a
    // diff that looks complete and changes nothing. The only durable fix is for
    // the prescreen to be DERIVED from the set; this row is what proves it,
    // by driving every reader through the real gate rather than inspecting
    // either list.
    for (const [name, command] of UNGATED_READERS) {
      expect(await G(command), `${name} did not survive the prescreen`).toBe('block');
    }
  });
});
