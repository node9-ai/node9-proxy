// The dotenv command-line tools and Ruby's dotenv reach `.env` without a
// reader the jail knows (node9Firewall#443, follow-up to #440). A print form
// is a read of the file; a run form is `source FILE; CMD`, a read only when
// CMD shows what was loaded; Ruby inline code follows the node/python rule.
//
// Rows assert at evaluatePolicy, the layer that gates.

import { describe, it, expect } from 'vitest';
import { evaluatePolicy, type PolicyConfig } from './index';
import { analyzeFsOperation, analyzeUnknownCredentialReads } from '../shell/index';
import { readDotenvCli } from '../shell/dotenv-cli';
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

describe('controls that already blocked', () => {
  it.each([
    'cat .env',
    'source .env; env',
    `node --env-file .env -e 'console.log(process.env.API_KEY)'`,
    `ruby -e 'puts File.read(".env")'`,
  ])('%s', async (command) => {
    expect(await G(command)).toBe('block');
  });
});

describe('a dotenv command that prints the file is a read of it', () => {
  it.each([
    'python3 -m dotenv list',
    'python3 -m dotenv get API_KEY',
    'python -m dotenv -f .env.production list',
    'dotenv list',
    'dotenv get KEY',
    'dotenv -f config/.env list',
    'dotenv --file=.env.local get KEY',
    'dotenv -p API_KEY',
    'npx dotenv-cli -e .env -p API_KEY',
    'dotenvx get API_KEY',
    'dotenvx get API_KEY -f .env.production',
    'dotenvx decrypt --stdout',
    'uv run dotenv list',
    'sudo -u app dotenv list',
    "sh -c 'python3 -m dotenv list'",
  ])('blocks: %s', async (command) => {
    expect(await G(command)).toBe('block');
  });

  it('names the .env rule', () => {
    expect(analyzeFsOperation('python3 -m dotenv list')?.ruleName).toBe(
      'shield:project-jail:block-read-env'
    );
  });
});

describe('a dotenv command that runs a command is `source FILE; CMD`', () => {
  it.each([
    ['printenv', 'npx dotenv -- printenv'],
    ['env', 'dotenv -e .env -- env'],
    ['printenv of one name', 'dotenv -e .env.local -- printenv API_KEY'],
    ['python-dotenv run', 'dotenv run -- printenv'],
    ['dotenvx run', 'dotenvx run -- printenv'],
    ['dotenvx run with a file', 'dotenvx run -f .env.production -- env'],
    ['the Ruby gem form', 'dotenv -f .env printenv'],
    ['bundle exec', 'bundle exec dotenv -f .env env'],
    ['a shell that echoes a loaded variable', "dotenv -e .env -- sh -c 'echo $API_KEY'"],
    [
      'inline node code that reads the environment',
      `dotenv -- node -e 'console.log(process.env.API_KEY)'`,
    ],
    [
      'inline python code that reads the environment',
      `dotenv run -- python3 -c 'import os; print(os.environ["API_KEY"])'`,
    ],
  ])('blocks: %s', async (_name, command) => {
    expect(await G(command)).toBe('block');
  });

  it.each([
    ['a dev server', 'dotenv -- npm run dev'],
    ['a node program', 'npx dotenv-cli -e .env -- node server.js'],
    ['a python program', 'dotenv run -- python app.py'],
    ['dotenvx with a program', 'dotenvx run -f .env.production -- node index.js'],
    ['the Ruby gem with rake', 'bundle exec dotenv -f .env rake db:migrate'],
    ['a variable the OUTER shell expands', 'dotenv -- echo $API_KEY'],
    ['a shell script that prints nothing loaded', "dotenv -e .env -- sh -c 'npm test'"],
    ['inline code that does not read the environment', `dotenv -- node -e 'console.log(1)'`],
  ])('allows: %s', async (_name, command) => {
    expect(analyzeFsOperation(command)).toBeNull();
    expect(await G(command)).toBe('allow');
  });
});

describe('false-positive controls', () => {
  it.each([
    ['a fixture file', 'dotenv -f .env.example list'],
    ['a fixture file through python', 'python3 -m dotenv -f .env.example get KEY'],
    ['a write', 'python3 -m dotenv set KEY value'],
    ['unset', 'dotenv unset KEY'],
    ['a bare call', 'dotenv'],
    ['a version check', 'dotenv --version'],
    ['another python module', 'python3 -m pytest tests/test_dotenv.py'],
    ['installing the package', 'pip install python-dotenv'],
    ['the word in a path', 'cat docs/dotenv.md'],
    ['python-dotenv export flag is not a file', 'dotenv -e true -f .env.example list'],
  ])('quiet: %s', (_name, command) => {
    expect(analyzeFsOperation(command)).toBeNull();
  });
});

describe('Ruby inline code joins the dotenv rule', () => {
  it.each([
    `ruby -e 'require "dotenv/load"; puts ENV["API_KEY"]'`,
    `ruby -e 'require "dotenv"; Dotenv.load; puts ENV["API_KEY"]'`,
    `ruby -e 'require "dotenv"; Dotenv.overload; puts ENV.fetch("API_KEY")'`,
    `ruby -rdotenv/load -e 'puts ENV["API_KEY"]'`,
    `ruby -r dotenv/load -e 'puts ENV["API_KEY"]'`,
    `ruby -e 'require "dotenv"; puts Dotenv.parse'`,
  ])('blocks: %s', async (command) => {
    expect(await G(command)).toBe('block');
  });

  it.each([
    ['a loader for another program', `ruby -e 'require "dotenv/load"; require "./app"'`],
    ['ENV with no loader', `ruby -e 'puts ENV["HOME"]'`],
    ['a fixture path', `ruby -e 'require "dotenv"; Dotenv.load(".env.example"); puts ENV["X"]'`],
    ['the gem named in a string', `ruby -e 'puts "use dotenv/load to read ENV"'`],
  ])('quiet: %s', (_name, command) => {
    expect(analyzeFsOperation(command)).toBeNull();
  });
});

describe('a file whose name is not known is not a read of .env; it is an unknown read', () => {
  it.each([
    `node --env-file "$F" -e 'console.log(process.env.API_KEY)'`,
    'dotenv -f "$F" list',
    'dotenv -e "$ENV_FILE" -- printenv',
  ])('unknown: %s', (command) => {
    expect(analyzeFsOperation(command)).toBeNull();
    expect(analyzeUnknownCredentialReads(command)).not.toBeNull();
  });

  it.each([
    ['the code does not read the environment', `node --env-file "$F" -e 'console.log(1)'`],
    ['a program, not inline code', 'node --env-file "$F" server.js'],
    ['a run form that prints nothing', 'dotenv -e "$ENV_FILE" -- npm test'],
  ])('not even that: %s', (_name, command) => {
    expect(analyzeUnknownCredentialReads(command)).toBeNull();
  });
});

describe('readDotenvCli: the reader alone', () => {
  const read = (...words: (string | null)[]) => readDotenvCli(words, 0);
  it('print forms', () => {
    expect(read('dotenv', 'list')).toEqual({ files: ['.env'], mode: 'print', inner: -1 });
    expect(read('dotenv', '-f', 'a.env', 'get', 'K')).toEqual({
      files: ['a.env'],
      mode: 'print',
      inner: -1,
    });
    expect(read('python3', '-m', 'dotenv', 'list')?.mode).toBe('print');
  });
  it('run forms point at the inner command', () => {
    expect(read('dotenv', '-e', '.env', '--', 'printenv')).toEqual({
      files: ['.env'],
      mode: 'run',
      inner: 4,
    });
    expect(read('dotenv', 'run', '--', 'env')?.inner).toBe(3);
    expect(read('dotenv', '-c', 'production', '-e', '.env', '--', 'env')?.inner).toBe(6);
    expect(read('dotenv', '-c', '--', 'env')?.inner).toBe(3);
  });
  it('several files, a dynamic one kept as null', () => {
    expect(read('dotenv', '-e', '.env', '-e', null, '--', 'env')?.files).toEqual(['.env', null]);
  });
  it('not a dotenv command', () => {
    expect(read('python3', 'manage.py', '-m', 'dotenv')).toBeNull();
    expect(read('python3', '-c', 'print(1)')).toBeNull();
    expect(read('dotenv', 'set', 'K', 'v')).toBeNull();
    expect(read('cat', 'dotenv')).toBeNull();
  });
});
