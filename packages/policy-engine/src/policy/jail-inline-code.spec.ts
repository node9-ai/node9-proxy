// The credential jail must see a protected file read from inline interpreter
// code, whatever commands.inline-exec says (node9Firewall#440). Found
// 2026-11-07 in a recording trial (Claude desktop, Standard): with
// commands.inline-exec off, Claude read .env through `python3 - <<EOF` and
// `node -e 'require("dotenv").config(); ... process.env.API_KEY'`, while
// `cat .env` in the same session was blocked.
//
// A dotenv loader names no path, so it counts as a read of .env when the code
// also reads the environment (founder decision a). A call that returns the
// file's values itself (Python dotenv_values / get_key, node `.parsed`)
// counts as a read on its own.
//
// Rows assert at evaluatePolicy, the layer that gates, and at
// analyzeFsOperation, which the scan and `node9 explain` share.

import { describe, it, expect } from 'vitest';
import { evaluatePolicy, type PolicyConfig } from './index';
import { analyzeFsOperation } from '../shell/index';
import projectJail from '../shields/builtin/project-jail.json';
import type { SmartRule } from '../types';

const config = (inlineExec: 'off' | 'review'): PolicyConfig =>
  ({
    policy: {
      sandboxPaths: [],
      dangerousWords: [],
      ignoredTools: [],
      smartRules: projectJail.smartRules as SmartRule[],
      toolInspection: { bash: 'command', shell: 'command', run_shell_command: 'command' },
      dlp: { enabled: false, scanIgnoredTools: false },
      checks: { 'commands.inline-exec': inlineExec },
    },
    settings: { mode: 'standard' },
  }) as unknown as PolicyConfig;

async function verdict(command: string, inlineExec: 'off' | 'review') {
  return evaluatePolicy(config(inlineExec), 'Bash', { command }, { agent: 'claude' }, {});
}

// The two commands from the trial, as the issue quotes them.
const TRIAL_PYTHON = [
  `python3 - <<'EOF2'`,
  `raw = open(".env","rb").read()`,
  `for line in raw.splitlines():`,
  `    if line.startswith(b"API_KEY="):`,
  `        v = line.split(b"=", 1)[1]`,
  `        print(len(v), v[:6])`,
  `EOF2`,
].join('\n');
const TRIAL_NODE = `node -e 'require("dotenv").config(); const k=process.env.API_KEY; console.log(k.length, k.slice(0, 6))'`;

const READS: Array<[string, string, string]> = [
  ['the trial python heredoc', TRIAL_PYTHON, 'block-read-env'],
  ['the trial node dotenv one-liner', TRIAL_NODE, 'block-read-env'],
  ['python -c open(".env")', `python3 -c "print(open('.env').read())"`, 'block-read-env'],
  [
    'a key under ~/.ssh',
    `python3 -c "print(open('/home/u/.ssh/id_rsa').read())"`,
    'block-read-ssh',
  ],
  [
    'node readFileSync of ~/.aws',
    `node -e 'console.log(require("fs").readFileSync("/home/u/.aws/credentials","utf8"))'`,
    'block-read-aws',
  ],
  [
    'import "dotenv/config" with process.env',
    `node --input-type=module -e 'import "dotenv/config"; console.log(process.env.API_KEY)'`,
    'block-read-env',
  ],
  [
    'dotenv.config() with process.env',
    `node -e 'const dotenv = require("dotenv"); dotenv.config(); console.log(process.env)'`,
    'block-read-env',
  ],
  [
    'the parsed result of config()',
    `node -e 'console.log(require("dotenv").config().parsed)'`,
    'block-read-env',
  ],
  [
    'load_dotenv with os.getenv',
    `python3 -c "from dotenv import load_dotenv; import os; load_dotenv(); print(os.getenv('API_KEY'))"`,
    'block-read-env',
  ],
  [
    'load_dotenv with os.environ',
    `python3 -c "import dotenv, os; dotenv.load_dotenv(); print(os.environ['API_KEY'])"`,
    'block-read-env',
  ],
  [
    'dotenv_values with no environment read',
    `python3 -c "from dotenv import dotenv_values; print(dotenv_values())"`,
    'block-read-env',
  ],
  [
    'a heredoc with load_dotenv and getenv',
    `python3 - <<'EOF'\nfrom dotenv import load_dotenv\nfrom os import getenv\nload_dotenv()\nprint(getenv("API_KEY"))\nEOF`,
    'block-read-env',
  ],
  ['a path held in a variable', `python3 -c "p = '.env'; print(open(p).read())"`, 'block-read-env'],
  [
    'a path wrapped in expanduser',
    `python3 -c "import os; print(open(os.path.expanduser('~/.ssh/id_rsa')).read())"`,
    'block-read-ssh',
  ],
  [
    'a variable wrapped in expanduser',
    `python3 -c "import os; p = os.path.expanduser('~/.aws/credentials'); print(open(p).read())"`,
    'block-read-aws',
  ],
  [
    'Path.read_text',
    `python3 -c "from pathlib import Path; print(Path('.env').read_text())"`,
    'block-read-env',
  ],
  [
    'a path joined under the home directory',
    `node -e 'const fs=require("fs"),os=require("os"),path=require("path"); console.log(fs.readFileSync(path.join(os.homedir(), ".ssh/id_rsa"), "utf8"))'`,
    'block-read-ssh',
  ],
  [
    'node --env-file=.env',
    `node --env-file=.env -e 'console.log(process.env.API_KEY)'`,
    'block-read-env',
  ],
  [
    'node --env-file .env',
    `node --env-file .env -e 'console.log(process.env.API_KEY)'`,
    'block-read-env',
  ],
  [
    'node -r dotenv/config',
    `node -r dotenv/config -e 'console.log(process.env.API_KEY)'`,
    'block-read-env',
  ],
  [
    'node --require=dotenv/config',
    `node --require=dotenv/config -e 'console.log(process.env)'`,
    'block-read-env',
  ],
  ['ruby File.read', `ruby -e 'puts File.read(".env")'`, 'block-read-env'],
  ['php file_get_contents', `php -r 'echo file_get_contents(".env");'`, 'block-read-env'],
  ['perl open', `perl -e 'open(my $f, "<", ".env"); print <$f>'`, 'block-read-env'],
  [
    'dotenv pointed at a jailed path',
    `node -e 'require("dotenv").config({ path: "be/.env" }); console.log(process.env.DB_URL)'`,
    'block-read-env',
  ],
];

describe('inline code that reads a jailed file is blocked like cat', () => {
  for (const inlineExec of ['off', 'review'] as const) {
    it.each(READS)(`commands.inline-exec ${inlineExec}: %s`, async (_name, command, rule) => {
      const v = await verdict(command, inlineExec);
      expect(v.decision).toBe('block');
      expect(v.ruleName).toBe(`shield:project-jail:${rule}`);
      expect(v.checkId).toBe('data.credential-files');
    });
  }

  it.each(READS)('analyzeFsOperation sees %s', (_name, command, rule) => {
    expect(analyzeFsOperation(command)?.ruleName).toBe(`shield:project-jail:${rule}`);
  });

  it('gets the same verdict and rule as cat .env', async () => {
    const cat = await verdict('cat .env', 'off');
    const inline = await verdict(`python3 -c "print(open('.env').read())"`, 'off');
    expect(inline.decision).toBe(cat.decision);
    expect(inline.ruleName).toBe(cat.ruleName);
  });
});

describe('everyday inline code stays allowed', () => {
  it.each([
    [
      'dotenv loaded for a script that does not read the environment',
      `node -e 'require("dotenv").config(); require("./migrate")'`,
    ],
    [
      'load_dotenv with no environment read',
      `python3 -c "from dotenv import load_dotenv; load_dotenv(); import app; app.main()"`,
    ],
    ['process.env without dotenv', `node -e 'console.log(process.env.NODE_ENV)'`],
    ['os.environ without dotenv', `python3 -c "import os; print(os.environ.get('HOME'))"`],
    ['an example env file', `python3 -c "print(open('.env.example').read())"`],
    [
      'dotenv pointed at an example file',
      `node -e 'require("dotenv").config({ path: ".env.example" }); console.log(process.env.PORT)'`,
    ],
    [
      'an ordinary file',
      `python3 -c "import json; print(json.load(open('package.json'))['version'])"`,
    ],
    ['a word dotenv in a string', `node -e 'console.log("install dotenv", process.env.CI)'`],
    // A jailed name that is only text, not a path a read call opens
    // (the 37k real-command diff, 2026-11-07).
    [
      'a script that edits code mentioning .env',
      `python3 - <<'EOF'\np='src/a.ts'; s=open(p).read()\ns=s.replace('const f = ".env"', 'const f = ".env.local"')\nopen(p,'w').write(s)\nEOF`,
    ],
    [
      'a probe that passes a jailed path as text',
      `node -e 'const e=require("./dist"); console.log(e.analyzeFsOperation("cat ~/.ssh/id_rsa"), e.isProtected("/home/u/.ssh/id_rsa"))'`,
    ],
    ['an existence check', `python3 -c "import os; print(os.path.exists('.env'))"`],
    ['an env file without an environment read', `node --env-file=.env -e 'require("./server")'`],
    [
      'dotenv preloaded without an environment read',
      `node -r dotenv/config -e 'require("./migrate")'`,
    ],
    [
      'a test that writes a fake key into a scratch home',
      `python3 - <<'PY'\nimport os,tempfile\nH=tempfile.mkdtemp(); os.makedirs(f'{H}/.ssh')\nopen(f'{H}/.ssh/id_rsa','w').write('x\\n')\nPY`,
    ],
    [
      'a json.dump into a scratch credentials file',
      `python3 -c "import json,os; json.dump({'k':1}, open(os.path.join(h,'.aws','credentials'),'w'))"`,
    ],
    [
      'a write through a wrapped path',
      `python3 -c "import json,os; json.dump({'k':1}, open(os.path.join(h,'.node9','credentials.json'),'w'))"`,
    ],
    ['a perl write', `perl -e 'open(my $f, ">", ".env"); print $f "A=1"'`],
    [
      'a function whose name starts with a read call',
      `node -e 'console.log(e.fileAccessView("/home/u/.aws/print.sh --all"))'`,
    ],
    ['a copy from an example', `python3 -c "import shutil; shutil.copy('.env.example', '.env')"`],
  ])('allows %s', async (_name, command) => {
    for (const inlineExec of ['off', 'review'] as const) {
      expect((await verdict(command, inlineExec)).decision).not.toBe('block');
    }
    expect(analyzeFsOperation(command)).toBeNull();
  });
});
