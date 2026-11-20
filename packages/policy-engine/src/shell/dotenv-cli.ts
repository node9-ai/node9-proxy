// packages/policy-engine/src/shell/dotenv-cli.ts
// The dotenv command-line tools, read from one command's words
// (node9Firewall#443). They reach a `.env` file without naming a reader the
// credential jail knows:
//   python-dotenv   dotenv [-f FILE] list | get KEY | run -- CMD
//                   python -m dotenv ...
//   dotenv-cli      dotenv [-e FILE]... [-p VAR] [--] CMD
//   dotenvx         dotenvx get KEY | run [-f FILE] -- CMD | decrypt --stdout
//   the Ruby gem    dotenv [-f FILE] CMD
// This module only says WHAT the command does with WHICH files. The jail
// decides the verdict: a print form is a read of the file; a run form is
// `source FILE; CMD`, a read only when CMD shows what was loaded.

export interface DotenvCliCall {
  /** The files the command loads, `.env` when it names none. A null entry is
   *  a name that is not literal (a variable, a substitution). */
  files: (string | null)[];
  /** 'print': it writes the file's values to its output. 'run': it runs the
   *  command that starts at `inner` with the file loaded into the environment. */
  mode: 'print' | 'run';
  /** Index in `words` of the inner command's first word; -1 in print mode. */
  inner: number;
}

const base = (w: string | null | undefined): string =>
  (w ?? '').split(/[\\/]/).pop()?.toLowerCase() ?? '';

/** Options whose value is a file to load. */
const FILE_FLAGS = new Set(['-f', '--file', '-e', '--env-file']);
/** Options that take a value which is not a file. */
const VALUE_FLAGS = new Set([
  '-q',
  '--quote',
  '-v',
  '--env',
  '-fk',
  '--env-keys-file',
  '--convention',
  '--log-level',
]);
/** Subcommands that neither print the file nor run a command with it. */
const QUIET_SUBCOMMANDS = new Set([
  'set',
  'unset',
  'encrypt',
  'ls',
  'help',
  'version',
  'rotate',
  'genexample',
  'gitignore',
  'prebuild',
  'precommit',
  'keypair',
  'ext',
]);

/** The files named by file flags from `from` on, added to `files`. */
function filesAfter(words: (string | null)[], from: number, files: (string | null)[]): void {
  for (let j = from; j < words.length; j++) {
    const w = words[j];
    if (w === null) continue;
    if (FILE_FLAGS.has(w)) {
      if (words[j + 1] !== undefined) files.push(words[j + 1]);
      j++;
      continue;
    }
    const joined = /^(?:--file|--env-file)=(.*)$/.exec(w);
    if (joined) files.push(joined[1]);
  }
}

/** Where the dotenv tool's own arguments start, or -1 when `words[head]` is
 *  not a dotenv tool. `head` is the command head, wrappers already skipped. */
function dotenvArgsStart(words: (string | null)[], head: number): number {
  const name = base(words[head]);
  if (name === 'dotenv' || name === 'dotenv-cli' || name === 'dotenvx') return head + 1;
  // `bundle exec dotenv ...`
  if (name === 'bundle' && words[head + 1] === 'exec' && base(words[head + 2]) === 'dotenv')
    return head + 3;
  // `python -m dotenv ...`: only interpreter options may come before `-m`.
  if (/^(?:python[\d.]*|py)$/.test(name)) {
    for (let i = head + 1; i < words.length; i++) {
      const w = words[i];
      if (w === null || !w.startsWith('-')) return -1;
      if (w === '-m') return words[i + 1] === 'dotenv' ? i + 2 : -1;
      if (w === '-c') return -1;
    }
  }
  return -1;
}

/**
 * What a dotenv command does, or null when the command is not one or does
 * nothing the jail cares about (`dotenv set`, a bare `dotenv`).
 */
export function readDotenvCli(words: (string | null)[], head: number): DotenvCliCall | null {
  const start = dotenvArgsStart(words, head);
  if (start < 0) return null;
  const files: (string | null)[] = [];
  let print = false;
  let sawRun = false;
  let inner = -1;
  let i = start;
  while (i < words.length) {
    const w = words[i];
    if (w === null) {
      // A word that is not literal where a command or a subcommand goes: the
      // inner command, whatever it is.
      inner = i;
      break;
    }
    if (w === '--') {
      inner = i + 1;
      break;
    }
    if (FILE_FLAGS.has(w)) {
      const value = words[i + 1];
      // python-dotenv's `-e` is `--export BOOLEAN`, not a file.
      if (!(w === '-e' && (value === 'true' || value === 'false')) && value !== undefined)
        files.push(value);
      i += 2;
      continue;
    }
    const joined = /^(?:--file|--env-file)=(.*)$/.exec(w);
    if (joined) {
      files.push(joined[1]);
      i++;
      continue;
    }
    if (w === '-p' || w === '--print') {
      // dotenv-cli: print the value of one variable.
      print = true;
      i += 2;
      continue;
    }
    if (VALUE_FLAGS.has(w)) {
      i += 2;
      continue;
    }
    if (w === '-c' || w === '--cascade') {
      // dotenv-cli: an optional environment name. It is one only when
      // something that is not the command follows it.
      const value = words[i + 1];
      const after = words[i + 2];
      const takes =
        typeof value === 'string' &&
        !value.startsWith('-') &&
        typeof after === 'string' &&
        after.startsWith('-');
      i += takes ? 2 : 1;
      continue;
    }
    if (w.startsWith('-')) {
      i++;
      continue;
    }
    // The first operand: a subcommand or the inner command.
    if (!sawRun) {
      if (w === 'list' || w === 'get') {
        print = true;
        // dotenvx writes the file after the subcommand: `get KEY -f FILE`.
        filesAfter(words, i + 1, files);
        break;
      }
      if (w === 'run') {
        sawRun = true;
        i++;
        continue;
      }
      if (w === 'decrypt') {
        print = words.slice(i + 1).some((x) => x === '--stdout');
        filesAfter(words, i + 1, files);
        break;
      }
      if (QUIET_SUBCOMMANDS.has(w)) return null;
    }
    inner = i;
    break;
  }
  const loaded = files.length > 0 ? files : ['.env'];
  if (print) return { files: loaded, mode: 'print', inner: -1 };
  if (inner >= 0 && inner < words.length) return { files: loaded, mode: 'run', inner };
  return null;
}
