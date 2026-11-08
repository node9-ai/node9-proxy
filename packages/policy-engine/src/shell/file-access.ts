// mvdan-sh exposes untyped AST nodes. Only this adapter knows their shape.
/* eslint-disable @typescript-eslint/no-explicit-any */
import { getSyntax, lazy } from './mvdan';
import { toPlainTree, walk } from './plain-tree';
import {
  parseShared,
  resolveWordLiteral,
  unwrapCommandHead,
  findStartPoints,
  readerPaths,
  copySourcePaths,
  literalShellPayload,
  shellConsumesPipe,
  FS_READ_TOOLS,
  SHELL_INTERPRETERS,
  functionBodies,
  rebindsPositionals,
} from './index';
import { type FileAccess, type FileAccessContext } from '../files/paths';

interface Word {
  value: string;
  pattern?: string;
  /**
   * The word contains an expansion this analysis cannot resolve. `value` is
   * the literal prefix and `pattern` is that prefix followed by `*`, so an
   * operand such as `/etc/pass$X` still reaches the protected-path matcher.
   */
  dynamic?: boolean;
  /** The pattern is find's, which also selects dotfiles. */
  dot?: boolean;
}
interface Piece {
  value: string;
  pattern: string;
  glob: boolean;
}
interface State {
  cwd: string[];
  vars: Map<string, string[] | null>;
  /**
   * Where the shell is if the statement just walked succeeded. Only a `cd` sets
   * it; the next command of a pure `&&` chain runs there. Everywhere else the
   * union in `cwd` applies, because a `cd` to a missing directory fails and
   * leaves the shell where it was.
   */
  onSuccess?: string[];
  /** How many function calls deep this walk is (node9Firewall#361). */
  callDepth?: number;
}
const MAX_ALTERNATIVES = 64;
const MAX_CALL_DEPTH = 4;
const MAX_CALL_WALKS = 256;
/** Longest script `echo NAMES | xargs CMD` is expanded into. */
const MAX_XARGS_PAYLOAD = 16_384;

const POSITIONAL = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '@', '*', '#'];
const MAX_DEPTH = 64;
const MAX_PAYLOAD_DEPTH = 24;
const unique = (a: string[]): string[] => [...new Set(a)].slice(0, MAX_ALTERNATIVES);
const clone = (s: State): State => ({
  cwd: [...s.cwd],
  vars: new Map(s.vars),
  ...(s.callDepth ? { callDepth: s.callDepth } : {}),
});

/**
 * bash executes the complete statements before a syntax error and stops at
 * it. Parse the longest prefix that ends before the reported error line, so a
 * heredoc body or multi-line string is never read as separate commands.
 */
function runnablePrefix(command: string): any | null {
  let text = command;
  for (let attempt = 0; attempt < 32; attempt++) {
    try {
      return toPlainTree(getSyntax().NewParser().Parse(text, ''));
    } catch (error: any) {
      const message = String(typeof error?.Error === 'function' ? error.Error() : error?.message);
      const line = Number(/^(\d+):/.exec(message)?.[1]);
      const lines = text.split('\n');
      if (!line || line <= 1 || line > lines.length) return null;
      text = lines.slice(0, line - 1).join('\n');
    }
  }
  return null;
}

/** Tools whose standard input goes to the network. */
const SENDING_STDIN = new Set(['nc', 'ncat', 'netcat', 'socat', 'telnet', 'curl', 'wget']);

/** Download tools: short flags that take a value (a bundle stops at the first). */
const DOWNLOAD_SHORT_VALUE: Record<string, string> = {
  curl: 'odDeEFHKmPrtTuUwxXyYzAbcCQ',
  wget: 'OoaPiBetTwQlARDXIUY',
  aria2c: 'odisx',
};
const DOWNLOAD_LONG_VALUE: Record<string, string[]> = {
  curl: [
    '--output',
    '--output-dir',
    '--dump-header',
    '--cookie-jar',
    '--data',
    '--data-binary',
    '--data-raw',
    '--data-ascii',
    '--data-urlencode',
    '--form',
    '--header',
    '--request',
    '--user',
    '--user-agent',
    '--referer',
    '--cookie',
    '--config',
    '--json',
    '--upload-file',
    '--max-time',
    '--proxy',
    '--write-out',
    '--url',
  ],
  wget: [
    '--output-document',
    '--output-file',
    '--append-output',
    '--directory-prefix',
    '--input-file',
    '--post-data',
    '--post-file',
    '--body-data',
    '--body-file',
    '--method',
    '--header',
    '--user-agent',
    '--user',
    '--password',
    '--tries',
    '--timeout',
  ],
  aria2c: ['--out', '--dir', '--input-file'],
};
const DOWNLOAD_OUTPUT_FLAGS: Record<string, string[]> = {
  curl: ['-o', '--output', '-D', '--dump-header', '-c', '--cookie-jar'],
  wget: ['-O', '--output-document', '-o', '--output-file', '-a', '--append-output'],
  aria2c: ['-o', '--out'],
};
const DOWNLOAD_DIR_FLAGS: Record<string, string[]> = {
  curl: ['--output-dir'],
  wget: ['-P', '--directory-prefix'],
  aria2c: ['-d', '--dir'],
};
/**
 * The file a transfer flag sends, if any: curl's `-d @F` family, `-F name=@F`
 * and `name=<F`, `--data-urlencode [name]@F`, `-T F`, `--json @F`; wget's
 * `--post-file` and `--body-file`. `--data-raw` sends its text literally, and
 * `@-`, `-` and `.` are standard input.
 */
function uploadedFile(tool: string, flag: string, value: Word): Word | null {
  const v = value.value;
  const file = (f: string | undefined): Word | null =>
    f && f !== '-' && f !== '.' ? { value: f } : null;
  if (tool === 'curl') {
    if (['-d', '--data', '--data-ascii', '--data-binary', '--json'].includes(flag))
      return v.startsWith('@') ? file(v.slice(1)) : null;
    if (flag === '--data-urlencode') return file(/^[^=@]*@(.+)$/.exec(v)?.[1]);
    if (flag === '-F' || flag === '--form') return file(/^[^=]*=[@<]([^;]+)/.exec(v)?.[1]);
    if (flag === '-T' || flag === '--upload-file') return file(v);
  }
  if (tool === 'wget' && ['--post-file', '--body-file'].includes(flag)) return file(v);
  return null;
}
const base = (s: string | null): string => (s ?? '').replace(/\/+$/, '').split('/').pop() ?? '';
const quoteGlob = (s: string): string => s.replace(/[\\*?\[\]{}()!+@]/g, '\\$&');
const asWord = (p: Piece): Word => ({ value: p.value, ...(p.glob ? { pattern: p.pattern } : {}) });

function merge(a: State, b: State): void {
  a.cwd = unique([...a.cwd, ...b.cwd]);
  for (const key of new Set([...a.vars.keys(), ...b.vars.keys()])) {
    const left = a.vars.get(key),
      right = b.vars.get(key);
    // Retain known possibilities even when another branch is unknowable.
    a.vars.set(key, left || right ? unique([...(left ?? []), ...(right ?? [])]) : null);
  }
}

function opOf(sample: string): number {
  return parseShared(sample).Stmts[0].Redirs[0].Op;
}
// Operator numbers read off the parser on first use, not at import (fw#425:
// mvdan-sh loads lazily, and a Read hook call must not pay its start-up).
const ops = lazy(() => ({
  WRITES: new Set(['>x', '>>x', '>|x', '&>x', '&>>x', '<>x'].map(opOf)),
  APPENDS: new Set(['>>x', '&>>x'].map(opOf)),
  READS: new Set(['<x', '<>x'].map(opOf)),
  /** `>&word` with a non-numeric word is `&>word` in bash. */
  DUP_OUT: opOf('>&x'),
  HERE_STRING: opOf('<<<x'),
  AND: parseShared('a && b').Stmts[0].Cmd.Op as number,
  OR: parseShared('a || b').Stmts[0].Cmd.Op as number,
  /** `${x:-d}` `${x-d}` `${x:=d}` `${x=d}`: the default is the value when x is unset. */
  DEFAULT_OPS: new Set<number>(
    ['${x:-y}', '${x-y}', '${x:=y}', '${x=y}'].map(
      (s) => parseShared(`echo ${s}`).Stmts[0].Cmd.Args[1].Parts[0].Exp.Op
    )
  ),
}));

function wordValues(word: any, state: State): Word[] {
  const toWords = (values: string[], quoted: boolean): Word[] =>
    values.map((value) => ({
      value,
      ...(!quoted && /[*?[{]/.test(value) ? { pattern: value } : {}),
    }));
  // A null result means the part cannot be resolved; the caller keeps the
  // literal prefix gathered so far and marks the word dynamic.
  const paramValues = (node: any, quoted: boolean): Word[] | null => {
    // `${arr[i]}`, `${arr[@]}`: any element the name holds.
    if (node.Index && !node.Excl && !node.Length && !node.Slice && !node.Repl && !node.Exp) {
      const held = state.vars.get(node.Param?.Value);
      return held && held.length ? toWords(held, quoted) : null;
    }
    if (
      node.Excl ||
      node.Length ||
      node.Width ||
      node.Index ||
      node.Slice ||
      node.Repl ||
      node.Names
    )
      return null;
    const name = node.Param?.Value;
    const known = name === 'PWD' ? state.cwd : state.vars.get(name);
    if (node.Exp) {
      if (!ops().DEFAULT_OPS.has(node.Exp.Op)) return null;
      if (known && known.length) return toWords(known, quoted);
      const fallback = expand(node.Exp.Word?.Parts ?? [], quoted);
      return fallback.dynamic ? null : fallback.out.map(asWord);
    }
    return known && known.length ? toWords(known, quoted) : null;
  };
  const expand = (nodes: any[], quoted: boolean): { out: Piece[]; dynamic: boolean } => {
    let out: Piece[] = [{ value: '', pattern: '', glob: false }];
    const combine = (pieces: Word[]): void => {
      const next: Piece[] = [];
      for (const prefix of out)
        for (const piece of pieces) {
          next.push({
            value: prefix.value + piece.value,
            pattern: prefix.pattern + (piece.pattern ?? quoteGlob(piece.value)),
            glob: prefix.glob || !!piece.pattern,
          });
          if (next.length >= MAX_ALTERNATIVES) break;
        }
      out = next.slice(0, MAX_ALTERNATIVES);
    };
    for (const node of nodes) {
      const kind = node.kind;
      let pieces: Word[] | null;
      if (kind === 'ParamExp') pieces = paramValues(node, quoted);
      else if (kind === 'DblQuoted') {
        const inner = expand(node.Parts ?? [], true);
        combine(inner.out.map(asWord));
        if (inner.dynamic) return { out, dynamic: true };
        continue;
      } else if (kind === 'Lit') {
        const raw: string = node.Value ?? '';
        const value = quoted ? raw.replace(/\\([$`"\\])/g, '$1') : raw.replace(/\\(.)/g, '$1');
        const active = !quoted && /(^|[^\\])[*?[{]/.test(raw);
        pieces = [{ value, ...(active ? { pattern: raw } : {}) }];
      } else {
        const value = resolveWordLiteral({ Parts: [node] });
        pieces = value === null ? null : [{ value }];
      }
      if (pieces === null) return { out, dynamic: true };
      combine(pieces);
    }
    return { out, dynamic: false };
  };
  const { out, dynamic } = expand(word?.Parts ?? [], false);
  if (!dynamic) return out.map(asWord);
  // Without a literal prefix the operand could be anything relative to the
  // working directory; claiming `cwd/*` would block `rm -rf $DIR` run from `/`.
  return out
    .filter((piece) => piece.value !== '')
    .map((piece) => ({ value: piece.value, pattern: piece.pattern + '*', dynamic: true }));
}

/** No verdict cache: cwd, homes, assignments, and host state belong to each call. */
/**
 * The replacement texts of a sed script made only of `s` commands (any
 * delimiter, an optional address, the usual flags), or null for any other
 * script: a deletion, a change, an unterminated or unknown command, whose
 * effect on the file cannot be told from the text (node9Firewall#385).
 */
export function sedSubstitutions(script: string): string[] | null {
  const out: string[] = [];
  for (const raw of script.split(/\r?\n|;/)) {
    const cmd = raw.trim();
    if (cmd === '') continue;
    const m = /^(?:(?:\d+|\$|\/(?:\\.|[^\\/])*\/)(?:,(?:\d+|\$|\/(?:\\.|[^\\/])*\/))?)?s(.)/.exec(
      cmd
    );
    if (!m) return null;
    const delimiter = m[1];
    if (delimiter === '\\') return null;
    const parts: string[] = [];
    let cur = '';
    let i = m[0].length;
    for (; i < cmd.length && parts.length < 2; i++) {
      const ch = cmd[i];
      if (ch === '\\' && i + 1 < cmd.length) {
        cur += ch + cmd[++i];
        continue;
      }
      if (ch === delimiter) {
        parts.push(cur);
        cur = '';
        continue;
      }
      cur += ch;
    }
    if (parts.length < 2) return null;
    if (!/^[gpiImM0-9]*$/.test(cmd.slice(i))) return null;
    out.push(parts[1].replace(/\\(.)/g, '$1'));
  }
  return out.length > 0 ? out : null;
}

export function collectShellFileAccesses(
  command: string,
  context: FileAccessContext = {}
): FileAccess[] {
  const out: FileAccess[] = [];
  let payloads = 256;
  // Functions defined in the script, by name; a call walks every definition
  // with its arguments bound (node9Firewall#361, see shell/index.ts).
  const functions = new Map<string, any[]>();
  const seenCalls = new Set<string>();
  // The literal text a pipeline stage receives on stdin (`echo NAMES | ...`).
  const pipedStdin = new WeakMap<object, string>();
  // The literal stdin (a heredoc or a herestring) of the statement whose
  // command is being walked; read by the handlers that write it to a file.
  let currentStdin: string | null = null;
  let callWalks = MAX_CALL_WALKS;
  const initial: State = {
    cwd: [context.cwd ?? ''],
    vars: new Map([['HOME', [context.homeDirs?.[0] ?? '~']]]),
  };

  function add(
    operation: FileAccess['operation'],
    word: Word,
    state: State,
    extra: Partial<FileAccess> = {}
  ): void {
    if ((!word.value && !word.pattern) || word.value === '-') return;
    for (const cwd of state.cwd)
      out.push({
        operation,
        path: word.value || (word.pattern as string),
        cwd,
        followFinal: operation !== 'remove',
        ...(word.pattern ? { glob: word.pattern } : {}),
        ...(word.dot ? { dotGlob: true } : {}),
        ...extra,
      });
  }
  function nestedPayload(payload: string | null, state: State, depth: number): void {
    if (payload === null || depth >= MAX_PAYLOAD_DEPTH || payloads-- <= 0) return;
    const f = parseShared(payload);
    if (typeof f !== 'symbol') statements(f.Stmts ?? [], state, depth + 1);
  }
  function assignments(items: any[], state: State): void {
    for (const item of items ?? []) {
      // `export f` / `readonly f` carry no value and keep what f already holds.
      if (!item.Name?.Value) continue;
      if (!item.Value && item.Array) {
        // `arr=(a b)`: the name holds every element (`${arr[i]}` reads one of them).
        const elems = (item.Array.Elems ?? []).flatMap((e: any) => wordValues(e.Value, state));
        state.vars.set(
          item.Name.Value,
          elems.length && !elems.some((v: Word) => v.dynamic)
            ? elems.map((v: Word) => v.value)
            : null
        );
        continue;
      }
      if (!item.Value) continue;
      const values = wordValues(item.Value, state);
      const known = values.some((v) => v.dynamic) ? null : values.map((v) => v.value);
      const previous = state.vars.get(item.Name.Value);
      state.vars.set(
        item.Name.Value,
        item.Append && known
          ? previous
            ? unique(previous.flatMap((p) => known.map((k) => p + k)))
            : null
          : known
      );
    }
  }
  function substitutions(word: any, state: State, depth: number): void {
    if (!word) return;
    walk(word, (node: any) => {
      if (!node) return false;
      if (['CmdSubst', 'ProcSubst'].includes(node.kind)) {
        statements(node.Stmts ?? [], clone(state), depth + 1);
        return false;
      }
      return true;
    });
  }
  function fromWords(tokens: Array<Word | null>, state: State, nested: State, depth: number): void {
    const words = tokens.map((w) => (w && !w.dynamic ? w.value : null));
    const head = unwrapCommandHead(words, true);
    const name = base(words[head]);
    if (name === 'find') {
      findActions(tokens, words, head, state, nested, depth);
      return;
    }
    const args = tokens.slice(head + 1);
    const strings = args.map((w) => w?.value ?? '');
    if (name === 'cd' || name === 'pushd') {
      // `cd -` returns to a directory this analysis does not track, and an
      // unresolvable target (`cd $DIR`) could be anywhere. Neither is a bare `cd`.
      if (args.some((w) => w === null || w.value === '-' || w.dynamic)) return;
      const home = nested.vars.get('HOME')?.[0] ?? '~';
      const target = args.find((w) => w && !w.value.startsWith('-')) ?? { value: home };
      if (!target.value || target.pattern || target.dynamic) return;
      const expanded =
        target.value === '~' || target.value.startsWith('~/')
          ? home + target.value.slice(1)
          : target.value;
      // The cd may fail (a missing directory), so every prior directory stays
      // possible. Only a following `&&` command may assume it succeeded.
      const next =
        expanded.startsWith('/') || expanded.startsWith('~')
          ? [expanded]
          : state.cwd.map((cwd) => `${cwd}/${expanded}`);
      state.cwd = unique([...state.cwd, ...next]);
      state.onSuccess = unique(next);
      return;
    }
    if (name === 'su' || name === 'runuser') {
      const flag = strings.findIndex((s) => s === '-c' || s === '--command');
      const inline = strings.find((s) => s.startsWith('--command='));
      const script = flag >= 0 ? args[flag + 1] : inline ? { value: inline.slice(10) } : null;
      if (script && !script.dynamic) nestedPayload(script.value, clone(nested), depth);
      return;
    }
    let payload = literalShellPayload(words.slice(head), name);
    // `sh -c -- 'script'`: the option terminator is not the script.
    if (payload === '--') payload = words[words.indexOf('--', head) + 1] ?? null;
    if (payload !== null) {
      // env assignments are inherited by the nested shell.
      for (const token of words.slice(0, head)) {
        const assignment = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(token ?? '');
        if (assignment) nested.vars.set(assignment[1], [assignment[2]]);
      }
      nestedPayload(payload, clone(nested), depth);
    }
    const locate = (p: string): Word => tokens.find((w) => w?.value === p) ?? { value: p };
    if (name === 'sed') {
      let inplace = false,
        hasScript = false,
        ended = false,
        scriptUnknown = false;
      const files: Word[] = [];
      const scriptParts: string[] = [];
      for (let i = 0; i < args.length; i++) {
        const token = args[i];
        if (!token) {
          hasScript = true;
          continue;
        }
        const value = token.value;
        if (!ended && value === '--') {
          ended = true;
          continue;
        }
        if (!ended && value.startsWith('--')) {
          if (/^--in-place(?:=|$)/.test(value)) inplace = true;
          else if (/^--(?:expression|file)(?:=|$)/.test(value)) {
            hasScript = true;
            const eq = value.indexOf('=');
            const script = eq < 0 ? args[++i] : { value: value.slice(eq + 1) };
            if (value.startsWith('--file')) {
              scriptUnknown = true;
              if (script) add('read', script, state);
            } else if (script?.value) scriptParts.push(script.value);
            else scriptUnknown = true;
          }
          continue;
        }
        if (!ended && value.startsWith('-') && value !== '-') {
          for (let j = 1; j < value.length; j++) {
            const flag = value[j];
            if (flag === 'i') {
              inplace = true;
              // BSD sed accepts a separate empty backup suffix.
              if (j === value.length - 1 && args[i + 1]?.value === '') i++;
              break;
            }
            if (flag === 'e' || flag === 'f') {
              hasScript = true;
              const script = value.slice(j + 1) ? { value: value.slice(j + 1) } : args[++i];
              if (flag === 'f') {
                scriptUnknown = true;
                if (script) add('read', script, state);
              } else if (script?.value) scriptParts.push(script.value);
              else scriptUnknown = true;
              break;
            }
            if (flag === 'l') {
              if (j === value.length - 1) i++;
              break;
            }
          }
          continue;
        }
        if (!hasScript) {
          hasScript = true;
          scriptParts.push(value);
        } else files.push(token);
      }
      const edits = inplace && !scriptUnknown ? sedSubstitutions(scriptParts.join('\n')) : null;
      for (const file of files)
        add(inplace ? 'write' : 'read', file, state, edits ? { edits } : {});
      return;
    }
    if (FS_READ_TOOLS.has(name) && name !== 'dd') {
      for (const p of readerPaths(words, head)) add('read', locate(p), state);
    }
    // A listing names a directory's entries without opening a file: its own
    // flag, so the rules about file content (password hashes, uploads) leave
    // it alone and the rule about another account's home sees it (fw#372 B9).
    if (['ls', 'tree', 'dir', 'vdir'].includes(name)) {
      for (const token of args) {
        if (!token || token.value.startsWith('-')) continue;
        add('read', token, state, { listing: true });
      }
    }
    if (name === 'dd') {
      for (const token of args)
        if (token && /^(?:if|of)=/.test(token.value)) {
          add(
            token.value.startsWith('if=') ? 'read' : 'write',
            {
              value: token.value.slice(3),
              ...(token.pattern ? { pattern: token.pattern.slice(3) } : {}),
              ...(token.dynamic ? { dynamic: true } : {}),
            },
            state
          );
        }
      return;
    }
    if (['cp', 'mv', 'install', 'ln'].includes(name)) {
      const operands: Word[] = [];
      let target: Word | null = null;
      let endFlags = false,
        noDirectory = false;
      const recursive = strings.some(
        (s) => /^-[^-]*[rRa]/.test(s) || ['--recursive', '--archive'].includes(s)
      );
      const preserveSourceLink = strings.some(
        (s) => /^-[^-]*[Pa]/.test(s) || s === '--no-dereference' || s === '--archive'
      );
      const linkOnly =
        name === 'cp' &&
        strings.some((s) => /^-[^-]*[sl]/.test(s) || s === '--symbolic-link' || s === '--link');
      const replaceDestLink =
        name === 'mv' || name === 'ln' || strings.includes('--remove-destination');
      for (let i = 0; i < args.length; i++) {
        const token = args[i];
        if (!token) continue;
        const s = token.value;
        if (!endFlags && s === '--') {
          endFlags = true;
          continue;
        }
        if (!endFlags && s.startsWith('-')) {
          if (s === '--no-target-directory' || /^-[^-]*T/.test(s)) noDirectory = true;
          const longTarget = /^--target-directory(?:=(.*))?$/.exec(s);
          // getopt stops a short bundle at the first option taking a value.
          // In -St, t is the backup suffix, not a target-directory flag.
          const valueLetters = name === 'install' ? 'tSmog' : 'tS';
          const shortValue = !s.startsWith('--')
            ? [...s.slice(1)].findIndex((letter) => valueLetters.includes(letter))
            : -1;
          const shortTarget =
            shortValue >= 0 && s[shortValue + 1] === 't' ? [s, s.slice(shortValue + 2)] : null;
          if (longTarget || shortTarget) {
            const value = (longTarget ?? shortTarget)![1];
            target = value ? { value } : (args[++i] ?? null);
          } else if (shortValue >= 0) {
            if (!s.slice(shortValue + 2)) i++;
          } else if (
            [
              '-S',
              '--suffix',
              '-m',
              '--mode',
              '-o',
              '--owner',
              '-g',
              '--group',
              '--context',
            ].includes(s)
          )
            i++;
          continue;
        }
        operands.push(token);
      }
      if (name === 'install' && strings.some((s) => s === '--directory' || /^-[^-]*d/.test(s)))
        return;
      target ??= operands.pop() ?? null;
      if (!target) return;
      const targetSpelling = target.value || (target.pattern as string);
      for (const source of operands) {
        if (name === 'mv') add('remove', source, state, { recursive: true, followFinal: false });
        else if (name !== 'ln' && !linkOnly)
          add('read', source, state, { recursive, followFinal: !preserveSourceLink, copy: true });
        if (!noDirectory)
          add(
            'write',
            {
              value: `${targetSpelling}/${base(source.value)}`,
              ...(target.pattern || source.pattern
                ? {
                    // A directory destination receives one basename, never an
                    // entire recursive source pattern (find's /** in particular).
                    pattern: `${target.pattern ?? quoteGlob(target.value)}/${source.pattern ? base(source.pattern).replace(/\*\*/g, '*') : quoteGlob(base(source.value))}`,
                  }
                : {}),
              ...(source.dot || target.dot ? { dot: true } : {}),
            },
            state,
            { directoryTarget: targetSpelling, followFinal: !replaceDestLink, recursive }
          );
      }
      // A directory destination gets the source basename. Recursing over the
      // destination itself would wrongly block copying ordinary docs to /etc.
      add('write', target, state, {
        followFinal: !replaceDestLink,
        recursive: recursive && noDirectory,
      });
      return;
    }
    if (['rm', 'unlink', 'shred', 'truncate', 'tee', 'touch'].includes(name)) {
      const valueFlags: Record<string, string[]> = {
        shred: ['-n', '--iterations', '-s', '--size', '--random-source'],
        truncate: ['-s', '--size', '-r', '--reference'],
        touch: ['-d', '--date', '-t', '-r', '--reference'],
      };
      let endFlags = false;
      for (let i = 0; i < args.length; i++) {
        const token = args[i];
        if (!token) continue;
        if (!endFlags && token.value === '--') {
          endFlags = true;
          continue;
        }
        if (!endFlags && token.value.startsWith('-')) {
          if (valueFlags[name]?.includes(token.value)) i++;
          continue;
        }
        if (name === 'touch' && strings.some((s) => s === '--no-create' || /^-[^-]*c/.test(s)))
          continue;
        const remove = name === 'rm' || name === 'unlink';
        const append =
          name === 'tee' && strings.some((s) => s === '--append' || /^-[^-]*a/.test(s));
        // `tee hook <<EOF`: the file gets the literal stdin text (fw#385).
        const teed = name === 'tee' && !append ? currentStdin : null;
        add(remove ? 'remove' : name === 'touch' ? 'create' : 'write', token, state, {
          recursive: remove && strings.some((s) => /^-[^-]*[rR]/.test(s) || s === '--recursive'),
          ...(append ? { append: true } : {}),
          ...(teed !== null ? { text: teed } : {}),
        });
      }
      return;
    }
    if (name === 'wget' || name === 'curl' || name === 'aria2c') {
      downloadOutputs(name, args, state);
      return;
    }
    if (['http', 'https', 'xh', 'xhs'].includes(name)) {
      // HTTPie and xh: `@F` is the raw body, `field@F` a multipart file,
      // `field=@F` a file's text as a field. URLs and headers are not files.
      for (const token of args) {
        if (!token || token.dynamic || /^[a-z][a-z0-9+.-]*:\/\//i.test(token.value)) continue;
        const m = /^(?:@|[^=:@\s]+@|[^=:@\s]*=@)(.+)$/.exec(token.value);
        if (m && m[1] !== '-') add('read', { value: m[1] }, state, { upload: true });
      }
      return;
    }
    if (name === 'scp' || name === 'rsync') {
      // A copy whose destination is a remote (`host:` or `user@host:`) sends
      // its sources off the machine.
      // Any operand after the first that names a remote: a trailing option
      // value (`--exclude tmp`) is not the destination.
      const operands = strings.filter((s) => s && !s.startsWith('-'));
      const remote = operands.slice(1).some((o) => /^[^/\s]+:/.test(o));
      for (const p of copySourcePaths(words))
        add('read', locate(p), state, remote ? { upload: true, copy: true } : { copy: true });
      return;
    }
    // Copy/archive source vocabulary already belongs to the credential jail.
    for (const p of copySourcePaths(words)) add('read', locate(p), state, { copy: true });
  }
  /**
   * The files a download writes. `-O F` / `-o F` name it; a server-chosen or
   * templated name (`-OJ`, `-o "f_#1"`, `wget -r`, `wget -i list`) is any
   * file under the directory (`D/*`, dotfiles included); otherwise the URL's
   * basename in the output directory. `-` is standard output. Header and
   * cookie dumps (`curl -D`, `-c`) and wget's logs (`-o`, `-a`) are writes too.
   */
  function downloadOutputs(name: string, args: Array<Word | null>, state: State): void {
    const valueShort = DOWNLOAD_SHORT_VALUE[name];
    const outputs: Word[] = [];
    const urls: string[] = [];
    // Assigned inside `take`; the cast keeps TypeScript from narrowing it to null.
    let dir = null as Word | null;
    let remoteName = false;
    let document = false;
    let serverNamed = false;
    const take = (flag: string, value: Word | null): void => {
      if (!value) return;
      const sent = uploadedFile(name, flag, value);
      if (sent) add('read', sent, state, { upload: true });
      if (DOWNLOAD_OUTPUT_FLAGS[name].includes(flag)) {
        // wget -O and aria2c -o name the downloaded file (stdout included), so
        // no URL basename is written; a log or a header dump does not.
        if (
          ['-O', '--output-document', '--out'].includes(flag) ||
          (name === 'aria2c' && flag === '-o')
        )
          document = true;
        if (value.value !== '-' || value.pattern || value.dynamic) outputs.push(value);
      } else if (DOWNLOAD_DIR_FLAGS[name].includes(flag)) dir = value;
      else if (name === 'wget' && (flag === '-i' || flag === '--input-file')) serverNamed = true;
    };
    for (let i = 0; i < args.length; i++) {
      const token = args[i];
      if (!token) continue;
      const v = token.value;
      if (v.startsWith('--')) {
        const eq = v.indexOf('=');
        const flag = eq < 0 ? v : v.slice(0, eq);
        if (['--remote-name', '--remote-name-all'].includes(flag)) remoteName = true;
        if (['--remote-header-name', '--recursive', '--mirror', '--page-requisites'].includes(flag))
          serverNamed = true;
        if (DOWNLOAD_LONG_VALUE[name].includes(flag))
          take(flag, eq < 0 ? (args[++i] ?? null) : { ...token, value: v.slice(eq + 1) });
        continue;
      }
      if (v.startsWith('-') && v.length > 1 && !token.dynamic) {
        for (let j = 1; j < v.length; j++) {
          const c = v[j];
          // wget's -nc, -nd, -nH, -np, -nv: two letters, no value.
          if (name === 'wget' && c === 'n') {
            j++;
            continue;
          }
          if (name === 'curl' && c === 'O') remoteName = true;
          if (name === 'curl' && c === 'J') serverNamed = true;
          if (name === 'wget' && (c === 'r' || c === 'm' || c === 'p')) serverNamed = true;
          if (valueShort.includes(c)) {
            const rest = v.slice(j + 1);
            take(`-${c}`, rest ? { value: rest } : (args[++i] ?? null));
            break;
          }
        }
        continue;
      }
      if (/^(?:https?|ftps?):\/\//i.test(v)) urls.push(v);
    }
    for (const out of outputs) {
      // aria2c's -o names a file inside its -d directory.
      const spelled =
        name === 'aria2c' && dir?.value && !out.value.startsWith('/')
          ? { ...out, value: `${dir.value.replace(/\/+$/, '')}/${out.value}` }
          : out;
      // curl's -o "file_#1" names files from the URL glob: any file there.
      if (name === 'curl' && /#\d/.test(spelled.value))
        add('write', { value: '', pattern: spelled.value.replace(/#\d+/g, '*'), dot: true }, state);
      else add('write', spelled, state);
    }
    const remote = name === 'curl' ? remoteName || serverNamed : !document || serverNamed;
    if (!remote) return;
    const into = dir?.value ? dir.value.replace(/\/+$/, '') : '.';
    if (serverNamed || urls.length === 0) {
      add('write', { value: '', pattern: `${quoteGlob(into)}/*`, dot: true }, state);
      return;
    }
    for (const url of urls) {
      const file = url
        .replace(/[?#].*$/, '')
        .replace(/^[a-z]+:\/\/[^/]*/i, '')
        .split('/')
        .pop();
      add('write', { value: `${into}/${file || 'index.html'}` }, state);
    }
  }
  function findActions(
    tokens: Array<Word | null>,
    words: (string | null)[],
    head: number,
    state: State,
    nested: State,
    depth: number
  ): void {
    const starts = findStartPoints(words, head).starts;
    const roots = (starts.length ? starts : ['.']).slice(0, MAX_ALTERNATIVES);
    for (const start of starts.slice(0, MAX_ALTERNATIVES))
      add('read', { value: start }, state, { listing: true });
    // Literal -name/-path tests and -maxdepth narrow what an action can reach.
    // Without them every entry below the start points is a candidate.
    let nameFilter: string | null = null;
    let pathFilter: string | null = null;
    let shallow = false;
    // Narrow only a plain conjunction of tests: negation, alternation and
    // grouping can make a later -name exclude rather than select.
    const end = words.findIndex(
      (w, k) => k > head && ['-exec', '-execdir', '-ok', '-okdir'].includes(w ?? '')
    );
    const expression = words.slice(head + 1, end < 0 ? words.length : end);
    const plain = !expression.some((w) =>
      ['!', '-not', '-o', '-or', '(', ')', ','].includes(w ?? '')
    );
    for (let i = head + 1; plain && i < tokens.length; i++) {
      const next = tokens[i + 1];
      if (!next || next.dynamic) continue;
      const flag = words[i];
      if ((flag === '-name' || flag === '-iname') && !next.value.includes('/'))
        nameFilter = next.value;
      // find matches -path against the whole path; only an absolute pattern
      // can stand in for the start points.
      if (
        (flag === '-path' || flag === '-ipath' || flag === '-wholename') &&
        next.value.startsWith('/')
      )
        pathFilter = next.value;
      if (flag === '-maxdepth' && /^[01]$/.test(next.value)) shallow = true;
    }
    const reach = (start: string): string => {
      const root = start.replace(/\/+$/, '');
      return pathFilter ?? `${root}${shallow ? '' : '/**'}/${nameFilter ?? '*'}`;
    };
    for (let i = head + 1; i < tokens.length; i++) {
      const flag = words[i];
      if (flag === '-delete') {
        for (const start of roots) {
          const pattern = reach(start);
          add('remove', { value: pattern, pattern, dot: true }, state, { recursive: true });
        }
        continue;
      }
      if (['-fprint', '-fprint0', '-fprintf', '-fls'].includes(flag ?? '') && tokens[i + 1]) {
        add('write', tokens[i + 1] as Word, state);
        continue;
      }
      if (!['-exec', '-execdir', '-ok', '-okdir'].includes(flag ?? '')) continue;
      let end = i + 1;
      while (end < tokens.length && ![';', '+'].includes(words[end] ?? '')) end++;
      if (depth < MAX_PAYLOAD_DEPTH && payloads-- > 0) {
        for (const start of roots) {
          const action = tokens.slice(i + 1, end).map((word) => {
            if (!word || !word.value.includes('{}')) return word;
            const pattern = word.value.replaceAll('{}', reach(start));
            return { value: pattern, pattern, dot: true };
          });
          fromWords(action, clone(state), clone(nested), depth + 1);
        }
      }
      i = end;
    }
  }
  function call(cmd: any, state: State, depth: number): void {
    const nested = clone(state);
    assignments(cmd.Assigns, nested);
    const nodes: any[] = cmd.Args ?? [];
    if (nodes.length && resolveWordLiteral(nodes[0]) === 'set')
      setPositionals(nodes.slice(1), state);
    for (const node of [...nodes, ...(cmd.Assigns ?? []).map((a: any) => a.Value)])
      substitutions(node, state, depth);
    if (!nodes.length) {
      state.vars = nested.vars;
      return;
    }
    let alternatives: Array<Array<Word | null>> = [[]];
    for (const node of nodes) {
      const words = wordValues(node, state);
      alternatives = alternatives
        .flatMap((prefix) => (words.length ? words : [null]).map((w) => [...prefix, w]))
        .slice(0, MAX_ALTERNATIVES);
    }
    for (const tokens of alternatives) {
      fromWords(tokens, state, nested, depth);
      inlineCall(tokens, state, depth);
    }
  }
  /** `set -- a b` (or `set a b`) sets $1, $2, "$@" for the rest of the script. */
  function setPositionals(nodes: any[], state: State): void {
    const words = nodes.map((n) => resolveWordLiteral(n));
    const end = words.indexOf('--');
    let args: (string | null)[];
    if (end >= 0) args = words.slice(end + 1);
    else if (words.length && words[0] !== null && !/^[-+]/.test(words[0])) args = words;
    else return;
    for (const name of POSITIONAL) state.vars.delete(name);
    args.slice(0, 9).forEach((v, i) => state.vars.set(String(i + 1), v === null ? null : [v]));
    const all = args.every((v) => v !== null) && args.length ? unique(args as string[]) : null;
    state.vars.set('@', all);
    state.vars.set('*', all);
    state.vars.set('#', [String(args.length)]);
  }
  /**
   * `while read f; do ...; done <<< TEXT` (or a heredoc, or `echo TEXT |`):
   * the names `read` sets hold the text's lines and words. Every name gets
   * every word and line: wider than bash, never narrower.
   */
  function bindReadLoop(loop: any, text: string | null, state: State): void {
    if (text === null) return;
    const conds: any[] = loop.Cond ?? [];
    const last = conds[conds.length - 1]?.Cmd;
    if (!last || last.kind !== 'CallExpr') return;
    const words = (last.Args ?? []).map((a: any) => resolveWordLiteral(a));
    if (words[0] !== 'read' || words.some((w: string | null) => w === null)) return;
    const names: string[] = [];
    for (let i = 1; i < words.length; i++) {
      const w = words[i] as string;
      if (/^-[dnNptua]$/.test(w)) {
        if (w === '-a' && words[i + 1]) names.push(words[i + 1] as string);
        i++;
      } else if (!w.startsWith('-')) names.push(w);
    }
    if (!names.length) names.push('REPLY');
    const lines = text
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean);
    const values = unique([...lines, ...lines.flatMap((l) => l.split(/\s+/))]).slice(
      0,
      MAX_ALTERNATIVES
    );
    for (const name of names) state.vars.set(name, values.length ? values : null);
  }
  /**
   * `echo a b | xargs CMD ARGS`: the command xargs runs, as a script, when the
   * piped text is literal. `-I R` substitutes each item; otherwise the items
   * are appended. Null when the text or the xargs words are not literal.
   */
  function xargsPayload(stmt: any, text: string | null): string | null {
    const cmd = stmt?.Cmd;
    if (text === null || !cmd || cmd.kind !== 'CallExpr') return null;
    const words = (cmd.Args ?? []).map((a: any) => resolveWordLiteral(a));
    if (words.some((w: string | null) => w === null)) return null;
    // unwrapCommandHead steps over xargs itself (a wrapper of its command), so
    // xargs is found among the words before the command it runs.
    const head = words
      .slice(0, unwrapCommandHead(words) + 1)
      .findIndex((w: string | null) => base(w) === 'xargs');
    if (head < 0) return null;
    let sep: string | null = null;
    let replace: string | null = null;
    let i = head + 1;
    for (; i < words.length; i++) {
      const w = words[i] as string;
      if (w === '--') {
        i++;
        break;
      }
      if (!w.startsWith('-')) break;
      if (w === '-0' || w === '--null') sep = '\0';
      else if (w === '-I') replace = (words[++i] as string) ?? null;
      else if (w.startsWith('-I')) replace = w.slice(2);
      else if (w === '-i' || w === '--replace') replace = '{}';
      else if (w.startsWith('-i')) replace = w.slice(2);
      else if (w.startsWith('--replace=')) replace = w.slice('--replace='.length);
      else if (w === '-d') sep = (words[++i] as string) ?? null;
      else if (w.startsWith('-d')) sep = w.slice(2);
      else if (w.startsWith('--delimiter=')) sep = w.slice('--delimiter='.length);
      else if (/^-[nLPsEa]$/.test(w)) i++;
    }
    const run = (words.slice(i) as string[]).length ? (words.slice(i) as string[]) : ['echo'];
    if (sep === '\\n') sep = '\n';
    // Every item: a name past the 64th must not escape (second review).
    const items = (sep === null ? text.split(/\s+/) : text.split(sep))
      .map((t) => (sep === null ? t : t.trim()))
      .filter(Boolean);
    if (!items.length) return null;
    const q = (w: string): string => `'${w.replace(/'/g, `'\\''`)}'`;
    // Without -I the items are appended once: the script grows with the input.
    if (!replace) return [...run, ...items].map(q).join(' ');
    // `-I X` with many X multiplies the command by the item count. Past a
    // bound, each item still reaches the command it runs, as its only operand:
    // the names are never dropped (a dropped name was a bypass).
    const lines = items.map((it) =>
      run.map((w) => q(w.split(replace as string).join(it))).join(' ')
    );
    const size = lines.reduce((n, l) => n + l.length + 1, 0);
    if (size <= MAX_XARGS_PAYLOAD) return lines.join('\n');
    return items.map((it) => `${q(run[0])} ${q(it)}`).join('\n');
  }
  /**
   * A call of a function defined in this script: walk its body again with $1..
   * bound to the call's literal arguments ("$@" and $* hold every argument as
   * alternatives). A dynamic argument is unknown; a body that uses `shift` gets
   * no bindings. The builtin reading of the same words was already walked, so a
   * function that shadows `rm` or `cat` hides nothing.
   */
  function inlineCall(tokens: Array<Word | null>, state: State, depth: number): void {
    const head = tokens[0];
    if (!head || head.dynamic || head.pattern) return;
    const bodies = functions.get(head.value);
    if (!bodies || (state.callDepth ?? 0) >= MAX_CALL_DEPTH) return;
    const args = tokens.slice(1).map((a) => (a && !a.dynamic ? a.value : null));
    // The variables in force are part of the call's meaning: the body may read them.
    const vars = JSON.stringify([...state.vars].sort(([a], [b]) => (a < b ? -1 : 1)));
    const key = `${head.value}\u0000${JSON.stringify(args)}\u0000${state.cwd.join('\u0001')}\u0000${vars}`;
    if (seenCalls.has(key)) return;
    seenCalls.add(key);
    for (const body of bodies) {
      if (callWalks-- <= 0) return;
      const local = clone(state);
      local.callDepth = (state.callDepth ?? 0) + 1;
      for (const name of POSITIONAL) local.vars.delete(name);
      if (!rebindsPositionals(body)) {
        args.slice(0, 9).forEach((v, i) => local.vars.set(String(i + 1), v === null ? null : [v]));
        const all = args.every((v) => v !== null) && args.length ? unique(args as string[]) : null;
        local.vars.set('@', all);
        local.vars.set('*', all);
        local.vars.set('#', [String(args.length)]);
      }
      statement(body, local, depth + 1);
    }
  }
  /** A shell with no script operand reads its program from stdin. */
  function readsScriptFromStdin(stmt: any): boolean {
    const cmd = stmt?.Cmd;
    if (!cmd || cmd.kind !== 'CallExpr') return false;
    const words = (cmd.Args ?? []).map((a: any) => resolveWordLiteral(a));
    const head = unwrapCommandHead(words);
    return SHELL_INTERPRETERS.has(base(words[head])) && shellConsumesPipe(words.slice(head + 1));
  }
  /** The literal text a statement feeds to stdin: a heredoc or a herestring. */
  function stdinText(stmt: any): string | null {
    for (const redir of stmt?.Redirs ?? []) {
      if (redir.Hdoc) return resolveWordLiteral(redir.Hdoc);
      if (redir.Op === ops().HERE_STRING) return resolveWordLiteral(redir.Word);
    }
    return null;
  }
  /** The literal text a pipeline stage writes: `cat <<EOF`, `echo ...`, `printf '...'`. */
  function producedText(stmt: any): string | null {
    const cmd = stmt?.Cmd;
    if (!cmd || cmd.kind !== 'CallExpr') return null;
    const words: (string | null)[] = (cmd.Args ?? []).map((a: any) => resolveWordLiteral(a));
    if (words.some((w) => w === null)) return null;
    const head = unwrapCommandHead(words);
    const name = base(words[head]);
    const rest = words.slice(head + 1) as string[];
    if (name === 'cat' && rest.length === 0) return stdinText(stmt);
    if (name === 'echo') return rest.filter((w) => !/^-[neE]+$/.test(w)).join(' ');
    const unescape = (t: string): string =>
      t.replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\0/g, '\0');
    if (name === 'printf' && rest[0] === '--') rest.shift();
    if (name === 'printf' && rest.length === 1 && !rest[0].includes('%')) return unescape(rest[0]);
    // `printf '%s\n' a b`: each argument, then the separator.
    if (name === 'printf' && rest.length > 1 && /^%s(\\n|\\0|\\t| )?$/.test(rest[0])) {
      const sep = unescape(rest[0].slice(2)) || '';
      return rest
        .slice(1)
        .map((a) => a + sep)
        .join('');
    }
    return null;
  }
  /** `bash <<EOF`, `bash <<< '...'`: the shell runs its stdin text. */
  function stdinScript(stmt: any, state: State, depth: number): void {
    if (readsScriptFromStdin(stmt)) nestedPayload(stdinText(stmt), clone(state), depth);
  }
  function statement(stmt: any, state: State, depth: number): void {
    if (!stmt || depth > MAX_DEPTH) return;
    state.onSuccess = undefined;
    if (stmt.Background) state = clone(state);
    // `nc host 9000 < F`: a network tool's standard input leaves the machine.
    const headWord =
      stmt.Cmd && stmt.Cmd.kind === 'CallExpr' ? base(resolveWordLiteral(stmt.Cmd.Args?.[0])) : '';
    const sends = SENDING_STDIN.has(headWord);
    // What a `>` redirect puts in the file, when every word of it is literal
    // (`cat <<EOF`, `echo`, `printf`): the hook-file check judges the text
    // instead of counting every shell write as an overwrite (fw#385).
    let produced: string | null | undefined;
    for (const redir of stmt.Redirs ?? []) {
      substitutions(redir.Word, state, depth);
      for (const word of wordValues(redir.Word, state)) {
        if (ops().WRITES.has(redir.Op)) {
          if (ops().APPENDS.has(redir.Op)) add('write', word, state, { append: true });
          else {
            // Only stdout carries the produced text; `2> hook` truncates the
            // file with stderr, whatever the command prints.
            const stdout = redir.N == null || redir.N.Value === '1';
            if (stdout && produced === undefined) produced = producedText(stmt);
            add('write', word, state, stdout && produced ? { text: produced } : {});
          }
        }
        if (ops().READS.has(redir.Op)) add('read', word, state, sends ? { upload: true } : {});
        if (redir.Op === ops().DUP_OUT && word.value && !/^\d+$/.test(word.value))
          add('write', word, state);
      }
      // An unquoted heredoc can execute substitutions, but its text is not argv.
      substitutions(redir.Hdoc, state, depth);
    }
    const cmd = stmt.Cmd;
    if (!cmd) return;
    stdinScript(stmt, state, depth);
    // `xargs CMD <<< NAMES`: the names reach CMD as operands.
    const fedText = stdinText(stmt);
    if (fedText !== null) nestedPayload(xargsPayload(stmt, fedText), clone(state), depth);
    currentStdin = fedText;
    switch (cmd.kind) {
      case 'CallExpr':
        call(cmd, state, depth);
        break;
      case 'DeclClause':
        for (const item of cmd.Args ?? []) substitutions(item.Value, state, depth);
        assignments(cmd.Args, state);
        break;
      case 'BinaryCmd': {
        // Lists nest to the left, so a long `a && b && ...` chain is walked
        // iteratively: its first command must not fall outside the depth budget.
        const segments: Array<{ op: number; part: any }> = [];
        let node = cmd;
        for (;;) {
          segments.unshift({ op: node.Op, part: node.Y });
          const left = node.X;
          if (
            left?.Cmd &&
            left.Cmd.kind === 'BinaryCmd' &&
            !left.Redirs?.length &&
            !left.Negated &&
            !left.Background
          )
            node = left.Cmd;
          else {
            segments.unshift({ op: node.Op, part: left });
            break;
          }
        }
        // A list may stop at any command, and a `cd` in it may fail, so the
        // state after the list is the union of every state seen in it. Inside
        // a pure `&&` chain a command runs only if its predecessor succeeded,
        // so it may use the predecessor's onSuccess directory. A `||` command
        // runs after a failure anywhere before it. Pipeline stages are
        // subshells; a literal script piped into a shell is parsed as code.
        const seen = clone(state);
        let pureAnd = true;
        segments.forEach(({ op, part }, i) => {
          if (op === ops().AND || op === ops().OR) {
            if (i > 0 && op === ops().AND && pureAnd && state.onSuccess)
              state.cwd = state.onSuccess;
            if (i > 0 && op === ops().OR) merge(state, seen);
            statement(part, state, depth + 1);
          } else {
            const fed = i > 0 ? producedText(segments[i - 1].part) : null;
            if (fed !== null) pipedStdin.set(part, fed);
            statement(part, clone(state), depth + 1);
            if (i > 0 && readsScriptFromStdin(part))
              nestedPayload(producedText(segments[i - 1].part), clone(state), depth);
            // `echo NAMES | xargs CMD`: the names reach CMD as operands.
            if (fed !== null) nestedPayload(xargsPayload(part, fed), clone(state), depth);
          }
          if (i > 0 && op !== ops().AND) pureAnd = false;
          merge(seen, state);
        });
        merge(state, seen);
        state.onSuccess = undefined;
        break;
      }
      case 'Block':
        statements(cmd.Stmts, state, depth + 1);
        break;
      case 'Subshell':
        statements(cmd.Stmts, clone(state), depth + 1);
        break;
      case 'IfClause': {
        let branch = cmd;
        while (branch) {
          const local = clone(state);
          statements(branch.Cond, local, depth + 1);
          statements(branch.Then, local, depth + 1);
          merge(state, local);
          branch = branch.Else;
        }
        break;
      }
      case 'WhileClause': {
        const local = clone(state);
        bindReadLoop(cmd, stdinText(stmt) ?? pipedStdin.get(stmt) ?? null, local);
        statements(cmd.Cond, local, depth + 1);
        statements(cmd.Do, local, depth + 1);
        merge(state, local);
        break;
      }
      case 'ForClause': {
        const local = clone(state);
        if (cmd.Loop?.Name?.Value && !(cmd.Loop.Items ?? []).length) {
          // `for f; do ...` loops over "$@".
          local.vars.set(cmd.Loop.Name.Value, state.vars.get('@') ?? null);
        } else if (cmd.Loop?.Name?.Value) {
          const items = (cmd.Loop.Items ?? []).flatMap((w: any) => wordValues(w, state));
          local.vars.set(
            cmd.Loop.Name.Value,
            items.length && !items.some((w: Word) => w.dynamic)
              ? items.map((w: Word) => w.value)
              : null
          );
        }
        statements(cmd.Do, local, depth + 1);
        merge(state, local);
        break;
      }
      case 'CaseClause':
        for (const item of cmd.Items ?? []) {
          const local = clone(state);
          statements(item.Stmts, local, depth + 1);
          merge(state, local);
        }
        break;
      case 'FuncDecl':
        statement(cmd.Body, clone(state), depth + 1);
        break;
      case 'TimeClause':
      case 'CoprocClause':
        statement(cmd.Stmt, state, depth + 1);
        break;
      default:
        // Test, arithmetic and let clauses have no file operands of their own,
        // but the substitutions inside them still run.
        substitutions(cmd, state, depth);
    }
  }
  function statements(stmts: any[], state: State, depth: number): void {
    for (const stmt of stmts ?? []) statement(stmt, state, depth);
  }
  const parsed = parseShared(command);
  const program = typeof parsed !== 'symbol' ? parsed : runnablePrefix(command);
  if (program) {
    for (const [name, bodies] of functionBodies(program)) functions.set(name, bodies);
    statements(program.Stmts ?? [], initial, 0);
  }
  return out;
}
