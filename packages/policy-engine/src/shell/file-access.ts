// mvdan-sh exposes untyped AST nodes. Only this adapter knows their shape.
/* eslint-disable @typescript-eslint/no-explicit-any */
import mvdanSh from 'mvdan-sh';
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
} from './index';
import { type FileAccess, type FileAccessContext } from '../files/paths';

const { syntax } = mvdanSh as any;
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
}
const MAX_ALTERNATIVES = 64;
const MAX_DEPTH = 64;
const MAX_PAYLOAD_DEPTH = 24;
const unique = (a: string[]): string[] => [...new Set(a)].slice(0, MAX_ALTERNATIVES);
const clone = (s: State): State => ({ cwd: [...s.cwd], vars: new Map(s.vars) });
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
const WRITES = new Set(['>x', '>>x', '>|x', '&>x', '&>>x', '<>x'].map(opOf));
const READS = new Set(['<x', '<>x'].map(opOf));
/** `>&word` with a non-numeric word is `&>word` in bash. */
const DUP_OUT = opOf('>&x');
const AND = parseShared('a && b').Stmts[0].Cmd.Op;
const OR = parseShared('a || b').Stmts[0].Cmd.Op;
/** `${x:-d}` `${x-d}` `${x:=d}` `${x=d}`: the default is the value when x is unset. */
const DEFAULT_OPS = new Set<number>(
  ['${x:-y}', '${x-y}', '${x:=y}', '${x=y}'].map(
    (s) => parseShared(`echo ${s}`).Stmts[0].Cmd.Args[1].Parts[0].Exp.Op
  )
);

function wordValues(word: any, state: State): Word[] {
  const toWords = (values: string[], quoted: boolean): Word[] =>
    values.map((value) => ({
      value,
      ...(!quoted && /[*?[{]/.test(value) ? { pattern: value } : {}),
    }));
  // A null result means the part cannot be resolved; the caller keeps the
  // literal prefix gathered so far and marks the word dynamic.
  const paramValues = (node: any, quoted: boolean): Word[] | null => {
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
      if (!DEFAULT_OPS.has(node.Exp.Op)) return null;
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
      const kind = syntax.NodeType(node);
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
  return out.map((piece) =>
    dynamic ? { value: piece.value, pattern: piece.pattern + '*', dynamic: true } : asWord(piece)
  );
}

/** No verdict cache: cwd, homes, assignments, and host state belong to each call. */
export function collectShellFileAccesses(
  command: string,
  context: FileAccessContext = {}
): FileAccess[] {
  const out: FileAccess[] = [];
  let payloads = 256;
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
      if (!item.Name?.Value || !item.Value) continue;
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
    syntax.Walk(word, (node: any) => {
      if (!node) return false;
      if (['CmdSubst', 'ProcSubst'].includes(syntax.NodeType(node))) {
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
      // `cd -` returns to a directory this analysis does not track.
      if (args.some((w) => w?.value === '-')) return;
      const home = nested.vars.get('HOME')?.[0] ?? '~';
      const target = args.find((w) => w && !w.value.startsWith('-')) ?? { value: home };
      if (!target.value || target.pattern || target.dynamic) return;
      const expanded =
        target.value === '~' || target.value.startsWith('~/')
          ? home + target.value.slice(1)
          : target.value;
      // After an absolute cd the shell is in exactly one place. A relative
      // target keeps every prior candidate.
      state.cwd =
        expanded.startsWith('/') || expanded.startsWith('~')
          ? [expanded]
          : unique([...state.cwd, ...state.cwd.map((cwd) => `${cwd}/${expanded}`)]);
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
        ended = false;
      const files: Word[] = [];
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
            if (value.startsWith('--file') && script) add('read', script, state);
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
              if (flag === 'f' && script) add('read', script, state);
              break;
            }
            if (flag === 'l') {
              if (j === value.length - 1) i++;
              break;
            }
          }
          continue;
        }
        if (!hasScript) hasScript = true;
        else files.push(token);
      }
      for (const file of files) add(inplace ? 'write' : 'read', file, state);
      return;
    }
    if (FS_READ_TOOLS.has(name) && name !== 'dd') {
      for (const p of readerPaths(words, head)) add('read', locate(p), state);
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
          add('read', source, state, { recursive, followFinal: !preserveSourceLink });
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
        add(remove ? 'remove' : name === 'touch' ? 'create' : 'write', token, state, {
          recursive: remove && strings.some((s) => /^-[^-]*[rR]/.test(s) || s === '--recursive'),
        });
      }
      return;
    }
    // Copy/archive source vocabulary already belongs to the credential jail.
    for (const p of copySourcePaths(words)) add('read', locate(p), state);
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
    // Literal -name/-path tests and -maxdepth narrow what an action can reach.
    // Without them every entry below the start points is a candidate.
    let nameFilter: string | null = null;
    let pathFilter: string | null = null;
    let shallow = false;
    for (let i = head + 1; i < tokens.length; i++) {
      const next = tokens[i + 1];
      if (!next || next.dynamic) continue;
      const flag = words[i];
      if ((flag === '-name' || flag === '-iname') && !next.value.includes('/'))
        nameFilter = next.value;
      if (flag === '-path' || flag === '-ipath' || flag === '-wholename') pathFilter = next.value;
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
    for (const tokens of alternatives) fromWords(tokens, state, nested, depth);
  }
  /** `bash <<EOF ... EOF`: a shell with no script operand runs the heredoc. */
  function heredocScript(stmt: any, cmd: any, state: State, depth: number): void {
    const hdoc = (stmt.Redirs ?? []).find((r: any) => r.Hdoc);
    if (!hdoc || syntax.NodeType(cmd) !== 'CallExpr') return;
    const words = (cmd.Args ?? []).map((a: any) => resolveWordLiteral(a));
    const head = unwrapCommandHead(words);
    if (!SHELL_INTERPRETERS.has(base(words[head])) || !shellConsumesPipe(words.slice(head + 1)))
      return;
    nestedPayload(resolveWordLiteral(hdoc.Hdoc), clone(state), depth);
  }
  function statement(stmt: any, state: State, depth: number): void {
    if (!stmt || depth > MAX_DEPTH) return;
    if (stmt.Background) state = clone(state);
    for (const redir of stmt.Redirs ?? []) {
      substitutions(redir.Word, state, depth);
      for (const word of wordValues(redir.Word, state)) {
        if (WRITES.has(redir.Op)) add('write', word, state);
        if (READS.has(redir.Op)) add('read', word, state);
        if (redir.Op === DUP_OUT && word.value && !/^\d+$/.test(word.value))
          add('write', word, state);
      }
      // An unquoted heredoc can execute substitutions, but its text is not argv.
      substitutions(redir.Hdoc, state, depth);
    }
    const cmd = stmt.Cmd;
    if (!cmd) return;
    heredocScript(stmt, cmd, state, depth);
    switch (syntax.NodeType(cmd)) {
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
            syntax.NodeType(left.Cmd) === 'BinaryCmd' &&
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
        // In an && / || list each command sees the state its predecessors
        // produced. The list may stop early, so the state from before it is
        // retained for whatever follows. Pipeline stages run in subshells.
        const before = clone(state);
        for (const { op, part } of segments) {
          if (op === AND || op === OR) statement(part, state, depth + 1);
          else statement(part, clone(state), depth + 1);
        }
        merge(state, before);
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
        statements(cmd.Cond, local, depth + 1);
        statements(cmd.Do, local, depth + 1);
        merge(state, local);
        break;
      }
      case 'ForClause': {
        const local = clone(state);
        if (cmd.Loop?.Name?.Value) {
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
  if (typeof parsed !== 'symbol') statements(parsed.Stmts, initial, 0);
  else {
    // bash runs the lines before a syntax error. Inspect each line that
    // parses on its own rather than treating the whole command as opaque.
    for (const line of command.split('\n')) {
      const f = parseShared(line);
      if (typeof f !== 'symbol') statements(f.Stmts ?? [], initial, 0);
    }
  }
  return out;
}
