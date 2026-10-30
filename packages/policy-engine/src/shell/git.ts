// packages/policy-engine/src/shell/git.ts
// The git checks, decided from the parsed command (node9Firewall#413).
//
// Until this module the git rules were two regexes anchored at the start of a
// command, so a destructive call written indirectly passed: `cmd="reset
// --hard"; git $cmd`, `git config alias.x 'reset --hard' && git x`,
// `git -C ../app reset --hard`, `env GIT_DIR=.git git reset --hard`,
// `timeout 30 git clean -fd`, `sh -c 'git push -f'`. And four ordinary
// commands were stopped: `git push --dry-run --force`, `git clean -fn`,
// `git branch -d x` (lowercase -d refuses an unmerged branch) and a plain
// `git rebase`.
//
// Here every git invocation is read from the shell AST the credential jail
// already walks, in the same scope: variables assigned earlier in the same
// command resolve, wrappers are peeled, `sh -c` / `eval` payloads and a
// heredoc into a shell are re-parsed, functions are inlined at their calls,
// git's own global options are skipped, and an alias defined in the same
// command expands at its use. Then one classifier per subcommand reads the
// flags as git does (short options bundle: `-fn` is `-f` and `-n`).
//
// The resolution steps only ever ADD invocations: a wrong expansion is a
// false positive, a missed one is what the regex did before. A command that
// does not parse is reported as such, and the regex rules keep speaking for
// it (policy/index.ts, astSuppressed).

import mvdanSh from 'mvdan-sh';
import {
  baseWord,
  literalShellPayload,
  parseShared,
  resolveWordLiteral,
  resolveWordPrefix,
  unwrapCommandHead,
  walkCommandScope,
} from './index';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const { syntax } = mvdanSh as any;

export type GitCheckId = 'commands.git-destructive' | 'commands.git-hooks-bypass';

export interface GitFinding {
  checkId: GitCheckId;
  /** The rule name the audit log and the catalog's legacy table know. */
  ruleName: 'review-force-push' | 'review-git-destructive' | 'review-git-hooks-bypass';
  reason: string;
  description: string;
  /** The invocation as resolved, for the reason and the explain trace. */
  shown: string;
}

export interface GitAnalysis {
  /** False when mvdan-sh could not parse the command: nothing was judged. */
  parsed: boolean;
  findings: GitFinding[];
}

/** One git invocation after resolution. */
export interface GitInvocation {
  /** The subcommand, or null when it could not be read (a dynamic word). */
  sub: string | null;
  /** The words after the subcommand; null marks a dynamic word. */
  args: (string | null)[];
  /** `-c key=value` pairs given before the subcommand, lowercased keys. */
  config: Map<string, string>;
  /** Assignments applied to this call (`HUSKY=0 git …`, `env K=V git …`). */
  env: Map<string, string | null>;
  /** How the call was written, for the reason. */
  shown: string;
}

/** `git` in any spelling, or a husky hook (`.husky/` holds no "git"). */
const GIT_PRESCREEN_RE = /git|husky/i;
const MAX_PAYLOAD_DEPTH = 8;
const MAX_ALIAS_DEPTH = 5;
const CACHE_MAX = 2_000;
const cache = new Map<string, GitAnalysis>();

/**
 * Every git finding in a shell command. Cached by the raw text; pure.
 */
export function analyzeGit(command: string): GitAnalysis {
  // Cheap pre-check: a command with no `git` in any spelling (`g''it`
  // resolves after the quotes go) has no git invocation.
  if (!GIT_PRESCREEN_RE.test(command.replace(/[\\'"]/g, ''))) {
    return { parsed: true, findings: [] };
  }
  const hit = cache.get(command);
  if (hit) {
    cache.delete(command);
    cache.set(command, hit);
    return hit;
  }
  const computed = analyzeGitImpl(command);
  if (cache.size >= CACHE_MAX) {
    const oldest = cache.keys().next().value;
    if (oldest !== undefined) cache.delete(oldest);
  }
  cache.set(command, computed);
  return computed;
}

/** The git invocations a command makes, resolved. Exposed for the explain trace and tests. */
export function gitInvocations(command: string): GitInvocation[] {
  const out: GitInvocation[] = [];
  const walk = new GitWalk(
    (inv) => out.push(inv),
    () => undefined
  );
  walk.run(command, 0);
  return out;
}

function analyzeGitImpl(command: string): GitAnalysis {
  const findings: GitFinding[] = [];
  const seen = new Set<string>();
  const found = (f: GitFinding): void => {
    const key = `${f.ruleName}\u0000${f.shown}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push(f);
  };
  const walk = new GitWalk((inv) => classify(inv).forEach(found), found);
  const parsed = walk.run(command, 0);
  return { parsed, findings };
}

// ── The walk ─────────────────────────────────────────────────────────────────

/** Shells whose literal payload (`-c`, a heredoc on stdin) is a command of its own. */
const PAYLOAD_SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'eval']);
/** The scopes `git config` takes before the key; all mean "write the alias". */
const CONFIG_SCOPE_FLAGS = new Set([
  '--global',
  '--local',
  '--system',
  '--worktree',
  '--add',
  '--replace-all',
]);
/** `git config` options that take a value and sit before the key. */
const CONFIG_VALUE_FLAGS = new Set(['-f', '--file', '--blob', '-t', '--type']);

/**
 * git's own options before the subcommand (`git [options] <command>`), as
 * `git --help` lists them. Each is skipped so the subcommand is read where
 * git reads it; `-c` is kept because it may define an alias or a hook path.
 */
const GLOBAL_VALUE_OPTIONS = new Set([
  '-C',
  '-c',
  '--git-dir',
  '--work-tree',
  '--namespace',
  '--exec-path',
  '--super-prefix',
  '--config-env',
  '--list-cmds',
  '--attr-source',
]);
const GLOBAL_FLAG_OPTIONS = new Set([
  '-p',
  '-P',
  '--paginate',
  '--no-pager',
  '--bare',
  '--no-replace-objects',
  '--no-lazy-fetch',
  '--no-optional-locks',
  '--no-advice',
  '--literal-pathspecs',
  '--glob-pathspecs',
  '--noglob-pathspecs',
  '--icase-pathspecs',
]);

/** The most iterations of a `for` loop expanded for its variable. */
const MAX_LOOP_ITEMS = 64;

class GitWalk {
  /** Aliases defined earlier in this command: name -> value (null = dynamic). */
  private aliases = new Map<string, string | null>();
  private payloads = new Set<string>();
  /** `for NAME in a b c`: the literal items, or null when one is dynamic. */
  private loopVars = new Map<string, string[] | null>();

  constructor(
    private readonly emit: (inv: GitInvocation) => void,
    /** A finding made outside an invocation (a chmod on a hook file). */
    private readonly found: (f: GitFinding) => void
  ) {}

  /** Walk one command string. Returns false when it did not parse. */
  run(command: string, depth: number): boolean {
    let status: 'ok' | 'parse-fail';
    try {
      status = walkCommandScope(command, (node) => this.visit(node, depth));
    } catch {
      return false;
    }
    return status === 'ok';
  }

  private visit(node: unknown, depth: number): boolean {
    if (!node) return false;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const n = node as any;
    const type = syntax.NodeType(n);
    // A heredoc on the stdin of a bare shell is the script it runs:
    // `bash <<'EOF' … EOF`. The redirect lives on the Stmt.
    if (type === 'Stmt') {
      this.visitHeredocShell(n, depth);
      return true;
    }
    // `for c in status "reset --hard"; do git $c; done`: the variable takes
    // each literal item in turn, so the body is judged once per item. The
    // jail's table does not record loop variables (it has no iteration);
    // here every iteration is judged, so nothing the loop runs is skipped.
    if (type === 'ForClause') {
      const loop = n.Loop;
      const name: string | undefined = loop?.Name?.Value;
      if (name && syntax.NodeType(loop) === 'WordIter') {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const items = ((loop.Items || []) as any[]).map((w) => resolveWordLiteral(w));
        const literal = items.length > 0 && items.every((v) => v !== null);
        this.loopVars.set(name, literal ? (items as string[]).slice(0, MAX_LOOP_ITEMS) : null);
      }
      return true;
    }
    if (type !== 'CallExpr') return true;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const rawArgs: any[] = n.Args || [];
    if (rawArgs.length === 0) return true;
    const prefixEnv = new Map<string, string | null>();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    for (const a of (n.Assigns || []) as any[]) {
      const name: string | undefined = a?.Name?.Value;
      if (name) prefixEnv.set(name, a.Value ? resolveWordLiteral(a.Value) : '');
    }
    // The first argument that is a loop variable with literal items expands
    // the call once per item; any other stays dynamic.
    const loopArg = rawArgs.findIndex((a) => {
      const v = plainParamName(a);
      return v !== null && (this.loopVars.get(v.name) ?? null) !== null;
    });
    if (loopArg >= 0) {
      const param = plainParamName(rawArgs[loopArg]) as { name: string; quoted: boolean };
      for (const item of this.loopVars.get(param.name) as string[]) {
        const words = rawArgs.flatMap((a, i) =>
          i === loopArg ? (param.quoted ? [item] : splitFields(item)) : resolveGitWords(a)
        );
        this.visitWords(words, new Map(prefixEnv), depth, false);
      }
      return true;
    }
    const words = rawArgs.flatMap((a) => resolveGitWords(a));
    this.visitWords(words, prefixEnv, depth, false);
    return true;
  }

  /** One resolved argv, wrappers still in front. */
  private visitWords(
    words: (string | null)[],
    env: Map<string, string | null>,
    depth: number,
    fromAlias: boolean
  ): void {
    let head = unwrapCommandHead(words);
    // `xargs -I{} git -C {} …`: the head finder reads `git` as the operand
    // of `-I{}`. A `git` word inside the wrapper prefix is the command.
    const inPrefix = words.findIndex((w, k) => k < head && baseWord(w) === 'git');
    if (inPrefix >= 0) head = inPrefix;
    const headWord = baseWord(words[head]);
    // `env K=V git …`: the assignments the wrapper carries apply to the call.
    for (let i = 0; i < head; i++) {
      const w = words[i];
      const m = w === null ? null : /^([A-Za-z_]\w*)=(.*)$/s.exec(w);
      if (m) env.set(m[1], m[2]);
    }
    const viaXargs = words.slice(0, head).some((w) => baseWord(w) === 'xargs');

    if (headWord === 'git') {
      this.visitGit(words.slice(head + 1), env, depth, viaXargs, fromAlias, shownOf(words));
      return;
    }
    if (headWord === 'chmod') {
      const f = chmodDisarmsHook(words.slice(head + 1), shownOf(words));
      if (f) this.found(f);
      return;
    }
    // A string-wrapped command: `sh -c "git …"`, `eval "git …"`, also behind
    // a wrapper (`sudo sh -c …`). Re-parsed once per distinct payload.
    if (depth < MAX_PAYLOAD_DEPTH) {
      const payload = literalShellPayload(words, baseWord(words[0]));
      if (payload !== null) this.runPayload(payload, depth);
    }
  }

  private runPayload(payload: string, depth: number): void {
    if (this.payloads.has(payload)) return;
    this.payloads.add(payload);
    this.run(payload, depth + 1);
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private visitHeredocShell(stmt: any, depth: number): void {
    const cmd = stmt.Cmd;
    if (!cmd || syntax.NodeType(cmd) !== 'CallExpr' || depth >= MAX_PAYLOAD_DEPTH) return;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const redirs: any[] = stmt.Redirs || [];
    const hdoc = redirs.find((r) => r?.Hdoc && (r.N == null || r.N.Value === '0'));
    if (!hdoc) return;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const words = ((cmd.Args || []) as any[]).map((a) => resolveWordLiteral(a));
    const head = unwrapCommandHead(words);
    const shell = baseWord(words[head]);
    if (!PAYLOAD_SHELLS.has(shell) || shell === 'eval') return;
    // A shell with a script operand or `-c` reads that, not stdin.
    if (words.slice(head + 1).some((w) => w === null || !w.startsWith('-'))) return;
    if (words.slice(head + 1).some((w) => w === '-c')) return;
    const text = resolveWordLiteral(hdoc.Hdoc);
    if (text !== null) this.runPayload(text, depth);
  }

  /** The words after `git`: global options, then the subcommand. */
  private visitGit(
    rest: (string | null)[],
    env: Map<string, string | null>,
    depth: number,
    viaXargs: boolean,
    fromAlias: boolean,
    shown: string
  ): void {
    const config = new Map<string, string>();
    let i = 0;
    while (i < rest.length) {
      const w = rest[i];
      if (w === null) break; // a dynamic word where git reads an option or the subcommand
      if (!w.startsWith('-')) break;
      const eq = w.indexOf('=');
      // `--git-dir=X` names the option before `=`; `-Cdir` / `-ck=v` attach
      // the value to the letter.
      const name = w.startsWith('--')
        ? eq > 0
          ? w.slice(0, eq)
          : w
        : w.length > 2 && /^-[cC]/.test(w)
          ? w.slice(0, 2)
          : w;
      if (GLOBAL_VALUE_OPTIONS.has(name)) {
        let value: string | null;
        if (name !== w) value = w.startsWith('--') ? w.slice(eq + 1) : w.slice(2);
        else {
          i++;
          value = i < rest.length ? rest[i] : null;
        }
        if (name === '-c' && value !== null) {
          const ceq = value.indexOf('=');
          const key = (ceq > 0 ? value.slice(0, ceq) : value).toLowerCase();
          config.set(key, ceq > 0 ? value.slice(ceq + 1) : 'true');
        }
        i++;
        continue;
      }
      if (GLOBAL_FLAG_OPTIONS.has(name)) {
        i++;
        continue;
      }
      // `-h`, `--version`, an option we do not know: judged as the subcommand
      // slot (no subcommand follows a help flag; an unknown option stops
      // git with an error).
      break;
    }
    const subWord = i < rest.length ? rest[i] : undefined;
    const args = rest.slice(i + 1);
    const inv: GitInvocation = { sub: null, args, config, env, shown };

    if (subWord === undefined) {
      // `git` alone prints help; `… | xargs git` reads the subcommand from
      // its input, which cannot be read here.
      if (!viaXargs) return;
      this.emit(inv);
      return;
    }
    if (subWord === null) {
      this.emit(inv);
      return;
    }
    if (subWord === POSITIONAL) return; // judged again at the call, bound
    // Aliases: `-c alias.NAME=VALUE` for this call, then the ones defined
    // earlier in the command.
    const fromConfig = config.get(`alias.${subWord.toLowerCase()}`);
    const alias = fromConfig !== undefined ? fromConfig : this.aliases.get(subWord);
    if (alias !== undefined && !fromAlias) {
      this.expandAlias(subWord, alias, args, env, depth, 0, shown);
      return;
    }
    inv.sub = subWord;
    this.emit(inv);
    this.recordAliasDefinition(inv, env, depth);
  }

  private expandAlias(
    name: string,
    value: string | null,
    args: (string | null)[],
    env: Map<string, string | null>,
    depth: number,
    level: number,
    shown: string
  ): void {
    if (value === null) {
      this.emit({ sub: null, args, config: new Map(), env, shown: `${shown} (alias ${name})` });
      return;
    }
    if (value.startsWith('!')) {
      // A shell alias runs the rest as a command, with the arguments appended.
      const tail = args.every((a) => a !== null) ? ' ' + (args as string[]).join(' ') : '';
      this.runPayload(value.slice(1) + tail, depth);
      return;
    }
    const words = splitAliasValue(value);
    if (words.length === 0) return;
    const sub = words[0];
    const nested = this.aliases.get(sub);
    const expandedShown = `${shown} (alias ${name} = ${value})`;
    if (nested !== undefined && level < MAX_ALIAS_DEPTH) {
      this.expandAlias(sub, nested, [...words.slice(1), ...args], env, depth, level + 1, shown);
      return;
    }
    this.emit({
      sub,
      args: [...words.slice(1), ...args],
      config: new Map(),
      env,
      shown: expandedShown,
    });
  }

  /**
   * `git config [scope] alias.NAME VALUE` (also `git config set`, git 2.46):
   * remembered for a later `git NAME` in the same command, and judged at
   * once by its value, because the use may come in the next tool call.
   */
  private recordAliasDefinition(
    inv: GitInvocation,
    env: Map<string, string | null>,
    depth: number
  ): void {
    if (inv.sub !== 'config') return;
    const args = inv.args;
    let i = 0;
    if (args[0] === 'set') i = 1;
    while (i < args.length) {
      const w = args[i];
      if (w === null) return;
      if (CONFIG_VALUE_FLAGS.has(w)) {
        i += 2;
        continue;
      }
      if (CONFIG_SCOPE_FLAGS.has(w) || w.startsWith('--file=') || w.startsWith('--type=')) {
        i++;
        continue;
      }
      if (w.startsWith('-')) return; // `--get`, `--unset`, `--list`: not a write of a value
      break;
    }
    const key = args[i];
    if (key === null || key === undefined) return;
    const m = /^alias\.(.+)$/i.exec(key);
    if (!m) return;
    const value = i + 1 < args.length ? args[i + 1] : null;
    this.aliases.set(m[1], value);
    // Judge the definition itself.
    this.expandAlias(m[1], value, [], env, depth, 0, `${inv.shown}`);
  }
}

// ── Words ────────────────────────────────────────────────────────────────────

/**
 * A word resolved for git, with one difference from the jail's resolver: an
 * UNQUOTED expansion that holds several words is split as the shell splits
 * it, so `cmd="reset --hard"; git $cmd` is `git reset --hard`. A quoted
 * `"$cmd"` stays one word, as it would for git.
 */
/**
 * A positional parameter (`$1`, `"$@"`) is unknown where the function is
 * declared and bound where it is called (walkWithCalls walks the body a
 * second time with the call's arguments). At the declaration the word is
 * marked rather than left dynamic, so `g() { git "$@"; }` is not reported as
 * a git call nobody can read; the call `g reset --hard` still is judged.
 */
const POSITIONAL = '\u0000positional';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function isPositionalParam(word: any): boolean {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let parts: any[] = word?.Parts || [];
  if (parts.length === 1 && syntax.NodeType(parts[0]) === 'DblQuoted') parts = parts[0].Parts || [];
  if (parts.length !== 1 || syntax.NodeType(parts[0]) !== 'ParamExp') return false;
  return /^(\d+|@|\*)$/.test(parts[0].Param?.Value ?? '');
}

/**
 * `"$@"` at a call with several arguments: the jail binds `$@` only for a
 * single argument (one word), so the list is rebuilt here from `$#` and
 * `$1`…`$9`, which the call did bind. Resolved through the same table the
 * walk is in; outside a call `$#` is unknown and the word stays positional.
 */
function boundPositionals(): (string | null)[] | null {
  const f = parseShared('x $# $1 $2 $3 $4 $5 $6 $7 $8 $9');
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const args: any[] = f?.Stmts?.[0]?.Cmd?.Args ?? [];
  if (args.length < 11) return null;
  const count = Number(resolveWordLiteral(args[1]));
  if (!Number.isInteger(count) || count < 0) return null;
  return args.slice(2, 2 + Math.min(count, 9)).map((a) => resolveWordLiteral(a));
}

/** The name of a word that is exactly one plain `$name` / `"$name"`, or null. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function plainParamName(word: any): { name: string; quoted: boolean } | null {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let parts: any[] = word?.Parts || [];
  let quoted = false;
  if (parts.length === 1 && syntax.NodeType(parts[0]) === 'DblQuoted') {
    parts = parts[0].Parts || [];
    quoted = true;
  }
  if (parts.length !== 1 || syntax.NodeType(parts[0]) !== 'ParamExp') return null;
  const p = parts[0];
  if (p.Excl || p.Length || p.Width || p.Index || p.Slice || p.Repl || p.Exp) return null;
  const name: string | undefined = p.Param?.Value;
  return name ? { name, quoted } : null;
}

/** Unquoted expansion: the shell splits the value on blanks. */
function splitFields(value: string): string[] {
  const pieces = value.split(/[ \t\n]+/).filter(Boolean);
  return pieces.length === 0 ? [''] : pieces;
}

/**
 * A global option whose VALUE is dynamic (`--git-dir=$G`, `-C$dir`) is still
 * that option: its literal prefix names it, and git reads the subcommand
 * after it. Returned with a marker in place of the value so the option
 * table skips it; nothing else is read from such a word.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function dynamicOptionWord(word: any): string | null {
  const { prefix, dynamic } = resolveWordPrefix(word);
  if (!dynamic) return null;
  if (/^--[a-z-]+=/.test(prefix) || /^-[cC]/.test(prefix)) return `${prefix}$…`;
  return null;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function resolveGitWords(word: any): (string | null)[] {
  const value = resolveWordLiteral(word);
  if (value === null) {
    if (isPositionalParam(word)) return boundPositionals() ?? [POSITIONAL];
    const option = dynamicOptionWord(word);
    return [option];
  }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const parts: any[] = word?.Parts || [];
  const expansion = parts.some((p) => {
    const t = syntax.NodeType(p);
    return t === 'ParamExp' || t === 'CmdSubst';
  });
  return expansion ? splitFields(value) : [value];
}

/** git splits an alias value like a shell line: quotes group, backslash escapes. */
function splitAliasValue(value: string): string[] {
  const out: string[] = [];
  let cur = '';
  let inWord = false;
  let quote: string | null = null;
  for (let i = 0; i < value.length; i++) {
    const ch = value[i];
    if (quote) {
      if (ch === quote) quote = null;
      else if (ch === '\\' && quote === '"' && i + 1 < value.length) cur += value[++i];
      else cur += ch;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      inWord = true;
    } else if (ch === '\\' && i + 1 < value.length) {
      cur += value[++i];
      inWord = true;
    } else if (/\s/.test(ch)) {
      if (inWord) out.push(cur);
      cur = '';
      inWord = false;
    } else {
      cur += ch;
      inWord = true;
    }
  }
  if (inWord) out.push(cur);
  return out;
}

function shownOf(words: (string | null)[]): string {
  return words
    .map((w) =>
      w === null ? '$…' : w === POSITIONAL ? '"$@"' : /\s/.test(w) ? JSON.stringify(w) : w
    )
    .join(' ');
}

// ── Options as git reads them ────────────────────────────────────────────────

interface ParsedOptions {
  /** Long options and single short letters, `-f`, `--force`; `--x=v` keeps only `--x`. */
  flags: Set<string>;
  operands: string[];
  /** True when a word in an option position was dynamic. */
  dynamic: boolean;
}

/**
 * Read a subcommand's options the way git's parse-options does: short
 * letters bundle (`-fn` is `-f` and `-n`), a value letter takes the rest of
 * its bundle or the next word (`-m "msg"`, `-mmsg`), `--opt=value` and
 * `--opt value` for long value options, `--` ends the options.
 */
function parseOptions(
  args: (string | null)[],
  shortValue: string,
  longValue: ReadonlySet<string>
): ParsedOptions {
  const flags = new Set<string>();
  const operands: string[] = [];
  let dynamic = false;
  let i = 0;
  let optionsOver = false;
  while (i < args.length) {
    const w = args[i++];
    if (w === null) {
      dynamic = true;
      continue;
    }
    if (optionsOver || !w.startsWith('-') || w === '-') {
      operands.push(w);
      continue;
    }
    if (w === '--') {
      optionsOver = true;
      continue;
    }
    if (w.startsWith('--')) {
      const eq = w.indexOf('=');
      const name = eq > 0 ? w.slice(0, eq) : w;
      flags.add(name);
      if (eq < 0 && longValue.has(name)) i++; // the next word is its value
      continue;
    }
    for (let k = 1; k < w.length; k++) {
      const letter = w[k];
      flags.add(`-${letter}`);
      if (shortValue.includes(letter)) {
        if (k + 1 >= w.length) i++; // value is the next word
        break; // or the rest of this bundle
      }
    }
  }
  return { flags, operands, dynamic };
}

// ── Part 1: destructive ──────────────────────────────────────────────────────

const FORCE_PUSH: GitFinding = {
  checkId: 'commands.git-destructive',
  ruleName: 'review-force-push',
  reason: 'Force push rewrites remote history — confirm this is intentional',
  description:
    'The AI wants to force push to a remote git branch. This rewrites shared history and can permanently destroy commits that teammates have already pulled.',
  shown: '',
};
const DESTRUCTIVE: GitFinding = {
  checkId: 'commands.git-destructive',
  ruleName: 'review-git-destructive',
  reason: 'Destructive git operation — discards history or working-tree changes',
  description:
    'The AI wants to run a destructive git operation (reset --hard, clean, or a forced branch or tag delete) that can permanently discard commits or uncommitted work.',
  shown: '',
};
const UNREADABLE: GitFinding = {
  checkId: 'commands.git-destructive',
  ruleName: 'review-git-destructive',
  reason: 'Git subcommand could not be read — it comes from a variable or from input',
  description:
    'The AI runs git with a subcommand node9 cannot read before it runs (a variable, a substitution or piped input), so it may be any operation, including a destructive one.',
  shown: '',
};

const PUSH_LONG_VALUE = new Set([
  '--repo',
  '--receive-pack',
  '--exec',
  '--push-option',
  '--recurse-submodules',
  '--signed',
]);
const BRANCH_LONG_VALUE = new Set([
  '--set-upstream-to',
  '--contains',
  '--no-contains',
  '--merged',
  '--no-merged',
  '--points-at',
  '--format',
  '--sort',
  '--color',
  '--column',
  '--abbrev',
]);
const TAG_LONG_VALUE = new Set([
  '--message',
  '--file',
  '--local-user',
  '--contains',
  '--no-contains',
  '--merged',
  '--no-merged',
  '--points-at',
  '--format',
  '--sort',
  '--color',
  '--column',
  '--cleanup',
]);
const CLEAN_LONG_VALUE = new Set(['--exclude']);

function classify(inv: GitInvocation): GitFinding[] {
  const out: GitFinding[] = [];
  const found = (f: GitFinding): void => {
    out.push({ ...f, shown: inv.shown, reason: `${f.reason}: ${inv.shown}` });
  };
  if (hooksBypass(inv)) found(HOOKS_BYPASS);
  if (inv.sub === null) {
    found(UNREADABLE);
    return out;
  }
  switch (inv.sub.toLowerCase()) {
    case 'push': {
      const o = parseOptions(inv.args, 'o', PUSH_LONG_VALUE);
      if (o.flags.has('-n') || o.flags.has('--dry-run')) break;
      const forced =
        o.flags.has('-f') ||
        o.flags.has('--force') ||
        o.flags.has('--force-with-lease') ||
        o.flags.has('--force-if-includes') ||
        o.flags.has('--mirror') ||
        o.operands.some((r) => r.startsWith('+'));
      if (forced) found(FORCE_PUSH);
      break;
    }
    case 'reset': {
      const o = parseOptions(inv.args, '', new Set());
      if (o.flags.has('--hard')) found(DESTRUCTIVE);
      break;
    }
    case 'clean': {
      const o = parseOptions(inv.args, 'e', CLEAN_LONG_VALUE);
      if (
        o.flags.has('-n') ||
        o.flags.has('--dry-run') ||
        o.flags.has('-i') ||
        o.flags.has('--interactive')
      )
        break;
      if (o.flags.has('-f') || o.flags.has('--force')) found(DESTRUCTIVE);
      break;
    }
    case 'branch': {
      const o = parseOptions(inv.args, 'u', BRANCH_LONG_VALUE);
      const del = o.flags.has('-d') || o.flags.has('--delete') || o.flags.has('-D');
      const force = o.flags.has('-D') || o.flags.has('-f') || o.flags.has('--force');
      if (del && force) found(DESTRUCTIVE);
      break;
    }
    case 'tag': {
      const o = parseOptions(inv.args, 'mFu', TAG_LONG_VALUE);
      if (o.flags.has('-d') || o.flags.has('--delete')) found(DESTRUCTIVE);
      break;
    }
    default:
      break;
  }
  return out;
}

// ── Part 2: the hooks bypassed ───────────────────────────────────────────────
//
// The agent switches off a check meant to oversee its own work (OWASP ASI10):
// `--no-verify`, a hook path pointed elsewhere, the husky / lefthook /
// pre-commit kill switches on the git call, or a hook file disarmed. A
// developer who does the same from the terminal is not judged here (the
// AST tier runs for agent calls only).

const HOOKS_BYPASS: GitFinding = {
  checkId: 'commands.git-hooks-bypass',
  ruleName: 'review-git-hooks-bypass',
  reason: 'Git hooks bypassed — the agent switches off a check on its own work',
  description:
    'The AI wants to commit or push without the git hooks that check its work (--no-verify, core.hooksPath, HUSKY=0 and the like, or a hook file disarmed). Hooks are the review you set up; confirm this is intentional.',
  shown: '',
};

/** Subcommands whose `--no-verify` skips a hook. On push `-n` is dry-run. */
const NO_VERIFY_SUBS = new Set(['push', 'merge', 'rebase', 'am', 'cherry-pick', 'revert']);
/** Kill switches of the hook managers, read on the git call they apply to. */
const HOOK_KILL_SWITCHES = ['HUSKY', 'HUSKY_SKIP_HOOKS', 'LEFTHOOK', 'SKIP'] as const;

function killSwitchSet(name: (typeof HOOK_KILL_SWITCHES)[number], value: string | null): boolean {
  if (value === null) return false; // unknown value: not claimed
  switch (name) {
    case 'HUSKY':
    case 'LEFTHOOK':
      return value === '0';
    case 'HUSKY_SKIP_HOOKS':
      return value !== '' && value !== '0';
    case 'SKIP':
      return value !== '';
  }
}

/**
 * The value a name has at this point of the command: applied to the call
 * (`HUSKY=0 git …`, `env HUSKY=0 git …`), else exported earlier in the
 * command (`export HUSKY=0; git …`), read through the walk's table.
 */
function appliedValue(env: Map<string, string | null>, name: string): string | null {
  if (env.has(name)) return env.get(name) ?? null;
  const f = parseShared(`x $${name}`);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const word: any = f?.Stmts?.[0]?.Cmd?.Args?.[1];
  return word ? resolveWordLiteral(word) : null;
}

function hooksBypass(inv: GitInvocation): boolean {
  if (inv.config.has('core.hookspath')) return true;
  for (const [name, value] of inv.env) {
    if (name === 'GIT_CONFIG_PARAMETERS' && value !== null && /core\.hookspath/i.test(value))
      return true;
    if (
      /^GIT_CONFIG_KEY_\d+$/.test(name) &&
      value !== null &&
      value.toLowerCase() === 'core.hookspath'
    )
      return true;
  }
  for (const name of HOOK_KILL_SWITCHES) {
    if (killSwitchSet(name, appliedValue(inv.env, name))) return true;
  }
  const sub = inv.sub?.toLowerCase();
  if (sub === 'commit') {
    const o = parseOptions(inv.args, 'mFCcut', COMMIT_LONG_VALUE);
    return o.flags.has('-n') || o.flags.has('--no-verify');
  }
  if (sub !== undefined && NO_VERIFY_SUBS.has(sub)) {
    return inv.args.some((a) => a === '--no-verify');
  }
  if (sub === 'config') return configWritesHooksPath(inv.args);
  return false;
}

const COMMIT_LONG_VALUE = new Set([
  '--message',
  '--file',
  '--author',
  '--date',
  '--reuse-message',
  '--reedit-message',
  '--fixup',
  '--squash',
  '--template',
  '--cleanup',
  '--trailer',
  '--pathspec-from-file',
  '--gpg-sign',
]);

/** `git config [scope] core.hooksPath V`, `set`, `--add`, `--unset`: a write. */
function configWritesHooksPath(args: (string | null)[]): boolean {
  let i = 0;
  if (args[0] === 'set' || args[0] === 'unset') i = 1;
  let write = i === 1;
  while (i < args.length) {
    const w = args[i];
    if (w === null) return false;
    if (CONFIG_VALUE_FLAGS.has(w)) {
      i += 2;
      continue;
    }
    if (w === '--unset' || w === '--unset-all' || w === '--add' || w === '--replace-all') {
      write = true;
      i++;
      continue;
    }
    if (CONFIG_SCOPE_FLAGS.has(w) || w.startsWith('--file=') || w.startsWith('--type=')) {
      i++;
      continue;
    }
    if (w.startsWith('-')) return false; // --get, --list, --show-origin: a read
    break;
  }
  const key = args[i];
  if (key === null || key === undefined || key.toLowerCase() !== 'core.hookspath') return false;
  // A bare `git config core.hooksPath` reads; with a value it writes.
  return write || i + 1 < args.length;
}

/** A path under a hook directory, read off the word as written. */
export function isHookPath(word: string): boolean {
  return /(^|[\\/])(\.git[\\/]hooks|\.husky)([\\/]|$)/.test(word);
}

/** chmod's options; anything else in the first slot is the mode. */
const CHMOD_OPTION_RE = /^-[RvcfHLP]+$/;

/** A mode that takes execute away: `-x`, `a-x`, `ugo-x`, `644`, `600`. */
function modeRemovesExecute(mode: string): boolean {
  if (/^[0-7]{3,4}$/.test(mode)) {
    const bits = mode.slice(-3);
    return [...bits].every((d) => (Number(d) & 1) === 0);
  }
  return mode.split(',').some((part) => /^[ugoa]*-[rwst]*x/.test(part));
}

function chmodDisarmsHook(args: (string | null)[], shown: string): GitFinding | null {
  let i = 0;
  while (i < args.length) {
    const w = args[i];
    if (w === null) return null;
    if (w === '--') {
      i++;
      break;
    }
    if (w.startsWith('--') || CHMOD_OPTION_RE.test(w)) {
      i++;
      continue;
    }
    break;
  }
  const mode = args[i];
  if (mode === null || mode === undefined || !modeRemovesExecute(mode)) return null;
  const hit = args.slice(i + 1).some((w) => w !== null && isHookPath(w));
  return hit ? { ...HOOKS_BYPASS, shown, reason: `${HOOKS_BYPASS.reason}: ${shown}` } : null;
}
