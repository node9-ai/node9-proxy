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

import {
  baseWord,
  literalShellPayload,
  parseShared,
  resolveWordLiteral,
  resolveWordPrefix,
  isPipeOp,
  arrayElements,
  recordedExpansion,
  unwrapCommandHead,
  walkCommandScope,
} from './index';

export type GitCheckId =
  'commands.git-destructive' | 'commands.git-hooks-bypass' | 'commands.git-stage-all';

export interface GitFinding {
  checkId: GitCheckId;
  /** The rule name the audit log and the catalog's legacy table know. */
  ruleName:
    | 'review-force-push'
    | 'review-git-destructive'
    | 'review-git-hooks-bypass'
    | 'review-git-stage-all';
  reason: string;
  description: string;
  /** The invocation as resolved, for the reason and the explain trace. */
  shown: string;
  /**
   * A stage-all finding that holds only if this directory (as written after
   * `-C`, relative to where the command runs) is the top of a work tree:
   * `git -C sub add .` stages `sub` alone, `git -C myapp add .` run from the
   * folder above the repository stages all of it. The command cannot tell
   * them apart; a host that knows the working directory asks the disk, and
   * without an answer the finding stands (node9Firewall#413).
   */
  ifWorkTreeTop?: string;
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
  /** Each `-C <path>` given before the subcommand, in order; null marks a dynamic word. */
  chdir?: (string | null)[];
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
  /** node9Firewall#385: variables assigned a tree-top word (`scope="$PWD"`,
   *  `root=$(git rev-parse --show-toplevel)`, `DIR=$(pwd)`), so the
   *  variable reads as the top where it is used. */
  private treeTopVars = new Set<string>();
  /** node9Firewall#385 (c): a string a script builds with `+=` from
   *  literals (`mode=--ha; mode+=rd`). The jail's table does not follow an
   *  append (JAIL-14a); the git rules read the built word, since a flag
   *  spelled in two halves is still that flag. name -> value, null once a
   *  half is unknown. */
  private appended = new Map<string, string | null>();
  private payloads = new Set<string>();
  /** node9Firewall#385 (a): the text this command writes to each path
   *  (`cat > /tmp/x.sh <<'SH' ... SH`, `echo '...' > f`, `>>` appends), so
   *  a later statement that runs the path (`bash f`, `sh f`, `./f`) is
   *  judged on what it runs. null once a write to the path is unknown. */
  private written = new Map<string, string | null>();
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
    const type = n.kind;
    // A heredoc on the stdin of a bare shell is the script it runs:
    // `bash <<'EOF' … EOF`. The redirect lives on the Stmt.
    if (type === 'Stmt') {
      this.visitHeredocShell(n, depth);
      this.visitPipeline(n, depth);
      this.visitHookWrite(n);
      this.recordScriptWrite(n);
      this.visitWrittenScript(n, depth);
      return true;
    }
    if (type === 'Assign' && n.Name?.Value && n.Value) {
      const name: string = n.Name.Value;
      if (n.Append) {
        const prev = this.appended.has(name)
          ? this.appended.get(name)
          : resolveWordLiteral(n.Value) === null
            ? null
            : undefined;
        const base = prev === undefined ? recordedExpansion(name) : prev;
        const piece = resolveWordLiteral(n.Value);
        this.appended.set(name, typeof base === 'string' && piece !== null ? base + piece : null);
        this.treeTopVars.delete(name);
        return true;
      }
      this.appended.delete(name);
      if (treeTopWord(n.Value, this.treeTopVars)) this.treeTopVars.add(name);
      else this.treeTopVars.delete(name);
      return true;
    }
    // `for c in status "reset --hard"; do git $c; done`: the variable takes
    // each literal item in turn, so the body is judged once per item. The
    // jail's table does not record loop variables (it has no iteration);
    // here every iteration is judged, so nothing the loop runs is skipped.
    if (type === 'ForClause') {
      const loop = n.Loop;
      const name: string | undefined = loop?.Name?.Value;
      if (name && loop.kind === 'WordIter') {
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
          i === loopArg
            ? param.quoted
              ? [item]
              : splitFields(item)
            : resolveGitWords(a, this.treeTopVars, this.appended)
        );
        this.visitWords(words, new Map(prefixEnv), depth, false);
      }
      return true;
    }
    const words = rawArgs.flatMap((a) => resolveGitWords(a, this.treeTopVars, this.appended));
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
    // node9Firewall#385 (e): the hook file removed, moved away, or renamed.
    if (headWord === 'rm' || headWord === 'unlink') {
      if (words.slice(head + 1).some((w) => w !== null && isLiveHookFile(w)))
        this.found(hooksBypassed(shownOf(words)));
      return;
    }
    if (headWord === 'mv') {
      const operands = words.slice(head + 1).filter((w) => w === null || !w.startsWith('-'));
      const src = operands[0];
      if (typeof src === 'string' && isLiveHookFile(src)) this.found(hooksBypassed(shownOf(words)));
      return;
    }
    if (headWord === 'perl') {
      const code = words.slice(head + 1).find((w) => w !== null && /\brename\b/.test(w));
      if (code && /rename\s*\(?\s*q[qw]?\s*[(\[{<'"]([^)\]}>'"]+)/.test(code)) {
        const from = RegExp.$1;
        if (isLiveHookFile(from)) this.found(hooksBypassed(shownOf(words)));
      }
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

  /**
   * node9Firewall#385: a pipeline whose last stage reads its pathspec from
   * stdin (`git add --pathspec-from-file=-`) or runs git over the names it
   * is fed (`xargs -0 git add --`), with a producer that is one literal
   * (`git rev-parse --show-toplevel`, `printf '%s\0' .`): the literal is
   * the operand, and the call is judged with it.
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private visitPipeline(stmt: any, depth: number): void {
    const cmd = stmt.Cmd;
    if (!cmd || cmd.kind !== 'BinaryCmd' || !isPipeOp(cmd.Op)) return;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const stages: any[] = [];
    let cur = cmd;
    while (cur?.kind === 'BinaryCmd' && isPipeOp(cur.Op)) {
      stages.unshift(cur.Y);
      const left = cur.X;
      if (left?.Cmd?.kind === 'BinaryCmd' && isPipeOp(left.Cmd.Op)) cur = left.Cmd;
      else {
        stages.unshift(left);
        break;
      }
    }
    if (stages.length < 2) return;
    const producer = stages[stages.length - 2]?.Cmd;
    const consumer = stages[stages.length - 1]?.Cmd;
    if (!producer || !consumer || producer.kind !== 'CallExpr' || consumer.kind !== 'CallExpr')
      return;
    const fed = producedLiteral(producer);
    if (fed === null) return;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const words = ((consumer.Args || []) as any[]).flatMap((a) =>
      resolveGitWords(a, this.treeTopVars, this.appended)
    );
    const head = unwrapCommandHead(words);
    const viaXargs = words.slice(0, head).some((w) => baseWord(w) === 'xargs');
    const fromFile = words.findIndex(
      (w) => w === '--pathspec-from-file=-' || w === '--pathspec-from-file'
    );
    if (!viaXargs && fromFile < 0) return;
    let fedWords: (string | null)[];
    if (fromFile >= 0) {
      fedWords = words.filter(
        (w, k) => !(k === fromFile || (w === '-' && words[k - 1] === '--pathspec-from-file'))
      );
      fedWords.push(fed);
    } else fedWords = [...words, fed];
    this.visitWords(fedWords, new Map(), depth, false);
  }

  /**
   * node9Firewall#385 (e): a hook file written with a body that checks
   * nothing (`cat > .githooks/pre-commit <<'SH' exit 0 SH`, `echo 'exit 0'
   * > .git/hooks/pre-push`, `: > .githooks/pre-commit`). A real body (a
   * test, a linter) is ordinary work on the hooks.
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private visitHookWrite(stmt: any): void {
    const cmd = stmt.Cmd;
    if (!cmd || cmd.kind !== 'CallExpr') return;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const redirs: any[] = stmt.Redirs || [];
    const target = redirs.find((r) => r?.Word && !r.Hdoc && (r.N == null || r.N.Value === '1'));
    if (!target) return;
    const path = resolveWordLiteral(target.Word);
    if (path === null || !isLiveHookFile(path)) return;
    // The body: a heredoc on stdin, or what echo/printf writes, or nothing.
    const hdoc = redirs.find((r) => r?.Hdoc);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const words = ((cmd.Args || []) as any[]).map((a) => resolveWordLiteral(a));
    const head = baseWord(words[0]);
    let body: string | null = null;
    if (hdoc) body = resolveWordLiteral(hdoc.Hdoc);
    else if (head === ':' || head === 'true' || words.length === 0) body = '';
    else if (head === 'echo' || head === 'printf') {
      const rest = words.slice(1);
      body = rest.some((w) => w === null)
        ? null
        : rest.filter((w) => !/^-[neE]+$/.test(w as string)).join(' ');
      if (body !== null) body = body.replace(/\\n/g, '\n');
    }
    if (body !== null && hookBodyIsEmpty(body)) this.found(hooksBypassed(shownOf(words)));
  }

  /** A statement that writes a literal text to a path, by redirect. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private recordScriptWrite(stmt: any): void {
    const cmd = stmt.Cmd;
    if (!cmd || cmd.kind !== 'CallExpr') return;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const redirs: any[] = stmt.Redirs || [];
    const target = redirs.find((r) => r?.Word && !r.Hdoc && (r.N == null || r.N.Value === '1'));
    if (!target) return;
    const path = resolveWordLiteral(target.Word);
    if (path === null) return;
    const append = /^>>/.test(target.Op?.toString() ?? '') || redirOpIsAppend(target);
    const hdoc = redirs.find((r) => r?.Hdoc);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const words = ((cmd.Args || []) as any[]).map((a) => resolveWordLiteral(a));
    const head = baseWord(words[0]);
    let text: string | null = null;
    if (hdoc && (head === 'cat' || head === 'tee')) text = resolveWordLiteral(hdoc.Hdoc);
    else if (head === 'echo' || head === 'printf') {
      const rest = words.slice(1);
      text = rest.some((w) => w === null)
        ? null
        : rest.filter((w) => !/^-[neE]+$/.test(w as string)).join(' ');
      if (text !== null && head === 'printf') text = text.replace(/\\n/g, '\n');
    } else return;
    const prev = this.written.get(path);
    if (text === null || (append && prev === null)) this.written.set(path, null);
    else this.written.set(path, append && typeof prev === 'string' ? `${prev}\n${text}` : text);
  }

  /** A statement that runs a path this command wrote: the text is the script. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private visitWrittenScript(stmt: any, depth: number): void {
    const cmd = stmt.Cmd;
    if (!cmd || cmd.kind !== 'CallExpr' || this.written.size === 0 || depth >= MAX_PAYLOAD_DEPTH)
      return;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const words = ((cmd.Args || []) as any[]).map((a) => resolveWordLiteral(a));
    const head = unwrapCommandHead(words);
    const name = baseWord(words[head]);
    let ran: string | null = null;
    if (PAYLOAD_SHELLS.has(name) && name !== 'eval') {
      const operand = words.slice(head + 1).find((w) => w === null || !w.startsWith('-'));
      if (typeof operand === 'string') ran = operand;
    } else if (typeof words[head] === 'string' && this.written.has(words[head] as string)) {
      ran = words[head] as string;
    }
    if (ran === null) return;
    const text = this.written.get(ran);
    if (typeof text === 'string') this.runPayload(text, depth);
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private visitHeredocShell(stmt: any, depth: number): void {
    const cmd = stmt.Cmd;
    if (!cmd || cmd.kind !== 'CallExpr' || depth >= MAX_PAYLOAD_DEPTH) return;
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
    const chdir: (string | null)[] = [];
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
        // `xargs -I{} git -C {} …`, `find -exec git -C {} …`: the directory
        // is filled in at run time, so it is dynamic.
        if (name === '-C') chdir.push(viaXargs || (value ?? '').includes('{}') ? null : value);
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
    const inv: GitInvocation = { sub: null, args, config, env, shown, chdir };

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
      this.expandAlias(subWord, alias, args, env, depth, 0, shown, chdir);
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
    shown: string,
    chdir: (string | null)[]
  ): void {
    if (value === null) {
      this.emit({
        sub: null,
        args,
        config: new Map(),
        env,
        shown: `${shown} (alias ${name})`,
        chdir,
      });
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
      this.expandAlias(
        sub,
        nested,
        [...words.slice(1), ...args],
        env,
        depth,
        level + 1,
        shown,
        chdir
      );
      return;
    }
    this.emit({
      sub,
      args: [...words.slice(1), ...args],
      config: new Map(),
      env,
      shown: expandedShown,
      chdir,
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
    // `git config alias.st` with no value READS the alias; only a value
    // (literal or dynamic) is a definition.
    if (i + 1 >= args.length) return;
    const value = args[i + 1];
    this.aliases.set(m[1], value);
    // Judge the definition itself.
    this.expandAlias(m[1], value, [], env, depth, 0, `${inv.shown}`, []);
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
  if (parts.length === 1 && parts[0].kind === 'DblQuoted') parts = parts[0].Parts || [];
  if (parts.length !== 1 || parts[0].kind !== 'ParamExp') return false;
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
  if (parts.length === 1 && parts[0].kind === 'DblQuoted') {
    parts = parts[0].Parts || [];
    quoted = true;
  }
  if (parts.length !== 1 || parts[0].kind !== 'ParamExp') return null;
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

/**
 * node9Firewall#385: a word that names the top of the work tree without
 * writing `.`: `$(git rev-parse --show-toplevel)`, `$(pwd)`, `$PWD`, alone
 * or as the whole of a quoted word. Read as the pathspec `:/` (the top), so
 * `git add "$(git rev-parse --show-toplevel)"` is `git add :/`. A path UNDER
 * it (`"$PWD/src"`) keeps its dynamic reading: it names a directory.
 */
const NO_VARS: ReadonlySet<string> = new Set();
const NO_APPENDS: ReadonlyMap<string, string | null> = new Map();

/** A word that is exactly `"${a[@]}"` / `${a[*]}` of a recorded literal
 *  array: its elements as words. Null for anything else. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function arrayExpansionWords(word: any): string[] | null {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let parts: any[] = word?.Parts || [];
  if (parts.length === 1 && parts[0].kind === 'DblQuoted') parts = parts[0].Parts || [];
  if (parts.length !== 1 || parts[0].kind !== 'ParamExp' || !parts[0].Index) return null;
  const index = resolveWordLiteral(parts[0].Index);
  if (index !== '@' && index !== '*') return null;
  const elems = arrayElements(recordedExpansion(parts[0].Param?.Value));
  return elems;
}

/** The one literal a producer stage writes: `printf '%s\0' X`, `echo X`,
 *  `git rev-parse --show-toplevel` (the top), null otherwise. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function producedLiteral(call: any): string | null {
  if ((call.Assigns || []).length > 0) return null;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const words = ((call.Args || []) as any[]).map((a) => resolveWordLiteral(a));
  if (words.length === 0 || words.some((w) => w === null)) return null;
  const head = baseWord(words[0] as string);
  const rest = words.slice(1) as string[];
  if (
    head === 'git' &&
    rest[0] === 'rev-parse' &&
    rest[1] === '--show-toplevel' &&
    rest.length === 2
  )
    return ':/';
  if (head === 'echo') {
    let i = 0;
    while (i < rest.length && /^-[neE]+$/.test(rest[i])) i++;
    return rest.length - i === 1 ? rest[i] : null;
  }
  if (head === 'printf' && rest.length === 2 && /^%s(\\[0n])?$/.test(rest[0])) return rest[1];
  return null;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function treeTopWord(word: any, treeTopVars: ReadonlySet<string> = NO_VARS): boolean {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let parts: any[] = word?.Parts || [];
  if (parts.length === 1 && parts[0].kind === 'DblQuoted') parts = parts[0].Parts || [];
  if (parts.length !== 1) return false;
  const p = parts[0];
  if (p.kind === 'ParamExp') {
    const name = plainParamName(word)?.name;
    return name === 'PWD' || (name !== undefined && treeTopVars.has(name));
  }
  if (p.kind !== 'CmdSubst') return false;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const stmts: any[] = p.Stmts || [];
  if (stmts.length !== 1 || !stmts[0].Cmd || stmts[0].Cmd.kind !== 'CallExpr') return false;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const words = ((stmts[0].Cmd.Args || []) as any[]).map((a) => resolveWordLiteral(a));
  if (words.some((w) => w === null)) return false;
  const head = baseWord(words[0] as string);
  if (head === 'pwd') return words.length === 1 || words[1] === '-P' || words[1] === '-L';
  return head === 'git' && words[1] === 'rev-parse' && words[2] === '--show-toplevel';
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function resolveGitWords(
  word: any,
  treeTopVars: ReadonlySet<string> = NO_VARS,
  appended: ReadonlyMap<string, string | null> = NO_APPENDS
): (string | null)[] {
  if (treeTopWord(word, treeTopVars)) return [':/'];
  const plain = plainParamName(word);
  if (plain && appended.has(plain.name)) {
    const v = appended.get(plain.name);
    if (v === null || v === undefined) return [null];
    return plain.quoted ? [v] : splitFields(v);
  }
  // node9Firewall#385 (c): `"${opts[@]}"` is one word per element.
  const elems = arrayExpansionWords(word);
  if (elems !== null) return elems;
  const value = resolveWordLiteral(word);
  if (value === null) {
    if (isPositionalParam(word)) return boundPositionals() ?? [POSITIONAL];
    const option = dynamicOptionWord(word);
    return [option];
  }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const parts: any[] = word?.Parts || [];
  const expansion = parts.some((p) => {
    const t = p.kind;
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
  const staged = stagesEverything(inv);
  if (staged) {
    found(staged.ifWorkTreeTop === undefined ? STAGE_ALL : { ...STAGE_ALL, ...staged });
  }
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
      // node9Firewall#385: a remote branch deleted (`--delete`, `-d`, or the
      // `:branch` refspec with nothing before the colon) loses it for
      // everyone who had not fetched it. `HEAD:refs/heads/x` pushes.
      const deletes =
        o.flags.has('-d') || o.flags.has('--delete') || o.operands.some((r) => /^:[^:]/.test(r));
      if (deletes) found(DESTRUCTIVE);
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
      // Without -f git refuses unless clean.requireForce is off, which the
      // walk sees when it is given on this call (`-c clean.requireForce=false`).
      const forced =
        o.flags.has('-f') ||
        o.flags.has('--force') ||
        inv.config.get('clean.requireforce') === 'false';
      if (forced) found(DESTRUCTIVE);
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
    // node9Firewall#385: history and work discarded through plumbing. A ref
    // deleted by hand, a stash dropped, the reflog expired or pruned: the
    // commits behind them are gone the way `branch -D` loses them.
    case 'update-ref': {
      const o = parseOptions(inv.args, 'm', new Set());
      if (o.flags.has('-d') && (o.dynamic || o.operands.some(isHistoryRef))) found(DESTRUCTIVE);
      break;
    }
    case 'reflog': {
      const o = parseOptions(inv.args, '', new Set());
      if (o.operands[0] === 'expire' || o.operands[0] === 'delete') found(DESTRUCTIVE);
      break;
    }
    case 'gc': {
      // `gc --prune=now` alone is maintenance; with the reflog expired first
      // (`reflog expire --expire=now`, or `-c gc.reflogExpire=now`) the
      // commits behind every ref are gone for good.
      if (inv.config.get('gc.reflogexpire') === 'now') found(DESTRUCTIVE);
      break;
    }
    case 'stash': {
      const o = parseOptions(inv.args, '', new Set());
      if (o.operands[0] === 'clear' || o.operands[0] === 'drop') found(DESTRUCTIVE);
      break;
    }
    case 'worktree': {
      const o = parseOptions(inv.args, '', new Set());
      if (o.operands[0] === 'remove' && (o.flags.has('-f') || o.flags.has('--force')))
        found(DESTRUCTIVE);
      break;
    }
    // The working tree overwritten: `restore` from another ref, a forced
    // checkout, or `checkout -- .` (every local change dropped). A bare
    // `restore .` or `checkout .` stays an ordinary undo, as pinned.
    case 'restore': {
      const o = parseOptions(inv.args, 's', RESTORE_LONG_VALUE);
      // From another ref onto the whole tree: every local change goes.
      // `restore --source=HEAD -- file` and `restore .` are ordinary undos.
      const src = restoreSource(inv.args);
      const whole = o.dynamic || o.operands.some(wholeTree);
      if (src !== null && src !== 'HEAD' && whole) found(DESTRUCTIVE);
      break;
    }
    case 'checkout': {
      const o = parseOptions(inv.args, 'bB', CHECKOUT_LONG_VALUE);
      const forced = o.flags.has('-f') || o.flags.has('--force');
      const dropAll = inv.args.includes('--') && o.operands.some(wholeTree);
      if (forced || dropAll) found(DESTRUCTIVE);
      break;
    }
    default:
      break;
  }
  return out;
}

/** `:!x`, `:^x`, `:(exclude)x`, `:(exclude,glob)x`: a pathspec that only
 *  takes away. `:(glob)x`, `:(top)` and `:/` name something to add. */
function isExcludePathspec(operand: string): boolean {
  return /^:[!^]/.test(operand) || /^:\([^)]*\bexclude\b[^)]*\)/.test(operand);
}

/** The value of `--source=<ref>` / `--source <ref>` / `-s <ref>` on restore. */
function restoreSource(args: (string | null)[]): string | null {
  for (let i = 0; i < args.length; i++) {
    const w = args[i];
    if (w === null) continue;
    if (w.startsWith('--source=')) return w.slice('--source='.length);
    if (w === '--source' || w === '-s') return args[i + 1] ?? null;
    if (/^-s./.test(w)) return w.slice(2);
  }
  return null;
}

/** A ref whose deletion loses commits: a branch or the stash. */
function isHistoryRef(ref: string): boolean {
  return /^refs\/(heads|stash)(\/|$)/.test(ref);
}

const RESTORE_LONG_VALUE = new Set(['--source', '--pathspec-from-file']);
const CHECKOUT_LONG_VALUE = new Set(['--pathspec-from-file', '--orphan', '--conflict']);

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

/**
 * A path as written, read lexically: its parts with `.` dropped and `..`
 * applied, and whether a `..` climbed above the start. Null for a path that
 * is not relative to where the command runs: absolute, a drive (`C:`), the
 * home directory (`~`), a variable. One reading for every git path rule here.
 */
function lexicalPath(p: string): { parts: string[]; climbed: boolean } | null {
  if (/^[\\/~$]/.test(p) || /^[A-Za-z]:/.test(p)) return null;
  const parts: string[] = [];
  let climbed = false;
  for (const part of p.split(/[\\/]+/)) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      if (parts.length === 0) climbed = true;
      else parts.pop();
    } else parts.push(part);
  }
  return { parts, climbed };
}

/**
 * Does pointing `core.hooksPath` at this value take the hooks away? git
 * reads a relative value from the root of the working tree, so a relative
 * path to a directory inside the tree (`.githooks`, `.husky`, `.git/hooks`)
 * is the project's own hooks, which keep running (node9Firewall#413
 * follow-up). Everything else is a bypass: an absolute path (`/dev/null`,
 * `/tmp/empty`, `C:\\x`), the home directory, a value that climbs
 * (`../hooks`), the root of the tree itself (`.`) or the git directory
 * (`.git`), where no hook files live, an empty value, a dynamic one.
 */
export function hooksPathBypasses(value: string | null | undefined): boolean {
  if (value === null || value === undefined) return true;
  const v = value.trim();
  if (v === '' || v === 'true') return true; // `-c core.hooksPath` with no value reads as true
  const lp = lexicalPath(v);
  if (lp === null || lp.climbed || lp.parts.length === 0) return true;
  return lp.parts[0] === '.git' && lp.parts[1] !== 'hooks';
}

function hooksBypass(inv: GitInvocation): boolean {
  if (inv.config.has('core.hookspath') && hooksPathBypasses(inv.config.get('core.hookspath')))
    return true;
  for (const [name, value] of inv.env) {
    // Its quoting is not parsed here: any mention of the key is a bypass.
    if (name === 'GIT_CONFIG_PARAMETERS' && value !== null && /core\.hookspath/i.test(value))
      return true;
    const key = /^GIT_CONFIG_KEY_(\d+)$/.exec(name);
    if (
      key &&
      value !== null &&
      value.toLowerCase() === 'core.hookspath' &&
      hooksPathBypasses(inv.env.get(`GIT_CONFIG_VALUE_${key[1]}`))
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
  // node9Firewall#385: a commit object written with the plumbing runs no
  // pre-commit or commit-msg hook at all.
  if (sub === 'commit-tree') return true;
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
  const unset =
    args.slice(0, i).some((w) => w === '--unset' || w === '--unset-all') || args[0] === 'unset';
  // `--unset` turns a project's hook manager (husky) off: a bypass.
  if (unset) return true;
  // A bare `git config core.hooksPath` reads; with a value it writes, and the
  // value decides (a hooks directory inside the tree is not a bypass).
  if (i + 1 < args.length) return hooksPathBypasses(args[i + 1]);
  return write;
}

/** A path under a hook directory, read off the word as written: git's own
 *  `.git/hooks`, husky's `.husky`, and the `.githooks` directory projects
 *  point `core.hooksPath` at (node9Firewall#385). */
export function isHookPath(word: string): boolean {
  return /(^|[\\/])(\.git[\\/]hooks|\.husky|\.githooks)([\\/]|$)/.test(word);
}

/** The file of a live hook: a hook directory itself (`rm -rf .husky`), or a
 *  bare hook name inside one (`pre-commit`, `.husky/_/pre-push`). A copy
 *  beside it (`pre-commit.bak`, `.sample`, `.new`) is not a hook git runs. */
export function isLiveHookFile(word: string): boolean {
  if (!isHookPath(word)) return false;
  const m = /(^|[\\/])(\.git[\\/]hooks|\.husky|\.githooks)(?:[\\/](.*))?$/.exec(word);
  if (!m) return false;
  const rest = m[3] ?? '';
  if (rest === '' || rest === '_') return true; // the directory itself
  const leaf = rest.replace(/^_[\\/]/, '');
  return /^[a-z-]+$/.test(leaf);
}

/** A hook body that checks nothing: empty, or only a shebang, blank lines,
 *  comments, `set` lines, `exit 0`, `true` or `:`. */
export function hookBodyIsEmpty(text: string): boolean {
  const lines = text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l !== '' && !l.startsWith('#'));
  return lines.every((l) => /^(exit(\s+0)?|true|:|set\s+-[a-zA-Z]+|set\s+-o\s+\w+)$/.test(l));
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

/** Whether a redirect is an append (`>>`), read off the parser's operator. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function redirOpIsAppend(redir: any): boolean {
  return redir?.Op === appendOp();
}
let _appendOp: number | null = null;
function appendOp(): number {
  if (_appendOp !== null) return _appendOp;
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const f: any = parseShared('echo x >> y');
    _appendOp = typeof f === 'symbol' ? -1 : (f.Stmts[0].Redirs[0].Op as number);
  } catch {
    _appendOp = -1;
  }
  return _appendOp;
}

/** The hooks-bypass finding for a command that disarms a hook file. */
function hooksBypassed(shown: string): GitFinding {
  return { ...HOOKS_BYPASS, shown, reason: `${HOOKS_BYPASS.reason}: ${shown}` };
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

// ── Part 3: stage everything at once (opt-in) ────────────────────────────────
//
// A preference, not harm: `git add -A`, `git add .`, `git commit -a` stage
// every change instead of the files the agent names, so a stray .env or a
// generated artifact goes into the commit unnoticed. Off at every level; the
// user switches it on.

const STAGE_ALL: GitFinding = {
  checkId: 'commands.git-stage-all',
  ruleName: 'review-git-stage-all',
  reason: 'Every change staged at once — the files are not named',
  description:
    'The AI stages every change in the working tree (git add -A, git add ., git commit -a) instead of naming the files, so anything lying around goes into the commit. You asked to be told when this happens.',
  shown: '',
};

const ADD_LONG_VALUE = new Set(['--chmod', '--pathspec-from-file']);
/** A pathspec that selects the whole tree. */
function wholeTree(operand: string): boolean {
  if (/^:\(top\)\.?$/.test(operand) || operand === ':/' || operand === '*') return true;
  if (operand.startsWith(':')) return false;
  // `.`, `./`, `src/..`: lexically the current directory.
  const lp = lexicalPath(operand);
  return lp !== null && lp.parts.length === 0;
}

/**
 * The directory `-C` moved into, relative to where the command runs, when
 * every `-C` is a literal relative path that does not climb (`sub`,
 * `packages/a`). Otherwise null: an absolute, climbing (`../app`, often the
 * root of another repository) or dynamic `-C` keeps the plain reading.
 */
function chdirPrefix(inv: GitInvocation): string | null {
  const dirs = inv.chdir ?? [];
  if (dirs.length === 0) return null;
  const parts: string[] = [];
  for (const d of dirs) {
    if (d === null || d === '') return null;
    const lp = lexicalPath(d);
    if (lp === null || lp.climbed) return null;
    parts.push(...lp.parts);
  }
  return parts.length === 0 ? null : parts.join('/');
}

/**
 * Does the call stage the whole tree? `{}` when it does wherever it runs;
 * `{ ifWorkTreeTop: dir }` when a pathspec selects the whole of a `-C`
 * directory, which is the whole tree only if that directory is the top of
 * one (`git -C sub add .` stages `sub`; `git -C myapp add .` from the folder
 * above the repository stages all of it); null when it does not.
 */
function stagesEverything(inv: GitInvocation): { ifWorkTreeTop?: string } | null {
  const sub = inv.sub?.toLowerCase();
  const prefix = chdirPrefix(inv);
  const judge = (operands: string[]): { ifWorkTreeTop?: string } | null => {
    // node9Firewall#385: a pathspec made only of excludes (`:!cache`) names
    // nothing to add and stages everything else, as a bare `.` would.
    if (operands.length > 0 && operands.every(isExcludePathspec)) return {};
    let conditional = false;
    for (const operand of operands) {
      if (!wholeTree(operand)) continue;
      // Pathspec magic (`:/`, `:(top)`) and an absolute path name the top
      // whatever the directory.
      if (prefix === null || operand.startsWith(':') || operand.startsWith('/')) return {};
      if (wholeTree(`${prefix}/${operand === '*' ? '.' : operand}`)) return {};
      conditional = true;
    }
    return conditional && prefix !== null ? { ifWorkTreeTop: prefix } : null;
  };
  if (sub === 'add') {
    const o = parseOptions(inv.args, '', ADD_LONG_VALUE);
    if (
      o.flags.has('-n') ||
      o.flags.has('--dry-run') ||
      o.flags.has('-i') ||
      o.flags.has('--interactive') ||
      o.flags.has('-p') ||
      o.flags.has('--patch') ||
      o.flags.has('-e') ||
      o.flags.has('--edit')
    )
      return null;
    const all =
      o.flags.has('-A') ||
      o.flags.has('--all') ||
      o.flags.has('--no-ignore-removal') ||
      o.flags.has('-u') ||
      o.flags.has('--update');
    if (all && o.operands.length === 0) return {};
    return judge(o.operands);
  }
  if (sub === 'commit') {
    const o = parseOptions(inv.args, 'mFCcut', COMMIT_LONG_VALUE);
    if (o.flags.has('--dry-run')) return null;
    if (o.flags.has('-a') || o.flags.has('--all')) return {};
    return judge(o.operands);
  }
  return null;
}
