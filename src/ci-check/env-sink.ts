// src/ci-check/env-sink.ts
// Gap 4 (CI-2.agent-output-to-env): the agent's text written into `$GITHUB_ENV` or
// `$GITHUB_PATH`. The runner reads those files after each step and applies them to every later
// step of the job (and to the post steps of actions), so a value the agent chose can set
// `NODE_OPTIONS`, `BASH_ENV`, `LD_PRELOAD` or the PATH: code execution in the job.
//
// Pure text analysis over ONE job's steps, in order. Conservative by design:
//   sources      the agent CLI's redirect target (`> f`, `>> f`, `| tee f`, `-o f`), a variable
//                assigned from a command that runs the CLI, and `steps.<agent>.outputs.*`;
//   propagation  shell assignments and file writes that read a source, to a fixed point
//                (variables live in one step, files and step outputs in the whole job);
//   sink         a command that writes to `$GITHUB_ENV` / `$GITHUB_PATH` and reads a source.
// Not a sink: a value that cannot hold a newline (`jq -c` or plain `jq`, `tr -d '\n'`,
// `head -n 1`, `read`) written under a fixed `NAME=`, a number or boolean (`tonumber`, `length`,
// `wc -l`, `grep -c`), and the `NAME<<$DELIM` form with a delimiter generated at run time.
// Everything here runs on attacker-controlled text: bounded sizes, no backtracking regexes.

/** `full`: may hold a newline. `line`: one line, no newline. */
export type Level = 'full' | 'line';

export interface SinkStep {
  id?: string;
  /** The `run:` text of a run step (absent on a `uses:` step). */
  run?: string;
  /** A `uses:` step: its action may have a post step that runs after the last step. */
  uses?: boolean;
  /** The step's own `env:`; values may reference `steps.<id>.outputs.*`. */
  stepEnv?: Record<string, unknown>;
  /** The step, job and workflow `env:` this step sees (names that point at a file). */
  env?: Record<string, unknown>;
  /** Is this step the agent: a run step that starts its CLI, or an agent action. */
  agent: 'run' | 'action' | null;
}

export interface EnvSink {
  /** Index of the step that writes the value. */
  step: number;
  target: 'GITHUB_ENV' | 'GITHUB_PATH';
  /** The command that writes it, as written. */
  text: string;
}

const RUN_MAX = 100_000;
const LINES_MAX = 4_000;
const PASSES = 3;
// Tainted files and variables kept per job, commands read per job, lines looked back for a block
// opener: the scanned text is attacker-controlled, and these keep one job linear in practice.
const TAINT_MAX = 256;
const COMMANDS_MAX = 40_000;
const LOOKBACK = 200;

// ── reading a run block into commands ───────────────────────────────────────

/** Logical lines of a shell script: a newline inside quotes or `$( )`, or after a backslash,
 *  does not end one; comments are dropped; an unquoted heredoc body is appended to the line
 *  that opens it (a quoted one is literal text and is dropped). One linear pass. */
export function logicalLines(src: string): string[] {
  const run = src.length > RUN_MAX ? src.slice(0, RUN_MAX) : src;
  const out: string[] = [];
  let buf = '';
  let quote: '"' | "'" | null = null;
  let depth = 0; // inside `$( )`
  const heredocs: { delim: string; strip: boolean; quoted: boolean }[] = [];
  let i = 0;
  const n = run.length;
  const endLine = () => {
    // Read the bodies of the heredocs this line opened.
    for (const h of heredocs) {
      const body: string[] = [];
      while (i < n) {
        let j = run.indexOf('\n', i);
        if (j < 0) j = n;
        const raw = run.slice(i, j);
        i = j + 1;
        if ((h.strip ? raw.replace(/^\t+/, '') : raw).trim() === h.delim) break;
        body.push(raw);
      }
      // Data, not syntax: its quotes and separators must not split or open anything.
      if (!h.quoted && body.length) buf += '\n' + body.join('\n').replace(/['"`;&|]/g, ' ');
    }
    heredocs.length = 0;
    if (buf.trim() && out.length < LINES_MAX) out.push(buf);
    buf = '';
  };
  while (i < n) {
    const c = run[i];
    if (quote === "'") {
      buf += c;
      if (c === "'") quote = null;
      i++;
      continue;
    }
    if (c === '\\' && i + 1 < n) {
      if (run[i + 1] === '\n') {
        buf += ' ';
        i += 2;
        continue;
      }
      buf += c + run[i + 1];
      i += 2;
      continue;
    }
    if (quote === '"') {
      buf += c;
      if (c === '"') quote = null;
      i++;
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      buf += c;
      i++;
      continue;
    }
    if (c === '$' && run[i + 1] === '(') {
      depth++;
      buf += '$(';
      i += 2;
      continue;
    }
    if (depth > 0 && c === '(') depth++;
    if (depth > 0 && c === ')') depth--;
    if (c === '#' && (buf === '' || /\s/.test(buf[buf.length - 1]))) {
      const j = run.indexOf('\n', i);
      i = j < 0 ? n : j;
      continue;
    }
    if (c === '<' && run[i + 1] === '<' && run[i + 2] !== '<') {
      const m = /^<<(-?)[ \t]*(["']?)([A-Za-z_][\w-]{0,60})\2/.exec(run.slice(i, i + 80));
      if (m) {
        heredocs.push({ delim: m[3], strip: m[1] === '-', quoted: m[2] !== '' });
        buf += m[0];
        i += m[0].length;
        continue;
      }
    }
    if (c === '\n') {
      i++;
      if (depth > 0) {
        buf += ' ; ';
        continue;
      }
      endLine();
      continue;
    }
    buf += c;
    i++;
  }
  endLine();
  return out;
}

/** Top-level commands of one logical line: split at `;`, `&&`, `||` and `&` outside quotes and
 *  `$( )`. A pipe stays inside its command. */
export function commandsOf(line: string): string[] {
  const out: string[] = [];
  let buf = '';
  let quote: '"' | "'" | null = null;
  let depth = 0;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      buf += c;
      if (c === '\\' && quote === '"' && i + 1 < line.length) buf += line[++i];
      else if (c === quote) quote = null;
      continue;
    }
    if (c === "'" || c === '"') quote = c;
    else if (c === '$' && line[i + 1] === '(') depth++;
    else if (c === '(' && depth > 0 && line[i - 1] !== '$') depth++;
    else if (c === ')' && depth > 0) depth--;
    else if (depth === 0 && c === '\n') {
      // a heredoc body line: part of the same command
    } else if (depth === 0 && (c === ';' || c === '&' || (c === '|' && line[i + 1] === '|'))) {
      if (c === '&' && (line[i - 1] === '>' || line[i + 1] === '>')) {
        buf += c; // `2>&1`, `&>`
        continue;
      }
      if (buf.trim()) out.push(buf);
      buf = '';
      if ((c === '&' && line[i + 1] === '&') || c === '|') i++;
      continue;
    }
    buf += c;
  }
  if (buf.trim()) out.push(buf);
  return out;
}

/** Top-level `$( … )` substitutions of a command, and the command with them blanked out. */
function substitutions(cmd: string): { subs: string[]; outer: string } {
  const subs: string[] = [];
  let outer = '';
  let quote: "'" | null = null;
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    if (quote) {
      outer += c;
      if (c === "'") quote = null;
      continue;
    }
    if (c === "'") {
      quote = c;
      outer += c;
      continue;
    }
    if (c === '$' && cmd[i + 1] === '(') {
      let depth = 1;
      let j = i + 2;
      for (; j < cmd.length && depth > 0; j++) {
        if (cmd[j] === '(') depth++;
        else if (cmd[j] === ')') depth--;
      }
      subs.push(cmd.slice(i + 2, j - 1));
      outer += ' $SUB' + (subs.length - 1) + ' ';
      i = j - 1;
      continue;
    }
    outer += c;
  }
  return { subs, outer };
}

// ── what a command writes to ────────────────────────────────────────────────

const SINK_TARGET_RE =
  /(?:>>?|\btee\b(?:\s+-a|\s+--append)*)\s*["']?\$\{?(GITHUB_ENV|GITHUB_PATH)\}?["']?|\$env:(GITHUB_ENV|GITHUB_PATH)\b/i;
const OUTPUT_TARGET_RE = />>?\s*["']?\$\{?GITHUB_OUTPUT\}?["']?|\$env:GITHUB_OUTPUT\b/i;
const REDIRECT_RE = /(?:^|[^<>&\d])>>?\s*(["']?)([^\s"'|;&<>()]{1,300})\1/g;
const TEE_RE = /\btee\s+((?:-a\s+|--append\s+)*)(["']?)([^\s"'|;&<>()]{1,300})\2/g;
const OUTPUT_FLAG_RE =
  /(?:^|\s)(?:-o|--output|--output-file|--output-last-message)(?:=|\s+)(["']?)([^\s"'|;&<>()]{1,300})\1/g;
const ASSIGN_RE =
  /^\s*(?:(?:export|local|readonly|typeset|declare)\s+(?:-[a-zA-Z]+\s+)*)?([A-Za-z_][A-Za-z0-9_]{0,100})=/;
const READ_RE = /^\s*read\s+((?:-[a-zA-Z]+\s+)*)([A-Za-z_][\w\s]{0,200})/;

function sinkTarget(cmd: string): 'GITHUB_ENV' | 'GITHUB_PATH' | null {
  const m = SINK_TARGET_RE.exec(cmd);
  if (!m) return null;
  return (m[1] ?? m[2]).toUpperCase() === 'GITHUB_PATH' ? 'GITHUB_PATH' : 'GITHUB_ENV';
}

/** `${X}` → `$X`, quotes dropped, a leading `./` dropped: one spelling per path. */
function normPath(p: string): string {
  return p
    .replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, '$$$1')
    .replace(/["']/g, '')
    .replace(/^\.\//, '');
}

function isSpecialTarget(p: string): boolean {
  return /^(\/dev\/|&|\$\{?GITHUB_(ENV|PATH|OUTPUT|STEP_SUMMARY|STATE)\b|\$env:)/i.test(p);
}

/** The text with what is inside quotes blanked, same length: a `>` in a message is no redirect,
 *  and a match index still points into the original. */
function maskQuoted(text: string): string {
  let out = '';
  let quote: '"' | "'" | null = null;
  for (const c of text) {
    if (quote) {
      if (c === quote) {
        quote = null;
        out += c;
      } else out += c === '\n' ? c : '_';
    } else {
      if (c === '"' || c === "'") quote = c;
      out += c;
    }
  }
  return out;
}

/** The files a command writes its output to. */
function writeTargets(cmd: string): string[] {
  const out: string[] = [];
  const { outer } = substitutions(cmd);
  const masked = maskQuoted(outer);
  // Match on the masked text, read the target from the original (`> "$OUT"`).
  for (const m of masked.matchAll(REDIRECT_RE)) {
    const start = (m.index ?? 0) + m[0].length - m[2].length - m[1].length * 2;
    const raw = outer.slice(start, (m.index ?? 0) + m[0].length);
    out.push(raw);
  }
  for (const m of masked.matchAll(TEE_RE)) {
    const start = (m.index ?? 0) + m[0].length - m[3].length - m[2].length * 2;
    out.push(outer.slice(start, (m.index ?? 0) + m[0].length));
  }
  return out.map(normPath).filter((p) => p && !isSpecialTarget(p) && !/^\$SUB\d+$/.test(p));
}

// ── how much of a source survives a command ─────────────────────────────────

const NUMERIC_RE =
  /\btonumber\b|\|\s*length\b|\|\s*test\(|\|\s*(?:startswith|endswith|contains|has)\(|\bwc\s+-[lwcm]\b|\bgrep\s+(?:-[a-zA-Z]*[cq][a-zA-Z]*|--count|--quiet)\b/g;
const STRIP_RE =
  /\btr\s+(?:-d|--delete|-cd|-dc)\s+["']?[^"'\s]{0,40}?(?:\\n|\[:space:\]|\[:cntrl:\])|\btr\s+-c?dc?\s+["']?\[:(?:alnum|print|digit|alpha|xdigit|graph):\]|\btr\s+["']\\n["']\s|\bhead\s+(?:-n\s*1|-1|--lines=1)\b/g;
const JQ_RE = /\bjq\b((?:\s+-{1,2}[a-zA-Z][\w-]{0,30})*)/g;

/** The last transform in `text` decides: a number (null), one line, or raw text. */
/** Pipeline stages of a command: split at a top-level `|` (not `||`) outside quotes. */
function pipelineStages(cmd: string): string[] {
  const out: string[] = [];
  let buf = '';
  let quote: '"' | "'" | null = null;
  let depth = 0;
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    if (quote) {
      if (c === quote) quote = null;
    } else if (c === '"' || c === "'") quote = c;
    else if (c === '(') depth++;
    else if (c === ')' && depth > 0) depth--;
    else if (c === '|' && depth === 0 && cmd[i + 1] !== '|' && cmd[i - 1] !== '|') {
      out.push(buf);
      buf = '';
      continue;
    }
    buf += c;
  }
  out.push(buf);
  return out;
}

/** The transform that decides a command's output. The agent's own stage is skipped, and so is
 *  everything before it: its arguments are a prompt, which may well mention `jq` or `tr`. */
function transformOf(cmd: string, agentLine: RegExp | null): { level: Level | null } | null {
  if (!agentLine) return lastTransform(cmd);
  const stages = pipelineStages(cmd);
  let last = -1;
  stages.forEach((st, i) => {
    if (agentLine.test(st)) last = i;
  });
  return lastTransform(stages.slice(last + 1).join(' | '));
}

function lastTransform(text: string): { at: number; level: Level | null } | null {
  let best: { at: number; level: Level | null } | null = null;
  const take = (at: number, level: Level | null) => {
    if (!best || at >= best.at) best = { at, level };
  };
  for (const m of text.matchAll(NUMERIC_RE)) take(m.index ?? 0, null);
  for (const m of text.matchAll(STRIP_RE)) take(m.index ?? 0, 'line');
  for (const m of text.matchAll(JQ_RE)) {
    const flags = m[1] ?? '';
    const raw = /(?:^|\s)-[a-zA-Z]*[rj]|--raw-output|--join-output/.test(flags);
    take(m.index ?? 0, raw ? 'full' : 'line');
  }
  return best;
}

const max = (a: Level | null, b: Level | null): Level | null =>
  a === 'full' || b === 'full' ? 'full' : (a ?? b);

// Agent action outputs that are not the agent's text (claude-code-action's branch and session).
const NON_TEXT_OUTPUT_RE =
  /^(branch_name|session_id|github_token|conclusion|exit_code|exit-code)$/i;
const PATH_OUTPUT_RE = /[_-](file|path)$/i;
const READER_RE = /\b(cat|jq|yq|head|tail|grep|sed|awk|cut|python3?|node)\b|<\s*["']?\$\{\{/;

interface Taint {
  vars: Map<string, Level>;
  files: Map<string, Level>;
  outputs: Map<string, Level>;
  /** Env names in this step whose value is a tainted file path: `$NAME` reads the file. */
  fileVars: Map<string, Level>;
  agentLine: RegExp | null;
}

/** Sources `text` reads directly (no transform applied), and where the first one is. */
function directSources(text: string, t: Taint): { level: Level | null; at: number } {
  let level: Level | null = null;
  let at = Infinity;
  const hit = (l: Level, i: number) => {
    level = max(level, l);
    if (i < at) at = i;
  };
  for (const m of text.matchAll(/\$\{?([A-Za-z_][A-Za-z0-9_]{0,100})/g)) {
    const l = t.vars.get(m[1]) ?? t.fileVars.get(m[1]);
    if (l) hit(l, m.index ?? 0);
  }
  for (const m of text.matchAll(/steps\.([\w-]{1,100})\.outputs\.([\w-]{0,100})/g)) {
    const l = t.outputs.get(m[1]);
    if (!l || NON_TEXT_OUTPUT_RE.test(m[2])) continue;
    // A path output (`execution_file`) is the agent's text only where a command reads it.
    if (PATH_OUTPUT_RE.test(m[2]) && !READER_RE.test(text)) continue;
    hit(l, m.index ?? 0);
  }
  if (t.files.size) {
    const norm = text.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, '$$$1').replace(/["']/g, '');
    for (const [p, l] of t.files) {
      let from = 0;
      for (;;) {
        const i = norm.indexOf(p, from);
        if (i < 0) break;
        from = i + 1;
        const before = i > 0 ? norm[i - 1] : ' ';
        const after = norm[i + p.length] ?? ' ';
        if (/[\w.-]/.test(before) || /[\w.-]/.test(after)) continue;
        // `norm` drops quotes, so `at` is approximate; it is only compared with a `NAME=`.
        hit(l, text.indexOf(p) >= 0 ? text.indexOf(p) : i);
        break;
      }
    }
  }
  if (t.agentLine) {
    const m = t.agentLine.exec(text);
    if (m) hit('full', m.index);
  }
  return { level, at };
}

/** The level of what a command produces from its sources, and where the first source is. */
export function levelOf(cmd: string, t: Taint): { level: Level | null; at: number } {
  const { subs, outer } = substitutions(cmd);
  const subLevels = subs.map((s) => {
    const d = directSources(s, t);
    if (!d.level) return null;
    const tr = transformOf(s, t.agentLine);
    // The last transform decides what is left: a number, one line, or raw text.
    return tr ? tr.level : d.level;
  });
  const direct = directSources(outer.replace(/\$SUB\d+/g, ''), t);
  let level = direct.level;
  let at = direct.at;
  for (const m of outer.matchAll(/\$SUB(\d+)/g)) {
    const l = subLevels[Number(m[1])];
    if (!l) continue;
    level = max(level, l);
    // Position in the original command: the n-th `$(`.
    const pos = nthIndexOf(cmd, '$(', Number(m[1]));
    if (pos >= 0 && pos < at) at = pos;
  }
  if (!level) return { level: null, at };
  // A pipeline after the sources: `cat f | tr -d '\n' >> "$GITHUB_ENV"`.
  const tr = transformOf(outer, t.agentLine);
  if (tr) level = tr.level;
  return { level, at };
}

function nthIndexOf(s: string, needle: string, n: number): number {
  let i = -1;
  for (let k = 0; k <= n; k++) {
    i = s.indexOf(needle, i + 1);
    if (i < 0) return -1;
  }
  return i;
}

// ── the analysis ────────────────────────────────────────────────────────────

const RANDOM_RE =
  /openssl\s+rand|uuidgen|\/dev\/urandom|\$RANDOM\b|\/proc\/sys\/kernel\/random\/uuid|secrets\.token_|randomUUID|randomBytes|mktemp\s+-u/;
// `NAME<<$DELIM` / `NAME<<EOF` (GitHub's multi-line form; a shell heredoc has a space first).
const GH_HEREDOC_RE =
  /[A-Za-z_][A-Za-z0-9_]{0,100}<<\s*["']?(?:\$\{?([A-Za-z_][A-Za-z0-9_]{0,100})\}?|([A-Za-z_][\w-]{0,60}))/;
const DONE_FROM_RE = /\bdone\s*<\s*\S{1,300}/;
const WHILE_READ_RE =
  /\bwhile\b[^;\n]{0,200}?\bread\s+(?:-[a-zA-Z]+\s+)*([A-Za-z_][\w\s]{0,200}?)\s*(?:;|$|\n)/;

/** `echo "$D"` / `echo EOF` alone: the line that ends a `NAME<<D` block. */
function echoes(delim: string, isVar: boolean): RegExp {
  const d = isVar ? `\\$\\{?${delim}\\}?` : delim;
  return new RegExp(`(?:^|[\\s;{])echo\\s+["']?${d}["']?\\s*(?:[>;}]|$)`, 'm');
}
// The written line starts with a name the workflow chose: `echo "NAME=…"`, `printf 'NAME=…'`, or
// a line of a shell heredoc body. An inline env assignment (`LC_ALL=C tr …`) is not one.
const FIXED_NAME_RE =
  /\b(?:echo|printf)(?:\s+-[a-zA-Z]+)*\s+["']?[A-Za-z_][A-Za-z0-9_]{0,100}(?:=|<<)|\n[ \t]*[A-Za-z_][A-Za-z0-9_]{0,100}(?:=|<<)/;
// The binary followed by an argument, not the word in a message (`echo "MODEL=claude"`).
const LOOSE_AGENT_RE = /(?:^|[\s;&|(])(?:claude|aider|codex|gemini)\s+[-"'$]/i;

/** Block closers whose redirect applies to the lines since the opener. */
const BLOCK_CLOSE_RE = /^\s*(\}|\)|done|fi)(?![\w-])/;
const BLOCK_OPEN: Record<string, RegExp> = {
  '}': /(?:^|\s)\{\s*$/,
  ')': /^\s*\(\s*$/,
  done: /^\s*(?:for|while|until)\b/,
  fi: /^\s*if\b/,
};

/** Raise a name's level, up to TAINT_MAX names per map. */
function taint(m: Map<string, Level>, k: string, l: Level): void {
  if (!m.has(k) && m.size >= TAINT_MAX) return;
  m.set(k, max(m.get(k) ?? null, l) as Level);
}

function envFilePaths(env: Record<string, unknown> | undefined, files: Map<string, Level>) {
  const out = new Map<string, Level>();
  if (!env || typeof env !== 'object') return out;
  for (const [k, v] of Object.entries(env)) {
    if (typeof v !== 'string' || !/^[A-Za-z_]\w{0,100}$/.test(k)) continue;
    const l = files.get(normPath(v.trim()));
    if (l) out.set(k, l);
  }
  return out;
}

/** The commands in one job that write the agent's output into `$GITHUB_ENV` or `$GITHUB_PATH`
 *  in a form that can set another variable (or any PATH entry). */
export function agentOutputSinks(steps: SinkStep[], agentCli: RegExp): EnvSink[] {
  const files = new Map<string, Level>();
  const outputs = new Map<string, Level>();
  const sinks: EnvSink[] = [];
  const agentRe = new RegExp(agentCli.source, agentCli.flags.replace('g', ''));
  let budget = COMMANDS_MAX;

  steps.forEach((st, idx) => {
    if (st.agent === 'action') {
      if (st.id) outputs.set(st.id, 'full');
      return;
    }
    if (typeof st.run !== 'string' || !st.run) return;
    const lines = logicalLines(st.run);
    // The agent lines of a run-step agent: its CLI, or (for the loose run-step heuristic) the
    // agent word.
    let agentLine: RegExp | null = null;
    if (st.agent === 'run')
      agentLine = lines.some((l) => agentRe.test(l)) ? agentRe : LOOSE_AGENT_RE;
    const vars = new Map<string, Level>();
    // The step `env:` can hand it an agent action's output.
    for (const [k, v] of Object.entries(st.stepEnv ?? {})) {
      if (!/^[A-Za-z_]\w{0,100}$/.test(k)) continue;
      const d = directSources(String(v ?? ''), {
        vars: new Map(),
        files: new Map(),
        outputs,
        fileVars: new Map(),
        agentLine: null,
      });
      if (d.level) vars.set(k, d.level);
    }
    const randomVars = new Set<string>();
    const stepSinks: EnvSink[] = [];
    for (let pass = 0; pass < PASSES; pass++) {
      const before = vars.size + files.size + outputs.size;
      stepSinks.length = 0;
      let open: { delim: string; random: boolean } | null = null;
      const t: Taint = {
        vars,
        files,
        outputs,
        fileVars: envFilePaths(st.env, files),
        agentLine,
      };
      for (let li = 0; li < lines.length && budget > 0; li++) {
        for (const cmd of commandsOf(lines[li])) {
          if (--budget < 0) break;
          const isAgentCmd = !!agentLine && agentLine.test(cmd);
          const target = sinkTarget(cmd);
          if (target) {
            // `{ …; } >> "$GITHUB_ENV"`: the redirect covers the block since its opener.
            let parts = [cmd];
            const close = BLOCK_CLOSE_RE.exec(cmd);
            if (close) {
              const opener = BLOCK_OPEN[close[1]];
              for (let k = li - 1; k >= Math.max(0, li - LOOKBACK); k--) {
                if (opener.test(lines[k])) {
                  parts = lines.slice(k, li).flatMap(commandsOf).concat(cmd);
                  break;
                }
              }
            }
            const content = parts.join('\n');
            // The `NAME<<DELIM` state over the step's writes to the file.
            const hd = GH_HEREDOC_RE.exec(content);
            if (hd) {
              const isVar = hd[1] !== undefined;
              const d = hd[1] ?? hd[2];
              const rest = content.slice(hd.index + hd[0].length);
              const closes = !!d && echoes(d, isVar).test(rest);
              open = closes ? null : { delim: d ?? '', random: isVar && randomVars.has(d) };
              // A delimiter made at run time: the value cannot end the block early.
              if (isVar && randomVars.has(d)) continue;
            } else if (open) {
              if (open.delim && echoes(open.delim, open.random).test(content)) {
                open = null;
                continue;
              }
              if (open.random) continue;
            }
            let level: Level | null = null;
            let fixedName = !!hd || !!open;
            for (const part of parts) {
              const r = levelOf(part, t);
              if (!r.level) continue;
              if (!level && !fixedName)
                fixedName = FIXED_NAME_RE.test(part.slice(0, Number.isFinite(r.at) ? r.at : 0));
              level = max(level, r.level);
            }
            if (!level) continue;
            // One line under a name the workflow fixed: cannot set another variable. Any entry
            // in PATH is a directory the later steps search for their commands.
            if (target === 'GITHUB_ENV' && level === 'line' && fixedName) continue;
            stepSinks.push({ step: idx, target, text: content });
            continue;
          }
          // `while read -r x; do …; done < "$F"`: each line of a tainted file, one at a time.
          const loopFile = DONE_FROM_RE.exec(cmd);
          if (loopFile) {
            const l = levelOf(loopFile[0], t).level;
            if (l) {
              for (let k = li; k >= Math.max(0, li - LOOKBACK); k--) {
                const w = WHILE_READ_RE.exec(lines[k]);
                if (!w) continue;
                for (const v of w[1].trim().split(/\s+/))
                  if (/^[A-Za-z_]\w*$/.test(v) && !vars.has(v)) vars.set(v, 'line');
                break;
              }
            }
          }
          // Propagation.
          const { level } = levelOf(cmd, t);
          const assign = ASSIGN_RE.exec(cmd);
          if (assign) {
            const rhs = cmd.slice(assign[0].length);
            if (RANDOM_RE.test(rhs)) randomVars.add(assign[1]);
            if (level) taint(vars, assign[1], level);
          }
          const read = READ_RE.exec(cmd);
          if (read && level && !/-d/.test(read[1])) {
            for (const v of read[2].trim().split(/\s+/))
              if (/^[A-Za-z_]\w*$/.test(v) && !vars.has(v)) vars.set(v, 'line');
          }
          if (level || isAgentCmd) {
            const l: Level = isAgentCmd ? 'full' : (level as Level);
            for (const p of writeTargets(cmd)) taint(files, p, l);
            if (isAgentCmd)
              for (const m of cmd.matchAll(OUTPUT_FLAG_RE)) {
                const p = normPath(m[2]);
                if (p && !isSpecialTarget(p)) taint(files, p, 'full');
              }
            if (st.id && OUTPUT_TARGET_RE.test(cmd))
              outputs.set(st.id, max(outputs.get(st.id) ?? null, l) as Level);
          }
        }
      }
      // A redirect target named by an env variable (`> "$OUT"`) is the file `OUT` points at.
      for (const [k, v] of Object.entries(st.env ?? {})) {
        if (typeof v !== 'string') continue;
        const l = files.get('$' + k);
        if (l && !files.has(normPath(v.trim()))) taint(files, normPath(v.trim()), l);
      }
      if (vars.size + files.size + outputs.size === before) break;
    }
    sinks.push(...stepSinks);
  });

  // GITHUB_ENV applies to the steps after the write, and to the post steps of actions.
  return sinks.filter(
    (s) => s.step < steps.length - 1 || steps.slice(0, s.step + 1).some((p) => p.uses)
  );
}
