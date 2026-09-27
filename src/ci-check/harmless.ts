// src/ci-check/harmless.ts
// Facts that make a content match harmless and that an attacker cannot forge (§Q). The quality study
// of 768 repositories found them behind a large share of the content false positives: an official
// vendor installer, a localhost address, a comment, a message printed for a person, a test fixture.
// A word ("install", "example", "never") is NOT such a fact (anyone can write it), so none is here.

// A URL, as a fetch or a destination names it. Its host is read with the URL parser, so
// `https://bun.sh.evil.test`, `https://bun.sh@evil.test` and `localhost:80@evil.test` name the
// host they really reach.
const URL_RE = /\bhttps?:\/\/[^\s'"`<>|)]+/gi;
function parse(u: string): URL | null {
  try {
    return new URL(u);
  } catch {
    return null;
  }
}

/** Install scripts served from the vendor's own domain. An attacker cannot serve code from these.
 *  A host that also serves other people's files is limited to the vendor's own path. */
const OFFICIAL_HOSTS = new Set([
  'bun.sh',
  'astral.sh',
  'sh.rustup.rs',
  'rustup.rs',
  'get.k3s.io',
  'ollama.com',
  'get.docker.com',
  'get.helm.sh',
  'fnm.vercel.app',
  'pyenv.run',
  'install.python-poetry.org',
  'sdk.cloud.google.com',
  'mise.run',
  'get.pnpm.io',
  'foundry.paradigm.xyz',
  'nixos.org',
]);
const OFFICIAL_PATHS: Record<string, RegExp> = {
  'deno.land': /^\/(install\.sh$|x\/install\/)/,
  'raw.githubusercontent.com': /^\/(Homebrew|nvm-sh|pyenv|golangci|helm)\//,
};
function isOfficialInstaller(u: URL): boolean {
  if (u.username || u.password) return false;
  const host = u.hostname.toLowerCase().replace(/^www\./, '');
  if (OFFICIAL_HOSTS.has(host)) return true;
  const path = OFFICIAL_PATHS[host];
  return !!path && path.test(u.pathname); // pathname is normalized: `..` cannot climb out
}

/** Every URL in `s` is a vendor's own installer, and there is at least one. */
export function onlyOfficialInstaller(s: string): boolean {
  const urls = s.match(URL_RE);
  return (
    !!urls &&
    urls.every((u) => {
      const url = parse(u);
      return !!url && isOfficialInstaller(url);
    })
  );
}

/** This machine: what is fetched from it is not remote code, what is sent to it does not leave. */
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '0.0.0.0', '[::1]']);
const BARE_LOCAL_RE = /(^|[\s'"=(])(localhost|127\.0\.0\.1)(:\d+)?(?=[/\s'")]|$)/i;
// Something dot two letters: a host name, or a file name, which errs toward "not local". Linear:
// no nested quantifier, since the line is the PR author's.
const HOST_LIKE_RE = /[a-z0-9-]\.[a-z]{2}/i;

/** How many harmless matches one line may excuse before the next one is reported anyway. A real
 *  line has one or two; the cap keeps a crafted line from costing a scan per match. */
export const MAX_EXCUSED_PER_LINE = 50;

/** Everything `s` reaches is this machine: every URL has a local host, or, with no URL, a bare
 *  `localhost:PORT` and nothing else that looks like a host. */
export function onlyLocal(s: string): boolean {
  const urls = s.match(URL_RE);
  if (urls) return urls.every((u) => LOCAL_HOSTS.has(parse(u)?.hostname.toLowerCase() ?? ''));
  return BARE_LOCAL_RE.test(s) && !HOST_LIKE_RE.test(s.replace(/\b127\.0\.0\.1\b/g, ''));
}

// A directory that holds tests, fixtures or examples, and a test file by its name.
const TEST_DIR_RE =
  /(^|\/)(tests?|__tests__|testdata|test-data|test_data|fixtures?|__fixtures__|examples?|samples?)\//i;
const TEST_FILE_RE = /(^|\/)(test_[^/]*|[^/]*_test\.[A-Za-z]+|[^/]*\.(test|spec)\.[A-Za-z]+)$/i;
// Where an agent's own configuration starts. A skill named `examples` under `.claude/skills/` is
// a real skill: only a test directory ABOVE this point makes the tree a fixture.
const AGENT_ROOT_RE = /(^|\/)\.(claude|agents|codex|cursor|github|gemini|windsurf|cline)\//;
// Files an agent loads by their name from whatever directory it works in.
const LOADED_BY_NAME_RE = /(^|\/)(CLAUDE|AGENTS|GEMINI)\.md$/;

// The last `skills/` folder: a skill tree with no agent folder above it (a plugin, a marketplace).
const SKILLS_DIR_RE = /(^|\/)skills\/(?!.*(^|\/)skills\/)/;

/** How a content file under a test, fixture or example tree is graded:
 *   none        not such a file: graded as usual.
 *   alerts-only its alerts (concealment) stay; its review items are dropped. The default: an agent
 *               may still load the file, and hidden characters have no legitimate use anywhere.
 *   skip        read, not graded: an instruction file in a fixture tree that no agent loads, i.e. with
 *               no agent folder (`.claude/` and the like) and not loaded by its name (CLAUDE.md). A
 *               scanner's own attack fixtures live there.
 *  Only the path ABOVE the agent folder, else above the last `skills/`, else the file's folder, is
 *  tested: a skill named `examples` is a real skill. Test file names count for scripts only. */
export function testPathKind(p: string, route: string): 'none' | 'skip' | 'alerts-only' {
  const root = AGENT_ROOT_RE.exec(p);
  const skills = root ? null : SKILLS_DIR_RE.exec(p);
  const cut = root
    ? root.index + root[1].length
    : skills
      ? skills.index + skills[1].length
      : p.lastIndexOf('/') + 1;
  const test =
    TEST_DIR_RE.test(p.slice(0, cut)) || (route !== 'instruction' && TEST_FILE_RE.test(p));
  if (!test) return 'none';
  return route === 'instruction' && !root && !LOADED_BY_NAME_RE.test(p) ? 'skip' : 'alerts-only';
}

/** A whole line that is a comment in the script languages an agent runs. It never executes. */
export const isCommentLine = (line: string): boolean =>
  /^\s*(#|\/\/|\/\*|\*|--\s|REM\b)/i.test(line);

// Output a person reads. Not assignments or arguments of anything that runs a command: a string
// handed to os.system, subprocess, exec, `bash -c` or execSync IS executed.
const MESSAGE_CALL_RE =
  /\b(print|console\.(?:log|warn|error|info)|echo|printf|log(?:ger)?\.(?:info|warn|warning|error|debug)|warn|raise\s+\w+|throw\s+new\s+\w+)\s*\(?\s*[fFrRbB]?["'`]$/;
const PIPED_TO_SHELL_RE = /\|\s*(sudo\s+)?(bash|sh|zsh|python3?|node|iex)\b/i;

/** The match at `index` sits inside a string that is only printed for a person: the string is the
 *  argument of a print/echo/log/error call on this line, and nothing pipes it onward to a shell. */
export function inPrintedMessage(line: string, index: number): boolean {
  const before = line.slice(0, index);
  for (const q of ['"', "'", '`']) {
    const open = before.lastIndexOf(q);
    if (open < 0 || before.split(q).length % 2 === 1) continue; // not inside a string of this quote
    const call = MESSAGE_CALL_RE.exec(line.slice(0, open + 1));
    if (!call) return false;
    const close = line.indexOf(q, index);
    if (close < 0) return false;
    // A string that runs code inside it is not a message: `$(…)` and backticks in a shell
    // string, `${…}` in a template, `{…}` in a Python f-string, and backticks after echo.
    const body = line.slice(open + 1, close);
    if (/\$\(|\$\{|`/.test(body)) return false;
    if (q === '`' && /^(echo|printf)$/.test(call[1])) return false;
    if (/[fF]["'`]$/.test(call[0]) && body.includes('{')) return false;
    return !PIPED_TO_SHELL_RE.test(line.slice(close + 1));
  }
  return false;
}
