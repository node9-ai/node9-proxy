// Inline code: ask only when the code does something dangerous
// (node9Firewall#385, design: docs/roadmap/active/inline-code-dangerous-only-design.md).
//
// commands.inline-exec used to review every `python3 -c`, `node -e` and heredoc
// into an interpreter on sight: the gate could not see what the code did, so
// it asked. That made every ordinary one-liner an agent writes (parse JSON,
// compute a checksum, run a small program and its tests) a prompt. This module
// reads the code instead and returns one of three outcomes:
//
//   null            readable and ordinary: no prompt
//   'dangerous'     the code deletes, writes outside the project, sends data
//                   out, opens a socket or a shell, runs other commands, reads
//                   a protected file, changes permissions, or amplifies
//   'unreadable'    the code builds what it runs (eval, exec, a module name
//                   made at run time, unsafe deserialization), or the language
//                   is one node9 does not scan
//
// The scan is textual: regular expressions over the literal code, per language
// family. It is not an interpreter. A dangerous operation spelled in a way the
// tables do not name passes; the tables are the harm categories the rest of
// node9 uses, and a miss becomes a corpus row and a new pattern. A module
// imported under an alias (`import os as o`) is resolved before the scan; a
// module whose name is built at run time is 'unreadable' and keeps the review.
// The jail, the destination extractors and the file policy keep judging the
// same command on their own; this decides only whether the inline FORM asks.
// Pure: no I/O.

export type InlineLanguage = 'python' | 'node' | 'perl' | 'ruby' | 'php';

export type InlineCodeCategory =
  | 'deletes'
  | 'writes-outside'
  | 'sends'
  | 'listens'
  | 'runs-commands'
  | 'reads-protected'
  | 'builds-code'
  | 'permissions'
  | 'monitors'
  | 'amplifies';

export interface InlineCodeFinding {
  outcome: 'dangerous' | 'unreadable';
  /** What the code does, for the approval prompt ("deletes files"). */
  what: string;
  /** The text that matched, cut short ("os.remove"). */
  evidence?: string;
  category?: InlineCodeCategory;
}

/** Code longer than this is not scanned; it keeps the review. */
export const MAX_INLINE_CODE = 64 * 1024;

const WHAT: Record<InlineCodeCategory, string> = {
  deletes: 'deletes files',
  'writes-outside': 'writes a file outside the project',
  sends: 'sends data over the network',
  listens: 'opens a listening socket or a shell',
  'runs-commands': 'runs other commands or processes',
  'reads-protected': 'reads a protected file',
  'builds-code': 'runs code it builds at run time',
  permissions: 'changes permissions or ownership',
  monitors: 'captures the screen, the clipboard or the keyboard',
  amplifies: 'writes or sends in an endless loop',
};

type Table = Array<[InlineCodeCategory, RegExp]>;

// A path literal that leaves the project: absolute, home-relative or climbing
// out with `../`, except the temp directories and the null/standard devices,
// where scripts write scratch. A temp path that climbs (`/tmp/../etc`) is not
// exempt.
const OUTSIDE = String.raw`(?:~|\.\.[\\/]|/(?!(?:tmp|var/tmp)/(?![^'"\n]*\.\.)|dev/(?:null|stdout|stderr)\b))`;

// `import a, b as c, socket` / `from socket import x`, anywhere in the code (a
// one-liner chains statements with `;`, so a line anchor would miss it).
const pyImport = (mods: string): RegExp =>
  new RegExp(String.raw`\b(?:import\s+(?:[\w.]+(?:\s+as\s+\w+)?\s*,\s*)*|from\s+)(?:${mods})\b`);
const either = (...res: RegExp[]): RegExp =>
  new RegExp(res.map((r) => `(?:${r.source})`).join('|'), 'm');

const PYTHON: Table = [
  [
    'deletes',
    /\bos\.(?:remove|unlink|rmdir|removedirs)\s*\(|\bshutil\.rmtree\s*\(|\.(?:unlink|rmdir)\s*\(|\bfrom\s+(?:os|shutil)\s+import\s+[^\n]*\b(?:remove|unlink|rmdir|removedirs|rmtree)\b/,
  ],
  [
    'writes-outside',
    new RegExp(
      String.raw`\bopen\s*\(\s*[rRbBuU]?['"]${OUTSIDE}[^'"\n]*['"]\s*,\s*(?:mode\s*=\s*)?[rRbB]?['"][^'"\n]*[wax+]|\bPath\s*\(\s*[rR]?['"]${OUTSIDE}[^'"\n]*['"]\s*\)\s*\.(?:write_text|write_bytes|touch|mkdir|symlink_to)\s*\(|\bshutil\.(?:copy\w*|move)\s*\([^)\n]*['"]${OUTSIDE}|\bos\.(?:rename|replace|symlink|link|truncate|makedirs|mkdir)\s*\([^)\n]*['"]${OUTSIDE}`
    ),
  ],
  [
    'sends',
    either(
      pyImport(
        String.raw`socket|requests|urllib2|urllib3|http\.client|httplib|smtplib|ftplib|paramiko|telnetlib|aiohttp|httpx|websockets?|xmlrpc|poplib|imaplib|pycurl|scapy`
      ),
      /\burllib\.request\b|\burlopen\s*\(|\bfrom\s+urllib\s+import\s+[^\n;]*\brequest\b|\basyncio\.open_connection\s*\(/
    ),
  ],
  [
    'listens',
    either(
      pyImport(String.raw`pty|socketserver|http\.server`),
      /\bpty\.spawn\s*\(|\.bind\s*\(\s*\(|\basyncio\.start_server\s*\(/
    ),
  ],
  [
    'runs-commands',
    either(
      pyImport('subprocess|pexpect|commands|psutil'),
      /\bos\.(?:system|popen|exec\w*|spawn\w*|posix_spawn\w*|fork|forkpty|kill|killpg)\s*\(|\bfrom\s+os\s+import\s+[^\n;]*\b(?:system|popen|exec\w*|spawn\w*|fork|kill)\b|\bfrom\s+(?:os|shutil|pty|ctypes)\s+import\s+\*/
    ),
  ],
  [
    'builds-code',
    /(?<![\w.])(?:exec|eval|compile|execfile)\s*\(|\b__import__\s*\(|\bimportlib\b|\b(?:c?pickle|dill|marshal|shelve)\.loads?\s*\(|\byaml\.(?:unsafe_)?load\s*\((?![^)\n]*SafeLoader)|\bctypes\b|\b(?:getattr|vars)\s*\(\s*(?:os|subprocess|shutil|socket|sys|pty|builtins|__builtins__)\b|\b(?:os|subprocess|shutil|socket|sys|pty|builtins)\.__dict__\b|\b__builtins__\b|\bsys\.modules\b|\bglobals\s*\(\s*\)\s*\[/,
  ],
  [
    // Spyware shapes: a screenshot, the clipboard, a key logger.
    'monitors',
    either(
      pyImport(String.raw`pyperclip|pynput|keyboard|pyautogui|pyscreenshot|mss|clipboard`),
      /\bImageGrab\b|\bpyautogui\.screenshot\b|\bscreencapture\b/
    ),
  ],
  [
    'permissions',
    /\bos\.(?:chmod|lchmod|fchmod|chown|lchown|fchown|setuid|setgid|seteuid|setegid|setreuid|setregid|setresuid)\s*\(|\.chmod\s*\(|\bshutil\.chown\s*\(/,
  ],
];

const NODE: Table = [
  [
    'deletes',
    /\.(?:rm|rmSync|rmdir|rmdirSync|unlink|unlinkSync)\s*\(|\brimraf\b|\bDeno\.remove(?:Sync)?\s*\(/,
  ],
  [
    'writes-outside',
    new RegExp(
      String.raw`(?:\.(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|copyFile|copyFileSync|cp|cpSync|rename|renameSync|truncate|truncateSync|symlink|symlinkSync|mkdir|mkdirSync)|\bDeno\.(?:writeTextFile|writeFile|rename|mkdir)(?:Sync)?|\bBun\.write)\s*\(\s*['"\x60]${OUTSIDE}`
    ),
  ],
  [
    'sends',
    /\bfetch\s*\(|(?:\brequire\s*\(\s*|\bfrom\s+|\bimport\s+)['"\x60](?:node:)?(?:http|https|http2|net|dgram|tls|axios|node-fetch|ws|request|got|undici|nodemailer)['"\x60]|\bnew\s+WebSocket\b|\bXMLHttpRequest\b|\b(?:Deno|Bun)\.connect\w*\s*\(/,
  ],
  ['listens', /\bcreateServer\s*\(|\b(?:Deno\.(?:listen\w*|serve)|Bun\.(?:listen|serve))\s*\(/],
  [
    'runs-commands',
    /\bchild_process\b|\bprocess\.(?:binding|dlopen|kill)\s*\(|\bDeno\.(?:run|Command)\b|\bBun\.(?:spawn|spawnSync|\$)\b|\bexecSync\s*\(|\bspawnSync\s*\(/,
  ],
  [
    'builds-code',
    /(?<![\w.])eval\s*\(|\bnew\s+Function\s*\(|(?<![\w.])Function\s*\(|(?:\brequire\s*\(\s*|\bfrom\s+)['"\x60](?:node:)?vm['"\x60]|\bvm\.\w+|\brequire\s*\(\s*[^'"\x60\s)]|\bimport\s*\(\s*[^'"\x60\s)]/,
  ],
  [
    'permissions',
    /\.(?:chmod|chmodSync|chown|chownSync|lchown|lchownSync|fchmod|fchmodSync|fchown|fchownSync)\s*\(|\bprocess\.set(?:e)?[ug]id\s*\(|\bDeno\.(?:chmod|chown)(?:Sync)?\s*\(/,
  ],
];

const PERL: Table = [
  ['deletes', /\b(?:unlink|rmdir|rmtree|remove_tree)\b/],
  [
    'writes-outside',
    new RegExp(
      String.raw`['"]\s*(?:\+?>>?|\+<)\s*['"]?\s*,?\s*['"]?${OUTSIDE}|\b(?:rename|symlink|link|copy|move)\s*\(?[^;\n]*['"]${OUTSIDE}`
    ),
  ],
  [
    'sends',
    /\b(?:IO::Socket|Socket|LWP|HTTP::Tiny|Net::\w+|Mojo::UserAgent|WWW::Mechanize|IO::Socket::INET)\b/,
  ],
  [
    'runs-commands',
    /\b(?:system|exec|fork|kill|syscall)\b|`[^`]*`|\bqx\s*[{([/|!'"]|\bopen\s*\(?[^;\n]*(?:['"]\s*\||\|\s*['"]|['"]-\|['"])/,
  ],
  ['builds-code', /\beval\b|\bStorable::thaw\b|\bdo\s+['"]/],
  ['permissions', /\b(?:chmod|chown)\b/],
];

const RUBY: Table = [
  [
    'deletes',
    /\bFile\.(?:delete|unlink)\b|\bFileUtils\.(?:rm\w*|remove\w*)\b|\bDir\.(?:rmdir|delete|unlink)\b|\.(?:rmtree|delete_all)\b/,
  ],
  [
    'writes-outside',
    new RegExp(
      String.raw`\bFile\.(?:write|binwrite|symlink|rename)\s*\(?\s*['"]${OUTSIDE}|\bFile\.open\s*\(?\s*['"]${OUTSIDE}[^'"\n]*['"]\s*,\s*['"][wa+]|\bFileUtils\.(?:cp\w*|mv|install|ln\w*|mkdir_p|touch)\s*\(?[^\n]*['"]${OUTSIDE}`
    ),
  ],
  [
    'sends',
    /\bNet::\w+|\b(?:TCPSocket|UDPSocket|UNIXSocket|Socket)\b|\bopen-uri\b|\bURI\.open\b|\b(?:HTTParty|Faraday|RestClient|Excon|Typhoeus)\b|\brequire\s+['"](?:socket|net\/\w+|open-uri)['"]/,
  ],
  ['listens', /\b(?:TCPServer|UNIXServer|WEBrick|PTY)\b/],
  [
    'runs-commands',
    /(?<![\w.])(?:system|exec|spawn|fork)\b|`[^`]*`|%x[{([|!]|(?<![\w.])open\s*\(?\s*['"]\||\bIO\.popen\b|\bOpen3\b|\bProcess\.(?:spawn|kill|exec)\b|\bKernel\.(?:system|exec|spawn|open)\b/,
  ],
  [
    'builds-code',
    /(?<![\w.])eval\b|\b(?:instance|class|module)_eval\b|\b(?:send|public_send)\s*\(?\s*:?['"]?(?:system|eval|exec|spawn)\b|\bMarshal\.load\b|\bYAML\.(?:unsafe_)?load\b|\bconst_get\b/,
  ],
  ['permissions', /\b(?:File|FileUtils)\.(?:chmod|chown|lchmod|lchown)\w*\b/],
];

const PHP: Table = [
  ['deletes', /\b(?:unlink|rmdir)\s*\(/],
  [
    'writes-outside',
    new RegExp(
      String.raw`\b(?:file_put_contents|symlink|link|copy|rename|mkdir|touch)\s*\([^)\n]*['"]${OUTSIDE}|\bfopen\s*\(\s*['"]${OUTSIDE}[^'"\n]*['"]\s*,\s*['"][waxc+]`
    ),
  ],
  [
    'sends',
    /\b(?:curl_exec|curl_init|fsockopen|pfsockopen|stream_socket_client|socket_create|socket_connect|mail|ftp_connect)\s*\(|\b(?:file_get_contents|fopen|file|readfile)\s*\(\s*['"](?:https?|ftp):/,
  ],
  ['listens', /\b(?:stream_socket_server|socket_bind|socket_listen)\s*\(/],
  [
    'runs-commands',
    /\b(?:system|exec|shell_exec|passthru|proc_open|popen|pcntl_exec|pcntl_fork|posix_kill)\s*\(|`[^`]*`/,
  ],
  [
    'builds-code',
    /\b(?:eval|assert|create_function|unserialize|call_user_func(?:_array)?)\s*\(|\bbase64_decode\b/,
  ],
  ['permissions', /\b(?:chmod|chown|chgrp|lchown|lchgrp)\s*\(/],
];

const TABLES: Record<InlineLanguage, Table> = {
  python: PYTHON,
  node: NODE,
  perl: PERL,
  ruby: RUBY,
  php: PHP,
};

/** The language family an interpreter name belongs to, or null when node9 does
 *  not scan that language (lua, PowerShell, osascript, R ...). */
export function inlineLanguageOf(interp: string): InlineLanguage | null {
  const i = interp.toLowerCase();
  if (/^python[\d.]*$/.test(i)) return 'python';
  if (/^(?:node|tsx|ts-node|deno|bun)$/.test(i)) return 'node';
  if (i === 'perl') return 'perl';
  if (i === 'ruby' || i === 'irb') return 'ruby';
  if (i === 'php') return 'php';
  return null;
}

// `import os as o` -> every use of `o` reads `os` (`o.remove`, `getattr(o, ...)`),
// so the call tables meet the alias. `import subprocess as sp` needs no rewrite
// (the import itself is the signal), but it is harmless there and keeps one
// rule for every module.
function resolvePythonAliases(code: string): string {
  const aliases = [...code.matchAll(/\bimport\s+([\w.]+)\s+as\s+(\w+)/g)].slice(0, 32);
  let out = code;
  for (const [, mod, alias] of aliases) {
    if (alias === mod) continue;
    out = out.replace(new RegExp(String.raw`(?<![\w.])${alias}\b`, 'g'), mod);
  }
  return out;
}

// String literals, for the protected-path check. Bounded: a pathological
// payload cannot make this walk forever, and a literal over 4 KiB is not a path.
const STRING_LITERAL = /(['"`])((?:\\.|(?!\1)[^\\\n]){1,4096})\1/g;

function protectedLiteral(code: string, isProtected: (p: string) => boolean): string | null {
  let n = 0;
  for (const m of code.matchAll(STRING_LITERAL)) {
    if (++n > 2048) break;
    const value = m[2].trim();
    if (value && isProtected(value)) return value;
  }
  return null;
}

// The paths inline code reads, for the credential jail (node9Firewall#440).
//
// A string counts only where a read call opens it: `open(".env")`,
// `readFileSync(path.join(os.homedir(), ".ssh/id_rsa"))`, `File.read(".env")`,
// or a variable assigned the string and then opened (`p = '.env'; open(p)`).
// A jailed name that is only text (a script that edits code mentioning `.env`,
// a probe that passes `"cat ~/.ssh/id_rsa"` to a function, `os.path.exists`)
// is not a read: on 63,797 real agent commands, reading every string literal
// stopped 480 commands, nearly all of them text; this reading stops 49, each a
// real read (2026-11-07). The trade-off: a path assembled from pieces at run time
// (`os.path.join(home, ".ssh", "id_rsa")`) is not seen.
//
// dotenv: a loader names no path, and `require("dotenv").config()`,
// `load_dotenv()`, `node -r dotenv/config` and `node --env-file=F` read ./.env
// (or F) into the environment. That counts as a read when the code also reads
// the environment (founder decision a): `require("dotenv").config();
// require("./migrate")` loads it for another program and stays quiet. A call
// that hands the file's values to the code itself (Python dotenv_values /
// get_key, node `.parsed` or config() used as a value) is a read on its own. A
// loader given a literal path reads that path, which the read-call scan judges.

/** What reaches the code before it runs: node's -r/--import and --env-file. */
export interface InlinePreload {
  /** `node -r dotenv/config`, `--import dotenv/config`. */
  dotenv?: boolean;
  /** `node --env-file=F`: each F is loaded into the environment. */
  envFiles?: string[];
}

// A call that opens its argument for reading. The name is matched whole:
// `reopen(` and `fileAccessView(` are not `open(` and `file(`.
const READ_CALL: Record<InlineLanguage, string> = {
  python: String.raw`(?:\b(?:io|codecs)\.)?\bopen|\b(?:dotenv_values|load_dotenv|get_key|read_file|loadtxt|read_csv)`,
  node: String.raw`\b(?:readFileSync|readFile|createReadStream|readTextFile(?:Sync)?|readFileStr|openSync|file)`,
  perl: String.raw`\b(?:open|sysopen|read_file|slurp)`,
  ruby: String.raw`\b(?:File|IO)\.(?:read|binread|readlines|foreach|open)|\bDotenv\.(?:load|parse|overload)`,
  php: String.raw`\b(?:file_get_contents|fopen|file|readfile|parse_ini_file|highlight_file|show_source)`,
};

// Up to three wrapping calls between the read call and the string, each with up
// to three plain arguments before it: `open(os.path.expanduser(`,
// `readFileSync(path.join(os.homedir(), __dirname, `, `open(my $f, "<", `. Bounded
// repetitions, no nested `*`: this runs once per string literal.
const ARG = String.raw`(?:(?:(?:my|our|local)\s+)?[\w.$]+(?:\s*\(\s*\))?|'[^'\n]{0,8}'|"[^"\n]{0,8}")\s*,\s*`;
const WRAP = String.raw`(?:(?:new\s+)?[\w.$]+\s*\(\s*(?:${ARG}){0,3}){0,3}`;
// Python string prefixes (`f"..."`, `rb"..."`), perl's 2-argument `open(F, "<x")`.
const STR_PREFIX = String.raw`[rRbBuUfF]{0,2}`;

// A write is not a read: `open(p, "w")`, `fopen(p, "a")`, `File.open(p, "w")`,
// perl's `open(F, ">", p)` / `">p"`. A test that writes a fake key into a
// scratch home (`open(f'{H}/.ssh/id_rsa','w')`) is a common agent shape.
const WRITE_MODE = String.raw`\s*,\s*(?:mode\s*=\s*)?['"](?=[rbtU+]*[wax])[rwaxbtU+]{1,4}['"]`;
// After the string, past the wrappers' closing parens: `open(join(h, 'x'), 'w')`.
const WRITE_MODE_AFTER = new RegExp(`^(?:\\s*\\)){0,3}${WRITE_MODE}`);
const PERL_WRITE_BEFORE = /['"]\s*(?:\+?[>|]|>>)\s*['"]\s*,\s*$/;

const readCallBefore = (language: InlineLanguage): RegExp =>
  new RegExp(
    String.raw`(?:${READ_CALL[language]})(?![\w$])\s*\(?\s*(?:${ARG}){0,3}${WRAP}${STR_PREFIX}$`
  );
const READ_BEFORE: Record<InlineLanguage, RegExp> = {
  python: readCallBefore('python'),
  node: readCallBefore('node'),
  perl: readCallBefore('perl'),
  ruby: readCallBefore('ruby'),
  php: readCallBefore('php'),
};
// `Path(".env").read_text()`: the read call comes after the string.
const READ_AFTER: Partial<Record<InlineLanguage, RegExp>> = {
  python: /^\s*\)\s*\.\s*(?:read_text|read_bytes|open)\s*\(/,
};
// `NAME = <wrappers>"..."`, the string being the assignment's value.
const ASSIGNED = new RegExp(String.raw`([$\w]+)\s*=\s*${WRAP}${STR_PREFIX}$`);

// A name a read call opens: `open(p)`, `readFileSync(path.join(dir, p))`, and
// python's `Path(p).read_text()`.
const openedName = (language: InlineLanguage): RegExp =>
  new RegExp(
    String.raw`(?:${READ_CALL[language]})(?![\w$])\s*\(?\s*(?:${ARG}){0,3}${WRAP}([$\w]+)(?!${WRITE_MODE})\s*[),]` +
      (language === 'python'
        ? String.raw`|\bPath\s*\(\s*([$\w]+)\s*\)\s*\.\s*(?:read_text|read_bytes|open)\s*\(`
        : ''),
    'g'
  );
const OPENED_NAME: Record<InlineLanguage, RegExp> = {
  python: openedName('python'),
  node: openedName('node'),
  perl: openedName('perl'),
  ruby: openedName('ruby'),
  php: openedName('php'),
};

const DOTENV = {
  node: {
    load: /\brequire\s*\(\s*['"`]dotenv(?:\/config)?['"`]\s*\)|\bimport\s*(?:[\w${}\s,*]+\s+from\s*)?['"`]dotenv(?:\/config)?['"`]|\bimport\s*\(\s*['"`]dotenv(?:\/config)?['"`]\s*\)/,
    values: /\.parsed\b|[(,]\s*(?:require\s*\(\s*['"`]dotenv['"`]\s*\)|dotenv)\s*\.\s*config\s*\(/,
    env: /\b(?:process|Deno|Bun)\s*\.\s*env\b/,
    literalPath: /\bconfig\s*\(\s*\{[^)]*\bpath\s*:\s*['"`]/,
  },
  python: {
    load: /\b(?:load_dotenv|dotenv_values|get_key)\s*\(/,
    values: /\b(?:dotenv_values|get_key)\s*\(/,
    env: /\b(?:environ|getenv)\b/,
    literalPath: /\b(?:load_dotenv|dotenv_values)\s*\(\s*(?:dotenv_path\s*=\s*)?[rRbBuU]?['"]/,
  },
} as const;
const DOTENV_PATH_OPTION = /\bconfig\s*\(\s*\{[^)]*\bpath\s*:\s*$/;

/**
 * The paths a block of inline code reads, as the credential jail should judge
 * them. Candidates only: the caller's path matcher decides which are jailed.
 */
export function inlineReadPaths(
  language: InlineLanguage,
  code: string,
  preload: InlinePreload = {}
): string[] {
  const out: string[] = [];
  const before = READ_BEFORE[language];
  const after = READ_AFTER[language];
  const assigned = new Map<string, string[]>();
  for (const m of code.matchAll(STRING_LITERAL)) {
    const raw = m[2].trim();
    const value = raw.replace(/^[<+]\s*/, ''); // perl `open(F, "<.env")`
    if (!value) continue;
    const head = code.slice(Math.max(0, m.index - 160), m.index);
    const tail = code.slice(m.index + m[0].length, m.index + m[0].length + 40);
    if (/^[>|]/.test(raw) || WRITE_MODE_AFTER.test(tail) || PERL_WRITE_BEFORE.test(head)) continue;
    if (
      before.test(head) ||
      after?.test(tail) ||
      (language === 'node' && DOTENV_PATH_OPTION.test(head))
    ) {
      out.push(value);
      continue;
    }
    const name = ASSIGNED.exec(head)?.[1];
    if (name) assigned.set(name, [...(assigned.get(name) ?? []), value]);
  }
  if (assigned.size > 0) {
    // One pass collects the names a read call opens; a per-name search was
    // quadratic on code with thousands of assignments.
    const opened = new Set<string>();
    for (const m of code.matchAll(OPENED_NAME[language])) opened.add(m[1] ?? m[2]);
    for (const [name, values] of assigned) if (opened.has(name)) out.push(...values);
  }
  if (language === 'python' || language === 'node') {
    const d = DOTENV[language];
    const readsEnv = d.env.test(code);
    const loads = /dotenv/.test(code) && d.load.test(code) && !d.literalPath.test(code);
    if ((loads || preload.dotenv) && (readsEnv || d.values.test(code))) out.push('.env');
    if (readsEnv) out.push(...(preload.envFiles ?? []));
  }
  return out;
}

/** Endless loop containing a write or a send: the amplification shape. */
function amplifies(language: InlineLanguage, code: string): string | null {
  const loop =
    language === 'python'
      ? /\bwhile\s+(?:True|1)\s*:/
      : language === 'node'
        ? /\bwhile\s*\(\s*(?:true|1)\s*\)|\bfor\s*\(\s*;\s*;\s*\)|\bsetInterval\s*\(/
        : /\bwhile\s*\(?\s*(?:1|true)\s*\)?|\bloop\s+do\b|\bfor\s*\(\s*;\s*;\s*\)/;
  const m = loop.exec(code);
  if (!m) return null;
  const body = code.slice(m.index);
  return /\.write\s*\(|\.(?:append|write)File(?:Sync)?\s*\(|\bopen\s*\(|\bprint\s*\(\s*[^)\n]*\bfile\s*=|\.send(?:all|to)?\s*\(|\bfwrite\s*\(|\bfile_put_contents\s*\(|\bsyswrite\b/.test(
    body
  )
    ? m[0]
    : null;
}

/**
 * Judge one block of inline code. `isProtected` is the credential jail's path
 * matcher, applied to every string literal (the same set `cat` would meet).
 * Returns null when the code is readable and ordinary.
 */
export function judgeInlineCode(
  language: InlineLanguage,
  code: string,
  isProtected: (p: string) => boolean
): InlineCodeFinding | null {
  if (code.length > MAX_INLINE_CODE) {
    return { outcome: 'unreadable', what: 'is too long for node9 to read' };
  }
  const text = language === 'python' ? resolvePythonAliases(code) : code;
  for (const [category, re] of TABLES[language]) {
    const m = re.exec(text);
    if (!m) continue;
    const evidence = m[0].trim().replace(/\s+/g, ' ').slice(0, 60);
    return {
      outcome: category === 'builds-code' ? 'unreadable' : 'dangerous',
      what: WHAT[category],
      evidence,
      category,
    };
  }
  const path = protectedLiteral(text, isProtected);
  if (path) {
    return {
      outcome: 'dangerous',
      what: WHAT['reads-protected'],
      evidence: path.slice(0, 60),
      category: 'reads-protected',
    };
  }
  const loop = amplifies(language, text);
  if (loop) {
    return { outcome: 'dangerous', what: WHAT.amplifies, evidence: loop, category: 'amplifies' };
  }
  return null;
}
