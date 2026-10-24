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
