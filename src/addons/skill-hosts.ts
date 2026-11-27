// src/addons/skill-hosts.ts
// The internet domains a skill sends the agent to (node9Firewall#376 item 6,
// phase 4, check B). A skill that names a domain nobody has registered hands
// that traffic to whoever registers it first (the Render case: a skill told
// agents private services live under a domain the vendor did not own).
//
// This module only reads text: it returns registrable domains for
// host-lookup.ts to ask DNS about. Pure, no network, no file access.
//
// Two rules keep it from crying wolf:
//   1. A name is taken only where it is plainly a host: a URL with a scheme,
//      `git@host:`, or the argument of a network command. Bare words with a
//      dot are everywhere in a skill (`os.path`, `README.md`, `java.io`).
//   2. The domain asked about is never LONGER than the registrable one. With
//      no public-suffix list on board, it is the last two labels, or three
//      under a known second-level suffix. Too short only misses (`co.uk`
//      exists); too long would call an unused subdomain "unregistered".

export interface SkillHost {
  /** The registrable domain, lowercase. */
  domain: string;
  /** Named where the agent sends or fetches something, not only as a link. */
  action: boolean;
}

const MAX_HOSTS = 40;
const MAX_TEXT = 400_000;

/** Suffixes under which the registrable name has three labels. Country-code
 *  second levels, and the hosting suffixes where each subdomain is someone's. */
const SECOND_LEVEL = new Set([
  'co.uk',
  'org.uk',
  'ac.uk',
  'gov.uk',
  'me.uk',
  'ltd.uk',
  'plc.uk',
  'net.uk',
  'com.au',
  'net.au',
  'org.au',
  'edu.au',
  'gov.au',
  'co.nz',
  'org.nz',
  'net.nz',
  'govt.nz',
  'co.il',
  'org.il',
  'ac.il',
  'gov.il',
  'net.il',
  'co.jp',
  'ne.jp',
  'or.jp',
  'ac.jp',
  'go.jp',
  'co.kr',
  'or.kr',
  'co.in',
  'net.in',
  'org.in',
  'gov.in',
  'ac.in',
  'co.za',
  'org.za',
  'com.br',
  'net.br',
  'org.br',
  'gov.br',
  'com.cn',
  'net.cn',
  'org.cn',
  'gov.cn',
  'com.hk',
  'com.tw',
  'com.sg',
  'com.mx',
  'com.ar',
  'com.co',
  'com.tr',
  'com.ua',
  'com.pl',
  'com.ru',
  'co.id',
  'co.th',
  'com.my',
  'com.ph',
  'com.vn',
  'com.eg',
  'com.sa',
  'github.io',
  'gitlab.io',
  'vercel.app',
  'netlify.app',
  'pages.dev',
  'workers.dev',
  'herokuapp.com',
  'web.app',
  'firebaseapp.com',
  'azurewebsites.net',
  'cloudfront.net',
  'onrender.com',
  'fly.dev',
  'railway.app',
  'repl.co',
  'appspot.com',
]);

/** Names that are never asked about: reserved, private, documentation. */
const RESERVED_TLD = new Set([
  'internal',
  'local',
  'localhost',
  'lan',
  'corp',
  'home',
  'test',
  'example',
  'invalid',
  'localdomain',
  'intranet',
  'private',
  'onion',
  'arpa',
]);
const RESERVED_DOMAIN = new Set([
  'example.com',
  'example.org',
  'example.net',
  'example.edu',
  // Placeholders skills write for "your own host".
  'your-domain.com',
  'yourdomain.com',
  'yourcompany.com',
  'your-company.com',
  'mycompany.com',
  'my-company.com',
  'company.com',
  'domain.com',
  'mydomain.com',
  'acme.com',
  'foo.com',
  'bar.com',
  'foo.bar',
  'host.com',
  'server.com',
  'site.com',
  'website.com',
  'test.com',
  'email.com',
  'your-org.com',
  'yourorg.com',
  'myapp.com',
  'yourapp.com',
  'my-app.com',
]);

const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
/** A first label that says "put your own here" or "for illustration". */
const PLACEHOLDER_LABEL =
  /^(your|my|some|any)([-_].*|app.*|site.*|api.*|service.*|company.*|org.*|domain.*|project.*|server.*|host.*|bucket.*|func.*)?$|^(example|exemplo|sample|demo|test|dummy|placeholder|foo|bar|baz)([-_0-9].*)?$|[-_]example$/;

/** "TLDs" that are file extensions far more often than domains. They only
 *  disqualify a bare command argument (`scp build.tar.gz host:`, `curl -o
 *  node.tgz`): 7 of the 8 wrong answers in the first measurement on 361
 *  skills. A URL with a scheme is a host whatever it ends with. */
const FILE_EXTENSION = new Set([
  'gz',
  'tgz',
  'zip',
  'tar',
  'bz',
  'xz',
  'exe',
  'msi',
  'dmg',
  'pkg',
  'deb',
  'rpm',
  'jar',
  'war',
  'nupkg',
  'whl',
  'bin',
  'so',
  'dll',
  'json',
  'yaml',
  'yml',
  'toml',
  'xml',
  'html',
  'htm',
  'css',
  'md',
  'txt',
  'log',
  'csv',
  'sql',
  'db',
  'bak',
  'tmp',
  'out',
  'env',
  'conf',
  'cfg',
  'ini',
  'lock',
  'pem',
  'key',
  'crt',
  'cer',
  'pub',
  'sh',
  'bash',
  'zsh',
  'ps',
  'py',
  'js',
  'mjs',
  'cjs',
  'ts',
  'tsx',
  'jsx',
  'rb',
  'go',
  'rs',
  'java',
  'kt',
  'cs',
  'php',
  'pl',
  'lua',
  'cc',
  'cpp',
  'hpp',
  'sock',
  'pid',
  'png',
  'jpg',
  'gif',
  'svg',
  'pdf',
  'mp',
  'mov',
]);

/** `api.eu.example.co.uk` -> `example.co.uk`; null for anything not asked about. */
export function registrableDomain(host: string): string | null {
  const h = host.toLowerCase().replace(/\.$/, '');
  if (h.length > 253 || /^[0-9.]+$/.test(h) || h.includes(':')) return null; // an IP
  const labels = h.split('.');
  if (labels.length < 2) return null;
  const tld = labels[labels.length - 1];
  if (!/^[a-z]{2,24}$/.test(tld) || RESERVED_TLD.has(tld)) return null;
  const two = labels.slice(-2).join('.');
  const three = labels.slice(-3).join('.');
  let take = 2;
  if (labels.length >= 3 && SECOND_LEVEL.has(two)) take = 3;
  else if (labels.length >= 4 && SECOND_LEVEL.has(three)) take = 4;
  // A bare public suffix (`co.uk`, `github.io`) is nobody's to register.
  if (SECOND_LEVEL.has(labels.slice(-take).join('.'))) return null;
  const kept = labels.slice(-take);
  // A placeholder label (`<service>`, `{tenant}`, `$HOST`, `your-...`) in the
  // registrable part means the skill names no real domain.
  if (!kept.every((l) => LABEL.test(l))) return null;
  const domain = kept.join('.');
  if (RESERVED_DOMAIN.has(domain)) return null;
  // One-letter names (`a.com`) are reserved or stand for "some site".
  if (kept[0].length === 1) return null;
  // `example.workers.dev`, `your.app`, `test.github.io`: a stand-in name.
  if (PLACEHOLDER_LABEL.test(kept[0])) return null;
  return domain;
}

// Host characters plus what placeholders are written with, so
// `https://<service>.internal-vendor.com:8080/x` still yields its domain.
const HOST_CHARS = String.raw`[A-Za-z0-9.\-_<>{}$*%]+`;
const URL_RE = new RegExp(
  String.raw`\b(https?|wss?|ssh|git|ftp|sftp)://(?:[^\s/@:]+@)?(${HOST_CHARS})`,
  'gi'
);
const GIT_AT_RE = new RegExp(String.raw`\bgit@(${HOST_CHARS}):`, 'gi');
// The first argument that is not a flag, after a command that takes a host.
const CMD_RE = new RegExp(
  String.raw`\b(curl|wget|ssh|scp|sftp|nc|ncat|telnet|ping|dig|nslookup|rsync)\b((?:\s+-{1,2}[A-Za-z][\w-]*(?:[= ][^\s-][^\s]*)?)*)\s+(?:[A-Za-z0-9._-]+@)?(${HOST_CHARS})`,
  'gi'
);
/** A URL is an action when a command or a verb in front of it sends or fetches. */
const ACTION_BEFORE =
  /\b(curl|wget|fetch|post|put|upload|send|push|clone|install|download|connect|ssh|scp|rsync|webhook|endpoint|base[_ -]?url|api[_ -]?url|registry|index-url|proxy)\b[^\n]{0,80}$/i;

function trimHost(raw: string): string {
  // Leading placeholder labels go; a trailing dot or wildcard too.
  return raw.replace(/^[.*]+/, '').replace(/[.]+$/, '');
}

/**
 * The registrable domains the texts of one skill name as hosts. Deduplicated;
 * a domain named once as an action is an action.
 */
export function skillHosts(texts: string[]): SkillHost[] {
  const out = new Map<string, boolean>();
  const add = (rawHost: string, action: boolean): void => {
    const domain = registrableDomain(trimHost(rawHost));
    if (!domain) return;
    if (out.size >= MAX_HOSTS && !out.has(domain)) return;
    out.set(domain, (out.get(domain) ?? false) || action);
  };
  for (const full of texts) {
    const text = full.length > MAX_TEXT ? full.slice(0, MAX_TEXT) : full;
    for (const m of text.matchAll(URL_RE)) {
      const before = text.slice(Math.max(0, (m.index ?? 0) - 100), m.index ?? 0);
      const scheme = m[1].toLowerCase();
      add(m[2], scheme !== 'http' && scheme !== 'https' ? true : ACTION_BEFORE.test(before));
    }
    for (const m of text.matchAll(GIT_AT_RE)) add(m[1], true);
    for (const m of text.matchAll(CMD_RE)) {
      // `curl https://...` is the URL rule's; here only a bare host argument.
      if (/^(https?|wss?|ssh|git|ftp|sftp)$/i.test(m[3])) continue;
      if (!m[3].includes('.')) continue;
      const last = m[3].toLowerCase().split('.').pop() ?? '';
      if (FILE_EXTENSION.has(last)) continue; // a file, not a host
      // curl and wget take URLs; a bare word after them is an output file or
      // a variable far more often than a host.
      if (/^(curl|wget)$/i.test(m[1])) continue;
      add(m[3], true);
    }
  }
  return [...out].map(([domain, action]) => ({ domain, action }));
}
