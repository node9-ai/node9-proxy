// Bash as a source and as a sink for the exposure gate (fw#318 P3, design
// untrusted-content-proxy-p2-p5-code-design.md section 5).
//
// A shell command FETCHES when it brings outside content into the session
// (its output is then marked as read) and SENDS when it carries something
// out (the call is then judged by destination). One command may do both
// (`curl -d @f https://x` fetches the response and sends the body). The
// classification is static, from the AST: no I/O, no DNS, never throws.
//
// Direction per binary:
//   curl, wget, iwr, irm       fetch; send with a body, upload or write method
//   scp, rsync                 send when the remote spec is the target,
//                              fetch when it is the source
//   nc, ncat, netcat, ssh      both
//   gh                         read verbs fetch, write verbs send (github.com
//                              or --hostname)
//   git                        clone, fetch, pull fetch; push sends
//   npm/pnpm/yarn publish, twine upload, cargo publish, gem push, docker push
//                              send, to the registry named or the ecosystem's
//   python -c, node -e ...     not read (out of scope; the taint gate's network
//                              regex still sees a literal curl inside them)
//
// Wrappers (`sudo`, `env X=1`, `timeout 5`) are stripped with
// unwrapCommandHead; `sh -c '...'`, `bash -c` payloads are parsed in turn.

import mvdanSh from 'mvdan-sh';
import {
  parseShared,
  resolveWordLiteral,
  resolveWordPrefix,
  unwrapCommandHead,
  parseDestHost,
  destTokensForBinary,
  VALUE_FLAGS,
} from '../shell';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const { syntax } = mvdanSh as any;

export interface ShellExposure {
  /** The command brings outside content in: its output is a source. */
  fetches: boolean;
  /** The command carries something out: the call is an action. */
  sends: boolean;
  /** Normalised destinations of the sending calls ('host:x.example'). */
  destinations: string[];
  /** `git push <remote-name>`: the remote names used, for the host to resolve. */
  gitRemotes: string[];
  /** Hosts the fetching calls reach ('host:x.example'), literal prefixes of dynamic URLs included. */
  fetchDestinations: string[];
  /** Short labels of the fetching calls ('curl', 'gh issue', 'git pull'), for the frame. */
  fetchKinds: string[];
}

const EMPTY: ShellExposure = {
  fetches: false,
  sends: false,
  destinations: [],
  gitRemotes: [],
  fetchDestinations: [],
  fetchKinds: [],
};

// curl flags that put a body or a file on the wire, or name a writing method.
const CURL_SEND_FLAGS = new Set([
  '-d',
  '--data',
  '--data-ascii',
  '--data-binary',
  '--data-raw',
  '--data-urlencode',
  '-F',
  '--form',
  '--form-string',
  '-T',
  '--upload-file',
  '--json',
]);
const WGET_SEND_FLAGS = new Set(['--post-data', '--post-file', '--body-data', '--body-file']);
const IWR_SEND_FLAGS = new Set(['-body', '-infile']);
const WRITE_METHODS = new Set(['post', 'put', 'patch', 'delete']);

const GH_READ = new Set(['view', 'list', 'diff', 'checks', 'status', 'download', 'clone']);
const GH_WRITE = new Set([
  'create',
  'comment',
  'edit',
  'close',
  'reopen',
  'merge',
  'review',
  'upload',
  'delete',
  'transfer',
  'pin',
  'lock',
  'ready',
  'set',
  'sync',
  'fork',
]);
const GH_HOSTNAME_FLAGS = new Set(['--hostname', '-h', '-R', '--repo']);

const GIT_FETCH = new Set(['clone', 'fetch', 'pull', 'ls-remote']);
const PUBLISH: Record<string, { verbs: Set<string>; registry: string; flag?: string[] }> = {
  npm: { verbs: new Set(['publish']), registry: 'registry.npmjs.org', flag: ['--registry'] },
  pnpm: { verbs: new Set(['publish']), registry: 'registry.npmjs.org', flag: ['--registry'] },
  yarn: {
    verbs: new Set(['publish', 'npm']),
    registry: 'registry.npmjs.org',
    flag: ['--registry'],
  },
  twine: { verbs: new Set(['upload']), registry: 'upload.pypi.org', flag: ['--repository-url'] },
  cargo: { verbs: new Set(['publish']), registry: 'crates.io', flag: ['--registry', '--index'] },
  gem: { verbs: new Set(['push']), registry: 'rubygems.org', flag: ['--host'] },
  docker: { verbs: new Set(['push']), registry: 'docker.io' },
};
const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh']);
const OWN_HEADS = new Set([...Object.keys(PUBLISH), 'git', 'gh']);
const MAX_DEPTH = 3;

function host(token: string | null | undefined): string | null {
  if (!token) return null;
  const h = parseDestHost(token);
  return h && h !== 'localhost' ? `host:${h}` : null;
}

/** The words of one call, wrappers stripped, as literals (null = dynamic);
 *  `prefixes` keeps each word's literal start so a URL whose query is
 *  dynamic (`"https://x/p?d=$(cat f)"`) still names its host. */
function callWords(
  call: unknown
): { head: string; args: (string | null)[]; prefixes: string[] } | null {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const raw: any[] = (call as any).Args || [];
  if (raw.length === 0) return null;
  const words = raw.map((a) => resolveWordLiteral(a));
  const prefixes = raw.map((a) => resolveWordPrefix(a).prefix);
  // `npm`, `yarn`, `cargo` are runners to unwrapCommandHead (`npm exec x`);
  // here they are the binaries themselves, so they are read before unwrapping.
  const first = (words[0] || '').toLowerCase().split('/').pop() ?? '';
  const at = OWN_HEADS.has(first) ? 0 : unwrapCommandHead(words);
  const head = (words[at] || '').toLowerCase().split('/').pop() ?? '';
  if (!head) return null;
  return { head, args: words.slice(at + 1), prefixes: prefixes.slice(at + 1) };
}

/** Flag values of the given names (`--x V`, `--x=V`), first one wins. */
function flagValue(args: (string | null)[], names: string[]): string | null {
  for (let i = 0; i < args.length; i++) {
    const w = args[i];
    if (w === null) continue;
    for (const n of names) {
      if (w === n && typeof args[i + 1] === 'string') return args[i + 1] as string;
      if (w.startsWith(`${n}=`)) return w.slice(n.length + 1);
    }
  }
  return null;
}

/** Non-flag operands, skipping the values of the binary's value flags. */
function positionals(args: (string | null)[], valueFlags: Set<string>): (string | null)[] {
  const out: (string | null)[] = [];
  for (let i = 0; i < args.length; i++) {
    const w = args[i];
    if (w === null) {
      out.push(null);
      continue;
    }
    if (w === '--') {
      out.push(...args.slice(i + 1));
      break;
    }
    if (w.startsWith('-')) {
      if (!w.includes('=') && valueFlags.has(w)) i++;
      continue;
    }
    out.push(w);
  }
  return out;
}

function classifyCall(
  head: string,
  args: (string | null)[],
  prefixes: string[],
  out: ShellExposure
): void {
  const lower = args.map((a) => (a === null ? null : a.toLowerCase()));
  switch (head) {
    case 'curl':
    case 'wget':
    case 'iwr':
    case 'invoke-webrequest':
    case 'irm':
    case 'invoke-restmethod': {
      const binary = head === 'wget' ? 'wget' : 'curl';
      const sendFlags =
        head === 'wget' ? WGET_SEND_FLAGS : head === 'curl' ? CURL_SEND_FLAGS : IWR_SEND_FLAGS;
      let sends = false;
      for (let i = 0; i < args.length; i++) {
        const w = args[i];
        if (w === null) continue;
        // Short flags are case-sensitive (`-F` is a form, `-f` is fail);
        // PowerShell's are not. Method VALUES fold either way.
        const name = (head === 'curl' || head === 'wget' ? w : w.toLowerCase()).split('=')[0];
        if (sendFlags.has(name)) sends = true;
        const next = lower[i + 1];
        if ((name === '-X' || name === '--request' || name === '-method') && next) {
          if (WRITE_METHODS.has(next)) sends = true;
        }
        if (/^(?:--request=|-X)(POST|PUT|PATCH|DELETE)$/i.test(w)) sends = true;
        if (name === '--method' && next && WRITE_METHODS.has(next)) sends = true;
      }
      // A dynamic URL word (`"https://x/p?d=$(cat f)"`) is null to the
      // destination extractor; its literal prefix still names the host.
      const withPrefixes = args.map((a, i) =>
        a === null && /^[a-z][a-z0-9+.-]*:\/\//i.test(prefixes[i] ?? '') ? prefixes[i] : a
      );
      const dests = destTokensForBinary(binary, withPrefixes)
        .map((t) => host(t))
        .filter((h): h is string => h !== null);
      out.fetches = true;
      out.fetchKinds.push(head);
      out.fetchDestinations.push(...dests);
      if (sends) {
        out.sends = true;
        out.destinations.push(...dests);
      }
      return;
    }
    case 'scp':
    case 'rsync': {
      const pos = positionals(args, VALUE_FLAGS[head] ?? new Set()).filter(
        (p): p is string => p !== null
      );
      if (pos.length < 2) return;
      const remote = (p: string) =>
        /^[a-z][a-z0-9+.-]*:\/\//i.test(p) || /^[^/]*[^/:]:[^/]/.test(p) || p.includes('@');
      const target = pos[pos.length - 1];
      const sources = pos.slice(0, -1);
      if (remote(target)) {
        out.sends = true;
        const h = host(target);
        if (h) out.destinations.push(h);
      }
      if (sources.some(remote)) {
        out.fetches = true;
        out.fetchKinds.push(head);
        for (const src of sources.filter(remote)) {
          const h = host(src);
          if (h) out.fetchDestinations.push(h);
        }
      }
      return;
    }
    case 'nc':
    case 'ncat':
    case 'netcat':
    case 'ssh': {
      out.fetches = true;
      out.sends = true;
      out.fetchKinds.push(head);
      for (const t of destTokensForBinary(head, args)) {
        const h = host(t);
        if (h) {
          out.destinations.push(h);
          out.fetchDestinations.push(h);
        }
      }
      return;
    }
    case 'gh': {
      const pos = positionals(args, GH_HOSTNAME_FLAGS);
      const group = pos[0] ?? null;
      const verb = pos[1] ?? null;
      const hn = flagValue(args, ['--hostname']);
      const dest = host(hn ?? 'github.com') ?? 'host:github.com';
      if (group === 'api') {
        const method = (flagValue(args, ['-X', '--method']) ?? 'get').toLowerCase();
        const hasBody = args.some(
          (w) => w !== null && /^(-f|--raw-field|-F|--field|--input)(=|$)/.test(w)
        );
        if (WRITE_METHODS.has(method) || hasBody) {
          out.sends = true;
          out.destinations.push(dest);
        } else {
          out.fetches = true;
          out.fetchKinds.push('gh api');
          out.fetchDestinations.push(dest);
        }
        return;
      }
      if (group === null || verb === null) return;
      if (GH_WRITE.has(verb)) {
        out.sends = true;
        out.destinations.push(dest);
      } else if (GH_READ.has(verb)) {
        out.fetches = true;
        out.fetchKinds.push(`gh ${group}`);
        out.fetchDestinations.push(dest);
      }
      return;
    }
    case 'git': {
      const pos = positionals(args, new Set(['-C', '-c', '--git-dir', '--work-tree']));
      const verb = pos[0];
      if (verb === null || verb === undefined) return;
      if (GIT_FETCH.has(verb)) {
        out.fetches = true;
        out.fetchKinds.push(`git ${verb}`);
        for (const p of pos.slice(1)) {
          const h = p !== null && /:\/\/|@/.test(p) ? host(p) : null;
          if (h) out.fetchDestinations.push(h);
        }
        return;
      }
      if (verb === 'push') {
        out.sends = true;
        const target = pos.slice(1).find((p) => p !== null && !p.startsWith('-')) ?? null;
        if (target === null) {
          out.gitRemotes.push('origin');
          return;
        }
        const h = host(target);
        if (h && /:\/\/|@/.test(target)) out.destinations.push(h);
        else out.gitRemotes.push(target);
      }
      return;
    }
    default: {
      const pub = PUBLISH[head];
      if (!pub) return;
      const pos = positionals(args, new Set(pub.flag ?? []));
      const verb = pos[0];
      if (verb === null || verb === undefined || !pub.verbs.has(verb)) return;
      if (head === 'yarn' && verb === 'npm' && pos[1] !== 'publish') return;
      out.sends = true;
      const named = pub.flag ? flagValue(args, pub.flag) : null;
      const h = named ? host(named) : null;
      if (named && !h) return; // a registry we cannot read: no destination claimed
      if (head === 'docker') {
        const image = pos[1];
        const first = image?.split('/')[0] ?? '';
        const reg = first.includes('.') || first.includes(':') ? host(first) : null;
        out.destinations.push(reg ?? 'host:docker.io');
        return;
      }
      out.destinations.push(h ?? `host:${pub.registry}`);
    }
  }
}

function walkCalls(command: string, out: ShellExposure, depth: number): void {
  const f = parseShared(command);
  if (typeof f === 'symbol' || !f) return;
  syntax.Walk(f, (node: unknown) => {
    if (!node) return false;
    if (syntax.NodeType(node) !== 'CallExpr') return true;
    const c = callWords(node);
    if (!c) return true;
    if (SHELLS.has(c.head) && depth < MAX_DEPTH) {
      const i = c.args.findIndex((w) => w === '-c' || w === '-lc' || w === '-ec');
      const payload = i >= 0 ? c.args[i + 1] : null;
      if (typeof payload === 'string') walkCalls(payload, out, depth + 1);
      return true;
    }
    classifyCall(c.head, c.args, c.prefixes, out);
    return true;
  });
}

/** Classify a shell command as a source, a sink, both or neither. Never throws. */
export function classifyShellExposure(command: string): ShellExposure {
  const out: ShellExposure = {
    ...EMPTY,
    destinations: [],
    gitRemotes: [],
    fetchDestinations: [],
    fetchKinds: [],
  };
  try {
    walkCalls(command, out, 0);
  } catch {
    return { ...EMPTY };
  }
  out.destinations = [...new Set(out.destinations)];
  out.fetchDestinations = [...new Set(out.fetchDestinations)];
  out.gitRemotes = [...new Set(out.gitRemotes)];
  out.fetchKinds = [...new Set(out.fetchKinds)];
  return out;
}
