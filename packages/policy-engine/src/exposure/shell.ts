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
//                              or --hostname); -R, a gist, a new repository
//                              or `gh api` name the repository reached
//   git                        clone, fetch, pull fetch; push, and pointing a
//                              remote at a url (remote add/set-url, config
//                              remote.*.url, -c), send
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
  devNetRedirectHost,
  VALUE_FLAGS,
} from '../shell';
import { gitRepoPath } from './destinations';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const { syntax } = mvdanSh as any;

export interface ShellExposure {
  /** The command brings outside content in: its output is a source. */
  fetches: boolean;
  /** The command carries something out: the call is an action. */
  sends: boolean;
  /** Normalised destinations of the sending calls ('host:x.example'). */
  destinations: string[];
  /** `git push <remote-name>`: the remote names used, for the host to resolve;
   *  '' is a push with no target (the branch's default remote). */
  gitRemotes: string[];
  /**
   * Repositories the git-host sends reach, `host/owner/name`. A host is not
   * enough there: github.com holds the project's origin and every attacker's
   * mirror. `host/*` is a repository the command does not name (a gist, a new
   * repository, a GraphQL call). A send to the current repository (`gh issue
   * comment 7`) names none.
   */
  repos: string[];
  /** A send whose target this command makes unknowable (`cd x && git push`,
   *  `git -C x push`, a dynamic `-R`): held after exposure. */
  unresolved: boolean;
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
  repos: [],
  unresolved: false,
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
// Value flags of `gh repo <verb>`, so a description or a topic is not read
// as the repository operand.
const GH_REPO_VALUE_FLAGS = new Set([
  '--hostname',
  '-R',
  '--repo',
  '-d',
  '--description',
  '-h',
  '--homepage',
  '--visibility',
  '--default-branch',
  '--add-topic',
  '--remove-topic',
  '-p',
  '--template',
  '-s',
  '--source',
  '-b',
  '--branch',
  '-l',
  '--license',
  '-g',
  '--gitignore',
  '-t',
  '--team',
  '-r',
  '--remote',
  '--org',
]);
const GH_API_VALUE_FLAGS = new Set([
  '--hostname',
  '-X',
  '--method',
  '-f',
  '--raw-field',
  '-F',
  '--field',
  '-H',
  '--header',
  '--input',
  '-q',
  '--jq',
  '-t',
  '--template',
  '--cache',
  '-p',
  '--preview',
]);

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

// Loopback hosts are kept: a send to localhost names a destination, which
// the gate then knows is the machine itself.
function host(token: string | null | undefined): string | null {
  if (!token) return null;
  const h = parseDestHost(token);
  return h ? `host:${h}` : null;
}

/** Calls that move the shell elsewhere, so a later `git push <remote>`
 *  resolves in a repository the hook did not read. */
const CWD_CHANGERS = new Set(['cd', 'pushd', 'popd']);

/** Per-command state across the calls of one command line. */
interface WalkState {
  cwdChanged: boolean;
  /** Variables set for the rest of the command (`export GH_REPO=x &&`). */
  env: Set<string>;
}

/** A repository named by `-R`/`gh repo` operands: `owner/name`,
 *  `host/owner/name` or a url. */
function ghRepoArg(v: string, defaultHost: string): { host: string; repo: string } {
  if (/:\/\/|@/.test(v)) {
    const r = gitRepoPath(v);
    if (r) return { host: r.split('/')[0], repo: r };
  }
  const parts = v
    .toLowerCase()
    .replace(/\.git$/, '')
    .split('/')
    .filter(Boolean);
  if (parts.length === 3) return { host: parts[0], repo: parts.join('/') };
  if (parts.length === 2) return { host: defaultHost, repo: `${defaultHost}/${parts.join('/')}` };
  return { host: defaultHost, repo: `${defaultHost}/*` };
}

/** The repository a `gh api` write reaches, from its endpoint. Undefined is
 *  the current repository (`repos/{owner}/{repo}/...`). */
function ghApiRepo(endpoint: string | null, ghHost: string): string | undefined {
  if (endpoint === null) return `${ghHost}/*`;
  const e = endpoint.replace(/^https?:\/\/[^/]+\//i, '').replace(/^\/+/, '');
  const m = /^repos\/([^/]+)\/([^/?#]+)/i.exec(e);
  if (!m) return `${ghHost}/*`;
  if (m[1] === '{owner}' && m[2] === '{repo}') return undefined;
  return `${ghHost}/${m[1].toLowerCase()}/${m[2].toLowerCase()}`;
}

/** A send that points a git remote at `url`. */
function sendToGitUrl(url: string | null | undefined, out: ShellExposure): void {
  out.sends = true;
  const h = typeof url === 'string' ? host(url) : null;
  if (!url || !h) {
    out.unresolved = true;
    return;
  }
  out.destinations.push(h);
  const r = gitRepoPath(url);
  if (r) out.repos.push(r);
}

/** The words of one call, wrappers stripped, as literals (null = dynamic);
 *  `prefixes` keeps each word's literal start so a URL whose query is
 *  dynamic (`"https://x/p?d=$(cat f)"`) still names its host. */
function callWords(call: unknown): {
  head: string;
  args: (string | null)[];
  prefixes: string[];
  /** Environment names set for this call (`X=1 cmd`, `env X=1 cmd`). */
  env: string[];
} | null {
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
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const assigns: any[] = (call as any).Assigns || [];
  const env = [
    ...assigns.map((a) => String(a?.Name?.Value ?? '')),
    ...words
      .slice(0, at)
      .map((w) => (w === null ? '' : (/^([A-Za-z_][A-Za-z0-9_]*)=/.exec(w)?.[1] ?? ''))),
  ].filter(Boolean);
  return { head, args: words.slice(at + 1), prefixes: prefixes.slice(at + 1), env };
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
  env: string[],
  state: WalkState,
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
      let dest = host(hn ?? 'github.com') ?? 'host:github.com';
      const ghHost = dest.slice('host:'.length);
      // GH_REPO and GH_HOST point gh at another repository than the current one.
      const envRepo = env.some((n) => n === 'GH_REPO' || n === 'GH_HOST');
      if (group === 'api') {
        const method = (flagValue(args, ['-X', '--method']) ?? 'get').toLowerCase();
        const hasBody = args.some(
          (w) => w !== null && /^(-f|--raw-field|-F|--field|--input)(=|$)/.test(w)
        );
        if (WRITE_METHODS.has(method) || hasBody) {
          out.sends = true;
          out.destinations.push(dest);
          const endpoint = positionals(args, GH_API_VALUE_FLAGS)[1] ?? null;
          const repo = ghApiRepo(endpoint, ghHost);
          if (repo !== undefined) out.repos.push(repo);
          else if (envRepo) out.repos.push(`${ghHost}/*`);
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
        // The repository reached: -R, a gist or a new repository (never one
        // of the project's), `gh repo <verb> owner/name`, or the current one.
        const rIdx = args.findIndex((w) => w === '-R' || w === '--repo');
        const rEq = args.find((w) => w !== null && /^(-R|--repo)=/.test(w));
        const rVal =
          rEq !== undefined && rEq !== null
            ? rEq.slice(rEq.indexOf('=') + 1)
            : rIdx >= 0
              ? args[rIdx + 1]
              : undefined;
        let repo: string | undefined;
        if (rIdx >= 0 || rEq !== undefined) {
          if (typeof rVal === 'string') {
            const named = ghRepoArg(rVal, ghHost);
            repo = named.repo;
            if (named.host !== ghHost) dest = `host:${named.host}`;
          } else repo = `${ghHost}/*`;
        } else if (
          group === 'gist' ||
          (group === 'repo' && (verb === 'create' || verb === 'fork'))
        ) {
          repo = `${ghHost}/*`;
        } else if (group === 'repo' && verb !== 'rename') {
          // `gh repo edit|delete|archive [<repository>]`; rename's operand is
          // the new name of the current repository, not another one.
          const operand = positionals(args, GH_REPO_VALUE_FLAGS)[2];
          if (operand === null) repo = `${ghHost}/*`;
          else if (operand !== undefined) repo = ghRepoArg(operand, ghHost).repo;
          else if (envRepo) repo = `${ghHost}/*`;
        } else if (envRepo) {
          repo = `${ghHost}/*`;
        }
        out.destinations.push(dest);
        if (repo !== undefined) out.repos.push(repo);
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
      // `git -c remote.x.url=URL <verb>`: the remote now points at URL.
      for (let i = 0; i < args.length; i++) {
        if (args[i] !== '-c') continue;
        const v = args[i + 1];
        if (v === null || v === undefined) {
          if (verb === 'push') out.unresolved = true;
          continue;
        }
        const m = /^remote\.[^=]+\.(?:push)?url=(.*)$/i.exec(v);
        if (m) sendToGitUrl(m[1], out);
      }
      // Pointing a remote at a url is how a later `git push <name>` leaves:
      // judged as the send it prepares, to that url.
      if (verb === 'remote') {
        const rp = positionals(args, new Set(['-C', '-c', '--git-dir', '--work-tree', '-t', '-m']));
        const sub = rp[1];
        if (sub === 'add' || sub === 'set-url') {
          const url = rp.slice(2).filter((p) => p !== '--push' && p !== '--add')[1];
          sendToGitUrl(url, out);
        }
        return;
      }
      if (verb === 'config') {
        // A read (`git config remote.origin.url`, `--get`) names no value.
        const reads = args.some(
          (w) =>
            w !== null && /^--(get|get-all|get-regexp|unset|unset-all|list|get-urlmatch)$/.test(w)
        );
        const k = pos.findIndex((p) => p !== null && /^remote\..+\.(?:push)?url$/i.test(p));
        if (k >= 0 && k + 1 < pos.length && !reads) sendToGitUrl(pos[k + 1], out);
        return;
      }
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
        // `git push "$URL"`: the repository is built at run time.
        if (pos.length > 1 && pos[1] === null) {
          out.sends = true;
          out.unresolved = true;
          return;
        }
        // `--repo=<repository>` names the target as the first operand would.
        const target =
          flagValue(args, ['--repo']) ??
          pos.slice(1).find((p) => p !== null && !p.startsWith('-')) ??
          null;
        // A url: scheme, `user@host:path`, or scp-like `host.tld:path`.
        if (
          target !== null &&
          (/:\/\/|@/.test(target) || /^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+:/.test(target))
        ) {
          sendToGitUrl(target, out);
          return;
        }
        // A local path (`../backup`, `/srv/git/app.git`) stays on the machine.
        if (target !== null && /^[./~]|\//.test(target)) return;
        out.sends = true;
        // A remote name resolves in the repository the hook reads; in
        // another one (`cd x &&`, `-C x`, GIT_DIR) it names nothing known.
        const elsewhere =
          state.cwdChanged ||
          args.some((w) => w !== null && /^(-C|--git-dir|--work-tree)(=|$)/.test(w)) ||
          env.some((n) => n === 'GIT_DIR' || n === 'GIT_WORK_TREE' || n === 'GIT_CONFIG');
        if (elsewhere) out.unresolved = true;
        else out.gitRemotes.push(target ?? '');
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

function walkCalls(command: string, out: ShellExposure, depth: number, state: WalkState): void {
  const f = parseShared(command);
  if (typeof f === 'symbol' || !f) return;
  syntax.Walk(f, (node: unknown) => {
    if (!node) return false;
    const type = syntax.NodeType(node);
    // `export GH_REPO=x && gh ...`, `declare -x GIT_DIR=...`, `GH_REPO=x; ...`:
    // the variable reaches every later call of the command.
    if (type === 'DeclClause') {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      for (const a of (node as any).Args || []) if (a?.Name?.Value) state.env.add(a.Name.Value);
      return true;
    }
    // A redirect into bash's /dev/tcp or /dev/udp pseudo-file sends whatever
    // the statement writes to that host (fw#372 A1).
    if (type === 'Stmt') {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      for (const r of (node as any).Redirs || []) {
        const h = devNetRedirectHost(r?.Word ? resolveWordLiteral(r.Word) : null);
        if (!h) continue;
        out.sends = true;
        out.destinations.push(`host:${h}`);
      }
      return true;
    }
    if (type !== 'CallExpr') return true;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const call = node as any;
    if ((call.Args || []).length === 0) {
      for (const a of call.Assigns || []) if (a?.Name?.Value) state.env.add(a.Name.Value);
      return true;
    }
    const c = callWords(node);
    if (!c) return true;
    if (SHELLS.has(c.head) && depth < MAX_DEPTH) {
      const i = c.args.findIndex((w) => w === '-c' || w === '-lc' || w === '-ec');
      const payload = i >= 0 ? c.args[i + 1] : null;
      if (typeof payload === 'string') walkCalls(payload, out, depth + 1, state);
      return true;
    }
    if (CWD_CHANGERS.has(c.head)) state.cwdChanged = true;
    classifyCall(c.head, c.args, c.prefixes, [...c.env, ...state.env], state, out);
    return true;
  });
}

/** Classify a shell command as a source, a sink, both or neither. Never throws. */
export function classifyShellExposure(command: string): ShellExposure {
  const out: ShellExposure = {
    ...EMPTY,
    destinations: [],
    gitRemotes: [],
    repos: [],
    fetchDestinations: [],
    fetchKinds: [],
  };
  try {
    walkCalls(command, out, 0, { cwdChanged: false, env: new Set() });
  } catch {
    return { ...EMPTY };
  }
  out.destinations = [...new Set(out.destinations)];
  out.fetchDestinations = [...new Set(out.fetchDestinations)];
  out.gitRemotes = [...new Set(out.gitRemotes)];
  out.repos = [...new Set(out.repos)];
  out.fetchKinds = [...new Set(out.fetchKinds)];
  return out;
}
