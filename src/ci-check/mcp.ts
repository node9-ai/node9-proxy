// src/ci-check/mcp.ts
// CI-3 — committed .mcp.json. Flags unpinned executable servers (supply-chain)
// and inline credential values (reusing the DLP scanner). Static, parse-only.

import { explainMcp } from './explain';
import { scanText } from '@node9/policy-engine';
import { lineAtIndex } from './lines';
import type { CiFinding } from './types';
import { safeText } from './suppress';

// The WHOLE command: `npx [-y] tsx ./file.ts [plain args]`; `${CLAUDE_PLUGIN_ROOT}/` is the plugin's
// own folder, set by Claude Code. Anchored, with no shell operator, so
// `sh -c "npx evil@latest; npx tsx ./a.ts"` is not excused by its tail.
const LOCAL_RUNNER_RE =
  /^(?:npx|pnpx|bunx)\s+(?:-y\s+|--yes\s+)?(?:tsx|ts-node|node)\s+(?:\.{1,2}\/|\$\{CLAUDE_PLUGIN_ROOT\}\/)?[\w@./-]+\.(?:m?[jt]s|cjs)(?:\s+[^\s;&|`$<>()]+)*$/;

// T.3 (2026-10-11): launchers that fetch a package by name when the server starts, and the
// registry each one fetches from (named in the explanation).
const LAUNCHERS: { re: RegExp; name: string; registry: string }[] = [
  { re: /\bnpx\b/, name: 'npx', registry: 'npm' },
  { re: /\bpnpx\b|\bpnpm\s+dlx\b/, name: 'pnpm dlx', registry: 'npm' },
  { re: /\byarn\s+dlx\b/, name: 'yarn dlx', registry: 'npm' },
  { re: /\bnpm\s+(?:exec|x)\b/, name: 'npm exec', registry: 'npm' },
  { re: /\bbunx\b|\bbun\s+x\b/, name: 'bunx', registry: 'npm' },
  { re: /\buvx\b|\buv\s+tool\s+run\b/, name: 'uvx', registry: 'PyPI' },
  { re: /\bpipx\s+run\b/, name: 'pipx run', registry: 'PyPI' },
];
// A version in either registry's spelling: `pkg@1.2.3`, `pkg==1.2.3`, `--from pkg==1.2.3`.
const PINNED_RE = /@\d|==\s*\d/;
// Flags of `docker run` / `podman run` / `nerdctl run` that take a separate value. A missing
// one made its value read as the image (`--tmpfs /tmp:rw` passed as pinned, review round 2).
const RUN_VALUE_FLAGS = new Set(
  [
    '-a --attach --add-host --annotation --blkio-weight --blkio-weight-device --cap-add',
    '--cap-drop --cgroup-parent --cgroupns --cgroups --cgroup-conf --cidfile --cpu-period',
    '--cpu-quota --cpu-rt-period --cpu-rt-runtime -c --cpu-shares --cpus --cpuset-cpus',
    '--cpuset-mems --device --device-cgroup-rule --device-read-bps --device-read-iops',
    '--device-write-bps --device-write-iops --dns --dns-option --dns-search --domainname',
    '--entrypoint -e --env --env-file --expose --gpus --group-add --health-cmd',
    '--health-interval --health-retries --health-start-interval --health-start-period',
    '--health-timeout -h --hostname --ip --ip6 --ipc --isolation --kernel-memory -l --label',
    '--label-file --link --link-local-ip --log-driver --log-opt --mac-address -m --memory',
    '--memory-reservation --memory-swap --memory-swappiness --mount --name --network --net',
    '--network-alias --oom-score-adj --pid --pids-limit --platform -p --publish --pull',
    '--restart --runtime --security-opt --shm-size --stop-signal --stop-timeout',
    '--storage-opt --sysctl --tmpfs --ulimit -u --user --userns --uts -v --volume',
    '--volume-driver --volumes-from -w --workdir --secret --pod --arch --os --variant',
    '--timezone --umask --requires --uidmap --gidmap --subuidname --subgidname --hooks-dir',
    '--init-path --seccomp-policy --sdnotify --personality --preserve-fds --chrootdirs',
  ]
    .join(' ')
    .split(' ')
);

/** The image a container `run` argv starts, or null when there is none. */
function runImage(tokens: string[]): string | null {
  const i = tokens.findIndex(
    (t, k) =>
      /(^|\/)(docker|podman|nerdctl)$/.test(t) &&
      (tokens[k + 1] === 'run' || (tokens[k + 1] === 'container' && tokens[k + 2] === 'run'))
  );
  if (i < 0) return null;
  const from = tokens[i + 1] === 'run' ? i + 2 : i + 3;
  for (let k = from; k < tokens.length; k++) {
    const t = tokens[k];
    if (t.startsWith('-')) {
      if (!t.includes('=') && RUN_VALUE_FLAGS.has(t)) k++;
      continue;
    }
    return t;
  }
  return null;
}

/** The packages a launcher installs (`uvx --from pkg==1 x` → pkg; `npx -p a -p b cmd` → a, b),
 *  lower case, without versions. With no package flag, the first positional token is the
 *  package. Empty when no launcher or package token is found. */
export function launchedPackages(argv: string): string[] {
  const t = argv.split(/\s+/).filter(Boolean);
  const i = t.findIndex((x) => /(^|\/)(npx|pnpx|bunx|uvx|dlx|exec|x|run)$/.test(x));
  if (i < 0) return [];
  const bare = (v: string) =>
    v.startsWith('@') ? v.replace(/^(@[^/]+\/[^@]+).*$/, '$1') : v.replace(/(==|@).*$/, '');
  const flagged: string[] = [];
  let positional: string | null = null;
  for (let k = i + 1; k < t.length; k++) {
    const tok = t[k];
    const eq = /^(--from|-p|--package)=(.*)$/.exec(tok);
    if (eq) {
      flagged.push(eq[2]);
      continue;
    }
    if (/^(--from|-p|--package)$/.test(tok)) {
      if (t[k + 1]) flagged.push(t[++k]);
      continue;
    }
    if (tok.startsWith('-')) continue;
    positional ??= tok;
  }
  // With a package flag, the positional token is a command from those packages.
  const names = flagged.length ? flagged : positional ? [positional] : [];
  return names.map((n) => bare(n).toLowerCase()).filter(Boolean);
}

// A shell around the launcher runs more than its first command.
const SHELL_RE = /(?:^|\/)(?:sh|bash|zsh|dash|cmd|pwsh|powershell)(?:\.exe)?$/i;
const SHELL_OP_RE = /[;&|`$<>()]/;

/** Is every package this server installs one the repository itself publishes, on the registry
 *  this launcher fetches from? `own` holds `npm:<name>` / `pypi:<name>` (ownPackageNames); a
 *  plain name matches any registry. */
function launchesOwnPackage(argv: string, own: ReadonlySet<string>): boolean {
  if (own.size === 0) return false;
  if (SHELL_OP_RE.test(argv) || SHELL_RE.test(argv.split(/\s+/)[0] ?? '')) return false;
  const l = LAUNCHERS.find((x) => x.re.test(argv));
  if (!l) return false;
  const reg = l.registry === 'PyPI' ? 'pypi' : 'npm';
  const pkgs = launchedPackages(argv);
  return pkgs.length > 0 && pkgs.every((p) => own.has(`${reg}:${p}`) || own.has(p));
}

/** Why this server's executable is unpinned, or null. `own` is what the repository itself
 *  publishes (its root package.json / pyproject.toml name): starting its own package is not a
 *  third-party supply chain. */
function unpinnedLauncher(
  argv: string,
  own: ReadonlySet<string>
): { launcher: string; registry: string } | null {
  if (LOCAL_RUNNER_RE.test(argv)) return null;
  if (launchesOwnPackage(argv, own)) return null;
  const image = runImage(argv.split(/\s+/));
  if (image) {
    if (image.includes('@sha256:')) return null;
    const tail = image.slice(image.lastIndexOf('/') + 1);
    const tag = tail.includes(':') ? tail.slice(tail.indexOf(':') + 1) : '';
    return !tag || tag === 'latest'
      ? { launcher: 'docker run', registry: 'the image registry' }
      : null;
  }
  // `go run module@version` fetches the module; without `@` it builds local code.
  const goMod = /\bgo\s+run\s+(?:-\S+\s+)*([^\s@]+)@(\S+)/.exec(argv);
  if (goMod)
    return /^v\d/.test(goMod[2]) || /^[0-9a-f]{40}$/.test(goMod[2])
      ? null
      : { launcher: 'go run', registry: 'the Go module proxy' };
  const l = LAUNCHERS.find((x) => x.re.test(argv));
  if (!l) return null;
  return /@latest\b/.test(argv) || !PINNED_RE.test(argv)
    ? { launcher: l.name, registry: l.registry }
    : null;
}

/** T.3: the package names a repository publishes, read from its root manifests, each with its
 *  registry (`npm:<name>`, `pypi:<name>`). A `private` package.json publishes nothing. */
export function ownPackageNames(manifests: { path: string; content: string }[]): Set<string> {
  const out = new Set<string>();
  for (const m of manifests) {
    if (m.path === 'package.json') {
      try {
        const pkg = JSON.parse(m.content) as { name?: unknown; private?: unknown };
        if (typeof pkg.name === 'string' && pkg.name && pkg.private !== true)
          out.add(`npm:${pkg.name.toLowerCase()}`);
      } catch {
        /* not JSON: no name */
      }
    } else if (m.path === 'pyproject.toml') {
      const sec = /^\[(project|tool\.poetry)\]\s*$([\s\S]*?)(?=^\[|(?![\s\S]))/m.exec(m.content);
      const name = sec && /^name\s*=\s*["']([^"']{1,200})["']/m.exec(sec[2]);
      if (name) {
        out.add(`pypi:${name[1].toLowerCase()}`);
        out.add(`pypi:${name[1].toLowerCase().replace(/_/g, '-')}`);
      }
    }
  }
  return out;
}

export interface McpServerSpec {
  command?: string;
  args?: unknown[];
  url?: string;
  env?: Record<string, unknown>;
  disabled?: boolean;
}

export function analyzeMcp(
  path: string,
  content: string,
  own: ReadonlySet<string> = new Set()
): CiFinding[] {
  let cfg: {
    mcpServers?: Record<string, McpServerSpec>;
    servers?: Record<string, McpServerSpec>;
    mcp?: Record<string, { command?: unknown; enabled?: boolean; url?: string }>;
  };
  try {
    cfg = JSON.parse(content);
  } catch {
    return [];
  }
  if (!cfg || typeof cfg !== 'object') return [];
  // T.3: VS Code keeps servers under `servers`; opencode under `mcp`, with the command as an
  // array (`["npx", "-y", "pkg"]`) and `enabled: false` to switch one off.
  const servers: Record<string, McpServerSpec> = {
    ...(cfg.mcpServers ?? {}),
    ...(cfg.servers ?? {}),
  };
  for (const [name, s] of Object.entries(cfg.mcp ?? {})) {
    if (!s || typeof s !== 'object') continue;
    const cmd = Array.isArray(s.command) ? s.command.map(String) : [];
    servers[name] = {
      command: cmd[0],
      args: cmd.slice(1),
      url: s.url,
      disabled: s.enabled === false,
    };
  }
  return analyzeMcpServers(servers, path, content, own);
}

/** Score a normalized MCP server map. Shared by `.mcp.json` (CI-3) and Codex's
 *  `.codex/config.toml` `[mcp_servers.*]` (1c-A) — same danger model, different
 *  container: an unpinned executable server = supply-chain risk; an inline credential
 *  in `env` = an agent-reachable secret committed to the repo. */
export function analyzeMcpServers(
  servers: Record<string, McpServerSpec>,
  path: string,
  content = '',
  own: ReadonlySet<string> = new Set()
): CiFinding[] {
  const findings: CiFinding[] = [];
  for (const [name, srv] of Object.entries(servers ?? {})) {
    if (!srv || srv.disabled) continue;
    const argv = [srv.command, ...(Array.isArray(srv.args) ? srv.args.map(String) : [])].join(' ');
    // Both CI-3 rules anchor at the server's name: `"name":` in JSON, `[mcp_servers.name]`
    // (or a dotted key) in TOML. Unknown → no line, never a wrong one.
    const esc = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const at = content.search(
      new RegExp(`"${esc}"\\s*:|^[ \\t]*\\[mcp_servers\\.(?:"${esc}"|${esc})\\]`, 'm')
    );
    const line = at >= 0 ? lineAtIndex(content, at) : undefined;

    // Unpinned executable server. A runner started on a file in the repository (`npx tsx
    // ./server.ts`) runs local code: only the runner is unversioned, not the server (§Q).
    const why = unpinnedLauncher(argv, own);
    if (why) {
      findings.push({
        check: 'CI-3',
        rule: 'CI-3.mcp-unpinned',
        locator: name,
        dimension: 'mcp',
        severity: 'medium',
        title: `MCP server "${name}" runs an unpinned executable`,
        file: path,
        ...(line ? { line } : {}),
        signals: [
          why.launcher === 'npx'
            ? `\`${safeText(argv, 120)}\`: unversioned/@latest npx`
            : `\`${safeText(argv, 120)}\`: unversioned/latest ${why.launcher}`,
        ],
        fix: 'Pin the MCP server package to an exact version so a PR (or a registry compromise) can’t swap the toolchain.',
        explain: explainMcp({ name, argv, registry: why.registry }),
      });
    }

    // Inline credential value in env.
    for (const [k, v] of Object.entries(srv.env ?? {})) {
      if (typeof v !== 'string') continue;
      const hit = scanText(v);
      if (hit) {
        findings.push({
          check: 'CI-3',
          rule: 'CI-3.mcp-inline-credential',
          locator: `${name}.env.${k}`,
          dimension: 'mcp',
          severity: 'high',
          title: `MCP server "${name}" has an inline credential`,
          file: path,
          ...(line ? { line } : {}),
          signals: [
            `env.${k} matches ${hit.patternName}: agent-reachable secret committed to the repo`,
          ],
          fix: 'Move the value to an env var reference (${VAR}) resolved at launch; never commit the secret.',
        });
      }
    }
  }
  return findings;
}
