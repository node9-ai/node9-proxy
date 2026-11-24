// src/addons/identity.ts
// A name an admin can recognise and approve for an MCP server, derived from
// its launch command: the package it runs (`npm:@scope/pkg`), the image
// (`docker:ghcr.io/org/image`), the remote host (`url:mcp.example.com`) or the
// program (`binary:my-server`). Never a path, an argument value or an env value:
// arguments can carry tokens, so only the one token that names the package is
// read, and only when it looks like a package name.

import path from 'path';

const MAX_LEN = 128;
/** Characters a package, image, host or program name is made of. Anything else
 *  means the token is not a name (a URL with a query, a quoted secret...). */
const NAME_SHAPE = /^[A-Za-z0-9@][A-Za-z0-9@/._+~-]*$/;

function clean(name: string | undefined): string | null {
  if (!name) return null;
  const v = name.trim();
  if (!v || v.length > MAX_LEN || !NAME_SHAPE.test(v)) return null;
  return v;
}

/** `pkg@1.2.3` -> `pkg`, `@scope/pkg@latest` -> `@scope/pkg`. */
function npmName(spec: string): string {
  const at = spec.lastIndexOf('@');
  return at > 0 ? spec.slice(0, at) : spec;
}

/** `pkg==1.2`, `pkg>=1`, `pkg@1.2`, `pkg[extra]` -> `pkg`. */
function pypiName(spec: string): string {
  return spec.split(/[=<>!~@[;]/)[0];
}

/** `image:tag` and `image@sha256:...` -> `image` (a registry port stays). */
function imageName(spec: string): string {
  const noDigest = spec.split('@')[0];
  const lastSlash = noDigest.lastIndexOf('/');
  const colon = noDigest.lastIndexOf(':');
  return colon > lastSlash ? noDigest.slice(0, colon) : noDigest;
}

/** The first argument that is not a flag. Flags in `withValue` consume the
 *  next argument; a `--flag=value` form consumes nothing. */
function firstPositional(args: string[], withValue: Set<string> = new Set()): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--') return args[i + 1];
    if (a.startsWith('-')) {
      if (!a.includes('=') && withValue.has(a)) i++;
      continue;
    }
    return a;
  }
  return undefined;
}

const NPX_VALUE_FLAGS = new Set(['-p', '--package', '-c', '--call', '--registry', '--cache']);
const UVX_VALUE_FLAGS = new Set([
  '--from',
  '--with',
  '--python',
  '-p',
  '--index',
  '--index-url',
  '--extra-index-url',
]);
const DOCKER_VALUE_FLAGS = new Set([
  '-e',
  '--env',
  '--env-file',
  '-v',
  '--volume',
  '--mount',
  '--name',
  '-p',
  '--publish',
  '--network',
  '--net',
  '-w',
  '--workdir',
  '-u',
  '--user',
  '--entrypoint',
  '--label',
  '-l',
  '--platform',
  '--pull',
  '--add-host',
  '--cpus',
  '-m',
  '--memory',
  '--hostname',
  '-h',
]);

function program(command: string): string {
  return path
    .basename(command.replace(/\\/g, '/'))
    .replace(/\.(exe|cmd|bat|ps1)$/i, '')
    .toLowerCase();
}

/** The identity of a local (spawned) MCP server. */
export function mcpIdentityFromCommand(command: string, args: string[]): string {
  const prog = program(command);
  const fallback = (): string => {
    const name = clean(prog);
    return name ? `binary:${name}` : 'unknown';
  };

  if (prog === 'npx' || prog === 'pnpx' || prog === 'bunx') {
    // `npx -p pkg bin` names the package after -p.
    const pi = args.findIndex((a) => a === '-p' || a === '--package');
    const eq = args.find((a) => a.startsWith('--package='));
    const spec =
      pi >= 0
        ? args[pi + 1]
        : eq
          ? eq.slice('--package='.length)
          : firstPositional(args, NPX_VALUE_FLAGS);
    const name = clean(spec && npmName(spec));
    return name ? `npm:${name}` : fallback();
  }
  if ((prog === 'pnpm' || prog === 'yarn' || prog === 'bun') && args[0] === 'dlx') {
    const spec = firstPositional(args.slice(1), NPX_VALUE_FLAGS);
    const name = clean(spec && npmName(spec));
    return name ? `npm:${name}` : fallback();
  }
  if (prog === 'npm' && (args[0] === 'exec' || args[0] === 'x')) {
    const spec = firstPositional(args.slice(1), NPX_VALUE_FLAGS);
    const name = clean(spec && npmName(spec));
    return name ? `npm:${name}` : fallback();
  }
  if (prog === 'uvx' || (prog === 'uv' && args[0] === 'tool' && args[1] === 'run')) {
    const rest = prog === 'uvx' ? args : args.slice(2);
    const fi = rest.indexOf('--from');
    const spec = fi >= 0 ? rest[fi + 1] : firstPositional(rest, UVX_VALUE_FLAGS);
    const name = clean(spec && pypiName(spec));
    return name ? `pypi:${name}` : fallback();
  }
  if (prog === 'pipx' && args[0] === 'run') {
    const name = clean(firstPositional(args.slice(1), new Set(['--spec']))?.split(/[=<>!~@[]/)[0]);
    return name ? `pypi:${name}` : fallback();
  }
  if ((prog === 'docker' || prog === 'podman') && args[0] === 'run') {
    const spec = firstPositional(args.slice(1), DOCKER_VALUE_FLAGS);
    const image = spec && imageName(spec);
    // A registry may carry a port (`registry:5000/img`); that is the only colon
    // an image name keeps, so it is checked apart from the general shape.
    const port = image ? /^([A-Za-z0-9.-]+):(\d{1,5})\/(.+)$/.exec(image) : null;
    const name = port
      ? clean(port[3]) && `${port[1]}:${port[2]}/${clean(port[3])}`
      : clean(image || undefined);
    return name ? `docker:${name}` : fallback();
  }
  if (/^python(\d+(\.\d+)?)?$/.test(prog) && args[0] === '-m') {
    const name = clean(args[1]);
    return name ? `python:${name}` : fallback();
  }
  if (prog === 'node' || prog === 'deno' || prog === 'bun' || /^python(\d+(\.\d+)?)?$/.test(prog)) {
    // A script run by an interpreter: name the package when the script sits in
    // node_modules, else the script's file name. Never the path.
    const script = firstPositional(args.filter((a) => a !== 'run'));
    if (script) {
      const norm = script.replace(/\\/g, '/');
      const nm = /node_modules\/((?:@[^/]+\/)?[^/]+)/.exec(norm);
      if (nm) {
        const name = clean(nm[1]);
        if (name) return `npm:${name}`;
      }
      const name = clean(path.posix.basename(norm));
      if (name) return `script:${name}`;
    }
    return fallback();
  }
  return fallback();
}

/** The identity of a remote (URL) MCP server: its host. */
export function mcpIdentityFromUrl(url: unknown): string {
  if (typeof url !== 'string') return 'url:unknown';
  try {
    const host = clean(new URL(url).hostname.toLowerCase());
    return host ? `url:${host}` : 'url:unknown';
  } catch {
    return 'url:unknown';
  }
}
