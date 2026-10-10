// resolve-version.js: prints the exact node9-ai version a `node9-version` input
// (a version, a range or a dist-tag) resolves to, so an upload reports the
// version that really scanned. Prints nothing when npm cannot answer; the
// caller then scans with the input as given and the upload is skipped.
//
// Plain CommonJS run by action.yml with `node`, like comment.js and upload.js.
// The 30 s bound is applied here rather than with `timeout`, which macOS
// runners lack and which on Windows is a different command.

'use strict';
const path = require('path');
const { execFileSync } = require('child_process');

const VERSION_RE = /^[0-9A-Za-z.+-]{1,50}$/;
const TIMEOUT_MS = 30_000;

/** Semver order: the numeric core first, then a release above its
 *  prereleases, then prerelease identifiers. Build metadata is ignored. */
function compare(a, b) {
  const split = (v) => {
    const [main, pre] = v.split('+')[0].split(/-(.*)/s);
    return { core: main.split('.').map((n) => Number(n) || 0), pre: pre ? pre.split('.') : [] };
  };
  const x = split(a);
  const y = split(b);
  for (let i = 0; i < 3; i++) {
    const d = (x.core[i] || 0) - (y.core[i] || 0);
    if (d) return d;
  }
  if (!x.pre.length || !y.pre.length) return y.pre.length - x.pre.length;
  for (let i = 0; i < Math.max(x.pre.length, y.pre.length); i++) {
    const p = x.pre[i];
    const q = y.pre[i];
    if (p === undefined) return -1;
    if (q === undefined) return 1;
    const pn = /^\d+$/.test(p);
    const qn = /^\d+$/.test(q);
    if (pn && qn && Number(p) !== Number(q)) return Number(p) - Number(q);
    if (pn !== qn) return pn ? -1 : 1;
    if (p !== q) return p < q ? -1 : 1;
  }
  return 0;
}

/** The highest version in `npm view <spec> version --json` output, or ''. */
function pickHighest(json) {
  let parsed;
  try {
    parsed = JSON.parse(json);
  } catch {
    return '';
  }
  const list = (Array.isArray(parsed) ? parsed : [parsed]).filter(
    (v) => typeof v === 'string' && VERSION_RE.test(v)
  );
  return list.sort(compare).pop() || '';
}

/** npm without a shell: the input is user-controlled. On Windows `npm` is a
 *  .cmd file that cannot be spawned directly, so its JS entry point is run
 *  with this same node. */
function npmView(spec, exec = execFileSync) {
  const args = ['view', `node9-ai@${spec}`, 'version', '--json', '--fetch-retries=1'];
  const opts = { encoding: 'utf8', timeout: TIMEOUT_MS, stdio: ['ignore', 'pipe', 'ignore'] };
  if (process.platform === 'win32') {
    const cli = path.join(
      path.dirname(process.execPath),
      'node_modules',
      'npm',
      'bin',
      'npm-cli.js'
    );
    return exec(process.execPath, [cli, ...args], opts);
  }
  return exec('npm', args, opts);
}

function resolve(spec, exec) {
  if (!spec || spec.length > 100) return '';
  try {
    return pickHighest(npmView(spec, exec));
  } catch {
    return '';
  }
}

if (require.main === module) {
  process.stdout.write(resolve(process.argv[2] || ''));
  process.exit(0);
}

module.exports = { compare, pickHighest, resolve, TIMEOUT_MS };
