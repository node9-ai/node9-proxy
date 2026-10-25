// The proxy's own version, from package.json, found by walking up from this
// file: `src/` in tests and `dist/` in the build sit at different depths.
import fs from 'fs';
import path from 'path';

function readVersion(): string {
  let dir = __dirname;
  for (let i = 0; i < 5; i++) {
    const p = path.join(dir, 'package.json');
    try {
      const pkg = JSON.parse(fs.readFileSync(p, 'utf-8')) as { name?: string; version?: string };
      if (pkg.name === '@node9/proxy' && typeof pkg.version === 'string') return pkg.version;
    } catch {
      /* not here */
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return 'unknown';
}

export const PROXY_VERSION = readVersion();
