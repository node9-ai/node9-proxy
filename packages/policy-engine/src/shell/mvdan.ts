// The mvdan-sh parser, loaded on first use (fw#425).
//
// mvdan-sh is a 1.5 MB GopherJS build whose package init costs 110-180 ms. A
// hook call for Read, Edit, Write or Grep never parses a shell command, so it
// must not pay that at start-up. Every engine module reaches the parser
// through `getSyntax()`; the first call loads it.
//
// `createRequire(__filename)`: native in the CJS build, injected by vitest,
// and provided to the ESM builds (engine index.mjs, the proxy's .mjs bundles)
// by tsup's `shims`. A bare `require` would not survive esbuild's ESM output.

import { createRequire } from 'module';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let syntax: any = null;

/** mvdan-sh's `syntax` namespace (NewParser, Walk, NodeType, ...). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function getSyntax(): any {
  if (syntax === null) {
    const req = createRequire(__filename);
    syntax = req('mvdan-sh').syntax;
  }
  return syntax;
}

/** A value computed on first use and kept: for the operator numbers the
 *  engine reads off the parser (so a renumbering mvdan cannot fool it), which
 *  must not force the parser to load at import time. */
export function lazy<T>(compute: () => T): () => T {
  let done = false;
  let value: T;
  return () => {
    if (!done) {
      value = compute();
      done = true;
    }
    return value;
  };
}
