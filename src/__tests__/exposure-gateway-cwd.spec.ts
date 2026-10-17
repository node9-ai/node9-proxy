// fw#318 review finding 3: the gateway passes its own working directory, so a
// write inside the project through a gateway filesystem server is not
// "outside the project". Source-level guard: the authorize call names cwd.
import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';

describe('gateway authorize call', () => {
  it('passes cwd: gatewayCwd next to sessionTaintGated', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'mcp-gateway', 'index.ts'), 'utf8');
    expect(src).toMatch(/sessionTaintGated: !readOnlyTools\.has\(toolName\), cwd: gatewayCwd/);
  });
});
