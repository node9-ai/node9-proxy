# @node9/policy-engine

Shared policy evaluation engine for [node9](https://node9.ai). Pure-function
library imported by `node9-proxy` (the local CLI) and `node9Firewall` (the
SaaS backend) so DLP patterns, AST shell parsing, smart-rule matching, and
shield definitions live in exactly one place.

**Status:** v0.1.0-alpha — under construction. See
[the migration plan](../../../doc/roadmap/v1.16.1-policy-engine.md) for the
day-by-day extraction schedule.

## Design rule

The engine is **pure**. It takes inputs, returns verdicts. It never reads
files, environment variables, or the network. Hosts pass everything in
explicitly. ESLint enforces this — no runtime imports of `fs`, `path`, `os`,
or `process` are allowed in `src/`.

## Public API (target — see migration plan for current state)

```typescript
import { createEngine } from '@node9/policy-engine';

const engine = createEngine({
  shields: ['bash-safe', 'postgres'],
  smartRules: [...],
  dlp: { enabled: true },
});

const verdict = engine.evaluatePolicy({
  toolName: 'bash',
  args: { command: 'rm -rf /tmp/test' },
});
// → { decision: 'block', reason: '...', matchedRule: { ... } }
```

## License

Apache-2.0
