// scripts/probe-gate.mjs — file-driven policy probe.
//
// WHY THIS EXISTS: reviewers need to run REAL commands through the engine
// rather than reason about regexes (a refuted-by-reasoning finding is worth
// little). But putting attack strings inline — `node -e "... 'sudo python3
// -c' ..."` — makes node9 inspect the PROBE ITSELF: the founder got a stream
// of approval prompts, and unanswered routed cards auto-denied, so agents
// measured "nobody was there" and would have reported it as "blocked"
// (2026-08-11). Payloads therefore live in a JSON FIXTURE and only the
// fixture's PATH ever appears on a command line.
//
// Usage:  node scripts/probe-gate.mjs <cases.json>
//
// cases.json:
//   {
//     "label": "bypass candidates",
//     "commandChecks": { "inlineExec": "off" },   // optional
//     "mode": "standard",                          // optional
//     "cases": ["python3 -c \"print(1)\"", "cd /tmp && python3 -c \"x\""]
//   }
//
// Write that file with the Write tool — NEVER with a heredoc or echo, or the
// payloads land in a command line again and you are back to square one.
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { evaluatePolicy } = require('../packages/policy-engine/dist/index.js');

const file = process.argv[2];
if (!file) {
  console.error('usage: node scripts/probe-gate.mjs <cases.json>');
  process.exit(2);
}

const spec = JSON.parse(readFileSync(file, 'utf-8'));
const cases = Array.isArray(spec.cases) ? spec.cases : [];

/** Minimal PolicyConfig: everything off except what a case is probing, so a
 *  verdict is attributable to the check under test and not to DLP/dangerous
 *  words firing incidentally.
 *
 *  ⚠️ READ THIS BEFORE CALLING A VERDICT A BUG. `smartRules: []` means NO
 *  SHIELDS. Much of node9's real coverage lives in shield rules (tier 2),
 *  which run BEFORE the built-in tiers this harness exercises. Verified
 *  example: `curl … | bash` reads `allow` here, but on a real machine the
 *  bash-safe shield (block-pipe-to-shell / block-eval-remote) blocks it, and
 *  bash-safe ships active. So an `allow` from this harness means "no BUILT-IN
 *  tier claimed it" — NOT "node9 permits it". To judge real-world coverage,
 *  add the relevant shield's smartRules to the fixture or say plainly that
 *  the finding is scoped to built-ins only. */
function cfg(commandChecks, mode) {
  return {
    policy: {
      sandboxPaths: [],
      dangerousWords: [],
      ignoredTools: [],
      smartRules: [],
      toolInspection: { bash: 'command', shell: 'command', run_shell_command: 'command' },
      dlp: { enabled: false, scanIgnoredTools: false },
      ...(commandChecks ? { commandChecks } : {}),
    },
    settings: { mode: mode || 'standard' },
  };
}

const config = cfg(spec.commandChecks, spec.mode);
console.log(
  `=== ${spec.label || 'probe'}  commandChecks=${JSON.stringify(spec.commandChecks || {})}  mode=${config.settings.mode}`
);

for (const command of cases) {
  let v;
  try {
    v = await evaluatePolicy(config, 'Bash', { command }, { agent: 'claude' }, {});
  } catch (err) {
    console.log(`ERROR  ${JSON.stringify(command)}  → ${err?.message ?? err}`);
    continue;
  }
  const why = v.blockedByLabel || v.ruleName || '';
  const tier = v.tier ? ` [t${v.tier}]` : '';
  // Single line per case: decision, the exact input, and what decided it.
  console.log(
    `${String(v.decision).padEnd(6)} ${JSON.stringify(command).padEnd(64)} ${why}${tier}`
  );
}
