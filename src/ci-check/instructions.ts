// src/ci-check/instructions.ts
// CI-6 — committed agent INSTRUCTION files (CLAUDE.md / AGENTS.md / GEMINI.md /
// .cursorrules / .github/copilot-instructions.md / .claude skills & commands). These
// are auto-loaded into the agent's system prompt straight from the repo, so a poisoned
// or careless one is a PERSISTENT injection vector — loaded into every future agent run
// by every contributor. LOW-FP BY DESIGN: only structural, undefendable signals fire
// high; ambiguous natural-language prose (autonomy phrasing) is deliberately NOT flagged
// here (needs an LLM pass — see the scope doc). Static, parse-only, never executed.

import type { CiFinding, Severity } from './types';

// ── Tier 1: structural, near-zero-FP → high/critical ──────────────────────────
// Hidden / invisible / bidi / Unicode-tag characters — used to conceal instructions
// from a human reviewer while the model still reads them. Deliberately EXCLUDES
// U+200C/U+200D (emoji ZWNJ/ZWJ) and U+FEFF (BOM) to avoid FPs on legitimate emoji.
//   U+200B zero-width space · U+2060 word joiner · U+202A–202E bidi · U+2066–2069
//   bidi isolates · U+E0000–E007F Unicode tag chars.
const HIDDEN_CHARS = /[\u200B\u2060\u202A-\u202E\u2066-\u2069]|[\u{E0000}-\u{E007F}]/u;

// Prompt-override / role-impersonation directives. The classic phrases only — no bare
// "system:" (too FP-prone in docs).
const OVERRIDE_RE =
  /ignore\s+(all\s+)?(previous|prior|the\s+above)\s+(instructions|prompts?|rules)|disregard\s+(the\s+|your\s+)?(system\s+)?(prompt|instructions|rules)|forget\s+(everything|all\s+(previous|prior))|you\s+are\s+now\s+(a|an|the)\b|<\/?system>/i;

// ── Tier 2: dangerous sink WITH agent-directive framing → medium ───────────────
// Remote-exec (fetch-and-obey).
const FETCH_OBEY_RE =
  /\b(curl|wget|iwr|invoke-webrequest)\b[^\n|]*\|\s*(bash|sh|zsh|python3?|node|iex)\b|\b(curl|wget)\b[^\n]*&&[^\n]*\b(bash|sh)\b/i;
// Credential-file access.
const SECRET_PATH_RE =
  /~\/\.aws\/credentials|~\/\.ssh\/id_[a-z]+|~\/\.config\/gh\/hosts|read\s+the\s+(token|secret|api[_ ]?key|password)\s+(in|from)\s+[.`'"]?\.?env/i;
// Exfil to an external endpoint.
const EXFIL_RE =
  /\b(post|send|upload|exfiltrate|forward)\b[^\n]{0,40}\b(to|at)\b[^\n]{0,50}(https?:\/\/|webhook|hook\.[a-z])/i;

// A human-facing section (install/dev docs) — a `curl|bash` here is setup guidance for a
// PERSON, not a directive to the agent. Down-weights Tier-2 sinks.
const HUMAN_SECTION_RE =
  /^#+\s*(install|installation|setup|set ?up|getting started|quick ?start|contributing|contribution|development|dev setup|build|prerequisites|requirements|usage)\b/i;

// A safety/negation clause ("never read ~/.aws/…", "do NOT curl | bash") — the presence
// of the sink here is a GUARDRAIL, not a directive. Prevents flagging a repo for its own
// safety instructions (the G-c lesson, applied to prose).
const NEGATION_RE = /\b(never|do not|don'?t|avoid|must not|should not|no need to|refuse to)\b/i;

function isNegated(text: string, idx: number): boolean {
  return NEGATION_RE.test(text.slice(Math.max(0, idx - 40), idx));
}

function inHumanSection(text: string, idx: number): boolean {
  const heading = text
    .slice(0, idx)
    .split('\n')
    .reverse()
    .find((l) => /^#+\s/.test(l));
  return !!heading && HUMAN_SECTION_RE.test(heading);
}

/** base64 blobs that DECODE to instruction-like text (concealment). Returns the decoded
 *  text so Tier-1 patterns can run against it. */
function decodeSuspiciousBase64(text: string): string {
  let out = '';
  for (const m of text.matchAll(/[A-Za-z0-9+/]{40,}={0,2}/g)) {
    try {
      const d = Buffer.from(m[0], 'base64').toString('utf8');
      if (/[\x20-\x7E]{16,}/.test(d) && /[a-z]{4,}/i.test(d)) out += ' ' + d;
    } catch {
      /* not base64 — ignore */
    }
  }
  return out;
}

function mk(
  severity: Severity,
  title: string,
  signals: string[],
  fix: string,
  path: string
): CiFinding {
  return { check: 'CI-6', dimension: 'instructions', severity, title, file: path, signals, fix };
}

/** Analyze one agent instruction file. Returns 0+ findings. Never throws. */
export function analyzeInstructionFile(path: string, content: string): CiFinding[] {
  const findings: CiFinding[] = [];
  const decoded = decodeSuspiciousBase64(content);

  // Tier 1 — structural
  if (HIDDEN_CHARS.test(content)) {
    findings.push(
      mk(
        'critical',
        'Hidden characters in an agent instruction file',
        [
          'contains zero-width / bidi / Unicode-tag characters — a technique to hide instructions from human review while the agent still reads them',
        ],
        'Remove the hidden characters. Instruction files must be plain, reviewable text.',
        path
      )
    );
  }
  const ov = OVERRIDE_RE.exec(content);
  const ovEnc = !ov ? OVERRIDE_RE.exec(decoded) : null;
  if (ov || ovEnc) {
    const m = (ov || ovEnc)!;
    findings.push(
      mk(
        ovEnc ? 'critical' : 'high',
        'Prompt-override directive in an agent instruction file',
        [
          `contains a prompt-override / role-impersonation directive (\`${m[0].slice(0, 60).trim()}\`)${ovEnc ? ' — concealed in a base64 blob' : ''}`,
        ],
        'Remove the override text. An instruction file should not tell the agent to ignore its own rules.',
        path
      )
    );
  }

  // Tier 2 — sink + agent-directive framing (skip human install docs + safety clauses)
  const fo = FETCH_OBEY_RE.exec(content);
  if (fo && !inHumanSection(content, fo.index) && !isNegated(content, fo.index)) {
    findings.push(
      mk(
        'medium',
        'Instruction directs the agent to fetch and run remote code',
        [`\`${fo[0].slice(0, 70).trim()}\` — fetch-and-obey, outside an install/setup section`],
        'Do not instruct the agent to pipe remote content into a shell; pin and vendor scripts instead.',
        path
      )
    );
  }
  const sp = SECRET_PATH_RE.exec(content);
  if (sp && !isNegated(content, sp.index)) {
    findings.push(
      mk(
        'medium',
        'Instruction points the agent at credential material',
        [`references \`${sp[0].slice(0, 50).trim()}\` — directs the agent toward secrets`],
        'Do not reference credential files or paths in agent instructions.',
        path
      )
    );
  }
  const ex = EXFIL_RE.exec(content);
  if (ex && !inHumanSection(content, ex.index) && !isNegated(content, ex.index)) {
    findings.push(
      mk(
        'medium',
        'Instruction directs the agent to send data to an external endpoint',
        [`\`${ex[0].slice(0, 70).trim()}\` — possible exfiltration directive`],
        'Remove external post/upload directives from agent instructions.',
        path
      )
    );
  }

  return findings;
}
