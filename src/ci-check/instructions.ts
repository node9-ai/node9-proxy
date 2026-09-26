// src/ci-check/instructions.ts
// CI-6 — committed agent INSTRUCTION files (CLAUDE.md / AGENTS.md / GEMINI.md /
// .cursorrules / .github/copilot-instructions.md, plus SKILL.md, a skill's supporting
// .md files, .claude/agents/*.md and .claude/commands/**.md). These are loaded into the
// agent's context straight from the repo, so a poisoned
// or careless one is a PERSISTENT injection vector — loaded into every future agent run
// by every contributor. LOW-FP BY DESIGN: only structural, undefendable signals fire
// high; ambiguous natural-language prose (autonomy phrasing) is deliberately NOT flagged
// here (needs an LLM pass — see the scope doc). Static, parse-only, never executed.
// The CONTENT is graded here; a skill's or command's `allowed-tools` frontmatter is a
// permission grant and is graded by CI-1 (analyzeSkillGrants in agent-config.ts).

import type { CiFinding, Severity } from './types';

// ── Tier 1: structural concealment — classified by LEGITIMACY, not "is it invisible" ──
// Presence of an invisible/formatting char ≠ concealment. Four classes, distinct handling
// (round-5 follow-up; live FP: a lone U+200B between Khmer syllables in a translated
// AGENTS.md is the legitimate word separator, not hidden text):
//   A — Unicode TAG chars (U+E0000–E007F): no legitimate use in prose → critical.
//   B — Bidi OVERRIDE (U+202D/202E): Trojan-Source visual reordering → critical.
//   C — Bidi embed/isolate (U+202A–202C, U+2066–2069): legit in RTL docs → advisory (surfaced,
//       not over-claimed as high/critical).
//   D — Zero-width (U+200B word-break, U+2060 word-joiner): legit in SE-Asian/CJK scripts →
//       fire ONLY on the concealment SIGNATURE (splits a visible Latin word; escalate to
//       critical only when de-hiding REVEALS a directive — mirrors decodeSuspiciousBase64).
const TAG_CHARS = /[\u{E0000}-\u{E007F}]/u; // A
const BIDI_OVERRIDE = /[‭‮]/; // B
const BIDI_EMBED_ISOLATE = /[‪-‬⁦-⁩]/; // C

// D allow-list: scripts where a zero-width space is a legitimate word/line-break hint (no
// inter-word spacing). Thai / Lao / Myanmar / Khmer / Kana / CJK / Hangul.
function isZwLegitScript(cp: number | undefined): boolean {
  if (cp === undefined) return false;
  return (
    (cp >= 0x0e00 && cp <= 0x0e7f) ||
    (cp >= 0x0e80 && cp <= 0x0eff) ||
    (cp >= 0x1000 && cp <= 0x109f) ||
    (cp >= 0x1780 && cp <= 0x17ff) ||
    (cp >= 0x3040 && cp <= 0x30ff) ||
    (cp >= 0x3400 && cp <= 0x9fff) ||
    (cp >= 0xac00 && cp <= 0xd7af)
  );
}
const isAsciiWordChar = (ch: string | undefined): boolean => !!ch && /[A-Za-z0-9]/.test(ch);

/** D: count zero-width chars (U+200B/U+2060) that SPLIT a visible Latin word — the concealment
 *  shape. Skips a neighbor in a ZW-legit script (word-break typography) and whitespace/edge
 *  boundaries (formatting). */
function suspiciousZeroWidth(text: string): number {
  let n = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c !== 0x200b && c !== 0x2060) continue;
    if (isZwLegitScript(text.codePointAt(i - 1)) || isZwLegitScript(text.codePointAt(i + 1)))
      continue;
    const prev = text[i - 1];
    const next = text[i + 1];
    if (!prev || !next || /\s/.test(prev) || /\s/.test(next)) continue;
    if (isAsciiWordChar(prev) && isAsciiWordChar(next)) n++;
  }
  return n;
}
const stripZeroWidth = (t: string): string => t.replace(/[​⁠]/g, '');

/** Every committed file an agent loads as instructions on its own. ONE definition: the tree
 *  walk in fetch.ts picks by it and the dispatcher in index.ts routes by it, so a file can
 *  never be fetched and then silently dropped, or the reverse. The last three shapes are the
 *  Agent Skills standard (`SKILL.md` in any letter case — `talmolab/sleap` commits
 *  `skill.md`, which every case-insensitive contributor disk resolves; the always-loaded
 *  CLAUDE.md/AGENTS.md stay case-exact — loaded by Claude Code, Codex, Hermes, OpenClaw and Pi)
 *  and Claude Code's own subagents and slash commands. Measured over 389 real skill files
 *  before they were added (2026-09-22): 4 of 4 known-malicious fixtures caught; 12 benign
 *  files flagged, every one a false positive, in the shapes fixed alongside this change. */
export const INSTRUCTION_FILE_RE =
  /(^|\/)(CLAUDE|AGENTS|GEMINI)\.md$|(^|\/)\.cursorrules$|(^|\/)\.(windsurf|cline)rules$|(^|\/)copilot-instructions\.md$|(^|\/)[Ss][Kk][Ii][Ll][Ll]\.md$|(^|\/)\.claude\/agents\/[^/]+\.md$|(^|\/)\.claude\/commands\/.+\.md$/;

/** Directories that hold a skill: the parent of every SKILL.md, except the repository
 *  root. A root-level SKILL.md is a repository that IS a skill package, and treating its
 *  root as a skill directory would pull every markdown file in the repo into the surface. */
export function skillDirsOf(paths: Iterable<string>): Set<string> {
  const dirs = new Set<string>();
  for (const p of paths) {
    const m = /^(.+)\/[Ss][Kk][Ii][Ll][Ll]\.md$/.exec(p);
    if (m) dirs.add(m[1]);
  }
  return dirs;
}

/** A markdown file inside a skill directory, other than a SKILL.md. SKILL.md is the entry
 *  point the agent loads; these are the reference files it points at and the agent reads
 *  on demand, so they carry the same trust. 515 of them sat beside 383 SKILL.md files in
 *  the 2026-09-24 corpus, more than half the text a skill can hand to an agent. */
export function isSkillSupportFile(path: string, skillDirs: ReadonlySet<string>): boolean {
  if (!path.endsWith('.md') || /(^|\/)[Ss][Kk][Ii][Ll][Ll]\.md$/.test(path)) return false;
  for (let d = path.lastIndexOf('/'); d > 0; d = path.lastIndexOf('/', d - 1)) {
    if (skillDirs.has(path.slice(0, d))) return true;
  }
  return false;
}

/** ONE answer to "is this an instruction file". `skillDirs` must come from skillDirsOf
 *  over the same tree: a skill's supporting files are instructions only by virtue of the
 *  SKILL.md beside them, so this cannot be decided from one path alone. */
export function isInstructionFile(path: string, skillDirs: ReadonlySet<string>): boolean {
  return INSTRUCTION_FILE_RE.test(path) || isSkillSupportFile(path, skillDirs);
}

// Prompt-override / role-impersonation directives. The classic phrases only — no bare
// "system:" (too FP-prone in docs).
const OVERRIDE_RE =
  /ignore\s+(all\s+)?(previous|prior|the\s+above)\s+(instructions|prompts?|rules)|disregard\s+(the\s+|your\s+)?(system\s+)?(prompt|instructions|rules)|forget\s+(everything|all\s+(previous|prior))|you\s+are\s+now\s+(a|an|the)\b|<\/?system>/i;

// ── Tier 2: dangerous sink WITH agent-directive framing → medium ───────────────
// Remote-exec (fetch-and-obey). `| python3 -m json.tool` pretty-prints the fetched bytes,
// it does not execute them (2 of the 12 skill-corpus false positives, 2026-09-22).
const FETCH_OBEY_RE =
  /\b(curl|wget|iwr|invoke-webrequest)\b[^\n|]*\|\s*(bash|sh|zsh|python3?(?!\s+-m\s+json\.tool\b)|node|iex)\b|\b(curl|wget)\b[^\n]*&&[^\n]*\b(bash|sh)\b/i;
// Credential-file access.
const SECRET_PATH_RE =
  /~\/\.aws\/credentials|~\/\.ssh\/id_[a-z]+|~\/\.config\/gh\/hosts|read\s+the\s+(token|secret|api[_ ]?key|password)\s+(in|from)\s+[.`'"]?\.?env/i;
// Exfil to an external endpoint. "Send the user to https://…" moves a person, not data
// (2 of the 12 skill-corpus false positives, 2026-09-22).
const EXFIL_RE =
  /\b(post|send|upload|exfiltrate|forward)\b(?!\s+(the\s+|your\s+)?(users?|them|him|her|people|visitors?|customers?|readers?)\b)[^\n]{0,40}\b(to|at)\b[^\n]{0,50}(https?:\/\/|webhook|hook\.[a-z])/i;

// A human-facing section (install/dev docs) — a `curl|bash` here is setup guidance for a
// PERSON, not a directive to the agent. Down-weights Tier-2 sinks.
// The keyword may sit anywhere in the heading: "### Standalone installer", and a
// `# Shell script (installs to …)` comment inside a fence that the line scan takes for a
// heading (2 of the 12 skill-corpus false positives, 2026-09-22).
const HUMAN_SECTION_RE =
  /^#+\s.*\b((?:re-?|un)?install(ation|ers?|ing|s)?|setup|set ?up|getting started|quick ?start|contributing|contribution|development|dev setup|build|prerequisites|requirements|usage)\b/i;

// A safety/negation clause ("never read ~/.aws/…", "do NOT curl | bash") — the presence
// of the sink here is a GUARDRAIL, not a directive. Prevents flagging a repo for its own
// safety instructions (the G-c lesson, applied to prose).
const NEGATION_RE = /\b(never|do not|don'?t|avoid|must not|should not|no need to|refuse to)\b/i;

function isNegated(text: string, idx: number): boolean {
  return NEGATION_RE.test(text.slice(Math.max(0, idx - 40), idx));
}

// A sink or override QUOTED as an example of what to ignore or refuse. An official Anthropic
// plugin tells the agent to treat strings like "ignore previous instructions" as inert labels,
// and a computer-use skill lists `curl … | bash` among its blocked patterns (2 of the 12
// skill-corpus false positives, 2026-09-22). BOTH conditions are required: the match is the
// whole of a quoted or backticked span, AND the 120 chars before it carry example/refusal
// framing. Quoting alone is not enough — a quoted directive is still a directive to a model.
const EXAMPLE_FRAMING_RE =
  /\b(like|such as|e\.g\.|for example|examples?|including|shaped like|inert|block ?list|blocked|blocks?|patterns?|treat|labels?|strings?|phrases?|reject|flags?|detects?|matches)\b/i;

function isQuotedExample(text: string, idx: number, len: number): boolean {
  const open = text[idx - 1];
  const close = text[idx + len];
  const quoted = (open === '"' || open === "'" || open === '`') && close === open;
  return quoted && EXAMPLE_FRAMING_RE.test(text.slice(Math.max(0, idx - 120), idx));
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
  rule: string,
  severity: Severity,
  title: string,
  signals: string[],
  fix: string,
  path: string
): CiFinding {
  // Every CI-6 signal fires at most once per file, so the rule id alone locates it.
  return {
    check: 'CI-6',
    rule,
    dimension: 'instructions',
    severity,
    title,
    file: path,
    signals,
    fix,
  };
}

/** Analyze one agent instruction file. Returns 0+ findings. Never throws. */
export function analyzeInstructionFile(path: string, content: string): CiFinding[] {
  const findings: CiFinding[] = [];
  const decoded = decodeSuspiciousBase64(content);

  // Tier 1 — structural concealment, classified by legitimacy (A/B/C/D).
  if (TAG_CHARS.test(content))
    findings.push(
      mk(
        'CI-6.unicode-tag-chars',
        'critical',
        'Unicode tag characters in an agent instruction file',
        [
          'contains Unicode tag characters (U+E0000–E007F) — an invisible instruction-smuggling channel with no legitimate use in text',
        ],
        'Remove the tag characters. Instruction files must be plain, reviewable text.',
        path
      )
    );
  if (BIDI_OVERRIDE.test(content))
    findings.push(
      mk(
        'CI-6.bidi-override',
        'critical',
        'Bidirectional override characters in an agent instruction file',
        [
          'contains a bidi override (U+202D/U+202E) — a Trojan-Source technique that visually reorders text so a human reads something different from what the agent parses',
        ],
        'Remove the bidi override characters.',
        path
      )
    );
  else if (BIDI_EMBED_ISOLATE.test(content))
    findings.push(
      mk(
        'CI-6.bidi-formatting',
        'advisory',
        'Bidirectional formatting characters in an agent instruction file',
        [
          'contains bidi embed/isolate characters (U+202A–202C / U+2066–2069) — legitimate in right-to-left text, but confirm they are not being used to hide or reorder instructions',
        ],
        'Confirm the bidi marks are legitimate RTL formatting; remove otherwise.',
        path
      )
    );
  const zw = suspiciousZeroWidth(content);
  if (zw > 0) {
    const revealed = OVERRIDE_RE.test(stripZeroWidth(content)) && !OVERRIDE_RE.test(content);
    findings.push(
      mk(
        'CI-6.zero-width',
        revealed ? 'critical' : 'medium',
        'Zero-width characters splitting text in an agent instruction file',
        [
          revealed
            ? 'a zero-width character conceals a prompt-override directive that only appears once the hidden characters are stripped'
            : 'a zero-width character splits a visible Latin word — a concealment technique (hides text from human review while the agent reads it as contiguous)',
        ],
        'Remove the zero-width characters. Instruction files must be plain, reviewable text.',
        path
      )
    );
  }
  const ovRaw = OVERRIDE_RE.exec(content);
  const ov = ovRaw && !isQuotedExample(content, ovRaw.index, ovRaw[0].length) ? ovRaw : null;
  const ovEnc = !ov ? OVERRIDE_RE.exec(decoded) : null;
  if (ov || ovEnc) {
    const m = (ov || ovEnc)!;
    findings.push(
      mk(
        'CI-6.prompt-override',
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
  if (
    fo &&
    !inHumanSection(content, fo.index) &&
    !isNegated(content, fo.index) &&
    !isQuotedExample(content, fo.index, fo[0].length)
  ) {
    findings.push(
      mk(
        'CI-6.fetch-and-obey',
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
        'CI-6.secret-path',
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
        'CI-6.exfil-directive',
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
