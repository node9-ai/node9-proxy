// src/ci-check/scripts.ts
// Scripts the agent will RUN: a hook under `.claude/hooks/` (before every agent action) or a
// script inside a skill directory (when the skill tells the agent to invoke it). Until now the
// scanner graded the instruction that names the script and never opened the script.
//
// Static, per logical line, never executed. Reuses the CI-6 detectors exported from
// instructions.ts and the same inline-parser exclusion, so a script is graded by the SAME laws
// as the prose that invokes it. Comments are NOT skipped in v1: stripping comments across seven
// shell/script dialects is its own project, and a wrong stripper is a bypass — a `# curl | bash`
// in a comment is a false positive we accept and name.

import type { CiFinding, Severity } from './types';
import {
  TAG_CHARS,
  BIDI_OVERRIDE,
  OVERRIDE_RE,
  FETCH_OBEY_RE,
  SECRET_PATH_RE,
  isInlineParser,
  maskPathPlaceholders,
} from './instructions';

/** A script larger than this is not read. It is REPORTED as unread — the third state — never
 *  silently skipped. 64 KiB covers every hook and skill script measured (the largest real
 *  fixture, dartsim/dart's pre-commit guard, is 32 KiB). */
export const MAX_SCRIPT_BYTES = 64 * 1024;

// The other fetch-and-run spellings a shell allows, beyond `curl … | sh`.
const PROCESS_SUBST_RE = /\b(bash|sh|zsh)\s+<\(\s*(curl|wget)\b/;
const EVAL_FETCH_RE = /\beval\s+["']?\$\(\s*(curl|wget)\b/;
const SHELL_C_FETCH_RE = /\b(sh|bash|zsh)\s+-c\s+["']\$\(\s*(curl|wget)\b/;
// Sending a local file somewhere: curl's upload/data-from-file forms, or netcat fed a file.
const CURL_UPLOAD_RE =
  /\bcurl\b[^\n]*\s(?:-d|--data(?:-binary|-raw|-urlencode)?)\s*["']?@|\bcurl\b[^\n]*\s(?:-T|--upload-file)\s+\S/;
const NETCAT_RE = /\b(nc|ncat|netcat)\b[^\n]*<\s*\S/;
// Credential material by its home path, in the spellings a script uses.
const HOME_SECRET_RE = /\$HOME\/\.(aws|ssh|config\/gh)\b|\$\{HOME\}\/\.(aws|ssh|config\/gh)\b/;
// What makes an upload EXFIL rather than a skill doing its job: the payload is sensitive —
// credential material, a system password file, a `.env`, or the environment itself. A
// publishing skill sending `"@$local_file"` to the `$upload_url` its service handed back is
// the skill's purpose (hermes-agent `here-now`, flagged HIGH by the first cut of this rule on
// a repository the manual review had called clean, 2026-09-26).
const SENSITIVE_PAYLOAD_RE =
  /\/etc\/(passwd|shadow)\b|(^|[\s"'@=])\.env\b|\$\(\s*(env|printenv)\b|\bid_(rsa|ed25519|ecdsa|dsa)\b/;
const isSensitive = (text: string) =>
  SECRET_PATH_RE.test(text) || HOME_SECRET_RE.test(text) || SENSITIVE_PAYLOAD_RE.test(text);
// The whole environment sent to a pipe or a file: the command, optionally its flags, then the
// pipe or redirect — nothing else in between, so a Python parameter named `env` followed by a
// union-type `|` (hermes-agent `unbroker/scripts/emailer.py:171`) is not a match. Advisory: it
// is diagnostics far more often than theft, and a redaction step on the same logical line
// makes it fine.
const ENV_DUMP_RE = /^\s*(env|printenv)(\s+-\S+)*\s*(\||>)/;
const REDACTION_RE = /\b(sed|redact|mask)\b|\*\*\*/i;

interface LogicalLine {
  text: string;
  line: number;
  /** Inside a heredoc body: the line is DATA the script emits, not code. */
  emitted: boolean;
}

// An override phrase is a finding only when the script EMITS it — a heredoc body, or an
// echo/printf/cat on the same logical line. The same phrase as a regex, a list entry or a test
// payload is a detector, not an attack: a prompt-injection classifier and its tests produced
// ten HIGH findings in the first full-width run of this rule (Project-K gstack, 2026-09-26).
const EMIT_RE = /\b(echo|printf|cat)\b/;
const HEREDOC_OPEN_RE = /<<-?\s*["']?([A-Za-z_][A-Za-z0-9_]*)["']?/;

/** Join backslash-continued lines so a pipeline split across lines is graded as one
 *  command, report the FIRST physical line number of each, and mark heredoc bodies. */
function logicalLines(content: string): LogicalLine[] {
  const out: LogicalLine[] = [];
  const raw = content.split(/\r?\n/);
  let heredocTag: string | null = null;
  for (let i = 0; i < raw.length; i++) {
    const start = i + 1;
    let text = raw[i];
    if (heredocTag) {
      const done = text.trim() === heredocTag;
      out.push({ text, line: start, emitted: !done });
      if (done) heredocTag = null;
      continue;
    }
    while (/\\$/.test(text) && i + 1 < raw.length) {
      text = text.slice(0, -1) + ' ' + raw[++i];
    }
    out.push({ text, line: start, emitted: false });
    const h = HEREDOC_OPEN_RE.exec(text);
    if (h) heredocTag = h[1];
  }
  return out;
}

/** Analyze one committed script. `rulePrefix` is `CI-1.hook-script` for a hook and
 *  `CI-6.skill-script` for a skill's script: same analyzer, distinct identity, and the check
 *  id follows the prefix so the finding sits with its siblings in the report. Returns 0+
 *  findings, at most one per rule (the first line that matched). Never throws. */
export function analyzeScript(path: string, content: string, rulePrefix: string): CiFinding[] {
  const check = rulePrefix.startsWith('CI-1') ? 'CI-1' : 'CI-6';
  const dimension = check === 'CI-1' ? 'toolRules' : 'instructions';
  const mk = (
    suffix: string,
    severity: Severity,
    title: string,
    signal: string,
    fix: string,
    line?: number
  ): CiFinding => ({
    check,
    rule: `${rulePrefix}.${suffix}`,
    dimension,
    severity,
    title,
    file: path,
    ...(line ? { line } : {}),
    signals: [signal],
    fix,
  });

  if (content.length > MAX_SCRIPT_BYTES) {
    return [
      mk(
        'unscanned-size',
        'advisory',
        'Committed agent script is too large for this scan to read',
        `${content.length} bytes — above the ${MAX_SCRIPT_BYTES}-byte limit; its contents were NOT graded`,
        'Split the script, or review it by hand: everything in it runs with the agent.'
      ),
    ];
  }

  const findings: CiFinding[] = [];
  const seen = new Set<string>();
  const once = (f: CiFinding) => {
    if (!seen.has(f.rule)) {
      seen.add(f.rule);
      findings.push(f);
    }
  };

  if (TAG_CHARS.test(content) || BIDI_OVERRIDE.test(content)) {
    once(
      mk(
        'hidden-chars',
        'critical',
        'Hidden or reordering characters in a committed agent script',
        'contains Unicode tag or bidi-override characters — text a human reads differently from what the shell runs',
        'Remove them. A script the agent runs must be plain, reviewable text.'
      )
    );
  }

  for (const { text, line, emitted } of logicalLines(content)) {
    const fo = FETCH_OBEY_RE.exec(text);
    const remote =
      (fo && !isInlineParser(text, fo)) ||
      PROCESS_SUBST_RE.test(text) ||
      EVAL_FETCH_RE.test(text) ||
      SHELL_C_FETCH_RE.test(text);
    if (remote) {
      once(
        mk(
          'remote-exec',
          'high',
          'Committed agent script fetches and runs remote code',
          `\`${text.trim().slice(0, 100)}\` — whatever that URL serves runs here, for everyone`,
          'Vendor the script and pin it; never pipe a download into a shell from a hook or skill.',
          line
        )
      );
    }
    if ((CURL_UPLOAD_RE.test(text) || NETCAT_RE.test(text)) && isSensitive(text)) {
      once(
        mk(
          'exfil',
          'high',
          'Committed agent script sends a local file to a remote host',
          `\`${text.trim().slice(0, 100)}\` — a file from this machine leaves it`,
          'Remove the upload, or make the destination and the file explicit and reviewed.',
          line
        )
      );
    }
    if (SECRET_PATH_RE.test(text) || HOME_SECRET_RE.test(text)) {
      once(
        mk(
          'secret-read',
          'medium',
          'Committed agent script reads credential material',
          `\`${text.trim().slice(0, 100)}\` — touches a credential file`,
          'Do not read credential files from an agent hook or skill; pass what is needed explicitly.',
          line
        )
      );
    }
    const ov = emitted || EMIT_RE.test(text) ? OVERRIDE_RE.exec(maskPathPlaceholders(text)) : null;
    if (ov) {
      once(
        mk(
          'prompt-override',
          'high',
          'Committed agent script feeds a prompt-override directive to a model',
          `\`${ov[0].slice(0, 60)}\` — an instruction to ignore rules, emitted by a script`,
          'Remove the override text.',
          line
        )
      );
    }
    if (ENV_DUMP_RE.test(text) && !REDACTION_RE.test(text)) {
      once(
        mk(
          'env-dump',
          'advisory',
          'Committed agent script prints the whole environment',
          `\`${text.trim().slice(0, 100)}\` — every variable, tokens included, goes to that pipe or file without redaction`,
          'Filter to the variables you need, or redact values (e.g. `| sed -E "s/(TOKEN|SECRET|KEY)=.*/\\\\1=***/"`).',
          line
        )
      );
    }
  }

  return findings;
}
