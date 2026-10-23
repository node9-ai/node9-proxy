// packages/policy-engine/src/dlp/injection.ts
// Heuristic indirect-prompt-injection detector for TOOL OUTPUT (gap1 v2).
//
// Detects text that tries to manipulate the agent — instruction-override
// phrases, fake role/turn markers, and action→destination directives — and
// combines them with provenance (untrusted tool origin) into a confidence.
//
// DELIBERATELY precision-conscious. Injection detection is fuzzy: a doc *about*
// prompt injection literally contains "ignore previous instructions", and a log
// line can start with "System:". So a SINGLE signal is only `low` — callers act
// on `medium`+, which requires CORROBORATION (another signal or an untrusted
// origin). No model dependency; bounded regexes (ReDoS-safe).

import { scanViews } from './normalize';

export type InjectionConfidence = 'low' | 'medium' | 'high';

export interface InjectionMatch {
  /** Names of the matched signals (+ 'untrusted-origin' when applicable). */
  signals: string[];
  confidence: InjectionConfidence;
}

export interface InjectionContext {
  /** Tool that produced the output. Untrusted origins (web/network) raise
   *  confidence — a fetched page is attacker-influenceable; a local read isn't. */
  tool?: string;
  /** The caller's own answer to "did this output come from outside?" (the
   *  #318 source roles: an unannotated MCP tool, a shell fetch). When set it
   *  decides the booster; when absent the tool-name regex below does. */
  untrusted?: boolean;
}

const MAX = 100_000; // mirror the DLP truncation bound

// Output whose content an attacker can influence (a fetched page, a search hit).
const UNTRUSTED_TOOLS =
  /\b(web_?fetch|web_?search|fetch|curl|wget|browser|http_get|read_url|open_url)\b/i;

interface Signal {
  name: string;
  any: RegExp[];
}

// The general vocabulary of real indirect injections (fw#372 B5), each
// phrasing measured on benign documentation and web pages before it joined:
// prior commands or tasks, "OVERRIDE:", "new directive", a request to reveal
// the system prompt, "SYSTEM NOTE", "[SYSTEM]", "decode ... and execute",
// "call X with url", and the exfiltration verbs forward, transmit, share
// with, log to, submit, whose destination window may run through dots.
const SIGNALS: Signal[] = [
  {
    name: 'override-instructions',
    any: [
      // "ignore/disregard/forget ... (previous|all|the|your) ... instructions/prompt/rules/commands/tasks"
      /\b(ignore|disregard|forget|discard)\b[^.!?\n]{0,40}\b(previous|prior|earlier|above|all|the|your)\b[^.!?\n]{0,24}\b(instruction|instructions|prompt|context|rules?|directives?|commands?|tasks?|guidelines?)\b/i,
      /\byou are now\b/i,
      /\bnew (instructions?|directives?)\s*:/i,
      /\bnew directive\b/i,
      /\boverride\s*:/i,
      /\bsystem note\s*:/i,
      /\bdeveloper mode\b/i,
      /\bignore (the )?system prompt\b/i,
      /\b(reveal|print|show|output|repeat|display|dump)\b[^.!?\n]{0,30}\b(system prompt|hidden instructions|initial instructions|your instructions)\b/i,
      /\b(do not|don'?t|never)\b[^.!?\n]{0,20}\btell the (user|human)\b/i,
      /\boverride (your|the)\b[^.!?\n]{0,20}\b(instruction|instructions|programming|rules?|guardrails?)\b/i,
    ],
  },
  {
    name: 'fake-role-marker',
    any: [
      /^\s*(system|assistant)\s*:/im, // a line impersonating a conversation turn
      /<\/?system>/i,
      /\[\s*system\s*\]/i,
      /\[\/?INST\]/i,
      /<\|im_(start|end)\|>/i,
    ],
  },
  {
    name: 'action-to-destination',
    any: [
      // exfil verb + to/at/with/into + a url / email / domain. "email" after a
      // possessive ("your email", "my email") is the noun, not the verb (X4).
      /\b(send|sent|post(?:ed)?|upload(?:ed)?|exfiltrate[sd]?|forward(?:ed|s)?|transmit(?:ted|s)?|share[sd]?|submit(?:ted|s)?|log(?:ged|s)?|report(?:ed|s)?|curl|wget|leak(?:ed|s)?|(?<!\b(?:your|my|the|an|a|this|that|our|their|his|her)\s+)email(?:ed|s)?)\b[^\n!?]{0,40}\b(to|at|with|into)\b[^\n!?]{0,24}(https?:\/\/|[\w.-]+@[\w.-]+\.[a-z]{2,}|[\w-]+\.[a-z]{2,})/i,
      /\brun (the )?following (command|code|script)\b/i,
      /\bexecute (this|the following)\b/i,
      /\bdecode\b[^.!?\n]{0,40}\b(and|then)\b[^.!?\n]{0,12}\b(execute|run|eval)\b/i,
      /\bcall\b[^.!?\n]{0,30}\b(tool|function|endpoint)\b[^.!?\n]{0,30}\b(url|link|address)\b/i,
    ],
  },
];

/**
 * A phrase that is quoted as an example is a mention, not an instruction
 * (fw#372 X4): "filters match phrases such as 'ignore previous instructions'",
 * 'the pattern "you are now"'. The quote has to be there and a word of
 * quoting or classifying has to precede it, so a quoted injection standing on
 * its own still counts.
 */
const MENTION_QUOTE_RE = /["'`“‘(]\s*$/;
const MENTION_WORD_RE =
  /\b(?:say|says|saying|said|such as|like|pattern|patterns|phrase|phrases|string|strings|text|e\.g\.|example|examples|contains?|containing|detects?|filters?|flags?|blocks?|matches|keywords?|wording|marker|markers)\b/i;

/** Does `re` match `text` somewhere other than inside a quoted mention? */
function matchesOutsideMention(re: RegExp, text: string): boolean {
  const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
  let m: RegExpExecArray | null;
  while ((m = g.exec(text)) !== null) {
    if (m[0].length === 0) {
      g.lastIndex = m.index + 1;
      continue;
    }
    // A mention: the phrase opens with a quote, and a word of quoting or
    // classifying stands within the 48 characters before it.
    const before = text.slice(Math.max(0, m.index - 48), m.index);
    if (!(MENTION_QUOTE_RE.test(before) && MENTION_WORD_RE.test(before))) return true;
  }
  return false;
}

/**
 * Scan tool output for indirect prompt injection. Returns the matched signals +
 * a confidence, or null when nothing matched. Scoring: +1 per matched signal,
 * +1 booster when the origin is an untrusted tool (booster needs ≥1 real
 * signal). score 1 → low (a single phrase, e.g. a doc discussing injection);
 * 2 → medium; 3+ → high. Callers should act only on medium+.
 */
export function scanInjection(text: string, ctx: InjectionContext = {}): InjectionMatch | null {
  if (!text) return null;
  const t = text.length > MAX ? text.slice(0, MAX) : text;

  // The patterns run on the text as written AND on its normalised readings
  // (invisibles stripped, lookalikes folded, base64/hex blobs decoded —
  // normalize.ts), so a hidden phrase counts exactly like a visible one.
  // Hiding does NOT score on its own: an earlier `obfuscated` signal made one
  // encoded phrase actionable by itself, and a README with a base64 example
  // of an injection would have tripped it.
  const matched: string[] = [];
  for (const view of scanViews(t)) {
    for (const sig of SIGNALS) {
      if (matched.includes(sig.name)) continue;
      const hit =
        sig.name === 'override-instructions'
          ? sig.any.some((re) => matchesOutsideMention(re, view.text))
          : sig.any.some((re) => re.test(view.text));
      if (hit) matched.push(sig.name);
    }
  }
  if (matched.length === 0) return null;

  const untrusted = ctx.untrusted ?? (!!ctx.tool && UNTRUSTED_TOOLS.test(ctx.tool));
  const score = matched.length + (untrusted ? 1 : 0);
  const confidence: InjectionConfidence = score >= 3 ? 'high' : score === 2 ? 'medium' : 'low';

  return { signals: untrusted ? [...matched, 'untrusted-origin'] : matched, confidence };
}
