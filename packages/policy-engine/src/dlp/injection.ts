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
}

const MAX = 100_000; // mirror the DLP truncation bound

// Output whose content an attacker can influence (a fetched page, a search hit).
const UNTRUSTED_TOOLS =
  /\b(web_?fetch|web_?search|fetch|curl|wget|browser|http_get|read_url|open_url)\b/i;

interface Signal {
  name: string;
  any: RegExp[];
}

const SIGNALS: Signal[] = [
  {
    name: 'override-instructions',
    any: [
      // "ignore/disregard/forget ... (previous|all|the|your) ... instructions/prompt/rules"
      /\b(ignore|disregard|forget)\b[^.!?\n]{0,40}\b(previous|prior|earlier|above|all|the|your)\b[^.!?\n]{0,24}\b(instruction|instructions|prompt|context|rules?|directives?)\b/i,
      /\byou are now\b/i,
      /\bnew instructions?\s*:/i,
      /\bdeveloper mode\b/i,
      /\bignore (the )?system prompt\b/i,
      /\b(do not|don'?t|never)\b[^.!?\n]{0,20}\btell the (user|human)\b/i,
      /\boverride (your|the)\b[^.!?\n]{0,20}\b(instruction|instructions|programming|rules?|guardrails?)\b/i,
    ],
  },
  {
    name: 'fake-role-marker',
    any: [
      /^\s*(system|assistant)\s*:/im, // a line impersonating a conversation turn
      /<\/?system>/i,
      /\[\/?INST\]/i,
      /<\|im_(start|end)\|>/i,
    ],
  },
  {
    name: 'action-to-destination',
    any: [
      // exfil verb + to/at + a url / email / domain
      /\b(send|post|upload|exfiltrate|email|curl|wget|leak)\b[^.\n]{0,40}\b(to|at)\b[^.\n]{0,24}(https?:\/\/|[\w.-]+@[\w.-]+|[\w-]+\.[a-z]{2,})/i,
      /\brun (the )?following (command|code|script)\b/i,
      /\bexecute (this|the following)\b/i,
    ],
  },
];

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

  const matched: string[] = [];
  for (const sig of SIGNALS) {
    if (sig.any.some((re) => re.test(t))) matched.push(sig.name);
  }
  if (matched.length === 0) return null;

  const untrusted = !!ctx.tool && UNTRUSTED_TOOLS.test(ctx.tool);
  const score = matched.length + (untrusted ? 1 : 0);
  const confidence: InjectionConfidence = score >= 3 ? 'high' : score === 2 ? 'medium' : 'low';

  return { signals: untrusted ? [...matched, 'untrusted-origin'] : matched, confidence };
}
