// Injected instructions inside an MCP tool DEFINITION (node9Firewall#342,
// add-ons plan phase 4, check C). A definition is text the model reads as
// part of its own instructions, written by whoever wrote the server, before
// any tool has run. That is a different text from a tool RESULT, and it is
// graded differently:
//
//   result      one suspicious phrase is weak evidence (a page that discusses
//               injection); scanInjection asks for two or three signals.
//   definition  a description has no reason to tell the model to hide
//               something from the user or to read a credential file. One
//               such signal is already strong.
//
// Measured 2026-11-27 (docs: addons-phase4-before-install-plan.md, step C0):
// scanInjection alone graded 5 of 6 known tool-poisoning shapes `low` and one
// nothing; with the signals below all 6 are `high`, and none of 670 real tool
// texts is `medium` or `high`. The attack set was used to write the signals,
// so that is a floor for false positives, not a recall figure.

import { scanInjection } from './injection';

export type DefinitionConfidence = 'low' | 'medium' | 'high';

export interface DefinitionMatch {
  /** Signal names only: never text from the definition. */
  signals: string[];
  confidence: DefinitionConfidence;
}

// A file that holds a credential and nothing else: no honest tool
// description tells the model to read one.
const SECRET_PATH =
  /(~\/\.ssh\b|\bid_(rsa|ed25519|ecdsa)\b|\.aws\/credentials|~\/\.aws\b|\.npmrc\b|\.netrc\b|\/etc\/shadow\b|\bssh keys?\b)/;
// A file an honest tool may well read (a dotenv loader, an MCP manager, a
// wallet that signs with a private key), and an attack reads too.
// `.env.example` and friends are templates.
const CONFIG_PATH =
  /((^|[\s"'`/(])\.env(?!\.(example|sample|template|dist)\b)\b|\bmcp\.json\b|~\/\.cursor\b|\.claude\.json\b|\/etc\/passwd\b|\bprivate keys?\b)/;
const READ_VERB =
  '\\b(read|access|open|load|cat|include|pass|send|upload|exfiltrate|copy|fetch)\\b[^.\\n]{0,60}';

const SIGNALS: ReadonlyArray<{ name: string; re: RegExp }> = [
  {
    // Telling the model to keep something from the person it works for.
    name: 'conceal-from-user',
    re: /\b(do not|don'?t|never|must not|should not|without)\s+(?:\w+\s+){0,2}?(mention|tell|notify|inform|alert)\b[^.\n]{0,80}\b(the\s+)?(user|human|operator)\b|\b(do not|don'?t|never|must not)\s+(reveal|mention|disclose)\s+(this|these|the)\s+(instructions?|steps?|rules?|notes?)\b|\b(could|would|will|might)\s+upset\s+the\s+user\b|\bwithout\s+(the\s+user('s)?\s+(knowledge|knowing|consent)|telling\s+the\s+user)\b|\bsilently\s+(send|upload|forward|copy|post|transmit|read|exfiltrate|include|add)\b/i,
  },
  {
    // A verb that takes a file, then a credential file, in one clause.
    name: 'credential-read',
    re: new RegExp(`${READ_VERB}${SECRET_PATH.source}`, 'i'),
  },
  {
    // The same with a file honest tools read too: weak on its own.
    name: 'config-read',
    re: new RegExp(`${READ_VERB}${CONFIG_PATH.source}`, 'i'),
  },
  {
    // Instructions about ANOTHER tool: the shape of tool shadowing.
    name: 'other-tool-redirect',
    re: /\bwhen(ever)?\b[^.\n]{0,80}\b(is|gets)\s+(called|invoked|used)\b[^.\n]{0,160}\b(instead|change the|replace the|redirect|make sure to)\b|\bside effect on the\s+\w+\s+tool\b|\bwhen\s+(using|calling|invoking)\s+(other tools|any other tool|the\s+\w+\s+tool|[a-z]+_[a-z_]+)\b[^.\n]{0,80}\b(always|also|redirect|include|send|change|add)\b|\bbefore\s+(calling|using)\s+any\s+other\s+tool\b/i,
  },
  {
    name: 'fetch-and-run',
    re: /\b(curl|wget|iwr)\b[^\n|]{0,200}\|\s*(bash|sh|zsh|python3?|node)\b/i,
  },
  {
    // "pass its content as the `notes` argument": data carried out in an argument.
    name: 'argument-smuggling',
    re: /\b(pass|include|put|add|send|append)\b[^.\n]{0,60}\b(its\s+)?(content|contents|history|conversation|key|keys|token|credentials?|it)\b[^.\n]{0,40}\b(as|in|into|to)\s+(the\s+)?["'`]?\w+["'`]?\s+(argument|parameter|param|field)\b|\bpass\s+the\s+entire\s+(conversation|chat)\b/i,
  },
  {
    name: 'role-tag',
    re: /<\/?(system|important|instructions?|admin|secret)>|\[(system|admin)\b[^\]\n]{0,30}\]/i,
  },
  {
    // Text a person reviewing the definition does not see: a zero-width
    // space, word joiner or invisible operator, a bidi embedding or override
    // (the Trojan Source shape), a byte-order mark past the start, a Unicode
    // tag character (the "ASCII smuggling" shape), or an HTML comment.
    // The joiners and direction marks (U+200C-U+200F) are left out: Persian,
    // Hebrew, Arabic and every multi-person emoji need them.
    name: 'hidden-text',
    re: /[\u200b\u202a-\u202e\u2060-\u2064]|(?<!^)\ufeff|[\u{e0000}-\u{e007f}]|<!--[\s\S]{0,400}?-->/u,
  },
  {
    name: 'exfiltration',
    re: /\bexfiltrat(e|ion)\b|\b(send|upload|post|forward|copy)\b[^.\n]{0,60}\bto\s+(an?\s+|the\s+)?attacker/i,
  },
  {
    // Data going out of the machine: what an upload or webhook tool does,
    // and what an exfiltration does. Weak on its own.
    name: 'outbound-transfer',
    re: /\b(send|upload|post|forward)\b[^.\n]{0,60}\b(to|at)\s+(an?\s+|the\s+)?(external|remote|third[- ]party|server|endpoint|webhook)\b/i,
  },
  {
    name: 'guardrail-off',
    re: /\bdisregard\s+(any|all|the)\s+(safety|security)\s+(guidelines?|rules?|checks?|policies|policy)\b/i,
  },
];

/** One of these alone is `high`: no honest description needs it. */
const STRONG = new Set(['conceal-from-user', 'credential-read', 'hidden-text', 'exfiltration']);

/** What honest tools say too (a destination next to an action verb, reading
 *  a .env or mcp.json, sending to a remote server). Alone it is `low`; two
 *  of them are `medium`; with any other signal it is `high`. */
const WEAK = new Set(['action-to-destination', 'config-read', 'outbound-transfer']);

/** A definition longer than this is not scanned past it; the caller decides
 *  what an oversized definition means (the gateway calls it incomplete). */
export const MAX_DEFINITION_CHARS = 100_000;

/**
 * Grade the text of one tool's definition (name, title, description, schema
 * text, annotations, joined by the caller). Null when nothing matched.
 *
 *   high    one strong signal, or two signals of which one is not weak
 *   medium  one signal that is neither strong nor weak, or two weak ones
 *   low     one weak signal ("send a text via https://...", "read the .env
 *           file"), which honest tools say too
 */
export function scanToolDefinitionText(text: string): DefinitionMatch | null {
  if (!text) return null;
  const t = text.length > MAX_DEFINITION_CHARS ? text.slice(0, MAX_DEFINITION_CHARS) : text;
  const signals: string[] = [];
  for (const s of SIGNALS) if (s.re.test(t)) signals.push(s.name);
  // The result detector's own signals count as well (override phrases, a
  // destination next to an action verb); its role marker is `role-tag` here.
  for (const s of scanInjection(t, { untrusted: false })?.signals ?? []) {
    if (s === 'fake-role-marker' && signals.includes('role-tag')) continue;
    if (!signals.includes(s)) signals.push(s);
  }
  if (signals.length === 0) return null;
  const weak = signals.filter((s) => WEAK.has(s)).length;
  const other = signals.length - weak;
  const confidence: DefinitionConfidence =
    signals.some((s) => STRONG.has(s)) || (other >= 1 && signals.length >= 2)
      ? 'high'
      : other === 1 || weak >= 2
        ? 'medium'
        : 'low';
  return { signals, confidence };
}
