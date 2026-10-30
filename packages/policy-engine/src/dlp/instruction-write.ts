// packages/policy-engine/src/dlp/instruction-write.ts
// The content rule of files.agent-instructions (node9Firewall#413, part 4).
//
// A line written into CLAUDE.md, AGENTS.md, a memory file or an agent's
// command is loaded into every later session, so an instruction to hide
// something from the user, to skip approvals or the guard, or to read or
// send a secret persists past the session that wrote it (OWASP ASI06). The
// file is itself the corroboration scanInjection otherwise asks for, so one
// signal is enough here.
//
// Precision first: every pattern below was measured on 338 of our own agent
// files (every CLAUDE.md, AGENTS.md and memory file on the development
// machine, third-party AGENTS.md files included) before it joined, and the
// design records the five lines that still match. The rules that came out of
// that: an action signal needs an IMPERATIVE context (a line start, a list
// item, a sentence end, or always / first / then / please / must / should /
// make sure to), a clause boundary ends the window, a negation in front
// cancels it ("never use --no-verify" is the protective form), a quoted
// mention after a classifying word does not count, and a command inside a
// code span or a fenced block is left to the jail that judges it when it runs.

import { scanViews } from './normalize';
import {
  isMention,
  matchesOutsideMention,
  INJECTION_SIGNALS,
  type InjectionMatch,
  type Signal as InjectionSignal,
} from './injection';

/** The imperative context an action signal needs in front of its verb. */
const IMPERATIVE = String.raw`(?:^[ \t]*(?:[-*>]|\d+[.)])?[ \t]*|[.!?:;\n][ \t]*|\b(?:always|first|then|also|please|and|must|should|need to|make sure to|remember to|be sure to|you (?:must|should|will|can))[ \t]+)`;

/** What a secret verb must aim at: a credential path, or a determiner and a credential noun. */
const SECRET_TARGET = String.raw`(?:\.env\b(?!\.(?:example|sample|template))|~?/?\.ssh\b|id_rsa\b|id_ed25519\b|\.aws/credentials|\.netrc\b|\.npmrc\b|credentials\.json|(?:the|your|all|any|every|its|their|our|my)\s+(?:\w+[ \t]+){0,2}(?:api[_ -]?keys?|access tokens?|auth tokens?|tokens?|passwords?|credentials|private keys?|secrets?)\b)`;

const GUARD = String.raw`(?:node9|firewall|(?:pre-commit |git |safety |security )?hooks?|guard(?:rails?)?s?|(?:approval|review|permission|confirmation) (?:gate|prompt|step|check|flow)s?|all (?:checks|guardrails|hooks|safeguards)|safety checks|security checks|safeguards|shields?|audit(?:ing| log)?)`;

interface Signal {
  name: string;
  any: RegExp[];
  /** A negation within 24 characters before the match cancels it. */
  negatable: boolean;
  /** Not read inside a code span or a fenced block. */
  skipCode: boolean;
}

const SIGNALS: Signal[] = [
  {
    name: 'hide-from-user',
    negatable: true,
    skipCode: false,
    any: [
      /\b(do not|don'?t|never|without|avoid)\b[^.!?;:\n]{0,30}\b(tell|telling|inform|informing|mention|mentioning|show|showing|notify|notifying|alert|alerting|disclose|disclosing|reveal|revealing|surface|surfacing)\b[^.!?;:\n]{0,20}\b(the )?(user|human|developer|owner|operator|anyone|them)\b/i,
      /\b(do not|don'?t|never|without|avoid)\b[^.!?;:\n]{0,30}\breport(?:ing)?\b[^.!?;:\n]{0,8}\b(this|it|that|these|them|any of this)\b[^.!?;:\n]{0,8}\bto\b[^.!?;:\n]{0,12}\b(the )?(user|human|developer|owner|operator|anyone)\b/i,
      /\bkeep (this|it|that|these) (from|hidden|secret|quiet|private)\b[^.!?;:\n]{0,20}\b(the )?(user|human|developer|owner|operator|anyone)\b/i,
      /\b(do not|don'?t|never)\b[^.!?;:\n]{0,12}\b(log|record|audit)\b[^.!?;:\n]{0,12}\b(this|it|these|that|any of this|what you did)\b/i,
      new RegExp(
        IMPERATIVE +
          String.raw`(?:hide|conceal)[ \t]+(?:this|it|that|these|the (?:change|changes|file|files|commit|commits|command|commands|output|edit|edits))\b`,
        'im'
      ),
      new RegExp(
        IMPERATIVE +
          String.raw`(?:work|act|operate|proceed|continue|do (?:this|it|that|so))[ \t]+(?:silently|covertly|in secret|secretly|without (?:telling|informing|notifying))\b`,
        'im'
      ),
    ],
  },
  {
    name: 'bypass-approval',
    // "do not ask for approval" is itself the attack, so the first pattern is
    // never cancelled by the negation in front of it; the others are.
    negatable: true,
    skipCode: false,
    any: [
      /\b(do not|don'?t|never|without|skip|avoid|no need to|stop)\b[^.!?;:\n]{0,16}\b(ask|asking|wait|waiting|prompt|prompting|check|checking)\b[^.!?;:\n]{0,12}\b(for (approval|confirmation|permission|consent)|(the |a )?(user|human|developer|owner)('s)? (approval|confirmation|permission|consent)|the (user|human|developer|owner)\b)/i,
      new RegExp(
        IMPERATIVE +
          String.raw`(?:approve|accept|allow)[ \t]+(?:everything|all (?:calls|tools|actions|commands|requests)|every (?:call|tool|action|command|request)|automatically|without (?:asking|review|reading))\b`,
        'im'
      ),
      /\b(enable|turn on|set|use|switch to|always)\b[^.!?;:\n]{0,16}\bauto[- ]?approv/i,
      new RegExp(
        IMPERATIVE +
          String.raw`(?:bypass|circumvent|get around|work around|disable|turn off|switch off|evade|defeat|remove|uninstall|pause)[ \t]+(?:the[ \t]+)?` +
          GUARD +
          String.raw`\b`,
        'im'
      ),
      /\b(use|run|pass|add|commit with|push with|always use|always pass)\b[^.!?;:\n]{0,20}--no-verify\b/i,
      /\b(use|run|start|launch|invoke|always run|always use)\b[^.!?;:\n]{0,24}--dangerously-skip-permissions\b/i,
      /\b(set|use|switch|change|enable)\b[^!?;:\n]{0,30}\bbypassPermissions\b/i,
      new RegExp(
        String.raw`\bignore[ \t]+(?:the[ \t]+)?(?:node9|firewall|(?:pre-commit |git |safety |security )?hooks?|guard(?:rails?)?s?|security (?:rules|checks|warnings|prompts)|safety (?:rules|checks|warnings|prompts)|approval (?:prompts?|requests?)|permission (?:prompts?|requests?)|any (?:warnings?|denials?|blocks?))\b`,
        'i'
      ),
    ],
  },
  {
    name: 'secret-access',
    negatable: true,
    skipCode: true,
    any: [
      new RegExp(
        IMPERATIVE +
          String.raw`(?:read|cat|open|print|echo|dump|include|paste|copy|collect|gather|send|upload|post|email|share|exfiltrate|forward|transmit|fetch|grab|extract|retrieve|insert|embed|attach|load|display|output|reveal|leak)\b[^.!?;\n]{0,30}` +
          SECRET_TARGET,
        'im'
      ),
    ],
  },
];

/**
 * The output scanner's signals, reused: override and fake role as they are;
 * the destination signal narrowed to a real destination (a URL, an e-mail,
 * a host with a known TLD), because an instruction file names paths like
 * `deferred/followups.md` all the time and the output scanner's looser
 * host shape read them as hosts.
 */
const DESTINATION_RE =
  /\b(send|sent|post(?:ed)?|upload(?:ed)?|exfiltrate[sd]?|forward(?:ed|s)?|transmit(?:ted|s)?|shared|submitted|logged|reported|curl|wget|leak(?:ed|s)?|(?<!\b(?:your|my|the|an|a|this|that|our|their|his|her)\s+)email(?:ed|s)?)\b(?:[^.\n!?]|\.(?=\S)){0,40}\b(to|at|with|into)\b(?:[^.\n!?]|\.(?=\S)){0,24}(https?:\/\/|[\w.-]+@[\w.-]+\.[a-z]{2,}|[\w-]+\.(?:com|net|org|io|ai|dev|co|me|sh|host|xyz|app|cloud|info|biz|us|uk|de|ru|cn|site|online|link|click|top)\b)/i;
const REUSED_SIGNALS: InjectionSignal[] = INJECTION_SIGNALS.map((sig) =>
  sig.name === 'action-to-destination'
    ? {
        ...sig,
        // The host-shaped pattern is the one that names a URL; replaced by
        // what it matches, not by its position in the list.
        any: sig.any.map((re) => (re.source.includes('https?:') ? DESTINATION_RE : re)),
      }
    : sig
);

/** The first pattern of bypass-approval is the negative form itself. */
const NEVER_NEGATED = new Set<RegExp>([SIGNALS[1].any[0]]);

const NEGATION_BEFORE =
  /\b(never|do not|don'?t|must not|mustn'?t|should not|shouldn'?t|not allowed to|forbidden to|avoid|without|no|not)\b[^.!?;:\n]{0,24}$/i;

function inCodeSpan(text: string, idx: number): boolean {
  const lineStart = text.lastIndexOf('\n', idx) + 1;
  const ticks = (text.slice(lineStart, idx).match(/`/g) ?? []).length;
  return ticks % 2 === 1;
}

function inFence(text: string, idx: number): boolean {
  const fences = (text.slice(0, idx).match(/^[ \t]*(```|~~~)/gm) ?? []).length;
  return fences % 2 === 1;
}

/** Every match of `re` in `text` that survives the mention, negation and code filters. */
function matches(re: RegExp, text: string, signal: Signal): boolean {
  const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
  let m: RegExpExecArray | null;
  while ((m = g.exec(text)) !== null) {
    if (m[0].length === 0) {
      g.lastIndex = m.index + 1;
      continue;
    }
    const before = text.slice(Math.max(0, m.index - 48), m.index);
    if (isMention(before)) continue;
    if (signal.negatable && !NEVER_NEGATED.has(re) && NEGATION_BEFORE.test(before)) continue;
    if (signal.skipCode && (inCodeSpan(text, m.index) || inFence(text, m.index))) continue;
    return true;
  }
  return false;
}

/**
 * Scan text about to be written into an agent instruction or memory file.
 * The three signals above, plus the override, fake-role and destination
 * signals of scanInjection; any one is a finding. Read on every view
 * (normalised, base64 and hex decoded), as the output scanner does.
 */
export function scanInstructionWrite(text: string): InjectionMatch | null {
  if (!text) return null;
  const matched: string[] = [];
  for (const view of scanViews(text.length > 100_000 ? text.slice(0, 100_000) : text)) {
    for (const sig of SIGNALS) {
      if (matched.includes(sig.name)) continue;
      if (sig.any.some((re) => matches(re, view.text, sig))) matched.push(sig.name);
    }
    for (const sig of REUSED_SIGNALS) {
      if (matched.includes(sig.name)) continue;
      const hit =
        sig.name === 'override-instructions'
          ? sig.any.some((re) => matchesOutsideMention(re, view.text))
          : sig.any.some((re) => re.test(view.text));
      if (hit) matched.push(sig.name);
    }
  }
  if (matched.length === 0) return null;
  return { signals: matched, confidence: matched.length >= 2 ? 'high' : 'medium' };
}
