// src/policy/negotiation.ts
// Builds context-specific negotiation messages for AI agents when a tool call is blocked.
// Instead of a generic "blocked" message, the AI gets actionable instructions
// based on WHY it was blocked so it can pivot intelligently.

import { stripTerminalEscapes } from '@node9/policy-engine';

/** What the block was about, from the verdict itself (AuthResult.blockKind /
 *  blockedPath), so the message does not have to guess from the label. */
export interface BlockContext {
  kind?: 'protected-path';
  path?: string;
  /** A person stopped the call and gave the agent an instruction instead
   *  (node9 tail recovery choice [2]); humanReason is that instruction. */
  redirect?: boolean;
  /** The rule's own plain-English sentence (SmartRule.description), for the
   *  line the user reads. */
  ruleDescription?: string;
}

// fw#420: the user line. In the Claude desktop app a hook's systemMessage is
// hidden behind the collapsed tool row, and the agent paraphrases the block in
// its own words, so the user never sees node9 itself. Measured 2026-10-30
// (Claude Code 2.1.280, Opus 5.5): with the message as it was, 0 of 3 replies
// showed node9's words; with one short line first and an instruction to quote
// it, every reply opened with that line. It is a UX layer, not a control: a
// hostile agent can drop it, and audit.log is what always knows.
//
// Unlike the agent-facing label (MSG-3), this line is the user's text: it keeps
// the shield and the "Node9" spelling, and has no em dash (product copy).
const USER_LINE_ICON = '\u{1F6E1}\uFE0F';
export const QUOTE_INSTRUCTION =
  'Start your reply with the line above, exactly as written, on its own line.';
const USER_LINE_PART_MAX = 160;

/** Pictographs and their joiners. Labels carry them for the dashboard; neither
 *  the agent's text (MSG-3) nor a quoted sentence wants them. */
const PICTOGRAPHS = /[\p{Extended_Pictographic}\u200D\uFE0F]/gu;

/** One line: no terminal escapes or control characters (the engine's
 *  stripTerminalEscapes, shared with the terminal and the logs), no em dash,
 *  single spaces. Paths, rule
 *  sentences and reasons come from config or from the agent's own arguments,
 *  so a newline in them must not start a second "instruction". */
function oneLine(text: string): string {
  return stripTerminalEscapes(text)
    .replace(/\s*\u2014\s*/g, ', ')
    .replace(/\s+/g, ' ')
    .trim();
}

function bounded(text: string, max = USER_LINE_PART_MAX): string {
  return text.length > max ? `${text.slice(0, max - 3).trimEnd()}...` : text;
}

/** A sentence for the user line: one line, no closing period, bounded. */
export function userLinePart(text: string): string {
  return bounded(oneLine(text).replace(/[.\s]+$/, ''));
}

/** A path or other value for the user line, in backticks so it reads as data
 *  the agent supplied, not as node9's words. Dots are kept: ".." is a path. */
function userLineValue(text: string, max = 80): string {
  const v = bounded(oneLine(text).replace(/`/g, "'"), max);
  return v ? `\`${v}\`` : '';
}

/** The user line of a block message, or undefined when it has none (a
 *  person's redirect carries only the agent's instruction). */
export function userLineOf(message: string): string | undefined {
  const first = message.split('\n', 1)[0];
  return first.startsWith(USER_LINE_ICON) ? first : undefined;
}

/** The message with the user line and the quote instruction on top. The
 *  agent instructions that follow are unchanged. */
function withUserLine(line: string, body: string): string {
  return `${USER_LINE_ICON} ${line}\n${QUOTE_INSTRUCTION}\n${body}`;
}

/** "Node9 blocked: <what>", from the rule's sentence when there is one, else
 *  from the caller's fallback. */
function blockedLine(context: BlockContext | undefined, fallback: string): string {
  return `Node9 blocked: ${ruleWhat(context?.ruleDescription) || fallback}`;
}

/** The first sentence of a text, unbounded and without emoji. A sentence ends
 *  at . ! or ? followed by a capital, so "e.g. ~/.bashrc" stays whole. */
function firstSentence(text: string): string {
  const plain = oneLine(text.replace(PICTOGRAPHS, ''));
  return plain.split(/(?<=[.!?])\s+(?=[A-Z])/)[0] ?? plain;
}

const IS_BLOCKED_BY = /^(.+?) (?:is|are) blocked by (.+?)\.?$/i;
const IS_BLOCKED = /^(.+?) (?:is|are) blocked\.?$/i;
const COMMA_BLOCKED_BY = /^(.+?), blocked by (.+?)\.?$/i;

/** What a rule stops, from its sentence, so the line does not read "Node9
 *  blocked: reading .env files is blocked by project-jail shield". The builtin
 *  shapes become "Reading .env files (project-jail shield)"; any other
 *  sentence, a user's own rule included, is kept as written. */
function ruleWhat(description: string | undefined): string {
  if (!description) return '';
  const s = firstSentence(description);
  const by = s.match(IS_BLOCKED_BY) ?? s.match(COMMA_BLOCKED_BY);
  if (by) return userLinePart(`${by[1]} (${by[2]})`);
  const bare = s.match(IS_BLOCKED);
  return userLinePart(bare ? bare[1] : s);
}

/** The reason's first sentence for the generic line (an egress block's reason
 *  names the address and why), without a leading "Blocked:" or "Node9:" that
 *  the line already says. A bare 'Node9 blocked "Bash".' adds nothing: ''. */
function reasonSentence(reason: string | undefined): string {
  if (!reason) return '';
  const s = firstSentence(reason)
    .replace(/^node9\b\s*:?\s*/i, '')
    .replace(/^blocked\b\s*:?\s*/i, '');
  if (/^("[^"]*")?\.?$/.test(s)) return '';
  return userLinePart(s);
}

/** "cors-utils is a known malicious package (MAL-2025-5493)" from the package
 *  check's reason ('Known malicious package: npm package "cors-utils@0.0.1"
 *  (MAL-...); ...'), every package it names, or '' when it has no such name. */
function maliciousPackageLine(reason: string | undefined): string {
  if (!reason) return '';
  const names = [...reason.matchAll(/"([^"]+)"/g)].map((m) => {
    const spec = m[1];
    const at = spec.lastIndexOf('@');
    return at > 0 ? spec.slice(0, at) : spec;
  });
  if (names.length === 0) return '';
  const advisories = [...reason.matchAll(/\b((?:MAL|GHSA|CVE|OSV|PYSEC|RUSTSEC)-[\w-]+)/g)].map(
    (m) => m[1]
  );
  const unique = [...new Set(names)];
  const suffix = advisories.length ? ` (${[...new Set(advisories)].join(', ')})` : '';
  return userLinePart(
    unique.length === 1
      ? `${unique[0]} is a known malicious package${suffix}`
      : `${unique.join(', ')} are known malicious packages${suffix}`
  );
}

export function buildNegotiationMessage(
  blockedByLabel: string,
  isHumanDecision: boolean,
  humanReason?: string,
  recoveryCommand?: string,
  context?: BlockContext
): string {
  if (isHumanDecision && context?.redirect && humanReason) {
    return `NODE9: The user stopped this action and gave you an instruction.
INSTRUCTION FROM THE USER: ${humanReason}
INSTRUCTIONS:
- Follow the user's instruction above.
- Retry the original action only if the instruction says you may.`;
  }

  if (isHumanDecision) {
    return withUserLine(
      'Node9: you blocked this action',
      `NODE9: The human user rejected this action.
REASON: ${humanReason || 'No specific reason provided.'}
INSTRUCTIONS:
- Do NOT retry this exact command.
- Acknowledge the block to the user and ask if there is an alternative approach.
- If you believe this action is critical, explain your reasoning and ask them to run "node9 pause 15m" to proceed.`
    );
  }

  // MSG-1: a protected FILE, before any label branch. A sensitive-path hit
  // shares the DLP label with a real secret, so the label branch below told the
  // agent "a sensitive credential was found in your tool call arguments ...
  // rotate it immediately" for a `Read .env`, and the agent told the user node9
  // had misfired. Nothing was in the arguments but a path, and nothing was read.
  if (context?.kind === 'protected-path') {
    // Operation-neutral: the same rules block reads, writes, edits and deletes.
    const subject = context.path ? `${context.path} is a protected file` : 'This file is protected';
    const shown = context.path ? userLineValue(context.path) : '';
    const line = shown
      ? `Node9 blocked access to ${shown} (protected file)`
      : 'Node9 blocked access to a protected file';
    return withUserLine(
      line,
      `NODE9: Blocked. ${subject}, and node9 stopped this call to it. The call did not run, so nothing was exposed.
INSTRUCTIONS:
- Do NOT retry, and do NOT reach the file another way (cat, grep, a copy, a script, a redirect).
- If this step needs that file, ask the user to provide what you need or to do the step themselves.
- Tell the user node9 protected this file, then ask how to proceed.`
    );
  }

  const label = blockedByLabel.toLowerCase();

  if (
    label.includes('dlp') ||
    label.includes('secret detected') ||
    label.includes('credential review')
  ) {
    return withUserLine(
      'Node9 blocked this command: it contains a secret',
      `NODE9 SECURITY ALERT: A sensitive credential (API key, token, or private key) was found in your tool call arguments.
CRITICAL INSTRUCTION: Do NOT retry this action.
REQUIRED ACTIONS:
1. Remove the hardcoded credential from your command or code.
2. Use an environment variable or a dedicated secrets manager instead.
3. Treat the leaked credential as compromised and rotate it immediately.
Do NOT attempt to bypass this check or pass the credential through another tool.
- Tell the user node9 blocked this and why, then ask how to proceed.`
    );
  }

  if (label.includes('package check')) {
    // The reason names the package and the advisory id (OSV MAL-…); the agent
    // needs both to tell the user what was stopped and to pick another package.
    const pkg = maliciousPackageLine(humanReason);
    return withUserLine(
      pkg ? `Node9 blocked: ${pkg}` : 'Node9 blocked: this package is known to be malicious',
      `NODE9: Blocked — ${humanReason || 'a package in this command is known to be malicious.'}
INSTRUCTIONS:
- Do NOT install this package, and do NOT fetch it another way (a different package manager, a tarball URL, a git URL, a mirror).
- If a dependency is needed, suggest a well-known alternative and let the user choose.
- Tell the user node9 blocked this install and name the advisory, then ask how to proceed.`
    );
  }

  if (label.includes('sql safety') && label.includes('delete without where')) {
    return withUserLine(
      blockedLine(context, 'DELETE without WHERE would wipe the whole table'),
      `NODE9: Blocked — DELETE without WHERE clause would wipe the entire table.
INSTRUCTION: Add a WHERE clause to scope the deletion (e.g. WHERE id = <value>).
Do NOT retry without a WHERE clause.
- Tell the user node9 blocked this and why, then ask how to proceed.`
    );
  }

  if (label.includes('sql safety') && label.includes('update without where')) {
    return withUserLine(
      blockedLine(context, 'UPDATE without WHERE would change every row'),
      `NODE9: Blocked — UPDATE without WHERE clause would update every row.
INSTRUCTION: Add a WHERE clause to scope the update (e.g. WHERE id = <value>).
Do NOT retry without a WHERE clause.
- Tell the user node9 blocked this and why, then ask how to proceed.`
    );
  }

  if (label.includes('dangerous word')) {
    const match = blockedByLabel.match(/dangerous word: "([^"]+)"/i);
    const word = match?.[1] ?? 'a dangerous keyword';
    return withUserLine(
      blockedLine(context, `the command contains ${userLineValue(word)}`),
      `NODE9: Blocked — command contains forbidden keyword "${word}".
INSTRUCTION: Do NOT use "${word}". Use a non-destructive alternative.
Do NOT attempt to bypass this with shell tricks or aliases — it will be blocked again.
- Tell the user node9 blocked this and why, then ask how to proceed.`
    );
  }

  if (label.includes('path blocked') || label.includes('sandbox')) {
    return withUserLine(
      blockedLine(context, 'this path is outside the allowed sandbox'),
      `NODE9: Blocked — operation targets a path outside the allowed sandbox.
INSTRUCTION: Move your output to an allowed directory such as /tmp/ or the project directory.
Do NOT retry on the same path.
- Tell the user node9 blocked this and why, then ask how to proceed.`
    );
  }

  if (label.includes('inline execution')) {
    return withUserLine(
      blockedLine(context, 'inline code execution is not allowed'),
      `NODE9: Blocked — inline code execution (e.g. bash -c "...") is not allowed.
INSTRUCTION: Use individual tool calls instead of embedding code in a shell string.
- Tell the user node9 blocked this and why, then ask how to proceed.`
    );
  }

  // The catch-all's label keeps its old wording ("Strict Mode Active"): audit
  // rows and dashboards key on it. The level is Block all.
  if (label.includes('strict mode')) {
    return withUserLine(
      'Node9: the Block all level is on, so every action needs your approval',
      `NODE9: Blocked — the Block all level is on. All tool calls require explicit human approval.
INSTRUCTION: Inform the user this action is pending approval. Wait for them to approve via the dashboard or run "node9 pause".`
    );
  }

  if (label.includes('rule') && label.includes('default block')) {
    const match = blockedByLabel.match(/rule "([^"]+)"/i);
    const rule = match?.[1] ?? 'a policy rule';
    return withUserLine(
      blockedLine(context, `${userLineValue(rule)} is not allowed by policy`),
      `NODE9: Blocked — action "${rule}" is forbidden by security policy.
INSTRUCTION: Do NOT use "${rule}". Find a read-only or non-destructive alternative.
Do NOT attempt to bypass this rule.
- Tell the user node9 blocked this and why, then ask how to proceed.`
    );
  }

  // Generic fallback. A timed-out approval lands here too (its label names the
  // timer, not a rule); the user line says so instead of "[Approval Timeout]".
  const timedOut = label.includes('approval timeout');
  const rule = ruleWhat(context?.ruleDescription);
  let line: string;
  if (timedOut) {
    line = rule
      ? `Node9 blocked: no one approved this in time (${rule.replace(/ \(([^()]+)\)$/, ', $1')})`
      : 'Node9 blocked: no one approved this in time';
  } else if (rule) {
    line = `Node9 blocked: ${rule}`;
  } else {
    const why = reasonSentence(humanReason);
    line = why
      ? `Node9 blocked: ${why}`
      : `Node9 blocked this action (${userLinePart(agentFacingLabel(blockedByLabel))})`;
  }
  const recovery = recoveryCommand
    ? `\nREQUIRED ACTION: Run \`${recoveryCommand}\` first, then retry your original command.`
    : '\n- Pivot to a non-destructive or read-only alternative.';
  return withUserLine(
    line,
    `NODE9: Action blocked by security policy [${agentFacingLabel(blockedByLabel)}].
INSTRUCTIONS:
- Do NOT retry this exact command or attempt to bypass the rule.${recovery}
- Inform the user which security rule was triggered and ask how to proceed.`
  );
}

// Builds the prompt text for an inline "ask" (review verdict routed to the
// agent's native approve/deny prompt). Unlike buildNegotiationMessage this is
// REQUEST-framed, not block-framed: node9 is asking the user to approve, not
// telling the agent it was blocked. Keep it short — it renders inside the
// agent's permission prompt.
export function buildReviewMessage(
  blockedByLabel?: string,
  ruleDescription?: string,
  reason?: string
): string {
  // Priority: the rule's own description (most specific), then the verdict's
  // human sentence (v2: taint / app-permission context — the dev must see WHY
  // in the inline prompt, not just a label), then the bare label.
  const why =
    ruleDescription ||
    (reason && reason !== blockedByLabel ? reason : undefined) ||
    blockedByLabel ||
    'this action needs your review';
  // MSG-2: a rule sentence that already ends in "." produced "backup.. Approve".
  // Add a period only when the sentence has no ending of its own: a question
  // stays a question and an ellipsis stays an ellipsis (/code-review). No
  // regex over the tail, so no backtracking on a long run of spaces.
  const trimmed = why.trimEnd();
  const sentence = /[.!?\u2026]$/.test(trimmed) ? trimmed : `${trimmed}.`;
  return `Node9 flagged this for your review: ${sentence} Approve to proceed, or deny to cancel.`;
}

/** ENG-2: whether a person refused this call, for the message the agent
 *  reads. A verdict that names a rule, a timeout or the organisation's policy
 *  as its decider (`blockedBy`) is never a person, whatever its label says: a
 *  rule named `review-user-data` made the label test below report a human
 *  rejection. The label words remain the signal for a person's own decision
 *  (`User Decision (...)`, blockedBy `local-decision`) and for callers that
 *  pass a bare label. */
export function isHumanDecision(label: string, blockedBy?: string, decidedBy?: string): boolean {
  // The decision record says who decided (approval-card design): only a
  // person is a human decision. The words below are read only for a result
  // without one (a caller that passes a bare label, an older peer).
  if (decidedBy !== undefined) return decidedBy === 'person';
  if (blockedBy !== undefined && blockedBy !== 'local-decision') return false;
  const l = label.toLowerCase();
  return l.includes('user') || l.includes('daemon') || l.includes('decision');
}

/** MSG-3: a label as the agent reads it. Labels carry emoji and the
 *  "Node9" spelling for the dashboard and the developer's terminal, which key
 *  on the exact string; agent-facing text has no emoji and names the product
 *  "node9". */
export function agentFacingLabel(label: string): string {
  const plain = label
    .replace(PICTOGRAPHS, '')
    .replace(/\bNode9\b/g, 'node9')
    .replace(/\s+/g, ' ')
    .trim();
  return plain || 'Security Policy';
}

const BLOCKED_BY = ' is blocked by ';
const DASH_BLOCKED_BY = ' \u2014 blocked by ';
const SHIELD = ' shield';

/** MSG-5: a builtin shield's block sentence, for the approval card a softened
 *  block opens. "Reading .env files is blocked by project-jail shield" reads
 *  as a verdict above an Allow button; the card asks instead. Only the two
 *  builtin shapes ending in "<name> shield" are rewritten; any other sentence,
 *  a user's own rule included, is returned unchanged (the card's header
 *  already says the rule is a block). indexOf, not a regex: the sentence can
 *  come from a user's own rule. */
export function asApprovalRequest(description: string): string {
  const is = description.lastIndexOf(BLOCKED_BY);
  if (is > 0) {
    const by = description.slice(is + BLOCKED_BY.length).replace(/\.$/, '');
    if (by.endsWith(SHIELD)) return `${description.slice(0, is)} needs your approval (${by})`;
  }
  const dash = description.lastIndexOf(DASH_BLOCKED_BY);
  if (dash > 0) {
    const by = description.slice(dash + DASH_BLOCKED_BY.length).replace(/\.$/, '');
    if (by.endsWith(SHIELD)) return `${description.slice(0, dash)}. Needs your approval (${by})`;
  }
  return description;
}
