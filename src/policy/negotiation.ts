// src/policy/negotiation.ts
// Builds context-specific negotiation messages for AI agents when a tool call is blocked.
// Instead of a generic "blocked" message, the AI gets actionable instructions
// based on WHY it was blocked so it can pivot intelligently.

export function buildNegotiationMessage(
  blockedByLabel: string,
  isHumanDecision: boolean,
  humanReason?: string,
  recoveryCommand?: string
): string {
  if (isHumanDecision) {
    return `NODE9: The human user rejected this action.
REASON: ${humanReason || 'No specific reason provided.'}
INSTRUCTIONS:
- Do NOT retry this exact command.
- Acknowledge the block to the user and ask if there is an alternative approach.
- If you believe this action is critical, explain your reasoning and ask them to run "node9 pause 15m" to proceed.`;
  }

  const label = blockedByLabel.toLowerCase();

  if (
    label.includes('dlp') ||
    label.includes('secret detected') ||
    label.includes('credential review')
  ) {
    return `NODE9 SECURITY ALERT: A sensitive credential (API key, token, or private key) was found in your tool call arguments.
CRITICAL INSTRUCTION: Do NOT retry this action.
REQUIRED ACTIONS:
1. Remove the hardcoded credential from your command or code.
2. Use an environment variable or a dedicated secrets manager instead.
3. Treat the leaked credential as compromised and rotate it immediately.
Do NOT attempt to bypass this check or pass the credential through another tool.`;
  }

  if (label.includes('sql safety') && label.includes('delete without where')) {
    return `NODE9: Blocked — DELETE without WHERE clause would wipe the entire table.
INSTRUCTION: Add a WHERE clause to scope the deletion (e.g. WHERE id = <value>).
Do NOT retry without a WHERE clause.`;
  }

  if (label.includes('sql safety') && label.includes('update without where')) {
    return `NODE9: Blocked — UPDATE without WHERE clause would update every row.
INSTRUCTION: Add a WHERE clause to scope the update (e.g. WHERE id = <value>).
Do NOT retry without a WHERE clause.`;
  }

  if (label.includes('dangerous word')) {
    const match = blockedByLabel.match(/dangerous word: "([^"]+)"/i);
    const word = match?.[1] ?? 'a dangerous keyword';
    return `NODE9: Blocked — command contains forbidden keyword "${word}".
INSTRUCTION: Do NOT use "${word}". Use a non-destructive alternative.
Do NOT attempt to bypass this with shell tricks or aliases — it will be blocked again.`;
  }

  if (label.includes('path blocked') || label.includes('sandbox')) {
    return `NODE9: Blocked — operation targets a path outside the allowed sandbox.
INSTRUCTION: Move your output to an allowed directory such as /tmp/ or the project directory.
Do NOT retry on the same path.`;
  }

  if (label.includes('inline execution')) {
    return `NODE9: Blocked — inline code execution (e.g. bash -c "...") is not allowed.
INSTRUCTION: Use individual tool calls instead of embedding code in a shell string.`;
  }

  if (label.includes('strict mode')) {
    return `NODE9: Blocked — strict mode is active. All tool calls require explicit human approval.
INSTRUCTION: Inform the user this action is pending approval. Wait for them to approve via the dashboard or run "node9 pause".`;
  }

  if (label.includes('rule') && label.includes('default block')) {
    const match = blockedByLabel.match(/rule "([^"]+)"/i);
    const rule = match?.[1] ?? 'a policy rule';
    return `NODE9: Blocked — action "${rule}" is forbidden by security policy.
INSTRUCTION: Do NOT use "${rule}". Find a read-only or non-destructive alternative.
Do NOT attempt to bypass this rule.`;
  }

  // Generic fallback
  const recovery = recoveryCommand
    ? `\nREQUIRED ACTION: Run \`${recoveryCommand}\` first, then retry your original command.`
    : '\n- Pivot to a non-destructive or read-only alternative.';
  return `NODE9: Action blocked by security policy [${blockedByLabel}].
INSTRUCTIONS:
- Do NOT retry this exact command or attempt to bypass the rule.${recovery}
- Inform the user which security rule was triggered and ask how to proceed.`;
}

// Builds the prompt text for an inline "ask" (review verdict routed to the
// agent's native approve/deny prompt). Unlike buildNegotiationMessage this is
// REQUEST-framed, not block-framed: node9 is asking the user to approve, not
// telling the agent it was blocked. Keep it short — it renders inside the
// agent's permission prompt.
export function buildReviewMessage(blockedByLabel?: string, ruleDescription?: string): string {
  const why = ruleDescription || blockedByLabel || 'this action needs your review';
  return `Node9 flagged this for your review: ${why}. Approve to proceed, or deny to cancel.`;
}
