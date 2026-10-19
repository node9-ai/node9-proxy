// src/auth/decision-record.ts
// Who decided an approval card, as ONE record shared by the daemon (which
// stores it on the card) and the hook (which reports it to the agent and the
// audit). Before this record, /wait carried a one-word `source` and every
// reader guessed the rest; each guess was a bug (fw#304 and its reviews).
// Design: docs roadmap/active/approval-card-ownership-code-design.md.

/** Who ended the card. */
export type DecidedBy =
  /** A person answered; `channel` says where. */
  | 'person'
  /** The card's deadline passed. */
  | 'timer'
  /** The organisation: an administrator in Slack or Mission Control, or its policy. */
  | 'cloud'
  /** A rule (evaluate cards only: the daemon checked the call itself). */
  | 'policy'
  /** No approver left: the only channels were local UIs, and they all went away. */
  | 'abandoned';

/** Where a card can be answered. */
export type Channel = 'terminal' | 'monitor' | 'native' | 'cloud';

export const CHANNELS: readonly Channel[] = ['terminal', 'monitor', 'native', 'cloud'];

/** Channels served by the daemon's own clients (node9 tail, node9 monitor). */
export const LOCAL_UI_CHANNELS: ReadonlySet<Channel> = new Set<Channel>(['terminal', 'monitor']);

/** Channels where a person answers on this machine. */
export const PERSON_CHANNELS: ReadonlySet<Channel> = new Set<Channel>([
  'terminal',
  'monitor',
  'native',
]);

/** A standing decision a person made together with this answer. */
export type Standing = 'always-allow' | 'always-deny' | 'trust' | 'trust-recipients';

export interface DecisionRecord {
  decision: 'allow' | 'deny';
  decidedBy: DecidedBy;
  channel?: Channel;
  /** A person's own words to the agent (node9 tail recovery choice [2]). */
  redirect?: string;
  /** What the agent and the audit row show. Set by whoever decided. */
  label: string;
  reason?: string;
  ruleName?: string;
  standing?: Standing;
  /** For `standing: 'trust'`: '30m' | '1h' | '2h'. */
  trustDuration?: string;
  decidedAt: number;
}

/** The card protocol this build speaks. A daemon or hook without it is older. */
export const CARD_PROTOCOL = 2;

// ── Labels ──────────────────────────────────────────────────────────────────
// The person labels keep the strings older releases wrote, because the
// dashboard, the report and saved audit rows key on them.

export const PERSON_LABELS: Record<Exclude<Channel, 'cloud'>, string> = {
  terminal: 'User Decision (Terminal (node9 tail))',
  monitor: 'User Decision (node9 monitor)',
  native: 'User Decision (Native)',
};
export const REDIRECT_LABEL = 'Steered Redirect (Terminal)';
export const TIMER_LABEL = 'Approval Timeout';
export const CLOUD_LABEL = 'Organization Policy (SaaS)';
export const ABANDONED_LABEL = 'No Approver (node9 tail closed)';

export function personRecord(
  channel: Exclude<Channel, 'cloud'>,
  decision: 'allow' | 'deny',
  extra: Partial<Pick<DecisionRecord, 'redirect' | 'reason' | 'standing' | 'trustDuration'>> = {},
  now = Date.now()
): DecisionRecord {
  return {
    decision,
    decidedBy: 'person',
    channel,
    label: extra.redirect ? REDIRECT_LABEL : PERSON_LABELS[channel],
    ...extra,
    decidedAt: now,
  };
}

export function timerRecord(timeoutMs: number, now = Date.now()): DecisionRecord {
  return {
    decision: 'deny',
    decidedBy: 'timer',
    label: TIMER_LABEL,
    reason: `No response within ${Math.round(timeoutMs / 1000)}s: auto-denied by the approval timeout.`,
    decidedAt: now,
  };
}

export function abandonedRecord(now = Date.now()): DecisionRecord {
  return {
    decision: 'deny',
    decidedBy: 'abandoned',
    label: ABANDONED_LABEL,
    reason: 'No approver was left to answer: node9 tail was closed.',
    decidedAt: now,
  };
}

// ── Wire validation ─────────────────────────────────────────────────────────

const DECIDED_BY: ReadonlySet<string> = new Set([
  'person',
  'timer',
  'cloud',
  'policy',
  'abandoned',
]);
const STANDING: ReadonlySet<string> = new Set([
  'always-allow',
  'always-deny',
  'trust',
  'trust-recipients',
]);

function boundedString(v: unknown, max: number): string | undefined {
  return typeof v === 'string' && v.length > 0 ? v.slice(0, max) : undefined;
}

/** A record read from the wire, or null when it is not one. Never throws. */
export function parseDecisionRecord(x: unknown): DecisionRecord | null {
  if (!x || typeof x !== 'object') return null;
  const r = x as Record<string, unknown>;
  if (r.decision !== 'allow' && r.decision !== 'deny') return null;
  if (typeof r.decidedBy !== 'string' || !DECIDED_BY.has(r.decidedBy)) return null;
  const label = boundedString(r.label, 200);
  if (!label) return null;
  const channel =
    typeof r.channel === 'string' && (CHANNELS as readonly string[]).includes(r.channel)
      ? (r.channel as Channel)
      : undefined;
  if (r.decidedBy === 'person' && (!channel || !PERSON_CHANNELS.has(channel))) return null;
  const out: DecisionRecord = {
    decision: r.decision,
    decidedBy: r.decidedBy as DecidedBy,
    label,
    decidedAt: typeof r.decidedAt === 'number' && Number.isFinite(r.decidedAt) ? r.decidedAt : 0,
  };
  if (channel) out.channel = channel;
  const redirect = boundedString(r.redirect, 2000);
  if (redirect) out.redirect = redirect;
  const reason = boundedString(r.reason, 2000);
  if (reason) out.reason = reason;
  const ruleName = boundedString(r.ruleName, 256);
  if (ruleName) out.ruleName = ruleName;
  if (typeof r.standing === 'string' && STANDING.has(r.standing))
    out.standing = r.standing as Standing;
  const trustDuration = boundedString(r.trustDuration, 8);
  if (trustDuration) out.trustDuration = trustDuration;
  return out;
}

// ── Older peers ─────────────────────────────────────────────────────────────

/** The fields a pre-protocol-2 hook reads from GET /wait. */
export interface LegacyWaitBody {
  decision: 'allow' | 'deny' | 'abandoned';
  source?: string;
  reason?: string;
}

/** What an older hook expects for this record on /wait. */
export function legacyWaitFields(record: DecisionRecord): LegacyWaitBody {
  switch (record.decidedBy) {
    case 'person': {
      // Older hooks know terminal, browser, native and terminal-redirect;
      // monitor is a person in the terminal family for them.
      const source = record.redirect
        ? 'terminal-redirect'
        : record.channel === 'native'
          ? 'native'
          : 'terminal';
      const reason = record.redirect ?? record.reason;
      return { decision: record.decision, source, ...(reason && { reason }) };
    }
    case 'timer':
      return {
        decision: record.decision,
        source: 'timeout',
        ...(record.reason && { reason: record.reason }),
      };
    case 'cloud':
    case 'policy':
      return {
        decision: record.decision,
        source: record.decidedBy,
        ...(record.reason && { reason: record.reason }),
      };
    case 'abandoned':
      return { decision: 'abandoned' };
  }
}

/** A record from an older daemon's /wait body, or null when the body names no
 *  decider (an older daemon's failed or unattributed answer). */
export function recordFromLegacyWait(
  body: LegacyWaitBody,
  now = Date.now()
): DecisionRecord | null {
  if (body.decision === 'abandoned') return abandonedRecord(now);
  const decision = body.decision;
  switch (body.source) {
    case 'terminal':
    case 'browser':
      return personRecord('terminal', decision, body.reason ? { reason: body.reason } : {}, now);
    case 'native':
      return personRecord('native', decision, {}, now);
    case 'terminal-redirect':
      return personRecord('terminal', decision, body.reason ? { redirect: body.reason } : {}, now);
    case 'timeout':
      return { ...timerRecord(0, now), ...(body.reason && { reason: body.reason }) };
    case 'cloud':
      return {
        decision,
        decidedBy: 'cloud',
        label: CLOUD_LABEL,
        ...(body.reason && { reason: body.reason }),
        decidedAt: now,
      };
    case 'policy':
      return {
        decision,
        decidedBy: 'policy',
        label: 'Policy',
        ...(body.reason && { reason: body.reason }),
        decidedAt: now,
      };
    default:
      return null;
  }
}
