// src/tui/dashboard/panels.tsx
//
// All panels for `node9 monitor`, kept in one file for navigability.
// Each panel is a small Ink component reading props passed from App.tsx.

import React from 'react';
import { Box, Text } from 'ink';
import type {
  ActivityEvent,
  AuditAggregates,
  BlastSnapshot,
  CostSnapshot,
  ForensicSseEvent,
  ProtectionSummary,
  SessionActivityAgg,
  SessionForensicAgg,
  SessionShieldsAgg,
  ShieldStatus,
  TimeWindow,
  View,
} from './types.js';
import type { HealthBadge } from './health.js';
import {
  cacheHitRate,
  formatCost,
  formatPct,
  formatTokens,
  localTimeOf,
  shortenModel,
  truncate,
} from './format.js';

export const COL = {
  brand: '#FF8C42', // orange — brand
  live: '#5BF58C', // green — connected status
  liveOff: '#F55B5B', // red — disconnected
  panelLive: '#5B9EF5', // blue — Live panel border
  panelHigh: '#F5C85B', // yellow — High Level panel border
  panelReport: '#5BF5A0', // green — Report panel border
  panelRisk: '#FF6B6B', // red — Risk panel border
  agentClaude: '#5BF5E0', // cyan
  agentGemini: '#5B9EF5', // blue
  agentCodex: '#E05BF5', // magenta
  agentShell: '#F5C85B', // yellow
  textDim: '#888888',
} as const;

// ---------------------------------------------------------------------------
// Header — period tabs + brand title + live indicator
// ---------------------------------------------------------------------------

export function Header(props: {
  connected: boolean;
  lastAgent?: string;
  lastTs?: string;
  health: HealthBadge;
}): React.ReactElement {
  // Phase 2 of two-view restructure: time-window tabs leave the header.
  // Realtime view is "since open"; Report view has its own period picker.
  return (
    <Box flexDirection="row" justifyContent="space-between" paddingX={1}>
      <Box>
        <Text color={COL.brand} bold>
          🛡 node9 dashboard
        </Text>
        <Text>{'   '}</Text>
        <Text color={props.connected ? COL.live : COL.liveOff}>●</Text>
        <Text dimColor>{props.connected ? ' live' : ' offline'}</Text>
        {props.lastAgent ? <Text dimColor>{`  ${props.lastAgent}`}</Text> : null}
      </Box>
      <Box>{renderHealthBadge(props.health)}</Box>
    </Box>
  );
}

function renderHealthBadge(h: HealthBadge): React.ReactNode {
  // Binary secure / at-risk indicator only — the prior multi-reason
  // chips ("5 paths exposed", "5 shields off", score) were retired
  // from the header pending a clearer definition. The new LIVE
  // SECURITY panel surfaces the same signals with proper detail.
  if (h.severity === 'secure') {
    return (
      <>
        <Text dimColor>{'  · '}</Text>
        <Text color={COL.live}>{'✓ secure'}</Text>
      </>
    );
  }
  const icon = h.severity === 'critical' ? '🛑' : '⚠';
  const color = h.severity === 'critical' ? COL.liveOff : COL.panelHigh;
  return (
    <>
      <Text dimColor>{'  · '}</Text>
      <Text color={color} bold>{`${icon} `}</Text>
      <Text color={color}>at risk</Text>
    </>
  );
}

// ---------------------------------------------------------------------------
// HighLevel — the HUD-like strip of counters
// ---------------------------------------------------------------------------

export function HighLevel(props: {
  window: TimeWindow;
  agg: AuditAggregates;
  cost: CostSnapshot | null;
  skillsPinned: number;
  mcpPinned: number;
}): React.ReactElement {
  const { agg, cost } = props;
  const blockColor = agg.block > 0 ? COL.liveOff : COL.textDim;
  return (
    <Box
      flexDirection="column"
      borderStyle="round"
      borderColor={COL.panelHigh}
      paddingX={1}
      marginX={1}
    >
      <Text wrap="truncate-end">
        <Text color={COL.brand} bold>
          HIGH LEVEL
        </Text>
        <Text dimColor>{`  · ${labelFor(props.window)}`}</Text>
      </Text>
      <Text wrap="truncate-end">
        {!cost ? (
          <Text dimColor>{'cost loading…  '}</Text>
        ) : (
          <>
            <Text bold>{formatCost(cost.totalUSD)}</Text>
            <Text dimColor>{' cost · '}</Text>
            <Text bold>{formatTokens(cost.inputTokens + cost.outputTokens)}</Text>
            <Text dimColor>{' tokens · '}</Text>
            <Text bold>{formatPct(cacheHitRate(cost))}</Text>
            <Text dimColor>{' cache  '}</Text>
          </>
        )}
        <Text bold>{agg.allow.toLocaleString()}</Text>
        <Text color="#5BF58C">{' ✓ allow  '}</Text>
        <Text bold color={blockColor}>{`${agg.block} `}</Text>
        <Text color={COL.liveOff}>{'🛑 block  '}</Text>
        <Text bold>{agg.review}</Text>
        <Text color={COL.panelHigh}>{' 🟡 review  '}</Text>
        <Text bold>{agg.total.toLocaleString()}</Text>
        <Text dimColor> events</Text>
      </Text>
      {/* Second line: activity-only metadata. Loops + blast moved
          out — they're security signals, surfaced exclusively in the
          DLP / LOOP / RISK panel below to avoid duplicate numbers. */}
      {/* MCP servers come from ~/.node9/mcp-pins.json (configuration —
          how many servers are pinned/trusted). MCP calls come from
          audit-log entries with mcpServer field set (observed usage in
          the window). They answer different questions; show both. */}
      <Text wrap="truncate-end">
        <Text bold>{agg.sessions}</Text>
        <Text dimColor> sessions · </Text>
        <Text bold>{props.mcpPinned}</Text>
        <Text dimColor>{` MCP (${agg.mcpCalls} calls)  ·  `}</Text>
        <Text bold>{props.skillsPinned}</Text>
        <Text dimColor> skills pinned</Text>
      </Text>
    </Box>
  );
}

function labelFor(w: TimeWindow): string {
  switch (w) {
    case 'now':
      return 'since dashboard opened';
    case '1d':
      return 'last 24 hours';
    case '7d':
      return 'last 7 days';
    case '30d':
      return 'last 30 days';
    case '60d':
      return 'last 60 days';
  }
}

// ---------------------------------------------------------------------------
// NotificationArea — fixed-height alert lane between HIGH LEVEL and
// LIVE. Always rendered (avoids the layout jump that came with the
// older conditional ApprovalCard). Content is computed by App.tsx
// from a priority cascade and passed in as `notification`:
//   1. action-needed (pending approval)   ← orange border, [a/d/t]
//   2. just-acted    (5s flash)           ← outcome-colored border
//   3. recent block  (last 60s)           ← red border
//   4. recent review (last 60s)           ← yellow border
//   5. recent loop   (last 60s)           ← yellow border
//   6. idle                                ← dim gray border
// Fixed height so the rest of the dashboard never shifts when the
// notification swaps in or out.
// ---------------------------------------------------------------------------

export type ApprovalStatus =
  | { kind: 'idle' }
  | { kind: 'sending' }
  | { kind: 'ok'; verdict: 'allow' | 'deny' | 'trust' }
  | { kind: 'error'; message: string };

export type Notification =
  | { kind: 'approval'; event: ActivityEvent; status: ApprovalStatus }
  | { kind: 'resolved'; event: ActivityEvent; outcome: 'allow' | 'deny' | 'trust' }
  | { kind: 'forensic'; category: ForensicSseEvent['category']; sessionId: string; firedAt: number }
  | { kind: 'block'; event: ActivityEvent; ageMs: number }
  | { kind: 'review'; event: ActivityEvent; ageMs: number }
  | { kind: 'loop'; event: ActivityEvent; ageMs: number }
  | { kind: 'idle'; protection: ProtectionSummary };

export const NOTIFICATION_HEIGHT = 4;
/** Fixed height for the REPORT panel (see Report() for the row math).
 *  3 columns now (Tools / Shell / Models). Worst case = 6 rows in any
 *  column (1 header + 5 data) + title (1) + 2 borders = 9. */
export const REPORT_PANEL_HEIGHT = 9;

export function NotificationArea(props: { notification: Notification }): React.ReactElement {
  const { notification } = props;
  const borderColor = (() => {
    switch (notification.kind) {
      case 'approval':
        return COL.brand;
      case 'resolved':
        return notification.outcome === 'allow'
          ? '#5BF58C'
          : notification.outcome === 'deny'
            ? COL.liveOff
            : COL.panelHigh;
      case 'forensic':
        return COL.liveOff;
      case 'block':
        return COL.liveOff;
      case 'review':
      case 'loop':
        return COL.panelHigh;
      case 'idle':
        return COL.textDim;
    }
  })();

  return (
    <Box
      flexDirection="column"
      borderStyle="round"
      borderColor={borderColor}
      paddingX={1}
      marginX={1}
      height={NOTIFICATION_HEIGHT}
    >
      {renderNotificationBody(notification)}
    </Box>
  );
}

function renderNotificationBody(n: Notification): React.ReactNode {
  if (n.kind === 'approval') return renderApproval(n.event, n.status);
  if (n.kind === 'resolved') return renderResolved(n.event, n.outcome);
  if (n.kind === 'forensic') return renderForensic(n.category, n.sessionId);
  // Past-tense labels for retrospective states. Active ones use
  // 'approval' kind (with [a/d/t] keys); these render only AFTER the
  // decision is taken (or hard-blocked) so they're never actionable —
  // labels need to communicate "already handled" so users don't wait
  // for keys that aren't coming.
  if (n.kind === 'block') return renderEventInfo(n.event, '🛑 BLOCKED', COL.liveOff, n.ageMs);
  if (n.kind === 'review') return renderEventInfo(n.event, '🟡 REVIEWED', COL.panelHigh, n.ageMs);
  if (n.kind === 'loop')
    return renderEventInfo(n.event, '🔁 LOOP DETECTED', COL.panelHigh, n.ageMs);
  return renderIdle(n.protection);
}

function renderForensic(
  category: ForensicSseEvent['category'],
  sessionId: string
): React.ReactNode {
  const label = (() => {
    switch (category) {
      case 'privilege-escalation':
        return 'PRIVILEGE ESCALATION';
      case 'destructive-op':
        return 'DESTRUCTIVE OPERATION';
      case 'eval-of-remote':
        return 'EVAL OF REMOTE CONTENT';
      default:
        return category.toUpperCase().replace(/-/g, ' ');
    }
  })();
  const sid = sessionId ? `·${sessionId.slice(0, 8)}` : '';
  return (
    <>
      <Text wrap="truncate-end">
        <Text color={COL.liveOff} bold>{`🛑 CRITICAL  `}</Text>
        <Text bold>{label}</Text>
        <Text dimColor>{`  ${sid}`}</Text>
      </Text>
      <Text dimColor wrap="truncate-end">
        forensic finding · see [2] scan for details (Claude session)
      </Text>
    </>
  );
}

function renderApproval(event: ActivityEvent, status: ApprovalStatus): React.ReactNode {
  if (event.kind !== 'tool') return null;
  const agent = event.agent ? capitalize(event.agent) : 'agent';
  const sid = event.sessionId ? `·${event.sessionId.slice(0, 4)}` : '';
  const subject = `${event.tool}  ${event.preview}`;

  const actionLine = (() => {
    if (status.kind === 'idle') {
      return (
        <Text wrap="truncate-end">
          {event.checkedBy ? (
            <Text
              dimColor
            >{`${event.checkedBy}${event.reason ? ` — ${event.reason}` : ''}   `}</Text>
          ) : null}
          <Text color="#5BF58C">[a]</Text>
          <Text dimColor>llow </Text>
          <Text color={COL.liveOff}>[d]</Text>
          <Text dimColor>eny </Text>
          <Text color={COL.panelHigh}>[t]</Text>
          <Text dimColor>rust </Text>
          <Text dimColor>[Esc]</Text>
        </Text>
      );
    }
    if (status.kind === 'sending') return <Text dimColor>sending decision…</Text>;
    if (status.kind === 'ok') {
      const v = status.verdict;
      const color = v === 'allow' ? '#5BF58C' : v === 'deny' ? COL.liveOff : COL.panelHigh;
      const label = v === 'allow' ? '✓ approved' : v === 'deny' ? '✗ denied' : '★ trusted';
      return <Text color={color}>{label}</Text>;
    }
    return (
      <Text color={COL.liveOff}>{`⚠ failed: ${status.message} (retry [a/d/t] or [Esc])`}</Text>
    );
  })();

  return (
    <>
      <Text wrap="truncate-end">
        <Text color={COL.brand} bold>
          ⚠ APPROVAL
        </Text>
        <Text dimColor>{`  · ${agent}${sid}  `}</Text>
        <Text bold>{subject}</Text>
      </Text>
      {actionLine}
    </>
  );
}

function renderResolved(
  event: ActivityEvent,
  outcome: 'allow' | 'deny' | 'trust'
): React.ReactNode {
  if (event.kind !== 'tool') return null;
  const agent = event.agent ? capitalize(event.agent) : 'agent';
  const subject = `${event.tool}  ${event.preview}`;
  const color = outcome === 'allow' ? '#5BF58C' : outcome === 'deny' ? COL.liveOff : COL.panelHigh;
  const label = outcome === 'allow' ? '✓ approved' : outcome === 'deny' ? '✗ denied' : '★ trusted';
  return (
    <>
      <Text wrap="truncate-end">
        <Text color={color} bold>
          {label}
        </Text>
        <Text dimColor>{`  · ${agent}  `}</Text>
        <Text>{subject}</Text>
      </Text>
      <Text dimColor>(dismissing…)</Text>
    </>
  );
}

function renderEventInfo(
  event: ActivityEvent,
  label: string,
  color: string,
  ageMs: number
): React.ReactNode {
  if (event.kind !== 'tool') return null;
  const ago = ageMs < 1000 ? 'just now' : `${Math.floor(ageMs / 1000)}s ago`;
  const agent = event.agent ? capitalize(event.agent) : 'agent';
  const subject = `${event.tool}  ${event.preview}`;
  return (
    <>
      <Text wrap="truncate-end">
        <Text color={color} bold>
          {label}
        </Text>
        <Text dimColor>{`  · ${agent}  `}</Text>
        <Text>{subject}</Text>
      </Text>
      <Text dimColor wrap="truncate-end">
        {event.checkedBy ? `rule: ${event.checkedBy} · ${ago}` : ago}
      </Text>
    </>
  );
}

function renderIdle(p: ProtectionSummary): React.ReactNode {
  // RISK box — replaces the old "blast 25/100" placeholder. Shows the
  // user where they stand (exposed vs effective) AND gives them the
  // single highest-value action they can take to improve it. The
  // suggestion line drops away when no protective shield is left to
  // enable, or when effective score is already in the safe zone.
  const effectiveColor =
    p.effective >= 80 ? '#5BF58C' : p.effective >= 50 ? COL.panelHigh : COL.liveOff;
  const headlineIcon = p.effective >= 80 ? '✓' : '⚠';
  return (
    <>
      <Text wrap="truncate-end">
        <Text color={effectiveColor} bold>{`${headlineIcon} `}</Text>
        <Text dimColor>exposed </Text>
        <Text bold>{p.exposed}</Text>
        <Text dimColor>{' · protect '}</Text>
        <Text bold color={p.protect > 0 ? '#5BF58C' : undefined}>{`+${p.protect}`}</Text>
        <Text dimColor>{' · effective '}</Text>
        <Text bold color={effectiveColor}>{`${p.effective}/100`}</Text>
      </Text>
      {p.suggestedShield ? (
        <Text wrap="truncate-end">
          <Text dimColor>↑ enable </Text>
          <Text bold>{p.suggestedShield}</Text>
          <Text dimColor>{` → +${p.suggestedBonus}`}</Text>
        </Text>
      ) : (
        <Text dimColor>(approvals + recent blocks/loops appear here)</Text>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// LiveLog — last N SSE events, FIFO. Approval card inlined for review/pending.
// ---------------------------------------------------------------------------

export function LiveLog(props: {
  events: ActivityEvent[];
  errorBanner?: string;
  maxRows: number;
  /** Active filter text. Empty string = no filter. */
  filter: string;
  /** True when the user is actively typing in the filter input. */
  filterInputMode: boolean;
}): React.ReactElement {
  // Fixed-size panel: always render exactly maxRows content rows so
  // the panel height never shifts as events arrive. Real events fill
  // from the bottom (newest last); empty slots above are blank.
  // First slot reserved for the empty-state hint when the buffer is
  // empty so the user gets a one-line explanation without inflating
  // the panel.
  const filtered = applyFilter(props.events, props.filter);
  const visible = filtered.slice(-props.maxRows);
  const padCount = Math.max(0, props.maxRows - visible.length);
  return (
    <Box
      flexDirection="column"
      borderStyle="round"
      borderColor={COL.panelLive}
      paddingX={1}
      marginX={1}
      flexGrow={1}
    >
      <Text wrap="truncate-end">
        <Text color={COL.brand} bold>
          LIVE
        </Text>
        <Text dimColor>{`  · last ${props.maxRows} events`}</Text>
        {props.filter || props.filterInputMode ? (
          <Text>
            <Text dimColor>{'   '}</Text>
            <Text color={COL.panelHigh}>
              {props.filterInputMode ? `🔍 /${props.filter}_` : `🔍 /${props.filter}`}
            </Text>
            <Text dimColor>
              {props.filterInputMode
                ? '   [Enter] apply  [Esc] cancel'
                : `   ${filtered.length}/${props.events.length} matches  [Esc] clear`}
            </Text>
          </Text>
        ) : null}
      </Text>
      {props.errorBanner ? <Text color={COL.liveOff}>{`⚠ ${props.errorBanner}`}</Text> : null}
      {Array.from({ length: padCount }, (_, i) =>
        i === 0 && visible.length === 0 ? (
          <Text key={`pad-${i}`} dimColor>
            {props.filter
              ? `(no events match "${props.filter}" — [Esc] to clear)`
              : '(no activity yet — agent must be running and daemon must be up)'}
          </Text>
        ) : (
          <Text key={`pad-${i}`}> </Text>
        )
      )}
      {visible.map((e) => (
        <ActivityRow key={e.id} event={e} />
      ))}
    </Box>
  );
}

/** Substring match (case-insensitive) on tool, agent, preview, checkedBy.
 *  Matches snapshot rows on hash + summary too. Empty filter passes everything. */
function applyFilter(events: ActivityEvent[], filter: string): ActivityEvent[] {
  if (!filter) return events;
  const needle = filter.toLowerCase();
  return events.filter((e) => {
    if (e.kind === 'snapshot') {
      return e.hash.toLowerCase().includes(needle) || e.summary.toLowerCase().includes(needle);
    }
    if (e.tool.toLowerCase().includes(needle)) return true;
    if (e.agent && e.agent.toLowerCase().includes(needle)) return true;
    if (e.preview.toLowerCase().includes(needle)) return true;
    if (e.checkedBy && e.checkedBy.toLowerCase().includes(needle)) return true;
    if (e.verdict.toLowerCase().includes(needle)) return true;
    return false;
  });
}

function ActivityRow({ event }: { event: ActivityEvent }): React.ReactElement {
  // Local 24-hour time (HH:MM:SS) — converts the daemon's UTC ISO
  // timestamp to the user's wall-clock time. Returns '--:--:--' on
  // malformed input as a defensive placeholder.
  const t = localTimeOf(event.ts);

  // Snapshot rows have a different shape (no agent, no verdict, no
  // command preview) — render them in a distinct one-line format that
  // matches `node9 tail`'s output: `📸 snapshot  <hash>  <summary> · N files`.
  if (event.kind === 'snapshot') {
    const filesSuffix =
      event.fileCount > 0 ? ` · ${event.fileCount} file${event.fileCount === 1 ? '' : 's'}` : '';
    return (
      <Text wrap="truncate-end">
        <Text dimColor>{t} </Text>
        <Text color={COL.agentClaude}>📸 snapshot</Text>
        <Text dimColor>{`  ${event.hash}  `}</Text>
        <Text>{event.summary}</Text>
        <Text dimColor>{filesSuffix}</Text>
      </Text>
    );
  }

  // Truncate agent name so the LIVE column stays aligned even when
  // the daemon emits long agent labels like "Claude Code" or
  // "claude code"; padEnd alone doesn't shrink, only grows.
  // Audit entries from `node9 check` invocations or older versions
  // lack agent metadata entirely — render as blank padding so the
  // column stays aligned without screaming "[?]" at the user.
  const agentLabel = event.agent
    ? `[${truncate(capitalize(event.agent), 8)}]`.padEnd(10)
    : ' '.repeat(10);
  // Loop-detected entries get a distinct icon (and color) so the user
  // can tell "blocked because of a real rule" apart from "blocked by
  // the loop detector" at a glance.
  const isLoop = event.checkedBy === 'loop-detected';
  const verdictIcon = isLoop
    ? '🔁'
    : event.verdict === 'block'
      ? '🛑'
      : event.verdict === 'review'
        ? '🟡'
        : event.verdict === 'allow'
          ? '✓ '
          : '… ';
  const verdictColor = isLoop
    ? COL.panelHigh
    : event.verdict === 'block'
      ? COL.liveOff
      : event.verdict === 'review'
        ? COL.panelHigh
        : event.verdict === 'allow'
          ? '#5BF58C'
          : COL.textDim;
  // Daemon may broadcast agent as 'claude' or 'Claude Code' or
  // 'claude-code' depending on which writer fired. Match on prefix
  // lowercase so the color stays right across all variants.
  const agentLower = (event.agent ?? '').toLowerCase();
  const agentColor = agentLower.startsWith('claude')
    ? COL.agentClaude
    : agentLower.startsWith('gemini')
      ? COL.agentGemini
      : agentLower.startsWith('codex')
        ? COL.agentCodex
        : COL.agentShell;
  // Always exactly 1 row per event. The secondary `└─ rule: reason`
  // line we used to render here broke the LiveLog padding math (which
  // assumes 1 row per visible event) and made the panel grow as
  // reason-bearing events accumulated, pushing the header off-screen.
  // The reason text is still shown in NotificationArea for the latest
  // alerted event; older row reasons live in the audit log.
  return (
    <Text wrap="truncate-end">
      <Text dimColor>{t} </Text>
      <Text color={agentColor}>{agentLabel}</Text>
      <Text> </Text>
      <Text bold>{truncate(event.tool, 14).padEnd(14)}</Text>
      <Text color={verdictColor}>{verdictIcon} </Text>
      <Text dimColor>{event.preview}</Text>
    </Text>
  );
}

function capitalize(s: string): string {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : '';
}

// ---------------------------------------------------------------------------
// Report — Tools + Shell breakdown side by side
// ---------------------------------------------------------------------------

export function Report(props: {
  agg: AuditAggregates;
  cost: CostSnapshot | null;
  window: TimeWindow;
}): React.ReactElement {
  const { agg, cost } = props;
  const maxTool = Math.max(1, ...agg.byTool.map((t) => t.calls));
  // Top-5 shell commands (already produced by aggregateAudit). Restored
  // in phase 2 of the two-view restructure: shell vocabulary is realtime
  // signal ("how is the agent using bash right now"), and Top Blocks
  // moves to View 2's Activity section where it sits alongside daily
  // and per-hour patterns.
  const maxShell = Math.max(1, ...agg.byShell.map((s) => s.count));
  // Top-3 models from cost data. Same data `node9 report` uses.
  const topModels = (cost?.byModel ?? []).slice(0, 3);
  const maxModelCost = Math.max(1, ...topModels.map((m) => m.costUSD));
  return (
    // Fixed height so adding/removing model rows doesn't reflow the rest
    // of the dashboard. Worst case: tools or shell column = 6 rows
    // (1 header + 5 data). Plus title (1) + 2 borders = 9.
    <Box
      flexDirection="column"
      borderStyle="round"
      borderColor={COL.panelReport}
      paddingX={1}
      marginX={1}
      height={REPORT_PANEL_HEIGHT}
    >
      <Text>
        <Text color={COL.brand} bold>
          REPORT
        </Text>
        <Text dimColor>{`  · ${labelFor(props.window)}`}</Text>
      </Text>
      <Box flexDirection="row">
        {/* Tools — top 5 by call count. */}
        <Box flexDirection="column" flexGrow={1}>
          <Text dimColor wrap="truncate-end">
            {'Tools'.padEnd(13) + 'calls'.padStart(6) + 'blk'.padStart(5)}
          </Text>
          {agg.byTool.length === 0 ? (
            <Text dimColor>(no tools)</Text>
          ) : (
            agg.byTool.map((t) => (
              <Text key={t.tool} wrap="truncate-end">
                <Text dimColor>{bar(t.calls, maxTool, 4)}</Text>
                <Text>{` ${truncate(t.tool, 11).padEnd(11)}`}</Text>
                <Text bold>{`${t.calls}`.padStart(5)}</Text>
                <Text color={t.blocked > 0 ? COL.liveOff : COL.textDim}>
                  {`  ${t.blocked}`.padStart(5)}
                </Text>
              </Text>
            ))
          )}
        </Box>
        {/* Shell — top 5 first-token commands. */}
        <Box flexDirection="column" flexGrow={1} marginLeft={2}>
          <Text dimColor wrap="truncate-end">
            {'Shell'.padEnd(13) + 'calls'.padStart(6) + 'blk'.padStart(5)}
          </Text>
          {agg.byShell.length === 0 ? (
            <Text dimColor>(no shell)</Text>
          ) : (
            agg.byShell.map((s) => (
              <Text key={s.cmd} wrap="truncate-end">
                <Text dimColor>{bar(s.count, maxShell, 4)}</Text>
                <Text>{` ${truncate(s.cmd, 11).padEnd(11)}`}</Text>
                <Text bold>{`${s.count}`.padStart(5)}</Text>
                <Text color={s.blocked > 0 ? COL.liveOff : COL.textDim}>
                  {`  ${s.blocked}`.padStart(5)}
                </Text>
              </Text>
            ))
          )}
        </Box>
        {/* Models — top 3 by cost. */}
        <Box flexDirection="column" flexGrow={1} marginLeft={2}>
          <Text dimColor wrap="truncate-end">
            {'Models'.padEnd(15) + 'cost'.padStart(8)}
          </Text>
          {topModels.length === 0 ? (
            <Text dimColor>(cost loading…)</Text>
          ) : (
            topModels.map((m) => (
              <Text key={m.model} wrap="truncate-end">
                <Text dimColor>{bar(m.costUSD, maxModelCost, 4)}</Text>
                <Text>{` ${truncate(shortenModel(m.model), 13).padEnd(13)}`}</Text>
                <Text bold>{formatCost(m.costUSD).padStart(7)}</Text>
              </Text>
            ))
          )}
        </Box>
      </Box>
    </Box>
  );
}

function bar(value: number, max: number, width: number): string {
  if (max <= 0 || width <= 0) return '░'.repeat(width);
  const filled = Math.max(1, Math.round((value / max) * width));
  return '█'.repeat(filled) + '░'.repeat(Math.max(0, width - filled));
}

// ---------------------------------------------------------------------------
// LiveSecurity — vertical "new issues since open" panel for Realtime
//
// Replaces the cramped two-line Risk panel. Shows 9 categorical rows
// sorted by count desc; sources are all live (no history walks):
//   - dlp / loops          → SessionActivityAgg (rule-tagged SSE events)
//   - paths                → blast.paths.length (sync FS snapshot)
//   - pii / read / priv /  → SessionForensicAgg (live ForensicSseEvent
//     dest / eval / pipe /    stream from the daemon's watermark scan)
//     long
//
// Rows with zero counts render dim and stay at the bottom — the
// category list is stable across sessions even when nothing has fired
// in a category yet.
// ---------------------------------------------------------------------------

// Total box height (incl. borders) shared by LIVE SECURITY and LIVE
// ACTIVITY. 2 borders + 1 title + 9 data rows = 12. Bumped from 11
// so the title is no longer clipped off the top — that was producing
// the "since open · N new" overlap on the first data row.
const LIVE_SECURITY_ROWS_HEIGHT = 12;

export function LiveSecurity(props: {
  blast: BlastSnapshot | null;
  forensicAgg: SessionForensicAgg;
  activityAgg: SessionActivityAgg;
}): React.ReactElement {
  // 9 categorical rows — matches the spec you gave: dlp, loop, paths,
  // pii, priv, dest, eval, pipe, long. sensitive-file-read is folded
  // into "priv" / "paths" semantics in practice and was dropping the
  // title off-screen at height=11; keeping it minimal so the title
  // stays visible.
  const rows: Array<{ label: string; count: number }> = [
    { label: 'dlp', count: props.activityAgg.dlp },
    { label: 'loops', count: props.activityAgg.loops },
    { label: 'paths', count: props.blast?.paths.length ?? 0 },
    { label: 'pii', count: props.forensicAgg.pii },
    { label: 'priv', count: props.forensicAgg.privilegeEscalation },
    { label: 'dest', count: props.forensicAgg.destructiveOp },
    { label: 'eval', count: props.forensicAgg.evalOfRemote },
    { label: 'pipe', count: props.forensicAgg.pipeToShell },
    { label: 'long', count: props.forensicAgg.longOutputRedacted },
  ];
  // Sort desc by count; zero rows naturally fall to the bottom.
  rows.sort((a, b) => b.count - a.count);
  const totalIssues = rows.reduce((sum, r) => sum + r.count, 0);
  return (
    <Box
      flexDirection="column"
      borderStyle="round"
      borderColor={totalIssues > 0 ? COL.panelRisk : COL.textDim}
      paddingX={1}
      flexGrow={1}
      flexBasis={0}
      height={LIVE_SECURITY_ROWS_HEIGHT}
    >
      <Text>
        <Text color={COL.brand} bold>
          LIVE SECURITY
        </Text>
      </Text>
      {rows.map((r) => (
        <Text key={r.label} wrap="truncate-end">
          <Text>{r.label.padEnd(10)}</Text>
          <Text bold={r.count > 0} color={r.count > 0 ? undefined : COL.textDim}>
            {`${r.count}`.padStart(4)}
          </Text>
        </Text>
      ))}
    </Box>
  );
}

// ---------------------------------------------------------------------------
// LiveActivity — vertical tools + shell distribution for Realtime
//
// SSE-driven counterpart to the Report panel in [2]. Two stacked
// sections (TOOLS / SHELL) inside one bordered box, each showing the
// top 5 by count. Counts come from SessionActivityAgg, which the App
// updates on every kind:'tool' event — so the panel grows in real time
// without any history walk.
// ---------------------------------------------------------------------------

// Top-N per section. 1 title + 1 TOOLS header + 4 + 1 SHELL header
// + 4 + 2 borders = 13 → doesn't fit in 12. Using 3 per section to
// fit symmetrically inside the same height as LIVE SECURITY.
const LIVE_ACTIVITY_ROWS = 3;

export function LiveActivity(props: { agg: SessionActivityAgg }): React.ReactElement {
  const tools = topNFromMap(props.agg.tools, LIVE_ACTIVITY_ROWS);
  const shell = topNFromMap(props.agg.shell, LIVE_ACTIVITY_ROWS);
  return (
    <Box
      flexDirection="column"
      borderStyle="round"
      borderColor={COL.panelReport}
      paddingX={1}
      flexGrow={1}
      flexBasis={0}
      height={LIVE_SECURITY_ROWS_HEIGHT}
    >
      <Text>
        <Text color={COL.brand} bold>
          LIVE ACTIVITY
        </Text>
      </Text>
      <Text dimColor wrap="truncate-end">
        TOOLS
      </Text>
      {tools.length === 0 ? (
        <Text dimColor>—</Text>
      ) : (
        tools.map((t) => (
          <Text key={t.name} wrap="truncate-end">
            <Text>{truncate(t.name, 10).padEnd(10)}</Text>
            <Text bold>{`${t.count}`.padStart(4)}</Text>
          </Text>
        ))
      )}
      <Text dimColor wrap="truncate-end">
        SHELL
      </Text>
      {shell.length === 0 ? (
        <Text dimColor>—</Text>
      ) : (
        shell.map((s) => (
          <Text key={s.name} wrap="truncate-end">
            <Text>{truncate(s.name, 10).padEnd(10)}</Text>
            <Text bold>{`${s.count}`.padStart(4)}</Text>
          </Text>
        ))
      )}
    </Box>
  );
}

function topNFromMap(
  map: Record<string, number>,
  n: number
): Array<{ name: string; count: number }> {
  return Object.entries(map)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, n);
}

// ---------------------------------------------------------------------------
// Shields — per-shield "is my coverage working" panel for Realtime
//
// Replaces the slim SETUP strip. Active shields render first, sorted
// desc by total fires (blocks + reviews) so the most-active shields
// surface on top. Inactive shields render below with an "off"
// indicator; capped by SHIELDS_INACTIVE_CAP so the panel never grows
// past its allocated height. Any beyond the cap collapse to
// "… N more off".
//
// Data sources (all live, no walks):
//   - shieldStatus.active / .inactive → which shields exist + state
//   - shieldsAgg.byShield[name] → per-shield block/review counts since
//     monitor opened, populated from SSE activity events via
//     applyActivityToShields in data.ts
//
// Built-in detectors (DLP / loops / privesc) don't map to a user
// shield and so don't appear here — their counts live in LIVE
// SECURITY.
// ---------------------------------------------------------------------------

// Total active+inactive rows shown. Title (1) + N rows + 2 borders =
// LIVE_SECURITY_ROWS_HEIGHT (12) → N = 9. Active first (sorted desc
// by total fires), inactive second; overflow collapses to "… N more".
const SHIELDS_MAX_ROWS = 9;

export function Shields(props: {
  shieldStatus: ShieldStatus | null;
  shieldsAgg: SessionShieldsAgg;
}): React.ReactElement {
  const loaded = props.shieldStatus !== null;
  const active = props.shieldStatus?.active ?? [];
  const inactive = props.shieldStatus?.inactive ?? [];
  const activeWithCounts = active
    .map((name) => {
      const counts = props.shieldsAgg.byShield[name] ?? { blocks: 0, reviews: 0 };
      return { name, ...counts, total: counts.blocks + counts.reviews };
    })
    .sort((a, b) => b.total - a.total);
  // Budget: show as many active as fit, then fill with inactive, then
  // collapse the rest as "… N more". Title takes 1 row already.
  const activeShown = activeWithCounts.slice(0, SHIELDS_MAX_ROWS);
  const remainingBudget = Math.max(0, SHIELDS_MAX_ROWS - activeShown.length);
  const inactiveShown = inactive.slice(0, Math.max(0, remainingBudget - 1));
  const overflow =
    activeWithCounts.length - activeShown.length + (inactive.length - inactiveShown.length);
  return (
    <Box
      flexDirection="column"
      borderStyle="round"
      borderColor={COL.textDim}
      paddingX={1}
      flexGrow={1}
      flexBasis={0}
      height={LIVE_SECURITY_ROWS_HEIGHT}
    >
      <Text>
        <Text color={COL.brand} bold>
          SHIELDS
        </Text>
      </Text>
      {!loaded ? (
        <Text dimColor>loading…</Text>
      ) : active.length === 0 && inactive.length === 0 ? (
        <Text dimColor>none</Text>
      ) : (
        <>
          {activeShown.map((row) => {
            const n = row.blocks + row.reviews;
            return (
              <Text key={`a-${row.name}`} wrap="truncate-end">
                <Text>{truncate(row.name, 10).padEnd(10)}</Text>
                <Text bold={n > 0} color={n > 0 ? undefined : COL.textDim}>
                  {`${n}`.padStart(4)}
                </Text>
              </Text>
            );
          })}
          {inactiveShown.map((name) => (
            <Text key={`i-${name}`} wrap="truncate-end">
              <Text dimColor>{truncate(name, 10).padEnd(10)}</Text>
              <Text color={COL.panelHigh}>{' off'}</Text>
            </Text>
          ))}
          {overflow > 0 ? <Text dimColor>{`… ${overflow} more`}</Text> : null}
        </>
      )}
    </Box>
  );
}

// ---------------------------------------------------------------------------
// StatusBar — footer with keypress hints
// ---------------------------------------------------------------------------

export function StatusBar(props: { view: View; lastRefreshAt: number }): React.ReactElement {
  const realtimeActive = props.view === 'realtime';
  const reportActive = props.view === 'report';
  // Local 24-hour time tied to the [r] key. Ticks every keypress so the
  // user gets visible feedback even when audit/cost/blast didn't change.
  const refreshedAt = localTimeOf(props.lastRefreshAt);
  return (
    <Box paddingX={1}>
      <Text color={realtimeActive ? COL.brand : undefined} bold={realtimeActive}>
        {`[1] realtime ${realtimeActive ? '●' : '○'} `}
      </Text>
      <Text color={reportActive ? COL.brand : undefined} bold={reportActive}>
        {`[2] report ${reportActive ? '●' : '○'} `}
      </Text>
      <Text dimColor>· </Text>
      <Text dimColor>{`[r] refresh (${refreshedAt}) `}</Text>
      <Text dimColor>[?] help </Text>
      <Text dimColor>[q] quit</Text>
    </Box>
  );
}

// ReportView lives in src/tui/dashboard/views/report/index.tsx as of phase 3c.
// The phase-1 stub that used to live here was replaced by the proper view
// shell — see views/report/index.tsx for the current implementation.

// ---------------------------------------------------------------------------
// SessionCounters — tiny "Since Open" strip on Realtime
//
// Replaces the old HIGH LEVEL panel which needed ~/.claude/projects walks
// for cost. This is purely SSE-driven — counters live in App.tsx state and
// increment as activity events arrive. Cost is intentionally absent; that
// lives in [2] Report now where the user has accepted "this view loads
// data."
//
// Stays small on purpose: 4 numbers + a label. If it grows, push back —
// the win is that Realtime mounts in milliseconds with zero history walks.
// ---------------------------------------------------------------------------

export function SessionCounters(props: {
  events: number;
  allow: number;
  block: number;
  review: number;
}): React.ReactElement {
  const { events, allow, block, review } = props;
  const blockColor = block > 0 ? COL.liveOff : COL.textDim;
  const reviewColor = review > 0 ? COL.panelHigh : COL.textDim;
  return (
    <Box
      flexDirection="column"
      borderStyle="round"
      borderColor={COL.panelHigh}
      paddingX={1}
      marginX={1}
    >
      <Text wrap="truncate-end">
        <Text color={COL.brand} bold>
          SINCE OPEN
        </Text>
        <Text dimColor>{'  ·  live SSE counter, no history walk'}</Text>
      </Text>
      <Text wrap="truncate-end">
        <Text bold>{events.toLocaleString()}</Text>
        <Text dimColor>{' events  '}</Text>
        <Text bold>{allow.toLocaleString()}</Text>
        <Text color="#5BF58C">{' ✓ allow  '}</Text>
        <Text bold color={blockColor}>{`${block} `}</Text>
        <Text color={COL.liveOff}>{'🛑 block  '}</Text>
        <Text bold color={reviewColor}>{`${review} `}</Text>
        <Text color={COL.panelHigh}>{'🟡 review'}</Text>
      </Text>
    </Box>
  );
}
