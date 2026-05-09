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
  ReportPeriod,
  SessionForensicAgg,
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

const COL = {
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
  const summary = h.reasons.length > 0 ? h.reasons.join(', ') : 'risk';
  // Hint ("see node9 scan") used to be inlined here but pushed the
  // header past 80 chars and forced 2-line wrapping that destabilised
  // FIXED_PANELS_HEIGHT. The [2] report key in StatusBar already
  // points users where to look.
  return (
    <>
      <Text dimColor>{'  · '}</Text>
      <Text color={color} bold>{`${icon} `}</Text>
      <Text color={color}>{summary}</Text>
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
  | { kind: 'idle'; blastScore: number };

export const NOTIFICATION_HEIGHT = 4;
/** Fixed height for the REPORT panel (see Report() for the row math).
 *  3 columns now (Tools / Shell / Models). Worst case = 6 rows in any
 *  column (1 header + 5 data) + title (1) + 2 borders = 9. */
export const REPORT_PANEL_HEIGHT = 9;
/** Fixed height for the RISK panel ("Live security"). Always exactly
 *  4 content rows (title + dlp/loops/score + forensic + shield-summary)
 *  plus 2 borders = 6. Pinned so the loading→loaded transition for
 *  shieldStatus doesn't shift the layout. */
export const RISK_PANEL_HEIGHT = 6;

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
  return renderIdle(n.blastScore);
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

function renderIdle(blastScore: number): React.ReactNode {
  const scoreColor = blastScore >= 80 ? '#5BF58C' : blastScore >= 50 ? COL.panelHigh : COL.liveOff;
  return (
    <>
      <Text wrap="truncate-end">
        <Text dimColor>✓ no recent alerts · blast </Text>
        <Text bold color={scoreColor}>{`${blastScore}/100`}</Text>
      </Text>
      <Text dimColor>(approvals + recent blocks/loops appear here)</Text>
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
// Risk — DLP/loop/blast summary
// ---------------------------------------------------------------------------

export function Risk(props: {
  agg: AuditAggregates;
  blast: BlastSnapshot;
  shieldStatus: ShieldStatus | null;
  forensicAgg: SessionForensicAgg;
  window: TimeWindow;
}): React.ReactElement {
  // Use the dedicated counters from aggregateAudit. Earlier this
  // panel derived counts by filtering byBlock (top-6 only), which
  // missed any DLP / loop rules that didn't make the top 6 — leading
  // to a misleading "0 loops" when there were really hundreds, just
  // spread across many rule names.
  const dlpHits = props.agg.dlpHits;
  const loopHits = props.agg.loops;
  const scoreColor =
    props.blast.score >= 80 ? '#5BF58C' : props.blast.score >= 50 ? COL.panelHigh : COL.liveOff;
  return (
    <Box
      flexDirection="column"
      borderStyle="round"
      borderColor={COL.panelRisk}
      paddingX={1}
      marginX={1}
      height={RISK_PANEL_HEIGHT}
    >
      <Text>
        <Text color={COL.brand} bold>
          Live security
        </Text>
        <Text dimColor>{`  · ${labelFor(props.window)}`}</Text>
      </Text>
      <Text wrap="truncate-end">
        <Text color={COL.liveOff}>{'🔑 '}</Text>
        <Text bold>{dlpHits}</Text>
        <Text dimColor> DLP · </Text>
        <Text color={COL.panelHigh}>{'🔁 '}</Text>
        <Text bold>{loopHits}</Text>
        <Text dimColor> loops · </Text>
        <Text color={COL.liveOff}>{'🔭 '}</Text>
        <Text bold>{props.blast.paths.length}</Text>
        <Text dimColor> paths · score </Text>
        <Text bold color={scoreColor}>{`${props.blast.score}/100`}</Text>
      </Text>
      {/* Forensic counts since `node9 monitor` opened. Updates within
          ~30s of a finding via the daemon's 'forensic' SSE channel.
          Claude-only — Cursor / Codex don't write JSONL the watermark
          scanner reads from. See doc/roadmap/daemon-redesign.md
          (option A) for multi-agent coverage plans. */}
      <Text wrap="truncate-end">
        <Text bold>{props.forensicAgg.pii}</Text>
        <Text dimColor> pii · </Text>
        <Text bold>{props.forensicAgg.sensitiveFileRead}</Text>
        <Text dimColor> read · </Text>
        <Text bold>{props.forensicAgg.privilegeEscalation}</Text>
        <Text dimColor> priv · </Text>
        <Text bold>{props.forensicAgg.destructiveOp}</Text>
        <Text dimColor> dest · </Text>
        <Text bold>{props.forensicAgg.evalOfRemote}</Text>
        <Text dimColor> eval · </Text>
        <Text bold>{props.forensicAgg.pipeToShell}</Text>
        <Text dimColor> pipe · </Text>
        <Text bold>{props.forensicAgg.longOutputRedacted}</Text>
        <Text dimColor> long (Claude)</Text>
      </Text>
      {/* Single-line shield summary: active vs inactive counts only.
          The full inactive-shield list and the "node9 shield enable"
          call-to-action move to View 2's Coverage section in phase 8.
          Likewise the path list (was rendered here) — V2 Coverage owns
          the detail; V1 keeps just enough context for an at-a-glance
          status check. Always rendered (with `…` placeholder while
          shieldStatus loads) so the panel height stays constant from
          first paint. */}
      <Text wrap="truncate-end">
        <Text color={COL.live}>{'🛡 '}</Text>
        <Text bold>{props.shieldStatus ? props.shieldStatus.active.length : '…'}</Text>
        <Text dimColor> active · </Text>
        <Text bold>{props.shieldStatus ? props.shieldStatus.inactive.length : '…'}</Text>
        <Text dimColor> inactive</Text>
      </Text>
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

// ---------------------------------------------------------------------------
// ReportView — phase-1 stub. Full implementation lands in phases 4-8 (see
// doc/roadmap/monitor-two-view.md). For now: shows the period picker and
// a "coming soon" placeholder for each section so the switcher is visibly
// alive end-to-end.
// ---------------------------------------------------------------------------

export function ReportView(props: { period: ReportPeriod }): React.ReactElement {
  return (
    <Box flexDirection="column" flexGrow={1} paddingX={1}>
      <Box paddingY={1}>
        <Text color={COL.brand} bold>
          REPORT
        </Text>
        <Text dimColor>{`  · period ${props.period}`}</Text>
      </Box>
      <Box flexDirection="column" gap={0}>
        <ReportSectionStub label="Security" hint="leaks · blocks · loops · forensic 90d" />
        <ReportSectionStub label="Activity" hint="top tools · top blocks · daily/hourly" />
        <ReportSectionStub label="Cost" hint="per model · per day · cache hit" />
        <ReportSectionStub label="Coverage" hint="inactive shields · reachable paths" />
      </Box>
      <Box marginTop={1}>
        <Text dimColor>(report sections land in phases 4–8 — press [1] to return to realtime)</Text>
      </Box>
    </Box>
  );
}

function ReportSectionStub(props: { label: string; hint: string }): React.ReactElement {
  return (
    <Box
      borderStyle="round"
      borderColor={COL.textDim}
      paddingX={1}
      marginX={1}
      flexDirection="column"
    >
      <Text>
        <Text bold>{props.label}</Text>
        <Text dimColor>{`  — ${props.hint}`}</Text>
      </Text>
      <Text dimColor>(coming soon)</Text>
    </Box>
  );
}
