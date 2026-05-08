// src/tui/dashboard/panels.tsx
//
// All panels for the dashboard spike, kept in one file for navigability.
// Each panel is a small Ink component reading props passed from App.tsx.

import React from 'react';
import { Box, Text } from 'ink';
import type {
  ActivityEvent,
  AuditAggregates,
  BlastSnapshot,
  CostSnapshot,
  TimeWindow,
} from './types.js';
import { TIME_WINDOWS } from './types.js';

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
  window: TimeWindow;
  connected: boolean;
  lastAgent?: string;
  lastTs?: string;
}): React.ReactElement {
  return (
    <Box flexDirection="row" justifyContent="space-between" paddingX={1}>
      <Box>
        {TIME_WINDOWS.map((w, i) => (
          <Text key={w}>
            {i > 0 ? '   ' : ''}
            {w === props.window ? (
              <Text color={COL.brand} bold>{`[ ${w} ]`}</Text>
            ) : (
              <Text dimColor>{w}</Text>
            )}
          </Text>
        ))}
      </Box>
      <Box>
        <Text color={COL.brand} bold>
          🛡 node9 dashboard
        </Text>
        <Text>{'   '}</Text>
        <Text color={props.connected ? COL.live : COL.liveOff}>●</Text>
        <Text dimColor>{props.connected ? ' live' : ' offline'}</Text>
        {props.lastAgent ? <Text dimColor>{`  ${props.lastAgent}`}</Text> : null}
      </Box>
    </Box>
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
      <Text wrap="truncate-end">
        <Text bold>{agg.sessions}</Text>
        <Text dimColor> sessions · </Text>
        <Text bold>{agg.mcpServers}</Text>
        <Text dimColor>{` MCP (${agg.mcpCalls} calls)  ·  `}</Text>
        <Text bold>{props.skillsPinned}</Text>
        <Text dimColor> skills pinned</Text>
      </Text>
    </Box>
  );
}

/** Compact cost format: `$0.42` for small, `$12.40` for normal, `$1.2K` for large. */
function formatCost(usd: number): string {
  if (usd === 0) return '$0';
  if (usd < 1) return `$${usd.toFixed(2)}`;
  if (usd < 100) return `$${usd.toFixed(2)}`;
  if (usd < 10_000) return `$${Math.round(usd).toLocaleString()}`;
  return `$${(usd / 1000).toFixed(1)}K`;
}

/** Compact token format: `1.2K` / `12K` / `1.2M`. */
function formatTokens(n: number): string {
  if (n < 1000) return `${n}`;
  if (n < 1_000_000) return `${(n / 1000).toFixed(n < 10_000 ? 1 : 0)}K`;
  return `${(n / 1_000_000).toFixed(1)}M`;
}

/** Whole-percent format: `94%`. Returns "—" when the input is NaN. */
function formatPct(pct: number): string {
  if (!Number.isFinite(pct)) return '—';
  return `${Math.round(pct)}%`;
}

/** Cache hit rate from a CostSnapshot. Reads / (reads + new input).
 *  Mirrors `node9 report`'s definition so the two surfaces match. */
function cacheHitRate(cost: CostSnapshot): number {
  const denom = cost.cacheReadTokens + cost.inputTokens;
  if (denom <= 0) return 0;
  return (cost.cacheReadTokens / denom) * 100;
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
  | { kind: 'block'; event: ActivityEvent; ageMs: number }
  | { kind: 'review'; event: ActivityEvent; ageMs: number }
  | { kind: 'loop'; event: ActivityEvent; ageMs: number }
  | { kind: 'idle'; blastScore: number };

export const NOTIFICATION_HEIGHT = 4;

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
  if (n.kind === 'block') return renderEventInfo(n.event, '🛑 BLOCKED', COL.liveOff, n.ageMs);
  if (n.kind === 'review') return renderEventInfo(n.event, '🟡 REVIEW', COL.panelHigh, n.ageMs);
  if (n.kind === 'loop') return renderEventInfo(n.event, '🔁 LOOP', COL.panelHigh, n.ageMs);
  return renderIdle(n.blastScore);
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
  // Defensive against unexpected ts shapes: data.ts:normalizeTs already
  // coerces incoming SSE payloads, but keep this row resilient too in
  // case a malformed event slips through.
  const tsStr = typeof event.ts === 'string' ? event.ts : '';
  const t = tsStr.length >= 19 ? tsStr.slice(11, 19) : '--:--:--';

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
  return (
    <Box flexDirection="column">
      <Text wrap="truncate-end">
        <Text dimColor>{t} </Text>
        <Text color={agentColor}>{agentLabel}</Text>
        <Text> </Text>
        <Text bold>{truncate(event.tool, 14).padEnd(14)}</Text>
        <Text color={verdictColor}>{verdictIcon} </Text>
        <Text dimColor>{event.preview}</Text>
      </Text>
      {event.reason ? (
        <Text dimColor wrap="truncate-end">
          {`           └─ ${event.checkedBy ?? 'rule'}: ${event.reason}`}
        </Text>
      ) : null}
    </Box>
  );
}

/** Truncate to width with single-char `…` overflow marker; pad-friendly. */
function truncate(s: string, width: number): string {
  return s.length <= width ? s : s.slice(0, width - 1) + '…';
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
  // Top-3 of each — keeps the right column readable on standard widths.
  const topBlocks = agg.byBlock.slice(0, 3);
  const maxBlock = Math.max(1, ...topBlocks.map((b) => b.count));
  // Top-3 models from cost data (already loaded). Provides per-model
  // cost split that mirrors what `node9 report` shows under "Cost".
  const topModels = (cost?.byModel ?? []).slice(0, 3);
  const maxModelCost = Math.max(1, ...topModels.map((m) => m.costUSD));
  return (
    <Box
      flexDirection="column"
      borderStyle="round"
      borderColor={COL.panelReport}
      paddingX={1}
      marginX={1}
    >
      <Text>
        <Text color={COL.brand} bold>
          REPORT
        </Text>
        <Text dimColor>{`  · ${labelFor(props.window)}`}</Text>
      </Text>
      <Box flexDirection="row">
        <Box flexDirection="column" flexGrow={1}>
          <Text dimColor wrap="truncate-end">
            {'Tools'.padEnd(16) + 'calls'.padStart(7) + 'blocked'.padStart(9)}
          </Text>
          {agg.byTool.length === 0 ? (
            <Text dimColor>(no tools)</Text>
          ) : (
            agg.byTool.map((t) => (
              <Text key={t.tool} wrap="truncate-end">
                <Text dimColor>{bar(t.calls, maxTool, 6)}</Text>
                <Text>{` ${truncate(t.tool, 14).padEnd(14)}`}</Text>
                <Text bold>{`${t.calls}`.padStart(6)}</Text>
                <Text color={t.blocked > 0 ? COL.liveOff : COL.textDim}>
                  {`  ${t.blocked}`.padStart(8)}
                </Text>
              </Text>
            ))
          )}
        </Box>
        <Box flexDirection="column" flexGrow={1} marginLeft={2}>
          {/* Top Blocks: which rules actually fired. Lifted from
              `node9 report` ("Top Blocks" section). Replaces the
              earlier shell-cmd breakdown — security signal beats
              shell-vocabulary trivia. */}
          <Text dimColor wrap="truncate-end">
            {'Top Blocks'.padEnd(20) + 'count'.padStart(8)}
          </Text>
          {topBlocks.length === 0 ? (
            <Text dimColor>(no blocks)</Text>
          ) : (
            topBlocks.map((b) => (
              <Text key={b.rule} wrap="truncate-end">
                <Text dimColor>{bar(b.count, maxBlock, 6)}</Text>
                <Text>{` ${truncate(b.rule, 18).padEnd(18)}`}</Text>
                <Text bold>{`${b.count}`.padStart(6)}</Text>
              </Text>
            ))
          )}
          {/* Models breakdown — per-model cost from cost.byModel. */}
          <Text dimColor wrap="truncate-end">
            {'Models'.padEnd(20) + 'cost'.padStart(8)}
          </Text>
          {topModels.length === 0 ? (
            <Text dimColor>(cost loading…)</Text>
          ) : (
            topModels.map((m) => (
              <Text key={m.model} wrap="truncate-end">
                <Text dimColor>{bar(m.costUSD, maxModelCost, 6)}</Text>
                <Text>{` ${truncate(shortenModel(m.model), 18).padEnd(18)}`}</Text>
                <Text bold>{formatCost(m.costUSD).padStart(6)}</Text>
              </Text>
            ))
          )}
        </Box>
      </Box>
    </Box>
  );
}

/** Strip noise from a model id for compact display:
 *    'claude-opus-4-7'    → 'opus-4-7'
 *    'claude-haiku-4-5-...'→ 'haiku-4-5'
 *    'gpt-5'              → 'gpt-5'
 */
function shortenModel(model: string): string {
  return model.replace(/^claude-/, '').replace(/-2025\d{4}$/, '');
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
    >
      <Text>
        <Text color={COL.brand} bold>
          DLP / LOOP / RISK
        </Text>
        <Text dimColor>{`  · ${labelFor(props.window)}`}</Text>
      </Text>
      <Text wrap="truncate-end">
        <Text color={COL.liveOff}>{'🔑 '}</Text>
        <Text bold>{dlpHits}</Text>
        <Text dimColor> DLP hits · </Text>
        <Text color={COL.panelHigh}>{'🔁 '}</Text>
        <Text bold>{loopHits}</Text>
        <Text dimColor> loops · </Text>
        <Text color={COL.liveOff}>{'🔭 '}</Text>
        <Text bold>{props.blast.paths.length}</Text>
        <Text dimColor> paths · score </Text>
        <Text bold color={scoreColor}>{`${props.blast.score}/100`}</Text>
      </Text>
      {props.blast.paths.length > 0 ? (
        // Inline path list — saves ~4 rows vs one-per-line. Long
        // joins get truncated by truncate-end with `…`; the count
        // above already says how many there are total, so a partial
        // visible list is honest.
        <Text wrap="truncate-end">
          <Text color={COL.liveOff}>{'  ✗ '}</Text>
          <Text>{props.blast.paths.join('  ·  ')}</Text>
        </Text>
      ) : null}
    </Box>
  );
}

// ---------------------------------------------------------------------------
// StatusBar — footer with keypress hints
// ---------------------------------------------------------------------------

export function StatusBar(): React.ReactElement {
  return (
    <Box paddingX={1}>
      <Text dimColor>[Tab] window </Text>
      <Text dimColor>[r] refresh blast/agg </Text>
      <Text dimColor>[?] help </Text>
      <Text dimColor>[q] quit</Text>
    </Box>
  );
}
