// src/tui/dashboard/panels.tsx
//
// All panels for the dashboard spike, kept in one file for navigability.
// Each panel is a small Ink component reading props passed from App.tsx.

import React from 'react';
import { Box, Text } from 'ink';
import type { ActivityEvent, AuditAggregates, BlastSnapshot, TimeWindow } from './types.js';
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
  blast: BlastSnapshot;
  skillsPinned: number;
}): React.ReactElement {
  const { agg, blast } = props;
  const blastColor =
    blast.score >= 80 ? '#5BF58C' : blast.score >= 50 ? COL.panelHigh : COL.liveOff;
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
        {agg.costUSD > 0 ? (
          <>
            <Text bold>{`$${agg.costUSD.toFixed(2)}`}</Text>
            <Text dimColor> cost </Text>
          </>
        ) : (
          <Text dimColor>{'cost n/a  '}</Text>
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
      <Text wrap="truncate-end">
        <Text bold>{agg.sessions}</Text>
        <Text dimColor> sessions · </Text>
        <Text bold>{agg.mcpServers}</Text>
        <Text dimColor>{` MCP (${agg.mcpCalls} calls)  ·  `}</Text>
        <Text bold>{props.skillsPinned}</Text>
        <Text dimColor> skills · </Text>
        <Text bold color={agg.loops > 0 ? COL.panelHigh : COL.textDim}>{`${agg.loops}`}</Text>
        <Text color={agg.loops > 0 ? COL.panelHigh : COL.textDim}>{' 🔁 loops'}</Text>
        <Text dimColor>{'  ·  blast '}</Text>
        <Text bold color={blastColor}>{`${blast.score}/100`}</Text>
        <Text dimColor>{` (${blast.paths.length} paths)`}</Text>
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
// LiveLog — last N SSE events, FIFO. Approval card inlined for review/pending.
// ---------------------------------------------------------------------------

export function LiveLog(props: {
  events: ActivityEvent[];
  errorBanner?: string;
  maxRows: number;
}): React.ReactElement {
  const visible = props.events.slice(-props.maxRows);
  return (
    <Box
      flexDirection="column"
      borderStyle="round"
      borderColor={COL.panelLive}
      paddingX={1}
      marginX={1}
      flexGrow={1}
    >
      <Text>
        <Text color={COL.brand} bold>
          LIVE
        </Text>
        <Text dimColor>{`  · last ${props.maxRows} events`}</Text>
      </Text>
      {props.errorBanner ? <Text color={COL.liveOff}>{`⚠ ${props.errorBanner}`}</Text> : null}
      {visible.length === 0 ? (
        <Text dimColor>(no activity yet — daemon needs to be up and an agent must be running)</Text>
      ) : (
        visible.map((e) => <ActivityRow key={e.id} event={e} />)
      )}
    </Box>
  );
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

  const agentLabel = `[${capitalize(event.agent ?? '?')}]`.padEnd(10);
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
  const agentColor =
    event.agent === 'claude'
      ? COL.agentClaude
      : event.agent === 'gemini'
        ? COL.agentGemini
        : event.agent === 'codex'
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

export function Report(props: { agg: AuditAggregates; window: TimeWindow }): React.ReactElement {
  const { agg } = props;
  const maxTool = Math.max(1, ...agg.byTool.map((t) => t.calls));
  const maxShell = Math.max(1, ...agg.byShell.map((s) => s.count));
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
            {'tool'.padEnd(16) + 'calls'.padStart(7) + 'blocked'.padStart(9)}
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
          <Text dimColor wrap="truncate-end">
            {'shell'.padEnd(16) + 'calls'.padStart(7) + 'blocked'.padStart(9)}
          </Text>
          {agg.byShell.length === 0 ? (
            <Text dimColor>(no shell)</Text>
          ) : (
            agg.byShell.map((s) => (
              <Text key={s.cmd} wrap="truncate-end">
                <Text dimColor>{bar(s.count, maxShell, 6)}</Text>
                <Text>{` ${truncate(s.cmd, 14).padEnd(14)}`}</Text>
                <Text bold>{`${s.count}`.padStart(6)}</Text>
                <Text color={s.blocked > 0 ? COL.liveOff : COL.textDim}>
                  {`  ${s.blocked}`.padStart(8)}
                </Text>
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
  window: TimeWindow;
}): React.ReactElement {
  const dlpHits = props.agg.byBlock
    .filter((b) => b.rule.includes('dlp'))
    .reduce((s, b) => s + b.count, 0);
  const loopHits = props.agg.byBlock
    .filter((b) => b.rule === 'loop-detected')
    .reduce((s, b) => s + b.count, 0);
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
