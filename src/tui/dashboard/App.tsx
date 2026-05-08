// src/tui/dashboard/App.tsx
//
// Spike: experimental Ink-based unified dashboard for node9.
// Renders four panels: Live SSE feed, High-Level summary, Report
// breakdown, and DLP/LOOP/RISK summary. Time-window selector at top.
//
// Status: spike — experimental, not a replacement for `node9 tail`.
// Run via `node9 dashboard-spike`. Reversible: delete this directory
// and the CLI registration to fully unwind.
import React, { useEffect, useMemo, useState } from 'react';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { Box, Text, useApp, useInput, useStdout } from 'ink';
import {
  TIME_WINDOWS,
  windowStartMs,
  type ActivityEvent,
  type AuditAggregates,
  type BlastSnapshot,
  type TimeWindow,
} from './types.js';
import { aggregateAudit, loadBlast, readAuditEntries, subscribeToSse } from './data.js';
import { Header, HighLevel, LiveLog, Report, Risk, StatusBar } from './panels.js';

const LIVE_BUFFER_CAP = 100;
const AUDIT_REFRESH_MS = 30_000;
const BLAST_REFRESH_MS = 5 * 60_000;

/**
 * Approximate fixed-row cost of every panel except LIVE.
 *   header (1) + HIGH LEVEL (5: 2 border + 3 content) + REPORT (8: 2
 *   border + col header + 5 rows) + RISK (4: 2 border + header + content
 *   + path strip) + status bar (1) + per-panel margins (~3) = ~22.
 * LIVE takes whatever rows are left. Floor at 4 so the panel never
 * collapses to nothing on a tiny terminal (it still scrolls visually
 * via FIFO; older events fall off the top).
 */
const FIXED_PANELS_HEIGHT = 22;
const LIVE_MIN_ROWS = 4;

export function App(): React.ReactElement {
  const { exit } = useApp();
  const { stdout } = useStdout();
  const [openedAt] = useState<number>(() => Date.now());
  const [window, setWindow] = useState<TimeWindow>('1d');
  const [events, setEvents] = useState<ActivityEvent[]>([]);
  const [sseError, setSseError] = useState<string | undefined>();
  const [agg, setAgg] = useState<AuditAggregates | null>(null);
  const [blast, setBlast] = useState<BlastSnapshot | null>(null);
  const [skillsPinned] = useState<number>(() => readSkillsPinned());

  // Track terminal rows so LIVE can size itself to fill whatever space
  // is left after the fixed-height panels above it. Re-renders on
  // SIGWINCH / window-resize so resizing the terminal mid-session
  // expands or shrinks the live feed in place.
  const [termRows, setTermRows] = useState<number>(stdout?.rows ?? 24);
  useEffect(() => {
    if (!stdout) return undefined;
    const onResize = () => setTermRows(stdout.rows ?? 24);
    stdout.on('resize', onResize);
    return () => {
      stdout.off('resize', onResize);
    };
  }, [stdout]);
  const liveMaxRows = Math.max(LIVE_MIN_ROWS, termRows - FIXED_PANELS_HEIGHT);

  // SSE subscription — runs once, fed by daemon.
  useEffect(() => {
    const teardown = subscribeToSse(
      (e) => {
        setEvents((prev) => {
          const next = [...prev, e];
          return next.length > LIVE_BUFFER_CAP ? next.slice(next.length - LIVE_BUFFER_CAP) : next;
        });
        setSseError(undefined);
      },
      (msg) => setSseError(msg)
    );
    return teardown;
  }, []);

  // Audit aggregation — recomputes when window changes or every 30s.
  useEffect(() => {
    const recompute = () => {
      const entries = readAuditEntries();
      const startMs = windowStartMs(window, openedAt);
      setAgg(aggregateAudit(entries, startMs));
    };
    recompute();
    const id = setInterval(recompute, AUDIT_REFRESH_MS);
    return () => clearInterval(id);
  }, [window, openedAt]);

  // Blast — once at start, then every 5 min. `r` keypress also triggers below.
  useEffect(() => {
    setBlast(loadBlast());
    const id = setInterval(() => setBlast(loadBlast()), BLAST_REFRESH_MS);
    return () => clearInterval(id);
  }, []);

  useInput((input, key) => {
    if (input === 'q' || (key.ctrl && input === 'c')) exit();
    else if (key.tab) {
      const idx = TIME_WINDOWS.indexOf(window);
      const next = TIME_WINDOWS[(idx + 1) % TIME_WINDOWS.length];
      setWindow(next);
    } else if (input === 'r') {
      // Manual refresh of audit + blast (cheap operations).
      const entries = readAuditEntries();
      setAgg(aggregateAudit(entries, windowStartMs(window, openedAt)));
      setBlast(loadBlast());
    }
  });

  const lastEvent = events[events.length - 1];
  const lastAgent = useMemo(() => {
    if (!lastEvent?.agent) return undefined;
    const a = lastEvent.agent;
    const sid = lastEvent.sessionId?.slice(0, 4);
    return sid ? `${capitalize(a)}·${sid}` : capitalize(a);
  }, [lastEvent]);

  if (!agg || !blast) {
    return (
      <Box paddingX={1}>
        <Text dimColor>Loading dashboard…</Text>
      </Box>
    );
  }

  return (
    <Box flexDirection="column" height="100%">
      <Header window={window} connected={!sseError} lastAgent={lastAgent} lastTs={lastEvent?.ts} />
      <HighLevel window={window} agg={agg} blast={blast} skillsPinned={skillsPinned} />
      <LiveLog events={events} errorBanner={sseError} maxRows={liveMaxRows} />
      <Report agg={agg} window={window} />
      <Risk agg={agg} blast={blast} window={window} />
      <StatusBar />
    </Box>
  );
}

function capitalize(s: string): string {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : '';
}

function readSkillsPinned(): number {
  try {
    const p = path.join(os.homedir(), '.node9', 'skill-pins.json');
    if (!fs.existsSync(p)) return 0;
    const parsed = JSON.parse(fs.readFileSync(p, 'utf8')) as { roots?: Record<string, unknown> };
    return parsed.roots ? Object.keys(parsed.roots).length : 0;
  } catch {
    return 0;
  }
}
