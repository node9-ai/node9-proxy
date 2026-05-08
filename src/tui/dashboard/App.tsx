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
import { Box, Text, useApp, useInput } from 'ink';
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

export function App(): React.ReactElement {
  const { exit } = useApp();
  const [openedAt] = useState<number>(() => Date.now());
  const [window, setWindow] = useState<TimeWindow>('1d');
  const [events, setEvents] = useState<ActivityEvent[]>([]);
  const [sseError, setSseError] = useState<string | undefined>();
  const [agg, setAgg] = useState<AuditAggregates | null>(null);
  const [blast, setBlast] = useState<BlastSnapshot | null>(null);
  const [skillsPinned] = useState<number>(() => readSkillsPinned());

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
      <LiveLog events={events} errorBanner={sseError} maxRows={12} />
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
