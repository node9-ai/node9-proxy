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
  type CostSnapshot,
  type TimeWindow,
} from './types.js';
import {
  aggregateAudit,
  aggregateCost,
  buildLiveBackfill,
  loadBlast,
  loadCostEntries,
  readAuditEntries,
  submitDecision,
  subscribeToSse,
} from './data.js';
import type { DailyEntry } from '../../costSync.js';
import {
  ApprovalCard,
  Header,
  HighLevel,
  LiveLog,
  Report,
  Risk,
  StatusBar,
  type ApprovalStatus,
} from './panels.js';

const LIVE_BUFFER_CAP = 100;
const AUDIT_REFRESH_MS = 30_000;
const BLAST_REFRESH_MS = 5 * 60_000;

/**
 * Approximate fixed-row cost of every panel except LIVE's content area.
 *   header             (1)
 *   HIGH LEVEL         (5: 2 border + 3 content)
 *   LIVE chrome        (3: 2 border + 1 title — content is variable)
 *   REPORT             (9: 2 border + 1 title + 1 col-header + 5 rows)
 *   RISK               (5: 2 border + 1 title + 1 counts + 1 paths)
 *   StatusBar          (1)
 *                      = 24
 * LIVE's content area takes (termRows − 24) rows. Floor at 4 so the
 * panel never collapses to nothing on a tiny terminal — older events
 * scroll off the top via the existing 100-event FIFO buffer.
 *
 * Calibration: prior value was 22, which made LIVE 2 rows too tall,
 * pushing the bottom panels off-screen on standard ~41-row terminals.
 */
const FIXED_PANELS_HEIGHT = 24;
const LIVE_MIN_ROWS = 4;
const COST_REFRESH_MS = 5 * 60_000;

export function App(): React.ReactElement {
  const { exit } = useApp();
  const { stdout } = useStdout();
  const [openedAt] = useState<number>(() => Date.now());
  const [window, setWindow] = useState<TimeWindow>('1d');
  const [events, setEvents] = useState<ActivityEvent[]>([]);
  const [sseError, setSseError] = useState<string | undefined>();
  const [agg, setAgg] = useState<AuditAggregates | null>(null);
  const [blast, setBlast] = useState<BlastSnapshot | null>(null);
  const [costEntries, setCostEntries] = useState<DailyEntry[] | null>(null);
  const [skillsPinned] = useState<number>(() => readSkillsPinned());
  // Pending approval — most-recent event that needs human action.
  // Set when an `add` event arrives (or any tool event with verdict
  // 'review' / 'pending'). Cleared on resolve via SSE, on user action,
  // or on Esc.
  const [pendingApproval, setPendingApproval] = useState<ActivityEvent | null>(null);
  const [approvalStatus, setApprovalStatus] = useState<ApprovalStatus>({ kind: 'idle' });
  // Filter — applied to the LIVE panel only. `/` enters input mode;
  // typing edits the filter live; Enter freezes; Esc clears+exits.
  const [filter, setFilter] = useState<string>('');
  const [filterInputMode, setFilterInputMode] = useState<boolean>(false);

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

  // Seed LIVE with the last N audit entries so the panel opens
  // populated rather than empty. Runs once on mount; SSE events
  // append to this buffer as they arrive. Backfill count tracks the
  // initial terminal-derived maxRows — switching window doesn't
  // re-seed (LIVE is independent of the time window per design).
  // Effect runs once on mount only; liveMaxRows is read at that moment
  // from the captured closure. We deliberately don't re-seed when the
  // terminal resizes (would double-fill the buffer).
  const initialMaxRowsRef = React.useRef(liveMaxRows);
  useEffect(() => {
    const backfill = buildLiveBackfill(initialMaxRowsRef.current);
    if (backfill.length > 0) setEvents(backfill);
  }, []);

  // SSE subscription — runs once, fed by daemon.
  useEffect(() => {
    const teardown = subscribeToSse(
      (e) => {
        setEvents((prev) => {
          const next = [...prev, e];
          return next.length > LIVE_BUFFER_CAP ? next.slice(next.length - LIVE_BUFFER_CAP) : next;
        });
        setSseError(undefined);
        // Surface pending review/approval rows in the ApprovalCard.
        // We only track the most recent — older pending approvals are
        // silently dropped from the card surface (they remain visible
        // in the LIVE feed). Daemon's own timeout still resolves them.
        if (e.kind === 'tool' && (e.verdict === 'review' || e.verdict === 'pending')) {
          setPendingApproval(e);
          setApprovalStatus({ kind: 'idle' });
        }
      },
      (resolvedId, finalVerdict) => {
        // Daemon resolved a pending entry (`activity-result` or
        // `remove`). Update the matching LIVE row's verdict so it
        // stops rendering as `pending`, and clear the approval card
        // if it was tracking this id.
        if (finalVerdict) {
          setEvents((prev) =>
            prev.map((e) =>
              e.kind === 'tool' && e.id === resolvedId ? { ...e, verdict: finalVerdict } : e
            )
          );
        }
        setPendingApproval((prev) => (prev && prev.id === resolvedId ? null : prev));
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

  // Cost — async because collectEntries() walks every JSONL under
  // ~/.claude/projects (1-5s on a heavy install). Render shows
  // "loading…" placeholder until the first walk completes.
  useEffect(() => {
    let cancelled = false;
    const loadAndSet = () => {
      loadCostEntries().then((entries) => {
        if (!cancelled) setCostEntries(entries);
      });
    };
    loadAndSet();
    const id = setInterval(loadAndSet, COST_REFRESH_MS);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);
  const costSnapshot: CostSnapshot | null = useMemo(() => {
    if (!costEntries) return null;
    return aggregateCost(costEntries, windowStartMs(window, openedAt));
  }, [costEntries, window, openedAt]);

  useInput((input, key) => {
    // Filter input mode takes the highest priority — every printable
    // key edits the filter, Esc clears, Enter freezes. Approval card
    // and global hotkeys are suppressed.
    if (filterInputMode) {
      if (key.escape) {
        setFilter('');
        setFilterInputMode(false);
        return;
      }
      if (key.return) {
        // Freeze the current filter, exit input mode (q/Tab/r work again).
        setFilterInputMode(false);
        return;
      }
      if (key.backspace || key.delete) {
        setFilter((prev) => prev.slice(0, -1));
        return;
      }
      if (input && input.length === 1 && input.charCodeAt(0) >= 32) {
        setFilter((prev) => prev + input);
        return;
      }
      return;
    }

    // Approval-card key dispatch — when a card is showing, q/Tab/r/`/`
    // are suppressed so a misclick can't quit the dashboard while the
    // user is trying to act on the card.
    if (pendingApproval && approvalStatus.kind !== 'sending') {
      if (input === 'a' || input === 'd' || input === 't') {
        const decision = input === 'a' ? 'allow' : input === 'd' ? 'deny' : 'trust';
        const id = pendingApproval.id;
        setApprovalStatus({ kind: 'sending' });
        void submitDecision(id, decision).then((res) => {
          if (res.ok) {
            setApprovalStatus({ kind: 'ok', verdict: decision });
            // Auto-dismiss after a short flash so the user gets feedback.
            setTimeout(() => {
              setPendingApproval((prev) => (prev && prev.id === id ? null : prev));
              setApprovalStatus({ kind: 'idle' });
            }, 600);
          } else {
            setApprovalStatus({ kind: 'error', message: res.error ?? 'unknown' });
          }
        });
        return;
      }
      if (key.escape) {
        // Local dismiss only — daemon's timeout still runs.
        setPendingApproval(null);
        setApprovalStatus({ kind: 'idle' });
        return;
      }
      // Other keys ignored while card is open.
      return;
    }

    // Global keys (no card, no filter input mode active).
    if (input === '/') {
      setFilterInputMode(true);
      return;
    }
    if (key.escape && filter) {
      // Outside input-mode, Esc clears any active filter.
      setFilter('');
      return;
    }
    if (input === 'q' || (key.ctrl && input === 'c')) exit();
    else if (key.tab) {
      const idx = TIME_WINDOWS.indexOf(window);
      const next = TIME_WINDOWS[(idx + 1) % TIME_WINDOWS.length];
      setWindow(next);
    } else if (input === 'r') {
      // Manual refresh of audit + blast (cheap) and cost (expensive,
      // dispatched async so the keypress feels instant).
      const entries = readAuditEntries();
      setAgg(aggregateAudit(entries, windowStartMs(window, openedAt)));
      setBlast(loadBlast());
      void loadCostEntries().then(setCostEntries);
    }
  });

  // Header's "last agent" badge tracks the most recent TOOL row only —
  // snapshot rows don't carry agent/session, so they're skipped.
  const lastToolEvent = useMemo(
    () => [...events].reverse().find((e) => e.kind === 'tool'),
    [events]
  );
  const lastAgent = useMemo(() => {
    if (!lastToolEvent || !lastToolEvent.agent) return undefined;
    const a = lastToolEvent.agent;
    const sid = lastToolEvent.sessionId?.slice(0, 4);
    return sid ? `${capitalize(a)}·${sid}` : capitalize(a);
  }, [lastToolEvent]);
  const lastEvent = events[events.length - 1];

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
      <HighLevel
        window={window}
        agg={agg}
        blast={blast}
        cost={costSnapshot}
        skillsPinned={skillsPinned}
      />
      {pendingApproval ? <ApprovalCard event={pendingApproval} status={approvalStatus} /> : null}
      <LiveLog
        events={events}
        errorBanner={sseError}
        maxRows={liveMaxRows}
        filter={filter}
        filterInputMode={filterInputMode}
      />
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
