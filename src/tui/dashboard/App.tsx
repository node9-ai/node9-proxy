// src/tui/dashboard/App.tsx
//
// Ink-based unified dashboard for node9, served by `node9 monitor`.
// Renders four panels: Live SSE feed, High-Level summary, Report
// breakdown, and DLP/LOOP/RISK summary, with a fixed-height
// notification area for approvals + recent security alerts.
// Time-window selector at top.
//
// Note: the directory is named `dashboard/` for historical reasons
// (the component is a dashboard); the user-facing command is
// `node9 monitor`. Internal symbols use neither name as gospel —
// the components are named for what they show, not the command.
import React, { useEffect, useMemo, useState } from 'react';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { Box, Text, useApp, useInput, useStdout } from 'ink';
import {
  EMPTY_SESSION_FORENSIC,
  windowStartMs,
  type ActivityEvent,
  type AuditAggregates,
  type BlastSnapshot,
  type CostSnapshot,
  type ForensicSseEvent,
  type ReportPeriod,
  type ScanSignalsSnapshot,
  type SessionForensicAgg,
  type ShieldStatus,
  type TimeWindow,
  type View,
} from './types.js';
import {
  aggregateAudit,
  aggregateCost,
  applyForensicEvent,
  buildCostBaseline,
  loadBlast,
  loadCostEntries,
  loadScanSignals,
  loadShieldStatus,
  readAuditEntries,
  subtractCostBaseline,
  submitDecision,
  subscribeToSse,
} from './data.js';
import { computeHealthBadge } from './health.js';
import type { DailyEntry } from '../../costSync.js';
import {
  Header,
  HighLevel,
  LiveLog,
  NotificationArea,
  Report,
  ReportView,
  Risk,
  StatusBar,
  type ApprovalStatus,
  type Notification,
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
// Post-cleanup: RISK panel is now exactly 6 rows (title + dlp/loops/
// score + forensic + shield-summary + 2 borders) — path list and full
// inactive-shield CTA moved to View 2 Coverage.
//   header (1) + HIGH LEVEL (5) + Notification (4) + LIVE chrome (3) +
//   REPORT (9) + RISK (6) + StatusBar (1) = 29
//
// +1 safety margin → 30. The exact-fit math (29 + maxRows == termRows)
// failed in practice on a terminal reporting 41 rows: Ink emits an
// extra newline at end-of-frame, or the terminal reserves a row for
// its status/scrollbar — either way header scrolled off the top once
// LIVE filled. Reserving 1 extra row makes the dashboard 1 row shorter
// than the terminal so there's no overflow.
const FIXED_PANELS_HEIGHT = 30;
/** Minimum content rows LIVE renders. 1 instead of a higher floor —
 *  on terminals smaller than 33 rows we'd rather LIVE shrink and keep
 *  the Header visible than over-claim space and push the dashboard
 *  past the terminal height (the outer Box's overflow="hidden" then
 *  clips the bottom panels instead of scrolling the top off). */
const LIVE_MIN_ROWS = 1;
const NOTIFICATION_RECENT_WINDOW_MS = 60_000;
const RESOLVED_HOLD_MS = 5_000;
const COST_REFRESH_MS = 5 * 60_000;
/** Once a non-approval notification (block/review/loop) is shown,
 *  don't replace it with a newer non-approval until this elapses.
 *  Stops the area from flickering when many blocks fire in a burst.
 *  Approval cards still preempt instantly. */
const NOTIFICATION_STICKY_MS = 10_000;
/** Cooldown between two notifications of the same critical-forensic
 *  category. A privesc storm or a tight rm -rf loop must not flood
 *  the notification area — one per category per 30 s window. */
const FORENSIC_NOTIFY_COOLDOWN_MS = 30_000;
/** How long a critical-forensic notification stays visible before
 *  falling through to lower-priority notifications. */
const FORENSIC_DISPLAY_MS = 5_000;

export function App(): React.ReactElement {
  const { exit } = useApp();
  const { stdout } = useStdout();
  const [openedAt] = useState<number>(() => Date.now());
  // Top-level view — '[1]' realtime (default) vs '[2]' report. Phase 1
  // of the two-view restructure: switcher + stub Report view. Phase 2+
  // trim the realtime view and populate Report. See plan in
  // doc/roadmap/monitor-two-view.md.
  const [view, setView] = useState<View>('realtime');
  // Last-refresh timestamp shown in StatusBar. Updated on mount and on
  // each [r] keypress so users get visible confirmation that a manual
  // refresh fired, even when the underlying data didn't change. Auto-
  // refresh ticks (audit 30s, blast/shield/cost/scan 5min) intentionally
  // do NOT touch this — keeping it manual-only makes it a clean
  // "did my keypress work?" diagnostic.
  const [lastRefreshAt, setLastRefreshAt] = useState<number>(() => Date.now());
  // Period setter wires up in phase 5 (period picker keys). Phase 1 just
  // shows the default in the stub Report view.
  const [reportPeriod] = useState<ReportPeriod>('7d');
  // Realtime view is "since monitor opened" — phase 2 of the two-view
  // restructure. The TimeWindow concept stays (used by audit/cost aggs)
  // but is pinned to 'now' which means startMs = openedAt. Period
  // selection moves to View 2 (Report) where it belongs.
  const [window] = useState<TimeWindow>('now');
  const [events, setEvents] = useState<ActivityEvent[]>([]);
  const [sseError, setSseError] = useState<string | undefined>();
  const [agg, setAgg] = useState<AuditAggregates | null>(null);
  const [blast, setBlast] = useState<BlastSnapshot | null>(null);
  const [shieldStatus, setShieldStatus] = useState<ShieldStatus | null>(null);
  const [scanSignals, setScanSignals] = useState<ScanSignalsSnapshot | null>(null);
  const [sessionForensicAgg, setSessionForensicAgg] = useState<SessionForensicAgg>(() => ({
    ...EMPTY_SESSION_FORENSIC,
  }));
  // Critical-severity forensic event currently displayed in NotificationArea.
  // Cleared automatically after FORENSIC_DISPLAY_MS via the tick re-render.
  const [recentForensic, setRecentForensic] = useState<{
    category: ForensicSseEvent['category'];
    sessionId: string;
    firedAt: number;
  } | null>(null);
  // Per-category cooldown ref so a privesc storm produces only one
  // notification per FORENSIC_NOTIFY_COOLDOWN_MS window.
  const forensicNotifyCooldownRef = React.useRef<Map<ForensicSseEvent['category'], number>>(
    new Map()
  );
  const [costEntries, setCostEntries] = useState<DailyEntry[] | null>(null);
  const [skillsPinned] = useState<number>(() => readSkillsPinned());
  const [mcpPinned] = useState<number>(() => readMcpPinned());
  // Pending approval — most-recent event that needs human action.
  // Set when an `add` event arrives (or any tool event with verdict
  // 'review' / 'pending'). Cleared on resolve via SSE, on user action,
  // or on Esc.
  const [pendingApproval, setPendingApproval] = useState<ActivityEvent | null>(null);
  const [approvalStatus, setApprovalStatus] = useState<ApprovalStatus>({ kind: 'idle' });
  // Stash the most recently acted-on approval for a few seconds after
  // resolution so the notification area shows a flash before falling
  // through to the next priority slot.
  const [resolvedApproval, setResolvedApproval] = useState<{
    event: ActivityEvent;
    outcome: 'allow' | 'deny' | 'trust';
    resolvedAt: number;
  } | null>(null);
  // A render-tick counter so resolved/recent notifications expire in
  // real time. Bumped every second; cheap.
  const [tick, setTick] = useState<number>(0);
  useEffect(() => {
    const id = setInterval(() => setTick((t) => t + 1), 1000);
    return () => clearInterval(id);
  }, []);
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

  // LIVE feed starts empty on mount — Realtime view is "since-open"
  // semantics, so backfilling from past audit entries would mismatch
  // the rest of the panels (which all aggregate from openedAt forward).
  // Earlier this used buildLiveBackfill but was removed in the phase 2
  // RISK/Realtime cleanup for consistency. To see history, switch to
  // [2] Report view.

  // SSE subscription — runs once, fed by daemon.
  useEffect(() => {
    const teardown = subscribeToSse(
      (e) => {
        setEvents((prev) => {
          const next = [...prev, e];
          return next.length > LIVE_BUFFER_CAP ? next.slice(next.length - LIVE_BUFFER_CAP) : next;
        });
        setSseError(undefined);
        // Surface real approval requests only:
        //   - verdict === 'review'        → shield/rule explicitly needs decision
        //   - isApprovalRequest === true  → SSE 'add' event (queued for approval)
        // Bare verdict === 'pending' is intentionally NOT triggered: those
        // are transient `activity`-event flashes for auto-allowed calls
        // that resolve in milliseconds via activity-result. Showing them
        // would pop the APPROVAL card on every tool call.
        if (e.kind === 'tool' && (e.verdict === 'review' || e.isApprovalRequest)) {
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
        // Universal resolution flash: if the resolved id matches the
        // dashboard's pendingApproval, capture it as resolvedApproval
        // BEFORE clearing. This makes the 5-second `✓ approved` /
        // `✗ denied` flash fire for ALL approver paths — terminal,
        // native popup, browser — not just the dashboard's own
        // [a/d/t]. Without this, an external approver decides and the
        // dashboard goes straight to idle with no confirmation.
        setPendingApproval((prev) => {
          if (!prev || prev.id !== resolvedId) return prev;
          if (finalVerdict && prev.kind === 'tool') {
            const outcome: 'allow' | 'deny' | null =
              finalVerdict === 'allow' ? 'allow' : finalVerdict === 'block' ? 'deny' : null;
            if (outcome) {
              setResolvedApproval({
                event: prev,
                outcome,
                resolvedAt: Date.now(),
              });
            }
          }
          return null;
        });
      },
      (forensicEvent) => {
        // Live forensic finding from the daemon's 30 s broadcast tick.
        // Always increment the counter (RISK panel reads from here).
        // Only critical-severity events trigger a NotificationArea pop,
        // and per-category cooldown prevents floods.
        setSessionForensicAgg((prev) => applyForensicEvent(prev, forensicEvent));
        if (forensicEvent.severity === 'critical') {
          const now = Date.now();
          const cooldown = forensicNotifyCooldownRef.current;
          const lastFired = cooldown.get(forensicEvent.category) ?? 0;
          if (now - lastFired >= FORENSIC_NOTIFY_COOLDOWN_MS) {
            cooldown.set(forensicEvent.category, now);
            setRecentForensic({
              category: forensicEvent.category,
              sessionId: forensicEvent.sessionId,
              firedAt: now,
            });
          }
        }
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

  // Shield status — same cadence as blast (cheap fs read; rarely changes).
  // Surfaces inactive shields at the bottom of the RISK panel.
  useEffect(() => {
    setShieldStatus(loadShieldStatus());
    const id = setInterval(() => setShieldStatus(loadShieldStatus()), BLAST_REFRESH_MS);
    return () => clearInterval(id);
  }, []);

  // Forensic scan signals (PII / sensitive-file-reads / etc.) — async
  // because the JSONL walk takes 5-10s. Same async pattern as cost.
  // Render shows '…' placeholder until first walk completes; never
  // blocks dashboard mount.
  useEffect(() => {
    let cancelled = false;
    const loadAndSet = () => {
      loadScanSignals().then((s) => {
        if (!cancelled) setScanSignals(s);
      });
    };
    loadAndSet();
    const id = setInterval(loadAndSet, COST_REFRESH_MS);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  // Cost — async because collectEntries() walks every JSONL under
  // ~/.claude/projects (1-5s on a heavy install). Render shows
  // "loading…" placeholder until the first walk completes.
  //
  // Baseline: snapshot today's-and-prior-days totals from the FIRST
  // load. Subsequent loads subtract the baseline so HIGH LEVEL shows
  // SINCE-MONITOR-OPENED spend, not today's running total. costSync's
  // data is day-granular per (date, model) so a "since 14:00" delta
  // requires this kind of bookkeeping.
  const costBaselineRef = React.useRef<Map<string, DailyEntry> | null>(null);
  useEffect(() => {
    let cancelled = false;
    const loadAndSet = () => {
      loadCostEntries().then((entries) => {
        if (cancelled) return;
        if (costBaselineRef.current === null) {
          costBaselineRef.current = buildCostBaseline(entries);
        }
        setCostEntries(entries);
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
    // Subtract the mount-time baseline so HIGH LEVEL shows since-open
    // spend, not today's full running total. Baseline is null until
    // the first loadCostEntries resolves; in that window we're rendering
    // the placeholder anyway because costEntries is also null.
    const baseline = costBaselineRef.current ?? new Map<string, DailyEntry>();
    const adjusted = subtractCostBaseline(costEntries, baseline);
    return aggregateCost(adjusted, windowStartMs(window, openedAt));
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
        const eventAtAction = pendingApproval;
        setApprovalStatus({ kind: 'sending' });
        void submitDecision(id, decision).then((res) => {
          if (res.ok) {
            setApprovalStatus({ kind: 'ok', verdict: decision });
            // Stash for the resolved-flash priority slot. NotificationArea
            // uses this for ~5s after action, then falls through to recent
            // block / review / idle.
            setResolvedApproval({
              event: eventAtAction,
              outcome: decision,
              resolvedAt: Date.now(),
            });
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
    else if (input === '1') {
      // Top-level view switch. Realtime is the default — pressing 1
      // from anywhere returns here. See monitor-two-view.md.
      setView('realtime');
    } else if (input === '2') {
      setView('report');
    } else if (input === 'r') {
      // Manual refresh of audit + blast + shields (cheap) and cost
      // + scan-signals (expensive, dispatched async so the keypress
      // feels instant). Update lastRefreshAt synchronously so the
      // StatusBar timestamp ticks immediately — gives users visible
      // confirmation [r] fired even when underlying data didn't change.
      setLastRefreshAt(Date.now());
      const entries = readAuditEntries();
      setAgg(aggregateAudit(entries, windowStartMs(window, openedAt)));
      setBlast(loadBlast());
      setShieldStatus(loadShieldStatus());
      void loadCostEntries().then(setCostEntries);
      void loadScanSignals().then(setScanSignals);
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

  // Priority cascade for the always-rendered NotificationArea:
  //   1. pending approval        — the only actionable state, preempts all
  //   2. recently-resolved (5s)  — flash so the user sees what they did
  //   3. recent block (60s)      — most recent security block
  //   4. recent review (60s)     — most recent review-verdict
  //   5. recent loop (60s)       — most recent loop-detected event
  //   6. idle                    — placeholder; shows blast score for context
  //
  // Filtering: observe-mode and timeout entries are skipped — they're
  // logging-only events that fired without actually blocking, so they
  // shouldn't surface as alerts. Rule: skip when checkedBy starts with
  // 'observe-mode' or equals 'timeout' / 'popup-timeout'.
  //
  // Stickiness: once a block/review/loop is shown, it stays for at
  // least NOTIFICATION_STICKY_MS even if a newer event arrives. Stops
  // the area from flickering when many blocks fire in a burst. Tracked
  // via stickyNotificationRef — the last non-approval notification +
  // when we first showed it.
  const stickyRef = React.useRef<{
    kind: 'block' | 'review' | 'loop';
    eventId: string;
    firstShownAt: number;
  } | null>(null);
  const notification: Notification = useMemo(() => {
    if (pendingApproval) {
      // Approval preempts; clear sticky so the next block after the
      // approval resolves doesn't get held over from before.
      stickyRef.current = null;
      return { kind: 'approval', event: pendingApproval, status: approvalStatus };
    }
    if (resolvedApproval && Date.now() - resolvedApproval.resolvedAt < RESOLVED_HOLD_MS) {
      stickyRef.current = null;
      return {
        kind: 'resolved',
        event: resolvedApproval.event,
        outcome: resolvedApproval.outcome,
      };
    }
    // Live critical forensic finding — privesc / destructive / eval-rem.
    // Sits ABOVE audit-derived block/review notifications because
    // forensic detection runs against Claude's full JSONL while audit
    // captures decisions, so the same call may produce both signals
    // and we'd rather surface the higher-severity one first.
    if (recentForensic && Date.now() - recentForensic.firedAt < FORENSIC_DISPLAY_MS) {
      stickyRef.current = null;
      return {
        kind: 'forensic',
        category: recentForensic.category,
        sessionId: recentForensic.sessionId,
        firedAt: recentForensic.firedAt,
      };
    }
    const now = Date.now();

    // Find the newest notification-worthy event in the recent window.
    let candidate: {
      kind: 'block' | 'review' | 'loop';
      event: ActivityEvent;
      ageMs: number;
    } | null = null;
    for (const e of [...events].reverse()) {
      if (e.kind !== 'tool') continue;
      if (!isNotificationWorthy(e)) continue;
      const ageMs = now - Date.parse(e.ts);
      if (Number.isNaN(ageMs) || ageMs > NOTIFICATION_RECENT_WINDOW_MS) continue;
      if (e.checkedBy === 'loop-detected') {
        candidate = { kind: 'loop', event: e, ageMs };
        break;
      }
      if (e.verdict === 'block') {
        candidate = { kind: 'block', event: e, ageMs };
        break;
      }
      if (e.verdict === 'review') {
        candidate = { kind: 'review', event: e, ageMs };
        break;
      }
    }

    if (!candidate) {
      stickyRef.current = null;
      return { kind: 'idle', blastScore: blast?.score ?? 100 };
    }

    // If we've been showing a different sticky notification for less
    // than NOTIFICATION_STICKY_MS, hold it instead of swapping.
    const sticky = stickyRef.current;
    if (sticky && sticky.eventId !== candidate.event.id) {
      const stuckFor = now - sticky.firstShownAt;
      if (stuckFor < NOTIFICATION_STICKY_MS) {
        // Re-resolve the sticky event to keep its ageMs fresh.
        const stickyEvent = events.find((x) => x.kind === 'tool' && x.id === sticky.eventId);
        if (stickyEvent && stickyEvent.kind === 'tool') {
          const stickyAge = now - Date.parse(stickyEvent.ts);
          if (!Number.isNaN(stickyAge) && stickyAge <= NOTIFICATION_RECENT_WINDOW_MS) {
            return { kind: sticky.kind, event: stickyEvent, ageMs: stickyAge };
          }
        }
      }
    }

    // New sticky — record id + first-shown time.
    if (!sticky || sticky.eventId !== candidate.event.id) {
      stickyRef.current = {
        kind: candidate.kind,
        eventId: candidate.event.id,
        firstShownAt: now,
      };
    }
    return candidate;
    // tick is intentionally a dep so age windows + sticky expiry re-eval each second.
  }, [pendingApproval, approvalStatus, resolvedApproval, recentForensic, events, blast, tick]);

  // Unified security-health badge for the Header. Pure compute over
  // every signal source the dashboard already tracks. Re-runs whenever
  // any input changes — same render cadence as the panels themselves.
  const healthBadge = useMemo(
    () =>
      computeHealthBadge({
        agg: agg ?? {
          total: 0,
          allow: 0,
          block: 0,
          review: 0,
          loops: 0,
          dlpHits: 0,
          sessions: 0,
          mcpServers: 0,
          mcpCalls: 0,
          byTool: [],
          byBlock: [],
          byShell: [],
        },
        blast: blast ?? { score: 100, paths: [], envFindings: 0 },
        scanSignals,
        shieldStatus,
        forensicAgg: sessionForensicAgg,
      }),
    [agg, blast, scanSignals, shieldStatus, sessionForensicAgg]
  );

  // Render Header + StatusBar in every state (including loading) so the
  // user always sees the brand strip and key hints. Earlier the loading
  // guard early-returned just "Loading dashboard…" with no chrome — that
  // gave the impression the header was missing on slow blast walks.
  //
  // overflow="hidden" guards against the case where total panel height
  // exceeds termRows (any terminal smaller than ~33 rows). Without it,
  // overflowing children push the top off-screen — the Header walks off
  // the moment the panels fill in. With it, the bottom (Risk, StatusBar)
  // gets clipped instead.
  const loading = !agg || !blast;
  return (
    <Box flexDirection="column" height="100%" overflow="hidden">
      <Header
        connected={!sseError}
        lastAgent={lastAgent}
        lastTs={lastEvent?.ts}
        health={healthBadge}
      />
      {loading ? (
        <Box flexGrow={1} paddingX={1}>
          <Text dimColor>Loading dashboard…</Text>
        </Box>
      ) : view === 'realtime' ? (
        <>
          <HighLevel
            window={window}
            agg={agg}
            cost={costSnapshot}
            skillsPinned={skillsPinned}
            mcpPinned={mcpPinned}
          />
          <NotificationArea notification={notification} />
          <LiveLog
            events={events}
            errorBanner={sseError}
            maxRows={liveMaxRows}
            filter={filter}
            filterInputMode={filterInputMode}
          />
          <Report agg={agg} cost={costSnapshot} window={window} />
          <Risk
            agg={agg}
            blast={blast}
            shieldStatus={shieldStatus}
            forensicAgg={sessionForensicAgg}
            window={window}
          />
        </>
      ) : (
        <ReportView period={reportPeriod} />
      )}
      <StatusBar view={view} lastRefreshAt={lastRefreshAt} />
    </Box>
  );
}

function capitalize(s: string): string {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : '';
}

/**
 * Filter for notification-worthy events. Drops:
 *   - observe-mode-* checkedBy values (logging only — action ran)
 *   - timeout / popup-timeout (handled silently, not real alerts)
 * Everything else (real blocks, reviews, loop-detected, etc.) passes.
 * Pure function — exported indirectly via tests if needed.
 */
function isNotificationWorthy(e: ActivityEvent): boolean {
  if (e.kind !== 'tool') return false;
  if (!e.checkedBy) return e.verdict === 'block' || e.verdict === 'review';
  if (e.checkedBy.startsWith('observe-mode')) return false;
  if (e.checkedBy === 'timeout' || e.checkedBy === 'popup-timeout') return false;
  return true;
}

function readMcpPinned(): number {
  try {
    const p = path.join(os.homedir(), '.node9', 'mcp-pins.json');
    if (!fs.existsSync(p)) return 0;
    const parsed = JSON.parse(fs.readFileSync(p, 'utf8')) as {
      servers?: Record<string, unknown>;
    };
    return parsed.servers ? Object.keys(parsed.servers).length : 0;
  } catch {
    return 0;
  }
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
