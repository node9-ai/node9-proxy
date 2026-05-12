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
import { Box, Text, useApp, useInput, useStdout } from 'ink';
import {
  EMPTY_SESSION_ACTIVITY,
  EMPTY_SESSION_FORENSIC,
  EMPTY_SESSION_SHIELDS,
  windowStartMs,
  type ActivityEvent,
  type AuditAggregates,
  type BlastSnapshot,
  type ForensicSseEvent,
  type ReportPeriod,
  type ScanCache,
  type ScanSignalsSnapshot,
  type SessionActivityAgg,
  type SessionForensicAgg,
  type SessionShieldsAgg,
  type ShieldStatus,
  type TimeWindow,
  type View,
} from './types.js';
import {
  aggregateAudit,
  applyActivityEvent,
  applyActivityToShields,
  applyForensicEvent,
  applyResolveStatus,
  buildRuleToShieldMap,
  computeProtection,
  loadBlast,
  loadReportAuditAsync,
  loadShieldStatus,
  readAuditEntriesAsync,
  startScanWalk,
  submitDecision,
  subscribeToSse,
} from './data.js';
import { computeHealthBadge } from './health.js';
import type { AggregateResult } from '../../cli/aggregate/report-audit.js';
import {
  Header,
  LiveActivity,
  LiveLog,
  LiveSecurity,
  NotificationArea,
  SessionCounters,
  Shields,
  StatusBar,
  type ApprovalStatus,
  type Notification,
} from './panels.js';
import { ReportView } from './views/report/index.js';

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
const FIXED_PANELS_HEIGHT = 40;
/** Minimum content rows LIVE renders. Bumped to 11 so the live event
 *  stream always has useful depth even when the new LIVE SECURITY /
 *  LIVE ACTIVITY panels grow the fixed-chrome budget. On terminals
 *  too small to fit chrome + 11 LIVE rows, the outer Box's
 *  overflow="hidden" clips the bottom (Setup / StatusBar) instead of
 *  shrinking LIVE — the live feed is the primary signal, the rest is
 *  context. */
const LIVE_MIN_ROWS = 11;
const NOTIFICATION_RECENT_WINDOW_MS = 60_000;
const RESOLVED_HOLD_MS = 5_000;

/**
 * Quit-key dispatch — extracted as a pure function so the rules are unit-
 * testable. Three conventions, in priority order:
 *   1. Ctrl+C always quits, regardless of mode. Terminal convention; the
 *      previous code path swallowed it inside an active approval card,
 *      which trapped users.
 *   2. `q` quits in every mode EXCEPT filter-input mode (where `q` must
 *      type a literal `q` into the filter — that's by design).
 *   3. Anything else: caller continues with normal dispatch.
 *
 * Note: pendingApproval state does NOT block quit anymore. The previous
 * handler returned early on a card without checking q/ctrl+c, so users
 * could see the dashboard freeze visually until the daemon's own
 * approvalTimeoutMs fired.
 */
export function shouldQuit(
  input: string,
  key: { ctrl?: boolean },
  context: { filterInputMode: boolean }
): boolean {
  if (key.ctrl === true && input === 'c') return true;
  if (input === 'q' && !context.filterInputMode) return true;
  return false;
}
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
  // Period selector for the Report [2] view. Default '7d' matches the CLI
  // (`node9 report --period 7d`). T/W/M hotkeys below set today/7d/30d.
  // The 'month' value is reachable via the CLI but not the dashboard —
  // M maps to 30d (rolling) here, which is the more common user intent.
  const [reportPeriod, setReportPeriod] = useState<ReportPeriod>('7d');
  // Audit aggregate for Report [2]. Re-loaded by useEffect when the user
  // switches to view='report' or changes the period. Null while initial
  // load runs (just one tick — sync ~10ms).
  const [reportAudit, setReportAudit] = useState<AggregateResult | null>(null);
  // Scan-walk cache for Report [2]. Phase 3b plumbed it; phase 3f starts
  // consuming results. Lazy: walks only run on first [2] press, not at
  // mount. See loadReportAudit / startScanWalk in data.ts.
  const [scanCache, setScanCache] = useState<ScanCache>({ status: 'idle' });
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
  // scanSignals is intentionally never set on Realtime (Phase 1: the
  // walk that fed it was removed, since Risk now uses SSE-driven
  // forensicAgg for live counts). Kept as a typed null reference so
  // computeHealthBadge's union-typed input keeps working.
  const [scanSignals] = useState<ScanSignalsSnapshot | null>(null);
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
  // Tiny "Since Open" counter strip on Realtime — pure SSE accumulator,
  // no history walks. Replaces the old HIGH LEVEL panel which needed
  // ~/.claude/projects walks for cost. The counters reset on mount and
  // grow as SSE activity events arrive. Cost is intentionally absent —
  // it lives in [2] Report now.
  const [sessionCounters, setSessionCounters] = useState({
    events: 0,
    allow: 0,
    block: 0,
    review: 0,
  });
  // Live activity tally — feeds the new LIVE ACTIVITY panel (tools +
  // shell distribution) and the dlp/loops rows of LIVE SECURITY. Pure
  // SSE accumulator; updates on every kind:'tool' event via
  // applyActivityEvent.
  const [sessionActivityAgg, setSessionActivityAgg] = useState<SessionActivityAgg>(() => ({
    ...EMPTY_SESSION_ACTIVITY,
    tools: {},
    shell: {},
    mcp: {},
  }));
  // Per-shield activity tally — feeds the SHIELDS panel. Built once at
  // mount, the ruleToShield map is a small (~30-entry) Map; lookups are
  // O(1) and the reducer is pure, so cost per event is microseconds.
  const ruleToShieldRef = React.useRef<Map<string, string>>(buildRuleToShieldMap());
  const [sessionShieldsAgg, setSessionShieldsAgg] = useState<SessionShieldsAgg>(() => ({
    ...EMPTY_SESSION_SHIELDS,
    byShield: {},
  }));
  // (skillsPinned / mcpPinned counters were inputs to the old HIGH LEVEL
  // panel; they're no longer rendered on Realtime in Phase 1. The
  // readSkillsPinned / readMcpPinned helpers below are kept for [2]
  // Report's HighLevel which still needs them.)
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

  // Report [2] data — re-aggregates the audit log when the user is on
  // the Report view and the period changes (or on manual [r] refresh).
  // Cheap (~10ms) so we can be liberal with re-runs. The scan walk is
  // separate (lazy + cached) — only kicks off the first time the user
  // presses [2], doesn't run while sitting on Realtime.
  useEffect(() => {
    if (view !== 'report') return;
    // loadReportAuditAsync uses readAuditEntriesAsync internally so the
    // JSON.parse loop yields between 1k-line chunks. The aggregator's
    // cost-walk pass (claude / codex JSONLs) is still synchronous — that's
    // the job of the scan-walker refactor. For now, this change alone
    // removes the audit-parse component of the [2] freeze; the user still
    // sees a brief pause from the cost walks until that lands.
    setReportAudit(null);
    let cancelled = false;
    void loadReportAuditAsync(reportPeriod).then((result) => {
      if (cancelled) return;
      setReportAudit(result);
    });
    return () => {
      cancelled = true;
    };
  }, [view, reportPeriod, lastRefreshAt]);

  // Scan walk auto-starts when the user enters [2] Report. The walker
  // is async (chunked + 7d mtime filter) so this is sub-second on most
  // installs — the spinner in LEAKS / LOOPS / TOP RULES gives feedback
  // when it isn't. The cancel fn is stashed in this ref so leaving [2]
  // can stop a walk cleanly mid-flight; [r] resets to idle which
  // re-fires the effect.
  const scanWalkCancelRef = React.useRef<(() => void) | null>(null);
  useEffect(() => {
    // Leaving [2]: cancel any in-flight walk and reset to idle so the
    // next [2] entry can start fresh.
    if (view !== 'report') {
      const cancel = scanWalkCancelRef.current;
      if (cancel) {
        cancel();
        scanWalkCancelRef.current = null;
        setScanCache((cur) => (cur.status === 'loading' ? { status: 'idle' } : cur));
      }
      return;
    }
    // Entering [2] with no cached scan: auto-start the walk. The
    // deps-loop bug that used to prevent this (scanCache.status in
    // deps caused an infinite cancel/restart cycle) is fixed by
    // keying on lastRefreshAt instead. [r] forces a re-walk by
    // resetting scanCache to idle, which is in this effect's body
    // (no longer in deps) so it re-fires only on view / refresh
    // changes — never on internal status transitions.
    if (scanCache.status === 'idle') {
      scanWalkCancelRef.current = startScanWalk((cache) => {
        setScanCache(cache);
        if (cache.status === 'ready' || cache.status === 'error') {
          scanWalkCancelRef.current = null;
        }
      });
    }
    // Intentional minimal deps: scanCache.status is updated *inside*
    // this effect (idle→loading→ready). Putting it in deps caused an
    // infinite cancel/restart loop. Re-run only on view + refresh.
  }, [view, lastRefreshAt]);

  // SSE subscription — runs once, fed by daemon.
  useEffect(() => {
    const teardown = subscribeToSse(
      (e) => {
        // 'add' SSE events feed the approval card and ONLY the approval
        // card — the daemon also broadcasts an `activity` event for the
        // same logical command in the same flush, which is what populates
        // LIVE. Without this early-return, every review-required call
        // produced THREE LIVE rows (two 'activity' events with different
        // ids — one tool-call id, one queue tracker id — plus the 'add'
        // row). Skip the events append for 'add' to bring it back to two.
        // Full collapse to one row needs a daemon-side fix (single
        // 'activity' broadcast per logical command) — tracked separately.
        if (e.kind === 'tool' && e.isApprovalRequest) {
          setPendingApproval(e);
          setApprovalStatus({ kind: 'idle' });
          setSseError(undefined);
          return;
        }
        setEvents((prev) => {
          const next = [...prev, e];
          return next.length > LIVE_BUFFER_CAP ? next.slice(next.length - LIVE_BUFFER_CAP) : next;
        });
        setSseError(undefined);
        // Increment Realtime "Since Open" counters for tool events.
        // Snapshot rows aren't tool calls, skip them. A 'pending' verdict
        // means the user hasn't decided yet — count it as an event but
        // don't bucket into allow/block/review until the result arrives
        // via the resolve handler below.
        if (e.kind === 'tool') {
          setSessionCounters((c) => ({
            events: c.events + 1,
            allow: c.allow + (e.verdict === 'allow' ? 1 : 0),
            block: c.block + (e.verdict === 'block' ? 1 : 0),
            review: c.review + (e.verdict === 'review' ? 1 : 0),
          }));
          setSessionActivityAgg((prev) => applyActivityEvent(prev, e));
          setSessionShieldsAgg((prev) => applyActivityToShields(prev, e, ruleToShieldRef.current));
        }
        // verdict === 'review' on a regular `activity` event is also a
        // pending-approval signal (shield/rule explicitly asked for
        // review without queuing through the 'add' channel).
        if (e.kind === 'tool' && e.verdict === 'review') {
          setPendingApproval(e);
          setApprovalStatus({ kind: 'idle' });
        }
      },
      (resolvedId, finalVerdict, rawStatus) => {
        // Daemon resolved a pending entry (`activity-result` or
        // `remove`). Update the matching LIVE row's verdict so it
        // stops rendering as `pending`, and clear the approval card
        // if it was tracking this id.
        //
        // rawStatus distinguishes `dlp` from a generic `block` — the
        // mapResultStatus collapse loses that, so we bump
        // sessionActivityAgg.dlp here based on the raw value. Without
        // this, DLP blocks (which arrive only as `activity-result`
        // resolves with status='dlp', not as pending events with a
        // checkedBy field) silently fail to register in LIVE SECURITY.
        setSessionActivityAgg((prev) => applyResolveStatus(prev, rawStatus));
        if (finalVerdict) {
          setEvents((prev) => {
            const target = prev.find((e) => e.kind === 'tool' && e.id === resolvedId);
            // Counter delta: the pending event was already counted in
            // `events` when it arrived, but its allow/block/review
            // bucket was 0 (verdict was 'pending'). Now that the final
            // verdict is in, bump the matching bucket so the
            // SessionCounters strip stays consistent.
            if (target && target.kind === 'tool' && target.verdict !== finalVerdict) {
              setSessionCounters((c) => ({
                events: c.events,
                allow: c.allow + (finalVerdict === 'allow' ? 1 : 0),
                block: c.block + (finalVerdict === 'block' ? 1 : 0),
                review: c.review + (finalVerdict === 'review' ? 1 : 0),
              }));
            }
            return prev.map((e) =>
              e.kind === 'tool' && e.id === resolvedId ? { ...e, verdict: finalVerdict } : e
            );
          });
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

  // Audit aggregation — gated to [2] Report view (Phase 1). On Realtime,
  // agg stays null and the Risk panel renders zero history counts; live
  // SSE-driven `forensicAgg` keeps the panel informative without needing
  // a history walk. When the user enters [2], this effect kicks off the
  // chunked async read; the [r] handler also re-fires it on demand.
  useEffect(() => {
    if (view !== 'report') return;
    let cancelled = false;
    const recompute = (): void => {
      void readAuditEntriesAsync().then((entries) => {
        if (cancelled) return;
        const startMs = windowStartMs(window, openedAt);
        setAgg(aggregateAudit(entries, startMs));
      });
    };
    recompute();
    const id = setInterval(recompute, AUDIT_REFRESH_MS);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [view, window, openedAt]);

  // Blast — once at start, then every 5 min. `r` keypress also triggers below.
  useEffect(() => {
    setBlast(loadBlast());
    const id = setInterval(() => setBlast(loadBlast()), BLAST_REFRESH_MS);
    return () => clearInterval(id);
  }, []);

  // Shield status — re-read every 5s so toggling a shield via
  // `node9 shield enable/disable` is reflected promptly in the
  // RISK box and SHIELDS panel. Previously this shared the 5-min
  // BLAST_REFRESH_MS cadence, which made shield toggles look like
  // they did nothing until the next blast tick or a manual [r].
  // The read is cheap (small JSON file under ~/.node9/).
  useEffect(() => {
    setShieldStatus(loadShieldStatus());
    const id = setInterval(() => setShieldStatus(loadShieldStatus()), 5_000);
    return () => clearInterval(id);
  }, []);

  // Forensic scan signals (PII / sensitive-file-reads / etc.) — async +
  // chunked: walks ~/.claude/projects per-batch with setImmediate yields
  // so the dashboard repaint and keypress dispatch keep working during
  // the walk. Render shows '…' placeholder until first walk completes.
  //
  // (loadCostEntries / loadScanSignals removed in the Phase 1 Realtime
  // refactor: those walks fed the old HIGH LEVEL and Risk forensic-count
  // panels which were either removed or are now SSE-driven via
  // sessionForensicAgg. Cost analytics live in [2] Report exclusively
  // now; the [r] handler still calls loadCostEntries on demand for the
  // Report view's HighLevel panel further down.)

  useInput((input, key) => {
    // Quit takes priority over every mode dispatch. q quits unless we're
    // typing into the filter (where q must remain a printable character);
    // Ctrl+C always quits, even with an approval card on screen. See
    // shouldQuit() at module scope for the full rule table.
    //
    // useApp().exit() unmounts ink but does NOT terminate the process —
    // active setInterval handles (cost refresh, blast refresh, hud
    // tickers) and the SSE keep-alive socket all hold the event loop
    // open. Without an explicit process.exit, q would *sometimes* quit
    // and *sometimes* leave the user staring at a blank dashboard for
    // 30+ seconds until the next interval fired. The 50ms timeout gives
    // ink one render tick to flush its restore-cursor sequence so the
    // terminal doesn't end up in a broken state.
    if (shouldQuit(input, key, { filterInputMode })) {
      exit();
      setTimeout(() => process.exit(0), 50).unref();
      return;
    }

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
    // q / Ctrl+C are handled at the top of the handler via shouldQuit().
    if (input === '1') {
      // Top-level view switch. Realtime is the default — pressing 1
      // from anywhere returns here. See monitor-two-view.md.
      setView('realtime');
    } else if (input === '2') {
      setView('report');
    } else if (view === 'report' && (input === 't' || input === 'T')) {
      setReportPeriod('today');
    } else if (view === 'report' && (input === 'w' || input === 'W')) {
      setReportPeriod('7d');
    } else if (view === 'report' && (input === 'm' || input === 'M')) {
      // [M] maps to 30d (rolling 30 days), not 'month' (calendar month).
      // 30d is what users almost always want; 'month' is reachable via
      // the CLI flag `node9 report --period month` for parity.
      setReportPeriod('30d');
    } else if (view === 'report' && input === 'Q') {
      // [Q]uarter — rolling 90 days. NOT calendar quarter. See
      // getDateRange '90d' case for rationale.
      // Uppercase Q ONLY: lowercase `q` is the global quit (see
      // shouldQuit). Shift+Q is required to set the period.
      setReportPeriod('90d');
    } else if (
      view === 'report' &&
      (input === 'l' ||
        input === 'b' ||
        input === 'p' ||
        input === 'o' ||
        input === 's' ||
        input === 'e' ||
        input === 'L' ||
        input === 'B' ||
        input === 'P' ||
        input === 'O' ||
        input === 'S' ||
        input === 'E')
    ) {
      // Reserved for drill-down sections (Leaks / Blocks / looPs / rules /
      // Shields / Exposures). Phase 3c reserves; future phase wires them
      // to per-section detail screens. Swallow now so the keys don't fall
      // through to other handlers.
    } else if (input === 'r') {
      // Manual refresh. Updates lastRefreshAt synchronously so the
      // StatusBar timestamp ticks immediately — gives users visible
      // confirmation [r] fired even when underlying data didn't change.
      setLastRefreshAt(Date.now());
      // Audit aggregation is gated to [2] view, so we re-aggregate
      // only when the user is actually on Report. Realtime stays a
      // pure SSE stream.
      if (view === 'report') {
        void readAuditEntriesAsync().then((entries) => {
          setAgg(aggregateAudit(entries, windowStartMs(window, openedAt)));
        });
        // Cancel any in-flight scan walk and reset cache to idle so the
        // [2]-view effect (which watches lastRefreshAt) re-fires and
        // starts a fresh walk. Without the explicit cancel + reset,
        // the effect would see status='ready' or 'loading' and skip.
        const prev = scanWalkCancelRef.current;
        if (prev) prev();
        scanWalkCancelRef.current = null;
        setScanCache({ status: 'idle' });
      }
      setBlast(loadBlast());
      setShieldStatus(loadShieldStatus());
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
      return { kind: 'idle', protection: computeProtection(blast, shieldStatus) };
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
  }, [
    pendingApproval,
    approvalStatus,
    resolvedApproval,
    recentForensic,
    events,
    blast,
    shieldStatus,
    tick,
  ]);

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
        effectiveScore: computeProtection(blast, shieldStatus).effective,
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
  // Loading gate — only blast is required for first paint. agg is null
  // on Realtime by design (audit aggregation gated to [2]) so we no
  // longer wait on it. blast is a small synchronous FS read (~3 ms) so
  // this gate clears almost immediately on mount.
  const loading = !blast;
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
          <SessionCounters
            events={sessionCounters.events}
            allow={sessionCounters.allow}
            block={sessionCounters.block}
            review={sessionCounters.review}
          />
          <NotificationArea notification={notification} />
          <LiveLog
            events={events}
            errorBanner={sseError}
            maxRows={liveMaxRows}
            filter={filter}
            filterInputMode={filterInputMode}
          />
          {/* Two-row bottom: row 1 = LIVE SECURITY + SHIELDS (50/50,
              each 2-column internal); row 2 = LIVE ACTIVITY (full
              width, 3-column internal for TOOLS / SHELL / MCP). The
              extra row of chrome buys breathing room — each section
              has adequate width to render long names without
              truncation. */}
          <Box flexDirection="row" marginX={1}>
            <LiveSecurity
              blast={blast}
              forensicAgg={sessionForensicAgg}
              activityAgg={sessionActivityAgg}
            />
            <Shields shieldStatus={shieldStatus} shieldsAgg={sessionShieldsAgg} />
          </Box>
          <LiveActivity agg={sessionActivityAgg} />
        </>
      ) : (
        <ReportView
          period={reportPeriod}
          audit={reportAudit}
          blast={blast}
          scanCache={scanCache}
          shieldStatus={shieldStatus}
        />
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

// readMcpPinned / readSkillsPinned removed in Phase 1 — they fed the
// HIGH LEVEL "skills pinned" / "mcp" counters which are no longer
// rendered on Realtime. If [2] Report's HighLevel needs them later,
// either inline the counts there or restore these helpers and pass
// them in as ReportView props.
