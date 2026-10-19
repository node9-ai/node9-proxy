// src/daemon/cards.ts
// The approval card as a state machine: the ONLY place a card's decision is
// written. Before this store, seven actors ended a card through five routes,
// each writing the decision, the audit row, the broadcast and the delete in
// its own way: a late decision could overwrite a person's, a decision could
// be deleted before the hook read it, a card could stay on screen forever.
// Design: docs roadmap/active/approval-card-ownership-code-design.md.
//
// No HTTP here. The daemon's routes are adapters: parse, call the store,
// answer. Side effects of a decision (broadcast, audit, insight counts) hang
// off `onDecided`, which fires exactly once per card.

import { randomUUID } from 'crypto';
import type { RiskMetadata } from '../context-sniper';
import {
  LOCAL_UI_CHANNELS,
  abandonedRecord,
  timerRecord,
  type Channel,
  type DecisionRecord,
} from '../auth/decision-record';

/**
 * - `review`: node9's own callers (hook, gateway, proxy). The caller already
 *   decided this call needs a person; the daemon never evaluates it.
 * - `evaluate`: external callers (the Python SDK). The daemon checks the call
 *   with the caller's working directory, then holds a review for a person.
 * - `discovery`: an MCP server's new or changed tool list, for a person to
 *   approve in node9 tail. Nobody waits for it.
 */
export type CardKind = 'review' | 'evaluate' | 'discovery';
export type CardState = 'open' | 'decided' | 'withdrawn';

export interface CardRequest {
  toolName: string;
  args: unknown;
  riskMetadata?: RiskMetadata;
  /** Recovery command for the node9 tail recovery menu. */
  recoveryCommand?: string;
  /** Shown for context only; no channel may decide it. */
  viewOnly?: boolean;
  agent?: string;
  mcpServer?: string;
  sessionId?: string;
  cwd?: string;
  /** CARD_PROTOCOL when the caller speaks it: its /wait must carry the token. */
  protocol?: number;
  /** discovery cards */
  serverKey?: string;
  mcpTools?: Array<{ name: string; description?: string }>;
}

export interface Card {
  readonly id: string;
  readonly kind: CardKind;
  state: CardState;
  readonly request: CardRequest;
  /** Who may answer. */
  readonly channels: readonly Channel[];
  readonly createdAt: number;
  /** Epoch ms when the timer decides the card, or null for no timer. */
  readonly deadline: number | null;
  /** Set once, never changed. */
  record?: DecisionRecord;
  /** When the card left `open`. */
  closedAt?: number;
}

export type WaitOutcome =
  { kind: 'decided'; record: DecisionRecord } | { kind: 'withdrawn' } | { kind: 'missing' };

export interface RegisterOptions {
  /** Reuse the caller's id (the flight recorder's activity id). */
  id?: string;
  kind: CardKind;
  channels: readonly Channel[];
  /** Milliseconds until the timer decides the card; 0 or null = no timer. */
  timeoutMs: number | null;
}

export interface CardStoreDeps {
  now?: () => number;
  setTimer?: (fn: () => void, ms: number) => unknown;
  clearTimer?: (handle: unknown) => void;
  /** Fires exactly once per card, when it is decided. */
  onDecided?: (card: Card) => void;
  /** Fires when an open card loses its asker. */
  onWithdrawn?: (card: Card) => void;
}

/** How long a decided card nobody read, or a withdrawn card, is kept. Also how
 *  long an asked card may stay open with no one ever waiting on it. */
export const CARD_RETENTION_MS = 60_000;

interface Slot {
  card: Card;
  waiters: Set<(o: WaitOutcome) => void>;
  everWaited: boolean;
  timer?: unknown;
}

export class CardStore {
  private readonly slots = new Map<string, Slot>();
  private readonly now: () => number;
  private readonly setTimer: (fn: () => void, ms: number) => unknown;
  private readonly clearTimer: (handle: unknown) => void;
  private readonly deps: CardStoreDeps;

  constructor(deps: CardStoreDeps = {}) {
    this.deps = deps;
    this.now = deps.now ?? Date.now;
    this.setTimer =
      deps.setTimer ??
      ((fn, ms) => {
        const t = setTimeout(fn, ms);
        t.unref?.();
        return t;
      });
    this.clearTimer = deps.clearTimer ?? ((h) => clearTimeout(h as ReturnType<typeof setTimeout>));
  }

  register(request: CardRequest, opts: RegisterOptions): Card {
    const id = opts.id && !this.slots.has(opts.id) ? opts.id : randomUUID();
    const createdAt = this.now();
    const timeoutMs = opts.timeoutMs && opts.timeoutMs > 0 ? opts.timeoutMs : null;
    const card: Card = {
      id,
      kind: opts.kind,
      state: 'open',
      request,
      channels: [...opts.channels],
      createdAt,
      deadline: timeoutMs === null ? null : createdAt + timeoutMs,
    };
    const slot: Slot = { card, waiters: new Set(), everWaited: false };
    if (timeoutMs !== null) {
      slot.timer = this.setTimer(() => {
        slot.timer = undefined;
        this.decide(id, timerRecord(timeoutMs, this.now()));
      }, timeoutMs);
    }
    this.slots.set(id, slot);
    return card;
  }

  get(id: string): Card | undefined {
    return this.slots.get(id)?.card;
  }

  /** Cards still waiting for a decision, oldest first. */
  open(): Card[] {
    return [...this.slots.values()].filter((s) => s.card.state === 'open').map((s) => s.card);
  }

  /**
   * The ONLY way a card gets a decision. The first call wins; a later call
   * gets the winning record back with `won: false`. A withdrawn card can
   * still be decided (its asker, an older hook, may report its own winner
   * after closing its wait). Null when the card does not exist.
   */
  decide(id: string, record: DecisionRecord): { record: DecisionRecord; won: boolean } | null {
    const slot = this.slots.get(id);
    if (!slot) return null;
    const { card } = slot;
    if (card.state === 'decided') return { record: card.record!, won: false };
    if (slot.timer !== undefined) {
      this.clearTimer(slot.timer);
      slot.timer = undefined;
    }
    card.state = 'decided';
    card.record = record;
    card.closedAt = this.now();
    this.deps.onDecided?.(card);
    if (slot.waiters.size > 0) {
      const waiters = [...slot.waiters];
      slot.waiters.clear();
      for (const w of waiters) w({ kind: 'decided', record });
      // The asker has the record: nothing else needs the card.
      this.slots.delete(id);
    }
    return { record, won: true };
  }

  /** The asker left before any decision. False when the card was not open. */
  withdraw(id: string): boolean {
    const slot = this.slots.get(id);
    if (!slot || slot.card.state !== 'open') return false;
    if (slot.timer !== undefined) {
      this.clearTimer(slot.timer);
      slot.timer = undefined;
    }
    slot.card.state = 'withdrawn';
    slot.card.closedAt = this.now();
    const waiters = [...slot.waiters];
    slot.waiters.clear();
    for (const w of waiters) w({ kind: 'withdrawn' });
    this.deps.onWithdrawn?.(slot.card);
    return true;
  }

  /**
   * Wait for the card's decision. Any number of waiters. A decided card
   * answers at once, and is removed once read. When the last waiter of an
   * open card goes away (its signal aborts), the card is withdrawn: nobody is
   * left to act on a decision.
   */
  wait(id: string, signal?: AbortSignal): Promise<WaitOutcome> {
    const slot = this.slots.get(id);
    if (!slot) return Promise.resolve({ kind: 'missing' });
    const { card } = slot;
    if (card.state === 'decided') {
      this.slots.delete(id);
      return Promise.resolve({ kind: 'decided', record: card.record! });
    }
    if (card.state === 'withdrawn') return Promise.resolve({ kind: 'withdrawn' });
    slot.everWaited = true;
    return new Promise<WaitOutcome>((resolve) => {
      const waiter = (o: WaitOutcome) => {
        signal?.removeEventListener('abort', onAbort);
        resolve(o);
      };
      const onAbort = () => {
        if (!slot.waiters.delete(waiter)) return;
        resolve({ kind: 'withdrawn' });
        if (slot.waiters.size === 0 && card.state === 'open') this.withdraw(id);
      };
      slot.waiters.add(waiter);
      if (signal) {
        if (signal.aborted) onAbort();
        else signal.addEventListener('abort', onAbort, { once: true });
      }
    });
  }

  /**
   * The daemon's local UIs all went away. Open cards that only they could
   * answer are decided as abandoned; a card that Slack or the native popup
   * can still answer stays open. Returns how many were abandoned.
   */
  abandonLocalOnly(): number {
    let n = 0;
    for (const card of this.open()) {
      const localOnly =
        card.channels.length > 0 && card.channels.every((c) => LOCAL_UI_CHANNELS.has(c));
      if (!localOnly) continue;
      if (this.decide(card.id, abandonedRecord(this.now()))?.won) n++;
    }
    return n;
  }

  /**
   * Housekeeping, run every few seconds:
   * - a decided card nobody read and a withdrawn card are removed after the
   *   retention;
   * - an asked card that nobody ever waited on (its asker died between
   *   registering and waiting) is withdrawn after the retention.
   */
  sweep(): void {
    const now = this.now();
    for (const [id, slot] of this.slots) {
      const { card } = slot;
      if (card.state !== 'open') {
        if (now - (card.closedAt ?? card.createdAt) >= CARD_RETENTION_MS) this.slots.delete(id);
        continue;
      }
      if (
        card.kind !== 'discovery' &&
        !slot.everWaited &&
        now - card.createdAt >= CARD_RETENTION_MS
      )
        this.withdraw(id);
    }
  }

  /** Cards in any state (tests and diagnostics). */
  size(): number {
    return this.slots.size;
  }
}
