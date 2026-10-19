// The approval card state machine (src/daemon/cards.ts). The matrix below is
// the guard for the whole approval seam: every decider, in every order, on
// one card. A new channel or decider must add its row here.
import { describe, it, expect, beforeEach } from 'vitest';
import { CardStore, CARD_RETENTION_MS, type Card, type WaitOutcome } from '../daemon/cards';
import { personRecord, type Channel, type DecisionRecord } from '../auth/decision-record';

/** A store on a fake clock with manual timers. */
function harness(channels: Channel[] = ['terminal', 'monitor']) {
  let now = 1_000_000;
  const timers = new Map<number, { fn: () => void; at: number }>();
  let nextTimer = 1;
  const decided: Card[] = [];
  const withdrawn: Card[] = [];
  const store = new CardStore({
    now: () => now,
    setTimer: (fn, ms) => {
      const h = nextTimer++;
      timers.set(h, { fn, at: now + ms });
      return h;
    },
    clearTimer: (h) => {
      timers.delete(h as number);
    },
    onDecided: (c) => decided.push(c),
    onWithdrawn: (c) => withdrawn.push(c),
  });
  const advance = (ms: number) => {
    now += ms;
    for (const [h, t] of [...timers]) {
      if (t.at <= now) {
        timers.delete(h);
        t.fn();
      }
    }
  };
  const register = (timeoutMs: number | null = 60_000) =>
    store.register(
      { toolName: 'bash', args: { command: 'echo x' } },
      {
        kind: 'review',
        channels,
        timeoutMs,
      }
    );
  return { store, advance, register, decided, withdrawn, timers, now: () => now };
}

type Decider = {
  name: string;
  /** Applies this decider to the card; returns the record it tried to set, if any. */
  apply: (h: ReturnType<typeof harness>, card: Card) => DecisionRecord | 'withdraw' | 'abandon';
};

const person: Decider = {
  name: 'person (tail)',
  apply: (h, card) => {
    const r = personRecord('terminal', 'allow', {}, h.now());
    h.store.decide(card.id, r);
    return r;
  },
};
const native: Decider = {
  name: 'hook (native popup via /resolve)',
  apply: (h, card) => {
    const r = personRecord('native', 'deny', {}, h.now());
    h.store.decide(card.id, r);
    return r;
  },
};
const cloud: Decider = {
  name: 'hook (cloud poller via /resolve)',
  apply: (h, card) => {
    const r: DecisionRecord = {
      decision: 'deny',
      decidedBy: 'cloud',
      label: 'Organization Policy (SaaS)',
      decidedAt: h.now(),
    };
    h.store.decide(card.id, r);
    return r;
  },
};
const evaluate: Decider = {
  name: 'evaluate (policy)',
  apply: (h, card) => {
    const r: DecisionRecord = {
      decision: 'deny',
      decidedBy: 'policy',
      label: 'Smart Rule: block-x',
      decidedAt: h.now(),
    };
    h.store.decide(card.id, r);
    return r;
  },
};
const timer: Decider = {
  name: 'timer',
  apply: (h) => {
    h.advance(60_000);
    return h.store.get(h.store.open()[0]?.id ?? '')?.record ?? ({} as DecisionRecord);
  },
};
const abandon: Decider = {
  name: 'abandon (tail closed)',
  apply: (h) => {
    h.store.abandonLocalOnly();
    return 'abandon';
  },
};
const withdraw: Decider = {
  name: 'withdraw (asker left)',
  apply: (h, card) => {
    h.store.withdraw(card.id);
    return 'withdraw';
  },
};

const DECIDERS: Decider[] = [person, native, cloud, evaluate, timer, abandon, withdraw];

describe('CardStore: every pair of deciders, in both orders', () => {
  for (const first of DECIDERS) {
    for (const second of DECIDERS) {
      if (first === second) continue;
      it(`${first.name}, then ${second.name}`, async () => {
        const h = harness();
        const card = h.register();
        first.apply(h, card);
        const afterFirst = h.store.get(card.id);
        const firstRecord = afterFirst?.record;
        const firstState = afterFirst?.state;
        second.apply(h, card);
        const after = h.store.get(card.id);

        if (firstState === 'decided') {
          // The first decision stands: never overwritten, decided exactly once.
          expect(after?.record).toBe(firstRecord);
          expect(h.decided).toHaveLength(1);
          // A late wait reads it, then the card is gone.
          const o = await h.store.wait(card.id);
          expect(o).toEqual({ kind: 'decided', record: firstRecord });
          expect(h.store.get(card.id)).toBeUndefined();
        } else {
          // The first was a withdraw: a later decision is still recorded once;
          // a timer or abandon no longer applies to a withdrawn card.
          expect(firstState).toBe('withdrawn');
          expect(h.decided.length).toBeLessThanOrEqual(1);
          if (after?.state === 'decided') expect(h.decided).toHaveLength(1);
        }
      });
    }
  }
});

describe('CardStore: waiting', () => {
  let h: ReturnType<typeof harness>;
  beforeEach(() => {
    h = harness();
  });

  it('a waiter gets the decision; the card is removed once read', async () => {
    const card = h.register();
    const p = h.store.wait(card.id);
    const r = personRecord('terminal', 'deny', {}, h.now());
    expect(h.store.decide(card.id, r)).toEqual({ record: r, won: true });
    expect(await p).toEqual({ kind: 'decided', record: r });
    expect(h.store.get(card.id)).toBeUndefined();
  });

  it('a decision made before anyone waits is kept for a late wait', async () => {
    const card = h.register();
    const r = personRecord('terminal', 'allow', {}, h.now());
    h.store.decide(card.id, r);
    h.advance(5_000);
    expect(await h.store.wait(card.id)).toEqual({ kind: 'decided', record: r });
  });

  it('two waiters both get the decision', async () => {
    const card = h.register();
    const a = h.store.wait(card.id);
    const b = h.store.wait(card.id);
    const r = personRecord('native', 'allow', {}, h.now());
    h.store.decide(card.id, r);
    expect(await a).toEqual({ kind: 'decided', record: r });
    expect(await b).toEqual({ kind: 'decided', record: r });
  });

  it('one waiter leaving does not withdraw the card while another waits', async () => {
    const card = h.register();
    const ctrl = new AbortController();
    const a = h.store.wait(card.id, ctrl.signal);
    const b = h.store.wait(card.id);
    ctrl.abort();
    expect(await a).toEqual({ kind: 'withdrawn' });
    expect(h.store.get(card.id)?.state).toBe('open');
    const r = personRecord('terminal', 'allow', {}, h.now());
    h.store.decide(card.id, r);
    expect(await b).toEqual({ kind: 'decided', record: r });
  });

  it('the last waiter leaving withdraws an open card', async () => {
    const card = h.register();
    const ctrl = new AbortController();
    const a = h.store.wait(card.id, ctrl.signal);
    ctrl.abort();
    expect(await a).toEqual({ kind: 'withdrawn' });
    expect(h.store.get(card.id)?.state).toBe('withdrawn');
    expect(h.withdrawn).toHaveLength(1);
  });

  it('an older hook reports its winner after closing its wait: still recorded', () => {
    const card = h.register();
    const ctrl = new AbortController();
    void h.store.wait(card.id, ctrl.signal);
    ctrl.abort();
    const r = personRecord('native', 'allow', {}, h.now());
    expect(h.store.decide(card.id, r)).toEqual({ record: r, won: true });
    expect(h.decided).toHaveLength(1);
  });

  it('an unknown card: wait says missing, decide says null', async () => {
    expect(await h.store.wait('nope')).toEqual({ kind: 'missing' });
    expect(h.store.decide('nope', personRecord('terminal', 'allow'))).toBeNull();
  });

  it('an already aborted signal withdraws at once', async () => {
    const card = h.register();
    const ctrl = new AbortController();
    ctrl.abort();
    const o: WaitOutcome = await h.store.wait(card.id, ctrl.signal);
    expect(o).toEqual({ kind: 'withdrawn' });
    expect(h.store.get(card.id)?.state).toBe('withdrawn');
  });
});

describe('CardStore: the timer', () => {
  it('decides at the deadline, with decidedBy timer', async () => {
    const h = harness();
    const card = h.register(2_000);
    expect(card.deadline).toBe(h.now() + 2_000);
    const p = h.store.wait(card.id);
    h.advance(1_999);
    expect(h.store.get(card.id)?.state).toBe('open');
    h.advance(1);
    const o = await p;
    expect(o.kind).toBe('decided');
    expect(o.kind === 'decided' && o.record.decidedBy).toBe('timer');
    expect(o.kind === 'decided' && o.record.decision).toBe('deny');
  });

  it('timeout 0 or null: no timer, the card stays open', () => {
    for (const t of [0, null]) {
      const h = harness();
      const card = h.register(t);
      expect(card.deadline).toBeNull();
      expect(h.timers.size).toBe(0);
      h.advance(24 * 60 * 60_000);
      expect(h.store.get(card.id)?.state).toBe('open');
    }
  });

  it('a decision clears the timer', () => {
    const h = harness();
    const card = h.register(2_000);
    h.store.decide(card.id, personRecord('terminal', 'allow', {}, h.now()));
    expect(h.timers.size).toBe(0);
  });
});

describe('CardStore: abandon', () => {
  it('abandons only cards the local UIs alone could answer', async () => {
    const local = harness(['terminal', 'monitor']);
    const c1 = local.register();
    expect(local.store.abandonLocalOnly()).toBe(1);
    const o = await local.store.wait(c1.id);
    expect(o.kind === 'decided' && o.record.decidedBy).toBe('abandoned');

    for (const channels of [
      ['terminal', 'cloud'],
      ['terminal', 'native'],
    ] as Channel[][]) {
      const h = harness(channels);
      const c = h.register();
      expect(h.store.abandonLocalOnly()).toBe(0);
      expect(h.store.get(c.id)?.state).toBe('open');
    }
  });

  it('never touches a decided card', () => {
    const h = harness();
    const card = h.register();
    const r = personRecord('terminal', 'allow', {}, h.now());
    h.store.decide(card.id, r);
    expect(h.store.abandonLocalOnly()).toBe(0);
    expect(h.store.get(card.id)?.record).toBe(r);
  });
});

describe('CardStore: sweep', () => {
  it('removes a decided card nobody read after the retention', () => {
    const h = harness();
    const card = h.register(null);
    h.store.decide(card.id, personRecord('terminal', 'allow', {}, h.now()));
    h.advance(CARD_RETENTION_MS - 1);
    h.store.sweep();
    expect(h.store.get(card.id)).toBeDefined();
    h.advance(1);
    h.store.sweep();
    expect(h.store.get(card.id)).toBeUndefined();
  });

  it('withdraws an asked card nobody ever waited on', () => {
    const h = harness();
    const card = h.register(null);
    h.advance(CARD_RETENTION_MS);
    h.store.sweep();
    expect(h.store.get(card.id)?.state).toBe('withdrawn');
  });

  it('keeps an open card someone waits on, with no timer, however long', () => {
    const h = harness();
    const card = h.register(null);
    void h.store.wait(card.id);
    h.advance(10 * CARD_RETENTION_MS);
    h.store.sweep();
    expect(h.store.get(card.id)?.state).toBe('open');
  });

  it('keeps a discovery card until its own timer', () => {
    const h = harness();
    const card = h.store.register(
      { toolName: 'mcp-discovery', args: {} },
      { kind: 'discovery', channels: ['terminal', 'monitor'], timeoutMs: null }
    );
    h.advance(CARD_RETENTION_MS);
    h.store.sweep();
    expect(h.store.get(card.id)?.state).toBe('open');
  });
});

describe('CardStore: ids', () => {
  it('reuses the caller id, but never a taken one', () => {
    const h = harness();
    const a = h.store.register(
      { toolName: 't', args: {} },
      { id: 'act-1', kind: 'review', channels: ['terminal'], timeoutMs: null }
    );
    const b = h.store.register(
      { toolName: 't', args: {} },
      { id: 'act-1', kind: 'review', channels: ['terminal'], timeoutMs: null }
    );
    expect(a.id).toBe('act-1');
    expect(b.id).not.toBe('act-1');
  });
});
