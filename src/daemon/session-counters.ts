// src/daemon/session-counters.ts
// In-memory session counters for the node9 HUD.
// Counters are daemon-lifetime — they reset when the daemon restarts.
// No persistence required: this is ambient awareness, not audit.

export interface HudStatus {
  mode: 'standard' | 'strict' | 'observe' | 'audit';
  session: {
    allowed: number;
    blocked: number;
    dlpHits: number;
    wouldBlock: number;
    estimatedCost: number;
  };
  taintedCount: number;
  lastRuleHit: string | null;
  lastBlockedTool: string | null;
}

class SessionCounters {
  private _allowed = 0;
  private _blocked = 0;
  private _dlpHits = 0;
  private _wouldBlock = 0;
  private _estimatedCost = 0;
  private _lastRuleHit: string | null = null;
  private _lastBlockedTool: string | null = null;

  incrementAllowed(): void {
    this._allowed++;
  }
  incrementBlocked(): void {
    this._blocked++;
  }
  incrementDlpHits(): void {
    this._dlpHits++;
  }
  incrementWouldBlock(): void {
    this._wouldBlock++;
  }

  addCost(amount: number): void {
    this._estimatedCost += amount;
  }

  recordRuleHit(label: string): void {
    this._lastRuleHit = label;
  }
  recordBlockedTool(toolName: string): void {
    this._lastBlockedTool = toolName;
  }

  get(): {
    allowed: number;
    blocked: number;
    dlpHits: number;
    wouldBlock: number;
    estimatedCost: number;
    lastRuleHit: string | null;
    lastBlockedTool: string | null;
  } {
    return {
      allowed: this._allowed,
      blocked: this._blocked,
      dlpHits: this._dlpHits,
      wouldBlock: this._wouldBlock,
      estimatedCost: this._estimatedCost,
      lastRuleHit: this._lastRuleHit,
      lastBlockedTool: this._lastBlockedTool,
    };
  }

  reset(): void {
    this._allowed = 0;
    this._blocked = 0;
    this._dlpHits = 0;
    this._wouldBlock = 0;
    this._estimatedCost = 0;
    this._lastRuleHit = null;
    this._lastBlockedTool = null;
  }
}

export const sessionCounters = new SessionCounters();
