// src/core.ts
// Barrel file — re-exports from focused modules for backwards compatibility.
// All importers (cli.ts, daemon/index.ts, tests) continue to import from './core'.
// New code should import directly from the relevant module.

export { redactSecrets, appendConfigAudit } from './audit';
export {
  type SmartCondition,
  type SmartRule,
  DANGEROUS_WORDS,
  DEFAULT_CONFIG,
  _resetConfigCache,
  getGlobalSettings,
  getCredentials,
  hasSlack,
  listCredentialProfiles,
  getConfig,
} from './config';
export { validateRegex, getCompiledRegex } from './utils/regex';
export {
  matchesPattern,
  shouldSnapshot,
  evaluateSmartConditions,
  checkDangerousSql,
  evaluatePolicy,
  isIgnoredTool,
  explainPolicy,
  type ExplainStep,
  type WaterfallTier,
  type ExplainResult,
} from './policy';
export {
  checkPause,
  pauseNode9,
  resumeNode9,
  getActiveTrustSession,
  writeTrustSession,
  getPersistentDecision,
} from './auth/state';
export { isDaemonRunning, DAEMON_PORT, DAEMON_HOST } from './auth/daemon';
export { type CloudApprovalResult } from './auth/cloud';
export { type AuthResult, authorizeHeadless, authorizeAction } from './auth/orchestrator';
