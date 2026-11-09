// src/cli/commands/forecast-cases.ts
//
// `node9 forecast-cases <cases.jsonl>` (hidden): judge a file of benchmark
// cases through the forecast entry under the configuration of the current
// HOME, and print one JSON object per case followed by a summary. The
// dashboard's OWASP report runs it on the server against a workspace policy
// (node9Firewall#320, step 2a); the fidelity gate runs it beside the real
// hook. Nothing is written under HOME: the forecast keeps audit rows in
// memory and this command keeps no cache.
//
// A case runs only with the settings this HOME has. A case whose profile
// needs a setting that is absent (a jail path, a decoy, an egress policy, an
// organisation, the hold-action checks, the injection opt-in) is reported
// `notApplicable`, never run under a setting the owner did not choose. The
// profile's files are fixtures (decoy content), created under HOME when
// `--profiles` names the benchmark's profiles directory.

import type { Command } from 'commander';
import fs from 'fs';
import os from 'os';
import path from 'path';
import readline from 'readline';
import { checkValue, type AsiId, isAsiId } from '@node9/policy-engine';
import { catalogSettingsFrom, type Config } from '../../config';
import { forecastDecision, type ForecastVerdict } from '../../auth/forecast';
import { HistoryJudge } from './scan-judge';
import { scanArgs } from '../../dlp';
import { collectToolOutputText } from '../../tool-output';
import { readJailPaths } from '../../shields/jail';
import { loadCanaries } from '../../canary/registry';
import { PROXY_VERSION } from '../../version';
import { writePolicyCache, type CloudPolicyBody } from '../../daemon/sync';

// ── Template ─────────────────────────────────────────────────────────────────
// The benchmark keeps credential-shaped values as parts ({"$join": [...]})
// and writes paths against {{HOME}} and {{CWD}}.

export interface TemplateEnv {
  home: string;
  cwd: string;
}

export function materialize(t: unknown, env: TemplateEnv): unknown {
  if (typeof t === 'string')
    return t.replaceAll('{{HOME}}', env.home).replaceAll('{{CWD}}', env.cwd);
  if (t === null || typeof t !== 'object') return t;
  if (Array.isArray(t)) return t.map((x) => materialize(x, env));
  const o = t as Record<string, unknown>;
  const keys = Object.keys(o);
  if (keys.length === 1 && keys[0] === '$join' && Array.isArray(o.$join))
    return materialize((o.$join as unknown[]).join(''), env);
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(o)) out[k] = materialize(v, env);
  return out;
}

// ── Cases ────────────────────────────────────────────────────────────────────

export type Expected = 'allow' | 'review' | 'block';

export interface PriorCall {
  stage: 'pre' | 'post';
  input: unknown;
  output?: unknown;
}

export interface CaseRecord {
  id: string;
  owasp?: string;
  section?: 'headline' | 'vendor';
  setup: string;
  expected: Expected;
  stage: 'pre' | 'post';
  tool: string;
  input: unknown;
  output?: unknown;
  prior?: PriorCall[];
  volatile?: true;
  channel?: string;
}

interface Profile {
  name: string;
  files?: Array<{ path: string; content: unknown }>;
}

// ── Applicability ────────────────────────────────────────────────────────────

/** What each benchmark profile assumes the HOME has, and the words for it. */
export type ProfileNeed =
  | 'user-jail-path'
  | 'managed-jail-path'
  | 'decoy'
  | 'egress-block'
  | 'egress-gated'
  | 'egress-deny-list'
  | 'organisation-domain'
  | 'hold-action-checks'
  | 'injection-scan'
  | 'agent-handoff-check';

export const PROFILE_NEEDS: Readonly<Record<string, ProfileNeed | null>> = {
  clean: null,
  'asb-sandbox': null,
  'git-guardrails': null,
  'jailed-agent': 'user-jail-path',
  'user-jail': 'user-jail-path',
  'org-jail': 'managed-jail-path',
  canary: 'decoy',
  'egress-lock': 'egress-block',
  'egress-watch': 'egress-gated',
  'exposure-org': 'organisation-domain',
  'ask-before-dangerous-actions': 'hold-action-checks',
  'injection-optin': 'injection-scan',
  // The brief handed to a subagent (node9Firewall#428): the check is off by default.
  'handoff-optin': 'agent-handoff-check',
};

/** The need of a profile. An `egress-deny-*` profile is a gated egress with
 *  a deny list (the benchmark's are mode review): it needs egress on and a
 *  deny list of the customer's own, whatever its mode. */
export function profileNeed(setup: string): ProfileNeed | null | undefined {
  if (setup in PROFILE_NEEDS) return PROFILE_NEEDS[setup];
  if (setup.startsWith('egress-deny-')) return 'egress-deny-list';
  return undefined; // an unknown profile: run, and say so
}

/** Which needs this HOME satisfies, read once. */
export function homeHas(config: Config): Record<ProfileNeed, boolean> {
  const settings = catalogSettingsFrom(config.settings, config.policy);
  const value = (id: string) => checkValue(settings, id);
  const egress = config.policy.egress;
  const gated = !!egress?.enabled && (egress.mode === 'block' || egress.mode === 'review');
  let userJail = false;
  try {
    userJail = readJailPaths().length > 0;
  } catch {
    userJail = false;
  }
  let decoy = false;
  try {
    decoy = loadCanaries().length > 0;
  } catch {
    decoy = false;
  }
  const held = (id: string) => value(id) === 'review' || value(id) === 'block';
  return {
    'user-jail-path': userJail,
    'managed-jail-path': (config.policy.managedJailPaths ?? []).length > 0,
    decoy,
    'egress-block': !!egress?.enabled && egress.mode === 'block',
    'egress-gated': gated,
    'egress-deny-list': gated && (egress?.deny?.length ?? 0) > 0,
    'organisation-domain': (config.policy.untrustedContent?.orgDomains ?? []).length > 0,
    'hold-action-checks':
      held('actions.money') && held('actions.access') && held('actions.publish'),
    'injection-scan': value('behavior.prompt-injection') !== 'off',
    'agent-handoff-check': value('behavior.agent-handoff') !== 'off',
  };
}

// ── Results ──────────────────────────────────────────────────────────────────

export interface CaseResult {
  id: string;
  owasp: AsiId | 'unknown';
  section: 'headline' | 'vendor' | 'unknown';
  setup: string;
  expected: Expected;
  volatile?: true;
  /** The gate's answer, when the case ran. */
  decision?: ForecastVerdict['decision'];
  enforced?: boolean;
  checkId?: string;
  layer?: string;
  notEnforcedBecause?: string;
  unknown?: string[];
  /** The profile needs a setting this HOME lacks. */
  notApplicable?: ProfileNeed;
  /** This step cannot simulate the case; the reason. */
  notSimulated?: 'post-stage';
  error?: string;
}

export interface Cell {
  attacks: number;
  stopped: number;
  loggedOnly: number;
  passed: number;
  benign: number;
  interrupted: number;
  notApplicable: number;
  notSimulated: number;
  volatile: number;
  /** An attack the forecast let through while it could not reproduce an
   *  input the verdict depends on (`unknown`, e.g. the package registry when
   *  offline): neither stopped nor passed, and not in `attacks`. */
  undetermined: number;
  errors: number;
}

export interface Summary {
  engineVersion: string;
  mode: string;
  policySource: 'local' | 'workspace';
  cases: number;
  byRisk: Record<string, Record<'headline' | 'vendor' | 'unknown', Cell>>;
  /** Headline attacks the policy let through (recorded or not), under the
   *  case's own risk: by the check that saw them, with its value, and the
   *  count no check named. Vendor cases never enter it. */
  passedHeadline: Record<string, PassedHeadline>;
  /** Superseded by `passedHeadline` (both sections, keyed by check alone, so
   *  a reader files a case under the check's risk): kept one release for
   *  servers that read stored summaries of older runs. */
  passedByCheck: Record<string, { value: string; count: number }>;
  /** Superseded by `passedHeadline[risk].unattributed` (this one sums both sections). */
  passedUnattributed: Record<string, number>;
  notApplicableBy: Record<ProfileNeed, number>;
}

export interface PassedHeadline {
  byCheck: Record<string, { value: string; count: number }>;
  unattributed: number;
}

const emptyCell = (): Cell => ({
  attacks: 0,
  stopped: 0,
  loggedOnly: 0,
  passed: 0,
  benign: 0,
  interrupted: 0,
  notApplicable: 0,
  notSimulated: 0,
  volatile: 0,
  undetermined: 0,
  errors: 0,
});

export function summarize(results: CaseResult[], config: Config): Summary {
  const settings = catalogSettingsFrom(config.settings, config.policy);
  const byRisk: Summary['byRisk'] = {};
  const passedByCheck: Summary['passedByCheck'] = {};
  const passedUnattributed: Summary['passedUnattributed'] = {};
  const passedHeadline: Summary['passedHeadline'] = {};
  // A headline attack the policy let through, under its own risk.
  const notePassed = (r: CaseResult) => {
    if (r.section !== 'headline') return;
    const p = (passedHeadline[r.owasp] ??= { byCheck: {}, unattributed: 0 });
    if (r.checkId) {
      const e = (p.byCheck[r.checkId] ??= { value: checkValue(settings, r.checkId), count: 0 });
      e.count++;
    } else p.unattributed++;
  };
  const notApplicableBy = {} as Record<ProfileNeed, number>;
  const cell = (r: CaseResult): Cell => {
    const risk = (byRisk[r.owasp] ??= {
      headline: emptyCell(),
      vendor: emptyCell(),
      unknown: emptyCell(),
    });
    return risk[r.section];
  };
  for (const r of results) {
    const c = cell(r);
    if (r.error) {
      c.errors++;
      continue;
    }
    if (r.notApplicable) {
      c.notApplicable++;
      notApplicableBy[r.notApplicable] = (notApplicableBy[r.notApplicable] ?? 0) + 1;
      continue;
    }
    if (r.notSimulated) {
      c.notSimulated++;
      continue;
    }
    if (r.volatile) {
      // Counted apart: the forecast's package check is offline.
      c.volatile++;
      continue;
    }
    const stopped = r.enforced === true && (r.decision === 'review' || r.decision === 'block');
    const recorded = !stopped && r.decision !== undefined && r.decision !== 'allow';
    if (r.expected === 'allow') {
      c.benign++;
      if (stopped) c.interrupted++;
      continue;
    }
    // An input the forecast could not reproduce leaves the outcome open only
    // when it could have changed it. A stop the level does not enforce
    // (observe) is known: the call goes through and is recorded.
    const notEnforcedStop =
      r.enforced === false && (r.decision === 'review' || r.decision === 'block');
    if (!stopped && !notEnforcedStop && (r.unknown?.length ?? 0) > 0) {
      c.undetermined++;
      continue;
    }
    c.attacks++;
    if (!stopped) notePassed(r);
    if (stopped) c.stopped++;
    else if (recorded) {
      c.loggedOnly++;
      if (r.checkId) {
        const e = (passedByCheck[r.checkId] ??= {
          value: checkValue(settings, r.checkId),
          count: 0,
        });
        e.count++;
      } else passedUnattributed[r.owasp] = (passedUnattributed[r.owasp] ?? 0) + 1;
    } else {
      c.passed++;
      passedUnattributed[r.owasp] = (passedUnattributed[r.owasp] ?? 0) + 1;
    }
  }
  return {
    engineVersion: PROXY_VERSION,
    mode: config.settings.mode ?? 'standard',
    policySource: config.policySource,
    cases: results.length,
    byRisk,
    passedHeadline,
    passedByCheck,
    passedUnattributed,
    notApplicableBy,
  };
}

// ── Running ──────────────────────────────────────────────────────────────────

interface HookPayload {
  tool_name?: string;
  tool_input?: unknown;
  tool_response?: unknown;
  session_id?: string;
  cwd?: string;
}

function toolOf(payload: HookPayload, fallback: string): string {
  return typeof payload.tool_name === 'string' && payload.tool_name ? payload.tool_name : fallback;
}

/** A tool result reached the session: what `scan` records for it. */
function notePostCall(
  judge: HistoryJudge,
  sessionId: string,
  tool: string,
  input: unknown,
  output: unknown,
  at: string,
  cwd: string
): void {
  const m = scanArgs(output);
  if (m) judge.noteOutputSecret(sessionId, m.patternName, at);
  judge.noteToolResult(sessionId, tool, at, cwd, {
    input,
    output: collectToolOutputText(output).text,
  });
}

export async function runCase(
  judge: HistoryJudge,
  rec: CaseRecord,
  env: TemplateEnv,
  has: Record<ProfileNeed, boolean>,
  at: string,
  online = false
): Promise<CaseResult> {
  const base: CaseResult = {
    id: rec.id,
    owasp: isAsiId(rec.owasp) ? rec.owasp : 'unknown',
    section: rec.section === 'headline' || rec.section === 'vendor' ? rec.section : 'unknown',
    setup: rec.setup,
    expected: rec.expected,
    ...(rec.volatile && { volatile: true as const }),
  };
  const need = profileNeed(rec.setup);
  if (need && !has[need]) return { ...base, notApplicable: need };
  if (rec.stage === 'post') return { ...base, notSimulated: 'post-stage' };
  const sessionId = `forecast-cases:${rec.id}`;
  const cwd = env.cwd;
  const config = judge.configFor(cwd);
  const meta = { agent: 'claude' as const, sessionId };
  for (const p of rec.prior ?? []) {
    const payload = (materialize(p.input, env) ?? {}) as HookPayload;
    const tool = toolOf(payload, rec.tool);
    if (p.stage === 'post') {
      notePostCall(judge, sessionId, tool, payload.tool_input, materialize(p.output, env), at, cwd);
      continue;
    }
    await forecastDecision(tool, payload.tool_input ?? {}, meta, {
      cwd,
      config,
      session: judge.session(sessionId),
      at: Date.parse(at),
      ...(online && { onlinePackages: true }),
    });
  }
  const payload = (materialize(rec.input, env) ?? {}) as HookPayload;
  const v = await forecastDecision(toolOf(payload, rec.tool), payload.tool_input ?? {}, meta, {
    cwd,
    config,
    session: judge.session(sessionId),
    at: Date.parse(at),
    ...(online && { onlinePackages: true }),
  });
  return {
    ...base,
    decision: v.decision,
    enforced: v.enforced,
    ...(v.checkId && { checkId: v.checkId }),
    layer: v.layer,
    ...(v.notEnforcedBecause && { notEnforcedBecause: v.notEnforcedBecause }),
    ...(v.unknown.length > 0 && { unknown: v.unknown }),
  };
}

/** Create a profile's fixture files under HOME and the scratch project. */
function materializeProfileFiles(profile: Profile, env: TemplateEnv): void {
  for (const f of profile.files ?? []) {
    const target = materialize(f.path, env) as string;
    // Fixtures stay inside HOME: a profile path outside it is refused.
    const rel = path.relative(env.home, target);
    if (rel.startsWith('..') || path.isAbsolute(rel)) continue;
    fs.mkdirSync(path.dirname(target), { recursive: true });
    const content = materialize(f.content, env);
    fs.writeFileSync(target, typeof content === 'string' ? content : JSON.stringify(content));
  }
}

export interface RunOptions {
  casesPath: string;
  profilesDir?: string;
  home: string;
  /** The project directory cases are judged in ({{CWD}}); default HOME/bench-project. */
  cwd?: string;
  /** A cloud policy sync response body: written as this HOME's rules cache before judging. */
  policy?: CloudPolicyBody & { etag?: string };
  /** The clock every case is judged at (a fixed ISO time keeps runs comparable). */
  at: string;
  /** The package check queries the advisory service and registries, as the hook does. */
  onlinePackages?: boolean;
  write: (line: string) => void;
}

/** What makes a HOME a real machine's: `--policy` refuses to write there. */
const POLICY_HOME_GUARDS = ['rules-cache.json', 'credentials.json'] as const;

export class PolicyHomeTaken extends Error {}

export async function runForecastCases(opts: RunOptions): Promise<Summary> {
  const env: TemplateEnv = {
    home: opts.home,
    cwd: opts.cwd ?? path.join(opts.home, 'bench-project'),
  };
  fs.mkdirSync(env.cwd, { recursive: true });
  // The one write under HOME this command makes, and only when asked: the
  // server judges a workspace's cases in a throwaway HOME that carries the
  // workspace's policy the way a device's daemon would have written it.
  if (opts.policy) {
    // A throwaway HOME only: on a real machine the write below would replace
    // the workspace policy its hook enforces until the next sync.
    const taken = POLICY_HOME_GUARDS.filter((f) =>
      fs.existsSync(path.join(opts.home, '.node9', f))
    );
    if (taken.length > 0)
      throw new PolicyHomeTaken(
        `--policy needs a fresh HOME; ${opts.home} already has ${taken
          .map((f) => `.node9/${f}`)
          .join(' and ')}`
      );
    writePolicyCache(opts.policy, opts.policy.etag);
    // A device that follows a workspace is keyed: the cloud config applies
    // verbatim and the local policy layers are inert. The loader reads the
    // key from the environment, so a placeholder makes this process judge as
    // such a device would. Nothing here calls the cloud (forecast context).
    if (!process.env.NODE9_API_KEY) process.env.NODE9_API_KEY = 'forecast-cases';
  }
  const judge = new HistoryJudge();
  const config = judge.configFor(env.cwd);
  const has = homeHas(config);
  const profiles = new Map<string, Profile | null>();
  const profileOf = (name: string): Profile | null => {
    if (!opts.profilesDir) return null;
    if (profiles.has(name)) return profiles.get(name)!;
    let p: Profile | null = null;
    try {
      p = JSON.parse(
        fs.readFileSync(path.join(opts.profilesDir, `${name}.json`), 'utf8')
      ) as Profile;
      materializeProfileFiles(p, env);
    } catch {
      p = null;
    }
    profiles.set(name, p);
    return p;
  };
  const results: CaseResult[] = [];
  const rl = readline.createInterface({
    input: fs.createReadStream(opts.casesPath, { encoding: 'utf8' }),
    crlfDelay: Infinity,
  });
  for await (const line of rl) {
    if (!line.trim()) continue;
    let rec: CaseRecord;
    try {
      rec = JSON.parse(line) as CaseRecord;
    } catch {
      continue;
    }
    if (!rec || typeof rec.id !== 'string') continue;
    profileOf(rec.setup);
    let result: CaseResult;
    try {
      result = await runCase(judge, rec, env, has, opts.at, opts.onlinePackages === true);
    } catch (err) {
      result = {
        id: rec.id,
        owasp: isAsiId(rec.owasp) ? rec.owasp : 'unknown',
        section: rec.section === 'headline' || rec.section === 'vendor' ? rec.section : 'unknown',
        setup: rec.setup,
        expected: rec.expected,
        error: err instanceof Error ? err.message : String(err),
      };
    }
    results.push(result);
    opts.write(JSON.stringify({ case: result }));
  }
  const summary = summarize(results, config);
  opts.write(JSON.stringify({ summary }));
  return summary;
}

export function registerForecastCasesCommand(program: Command): void {
  program
    .command('forecast-cases <cases>', { hidden: true })
    .description(
      'Judge a file of benchmark cases through the forecast entry under this HOME; JSON per case, then a summary'
    )
    .option(
      '--profiles <dir>',
      'The benchmark profiles directory: its fixture files are created under HOME'
    )
    .option('--at <iso>', 'The clock every case is judged at', '2026-01-01T00:00:00.000Z')
    .option(
      '--online-packages',
      'Let the package check query the advisory service and the registries, as the hook does (default: offline)'
    )
    .option(
      '--cwd <dir>',
      'The project directory the cases are judged in ({{CWD}}); default HOME/bench-project'
    )
    .option(
      '--policy <file>',
      "A cloud policy sync response body (JSON), written as this HOME's rules cache first"
    )
    .action(
      async (
        cases: string,
        opts: {
          profiles?: string;
          at: string;
          cwd?: string;
          policy?: string;
          onlinePackages?: boolean;
        }
      ) => {
        const casesPath = path.resolve(cases);
        if (!fs.existsSync(casesPath)) {
          console.error(`forecast-cases: no such file: ${casesPath}`);
          process.exitCode = 2;
          return;
        }
        let policy: CloudPolicyBody | undefined;
        if (opts.policy) {
          const parsed = readPolicyBody(path.resolve(opts.policy));
          if (!parsed) {
            console.error(`forecast-cases: --policy is not a JSON object: ${opts.policy}`);
            process.exitCode = 2;
            return;
          }
          policy = parsed;
        }
        try {
          await runForecastCases({
            casesPath,
            profilesDir: opts.profiles ? path.resolve(opts.profiles) : undefined,
            home: os.homedir(),
            cwd: opts.cwd ? path.resolve(opts.cwd) : undefined,
            policy,
            onlinePackages: opts.onlinePackages === true,
            at: opts.at,
            write: (line) => process.stdout.write(line + '\n'),
          });
        } catch (err) {
          if (!(err instanceof PolicyHomeTaken)) throw err;
          console.error(`forecast-cases: ${err.message}`);
          process.exitCode = 2;
        }
      }
    );
}

function readPolicyBody(file: string): (CloudPolicyBody & { etag?: string }) | undefined {
  try {
    const v: unknown = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!v || typeof v !== 'object' || Array.isArray(v)) return undefined;
    return v as CloudPolicyBody & { etag?: string };
  } catch {
    return undefined;
  }
}
