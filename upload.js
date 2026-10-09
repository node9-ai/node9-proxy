// upload.js: sends a push scan to the node9 workspace the repository is
// connected to (repository dashboard). Runs only when the caller passes
// `node9-upload-key`, only on `push`, and never changes the job's result:
// every path ends with exit code 0, and the gate in comment.js is unaffected.
//
// Credentials: the upload key (a repository secret) and a GitHub OIDC token
// with audience `node9`, which proves which repository, branch, workflow and
// commit produced the scan. The server checks both; the envelope fields below
// must agree with the token's claims.
//
// Dependency-free (Node 22 global fetch). The I/O is injected so the tests can
// drive every path without a network.

'use strict';
const fs = require('fs');
const { execFileSync } = require('child_process');

const INGEST_PATH = '/api/v1/repository-scans/ingest';
const DEFAULT_API = 'https://api.node9.ai';
// The only places a key and a token may be sent. dev-api is node9's own test
// deployment; anything else is refused, including lookalike and http URLs.
const ALLOWED_APIS = ['https://api.node9.ai', 'https://dev-api.node9.ai'];
const KEY_RE = /^n9r_[A-Za-z0-9_-]{43}$/;
const ATTEMPTS = 3;
const TIMEOUT_MS = 15_000;
const BACKOFF_MS = [2_000, 5_000];
// The server parses at most 1 MiB on this route; a larger body is refused
// before anything is sent.
const MAX_BODY_BYTES = 1024 * 1024;

/** The exact API origin, or null when the input is not an allowed one. */
function apiOrigin(input) {
  const value = String(input || DEFAULT_API)
    .trim()
    .replace(/\/+$/, '');
  return ALLOWED_APIS.includes(value) ? value : null;
}

/** One line, bounded: a server message is shown in the log and the summary. */
function oneLine(value) {
  return String(value)
    .replace(/[\r\n\u2028\u2029]+/g, ' ')
    .slice(0, 300);
}

/** The scan result as the server reads it: the findings, the files read and
 *  whether the scan was complete. The rest of the CLI output (the local path,
 *  notes) is not needed and is not sent. */
function resultPayload(raw) {
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (
    !parsed ||
    !Array.isArray(parsed.findings) ||
    !Array.isArray(parsed.inspected) ||
    typeof parsed.incomplete !== 'boolean'
  ) {
    return null;
  }
  return {
    findings: parsed.findings,
    inspected: parsed.inspected,
    incomplete: parsed.incomplete,
  };
}

/** The upload body. Every field comes from the runner's own environment, the
 *  same source GitHub uses for the token's claims. */
function buildEnvelope(env, result) {
  return {
    schemaVersion: 1,
    repository: { githubId: env.GITHUB_REPOSITORY_ID, fullName: env.GITHUB_REPOSITORY },
    ref: env.GITHUB_REF,
    commitSha: env.GITHUB_SHA,
    workflowRunId: env.GITHUB_RUN_ID,
    workflowRunAttempt: Number(env.GITHUB_RUN_ATTEMPT),
    workflowJobKey: env.GITHUB_JOB,
    scannerVersion: env.NODE9_SCANNER_VERSION,
    startedAt: env.NODE9_SCAN_STARTED_AT,
    completedAt: env.NODE9_SCAN_COMPLETED_AT,
    result,
  };
}

/** Why the envelope cannot be sent, or null. Mirrors the server's schema so a
 *  runner that lacks a field says so here instead of as a 400. */
function envelopeProblem(e) {
  const iso = (v) => typeof v === 'string' && !Number.isNaN(Date.parse(v));
  if (!/^\d{1,20}$/.test(e.repository.githubId || '')) return 'GITHUB_REPOSITORY_ID is missing';
  if (!e.repository.fullName) return 'GITHUB_REPOSITORY is missing';
  if (!e.ref) return 'GITHUB_REF is missing';
  if (!/^[0-9a-f]{40}$/.test(e.commitSha || '')) return 'GITHUB_SHA is missing';
  if (!/^\d{1,20}$/.test(e.workflowRunId || '')) return 'GITHUB_RUN_ID is missing';
  if (!Number.isInteger(e.workflowRunAttempt) || e.workflowRunAttempt < 1)
    return 'GITHUB_RUN_ATTEMPT is missing';
  if (!/^[A-Za-z0-9_.-]{1,100}$/.test(e.workflowJobKey || '')) return 'GITHUB_JOB is not usable';
  if (!/^[0-9A-Za-z.+-]{1,50}$/.test(e.scannerVersion || ''))
    return 'the scanner version is unknown';
  if (!iso(e.startedAt) || !iso(e.completedAt)) return 'the scan times are missing';
  return null;
}

/** A GitHub OIDC token for audience `node9`, or an Error saying why not. */
async function requestOidcToken(env, fetchImpl) {
  const url = env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const bearer = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!url || !bearer) {
    return new Error(
      'the job cannot request a GitHub OIDC token. Add `permissions: id-token: write` to the push job'
    );
  }
  try {
    const target = new URL(url);
    target.searchParams.set('audience', 'node9');
    const res = await fetchImpl(target.toString(), {
      headers: { Authorization: `Bearer ${bearer}`, Accept: 'application/json' },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) return new Error(`GitHub refused the OIDC token request (${res.status})`);
    const body = await res.json();
    if (!body || typeof body.value !== 'string' || !body.value) {
      return new Error('GitHub returned no OIDC token');
    }
    return body.value;
  } catch (err) {
    return new Error(`could not reach GitHub for the OIDC token (${oneLine(err.message)})`);
  }
}

/** Whether a failed attempt is worth repeating: the network, a timeout or the
 *  server itself. A refusal (4xx) or a refused redirect will not change on a
 *  retry. */
const retryable = (last) => (last.status === 0 && !last.final) || last.status >= 500;

/** A fetch that threw. A redirect is refused by design (`redirect: 'error'`)
 *  and is final; anything else thrown is the network or the timeout. */
function thrown(err) {
  const cause = err && err.cause && err.cause.message ? String(err.cause.message) : '';
  const message = err && err.message ? err.message : String(err);
  return {
    status: 0,
    final: /redirect/i.test(cause) || /redirect/i.test(message),
    message: oneLine(cause ? `${message}: ${cause}` : message),
  };
}

async function send(origin, key, token, body, deps) {
  let last = { status: 0, message: '' };
  for (let attempt = 1; attempt <= ATTEMPTS; attempt++) {
    try {
      const res = await deps.fetch(`${origin}${INGEST_PATH}`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${key}`,
          'X-GitHub-OIDC-Token': token,
          'Content-Type': 'application/json',
        },
        body,
        // A redirect would carry the token and the scan to another address.
        redirect: 'error',
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      let payload = null;
      try {
        payload = await res.json();
      } catch {
        payload = null;
      }
      if (res.ok) return { ok: true, status: res.status, payload, attempts: attempt };
      const message = payload && payload.message ? payload.message : res.statusText;
      const text = Array.isArray(message) ? message.join('; ') : String(message);
      // The log is public on a public repository: neither credential is ever
      // printed, even if a response were to repeat one.
      last = {
        status: res.status,
        message: oneLine(text.split(key).join('[key]').split(token).join('[token]')),
      };
    } catch (err) {
      last = thrown(err);
    }
    if (!retryable(last) || attempt === ATTEMPTS) {
      return { ok: false, ...last, attempts: attempt };
    }
    await deps.sleep(BACKOFF_MS[attempt - 1]);
  }
  return { ok: false, ...last, attempts: ATTEMPTS };
}

/** Runs the upload. Returns the line written to the log and the job summary;
 *  never throws and never decides the job's result. */
async function run(env, deps) {
  const skip = (reason) => ({ uploaded: false, line: `node9 upload skipped: ${reason}.` });
  const key = (env.NODE9_UPLOAD_KEY || '').trim();
  if (!key) return skip('no upload key');
  if (env.GITHUB_EVENT_NAME !== 'push') return skip('only push runs upload');
  if (!KEY_RE.test(key)) {
    return skip(
      'the upload key is not a node9 repository key. Copy it again from the repository page'
    );
  }
  const origin = apiOrigin(env.NODE9_API_URL);
  if (!origin) return skip('node9-api-url must be https://api.node9.ai');

  let head;
  try {
    head = deps.gitHead(env.GITHUB_WORKSPACE);
  } catch {
    head = '';
  }
  if (head !== env.GITHUB_SHA) {
    return skip(
      'the checked-out commit is not the pushed commit, so the result would be labelled with the wrong commit'
    );
  }

  if (!env.NODE9_RESULT) return skip('the scan step reported no result file');
  let raw;
  try {
    raw = deps.readFile(env.NODE9_RESULT);
  } catch (err) {
    return skip(`could not read the scan result (${oneLine((err && err.code) || err)})`);
  }
  const result = resultPayload(raw);
  if (!result) return skip('the scan did not produce a result');

  const envelope = buildEnvelope(env, result);
  const problem = envelopeProblem(envelope);
  if (problem) return skip(problem);
  const body = JSON.stringify(envelope);
  if (Buffer.byteLength(body, 'utf8') > MAX_BODY_BYTES)
    return skip('the result is larger than 1 MiB');

  const token = await requestOidcToken(env, deps.fetch);
  if (token instanceof Error) return skip(token.message);

  const outcome = await send(origin, key, token, body, deps);
  if (outcome.ok) {
    const again = outcome.payload && outcome.payload.duplicate ? ' (already received)' : '';
    return {
      uploaded: true,
      line: `node9: scan of ${env.GITHUB_SHA.slice(0, 7)} sent to your node9 workspace${again}.`,
    };
  }
  const why = outcome.status ? `${outcome.status} ${outcome.message}` : outcome.message;
  return {
    uploaded: false,
    line: `node9 upload failed after ${outcome.attempts} attempt${outcome.attempts === 1 ? '' : 's'}: ${why}. The check result is not affected.`,
  };
}

const realDeps = {
  fetch: (...args) => fetch(...args),
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  gitHead: (cwd) =>
    execFileSync('git', ['-C', cwd || '.', 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
  readFile: (file) => fs.readFileSync(file, 'utf8'),
};

if (require.main === module) {
  run(process.env, realDeps)
    .then(({ line }) => {
      console.log(line);
      if (process.env.GITHUB_STEP_SUMMARY) {
        try {
          fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${line}\n`);
        } catch {
          // The summary is a convenience; the log line above is enough.
        }
      }
    })
    .catch((err) => {
      console.log(
        `node9 upload failed: ${oneLine(err && err.message)}. The check result is not affected.`
      );
    })
    .finally(() => process.exit(0));
}

module.exports = {
  run,
  apiOrigin,
  resultPayload,
  buildEnvelope,
  envelopeProblem,
  ALLOWED_APIS,
  INGEST_PATH,
};
