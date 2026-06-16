// src/posture/secrets.ts
// Check 1 — Secrets exposure.
//
// Reuses the SAME DLP engine that runs in-path (`scanText`), so "what posture
// flags" == "what node9 would block on a tool call." Two distinct findings:
//   • plaintext secrets sitting in files the agent can read   → critical
//   • private-key / cloud-credential material on disk         → high
//
// Safety: only the secret *type* (DLP pattern name) + file location are
// recorded. The matched value (`redactedSample`) is never surfaced or shipped.

import fs from 'fs';
import path from 'path';
import os from 'os';
import { scanText } from '@node9/policy-engine';
import { AGENT_SPECS } from '../agent-wiring';
import type { CheckContext, Finding } from './types';

const MAX_FILE_BYTES = 256 * 1024;

/** Render an absolute path as `~/…` for display, never leaking the full home. */
function displayPath(p: string, home: string): string {
  if (p === home) return '~';
  // Match on a `home + sep` boundary so a sibling dir sharing the prefix
  // (e.g. /home/nadavfoo vs /home/nadav) is not mis-rendered as `~foo`.
  const prefix = home.endsWith(path.sep) ? home : home + path.sep;
  if (p.startsWith(prefix)) return '~' + path.sep + p.slice(prefix.length);
  return p;
}

/** Read a file as text with a size cap; null on any error (missing/binary/perm). */
function safeRead(file: string): string | null {
  try {
    const stat = fs.statSync(file);
    if (!stat.isFile() || stat.size === 0 || stat.size > MAX_FILE_BYTES) return null;
    return fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  }
}

/** Candidate files that commonly hold plaintext secrets. */
function candidateFiles(home: string, cwd: string): string[] {
  const files = new Set<string>();

  // .env* in the working directory (the classic leak).
  try {
    for (const name of fs.readdirSync(cwd)) {
      if (name === '.env' || name.startsWith('.env.')) files.add(path.join(cwd, name));
    }
  } catch {
    /* cwd unreadable — skip */
  }

  // Agent config + MCP files (tokens routinely live in these). Scan BOTH the
  // hook file and the MCP file for every known agent — for some agents (e.g.
  // Claude) secrets live in the MCP config, not the hook settings.
  for (const spec of AGENT_SPECS) {
    if (spec.hookFile) files.add(spec.hookFile(home));
    if (spec.mcpFile) files.add(spec.mcpFile(home));
  }

  // Home-level .env.
  files.add(path.join(home, '.env'));

  return [...files];
}

/** Private-key / cloud-credential files an unsandboxed agent can read. */
function credentialMaterial(home: string): string[] {
  return [
    path.join(home, '.ssh', 'id_rsa'),
    path.join(home, '.ssh', 'id_dsa'),
    path.join(home, '.ssh', 'id_ecdsa'),
    path.join(home, '.ssh', 'id_ed25519'),
    path.join(home, '.aws', 'credentials'),
    path.join(home, '.config', 'gcloud', 'application_default_credentials.json'),
  ];
}

export function checkSecrets(ctx: CheckContext): Finding[] {
  const home = ctx.home || os.homedir();
  const findings: Finding[] = [];

  // ── Plaintext secrets in readable files (critical) ──────────────────────
  const plaintext: string[] = [];
  const plaintextPaths: string[] = [];
  for (const file of candidateFiles(home, ctx.cwd)) {
    const text = safeRead(file);
    if (!text) continue;
    const match = scanText(text);
    if (match) {
      // Type + location only — never the value.
      plaintext.push(`${match.patternName} in ${displayPath(file, home)}`);
      plaintextPaths.push(file);
    }
  }
  if (plaintext.length > 0) {
    findings.push({
      category: 'Secrets',
      severity: 'critical',
      title: `${plaintext.length} plaintext secret${plaintext.length === 1 ? '' : 's'} on disk`,
      what: 'API keys/tokens are sitting unencrypted in files on disk.',
      why: 'They were saved in plaintext config / .env files.',
      who: 'A tricked agent (or any program you run) could read and leak them.',
      detail: plaintext,
      fix: 'node9 can gate reads of these files in-path (DLP block).',
      // Coverage is decided at the DLP layer — does node9 block the agent
      // reading these? (See enforcement.ts.)
      coverageProbe: { kind: 'fileRead', paths: plaintextPaths },
    });
  }

  // ── Credential material the agent can read (high) ───────────────────────
  const creds: string[] = [];
  const credPaths: string[] = [];
  for (const file of credentialMaterial(home)) {
    try {
      if (fs.statSync(file).isFile()) {
        creds.push(displayPath(file, home));
        credPaths.push(file);
      }
    } catch {
      /* absent — good */
    }
  }
  if (creds.length > 0) {
    findings.push({
      category: 'Secrets',
      severity: 'high',
      title: `${creds.length} credential file${creds.length === 1 ? '' : 's'} readable by the agent`,
      what: 'Your SSH keys / cloud login files can be read by programs you run.',
      why: 'They sit unlocked in your home folder.',
      who: 'An unsandboxed agent could read them and use them to reach your servers / cloud.',
      detail: creds,
      fix: 'node9 can block reads of sensitive paths (~/.ssh, ~/.aws) in-path.',
      coverageProbe: { kind: 'fileRead', paths: credPaths },
    });
  }

  return findings;
}
