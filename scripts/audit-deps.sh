#!/usr/bin/env bash
# Dependency audit with THREE outcomes instead of two.
#
# `npm audit` exits non-zero both when it FINDS a vulnerability and when it
# could not ASK (registry outage, endpoint retired, or a hang). CI used to
# treat those identically, so an npm-side incident read as a security failure
# and blocked every merge to main — measured 2026-09-04: 503 on ubuntu, 400 on
# windows, and a 90s hang locally, all on an unchanged lockfile.
#
#   clean        -> exit 0
#   vulnerable   -> exit 1   (the gate; unchanged behaviour)
#   unavailable  -> exit 0 + ::warning:: + a line in the step summary that says
#                   the audit DID NOT RUN. "Could not check" is not "checked".
#   anything else-> exit non-zero (fail closed; never mistaken for clean)
#
# Usage: scripts/audit-deps.sh [npm audit args...]
# Env:   AUDIT_TIMEOUT (seconds, default 120)
#        AUDIT_EXEMPTIONS — exemptions file (default scripts/audit-exemptions.json)
#        AUDIT_TODAY — YYYY-MM-DD test seam for exemption expiry
#
# Exemptions: an advisory with NO patched version blocks every merge until
# upstream ships one. scripts/audit-exemptions.json lists such advisories,
# each with a reason and an expiry date. A finding passes only when EVERY
# advisory behind every package at or above the threshold is exempted and not
# expired; it then exits 0 with a ::warning:: naming the exemption, never a
# silent pass. An expired exemption stops applying on its date.
#        AUDIT_STUB_RC / AUDIT_STUB_STDOUT / AUDIT_STUB_STDERR — test seams that
#        bypass npm so every branch can be exercised without the network.
set -uo pipefail

label="npm audit ${*:-}"
timeout_s="${AUDIT_TIMEOUT:-120}"

if [[ -n "${AUDIT_STUB_RC:-}" ]]; then
  rc="$AUDIT_STUB_RC"; out="${AUDIT_STUB_STDOUT:-}"; err="${AUDIT_STUB_STDERR:-}"
else
  errfile="$(mktemp)"
  out="$(timeout "$timeout_s" npm audit --json "$@" 2>"$errfile")"; rc=$?
  err="$(cat "$errfile")"; rm -f "$errfile"
fi

summary() { # $1 = markdown line
  echo "$1"
  [[ -n "${GITHUB_STEP_SUMMARY:-}" ]] && echo "$1" >> "$GITHUB_STEP_SUMMARY" || true
}

# Did npm produce a real audit result? Only then is exit 1 a finding.
has_report=0
if [[ -n "$out" ]] && node -e '
  let d; try { d = JSON.parse(require("fs").readFileSync(0, "utf8")); } catch { process.exit(1); }
  process.exit(d && d.metadata && d.metadata.vulnerabilities ? 0 : 1);
' <<<"$out"; then has_report=1; fi

if (( rc == 0 )) && (( has_report )); then
  summary "✅ ${label}: no vulnerabilities at or above the threshold."
  exit 0
fi

if (( rc == 124 )); then
  summary "⚠️ ${label}: **DID NOT RUN** — npm did not answer within ${timeout_s}s. Dependencies were NOT checked on this run."
  echo "::warning title=Dependency audit did not run::npm audit hung for ${timeout_s}s; skipped, not passed."
  exit 0
fi

if [[ "$err" == *"audit endpoint returned an error"* ]] || { [[ -n "$out" ]] && (( has_report == 0 )) && node -e '
  let d; try { d = JSON.parse(require("fs").readFileSync(0, "utf8")); } catch { process.exit(1); }
  process.exit(d && d.error ? 0 : 1);
' <<<"$out"; }; then
  summary "⚠️ ${label}: **DID NOT RUN** — the npm audit endpoint returned an error. Dependencies were NOT checked on this run."
  echo "::warning title=Dependency audit did not run::npm audit endpoint unavailable; skipped, not passed."
  printf '%s\n' "$err" | tail -n 3 >&2
  exit 0
fi

if (( rc == 1 )) && (( has_report )); then
  exemptions_file="${AUDIT_EXEMPTIONS:-$(dirname "$0")/audit-exemptions.json}"
  AUDIT_ARGS="$*" EXEMPT_FILE="$exemptions_file" node -e '
    const fs = require("fs");
    const d = JSON.parse(fs.readFileSync(0, "utf8"));
    const order = ["info", "low", "moderate", "high", "critical"];
    const lv = /--audit-level[= ](\w+)/.exec(process.env.AUDIT_ARGS || "");
    const level = Math.max(0, order.indexOf(lv ? lv[1] : "info"));
    const today = process.env.AUDIT_TODAY || new Date().toISOString().slice(0, 10);
    let listed = [];
    try {
      listed = JSON.parse(fs.readFileSync(process.env.EXEMPT_FILE, "utf8")).exemptions || [];
    } catch {
      listed = [];
    }
    const active = new Map();
    const expired = [];
    for (const e of listed) {
      if (!e || typeof e.advisory !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(e.expires || "")) continue;
      if (e.expires >= today) active.set(e.advisory, e);
      else expired.push(e);
    }
    const vulns = d.vulnerabilities || {};
    const advisoryOf = (via) =>
      via && typeof via === "object" && typeof via.url === "string"
        ? (via.url.match(/GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}/i) || [])[0]
        : undefined;
    // A package is exempt only when EVERY advisory reaching it, directly or
    // through another vulnerable package, is on the active list.
    const exempt = (name, seen = new Set()) => {
      if (seen.has(name)) return true;
      seen.add(name);
      const v = vulns[name];
      if (!v || !Array.isArray(v.via) || v.via.length === 0) return false;
      return v.via.every((x) => (typeof x === "string" ? exempt(x, seen) : active.has(advisoryOf(x))));
    };
    const gating = Object.entries(vulns).filter(([, v]) => order.indexOf(v && v.severity) >= level);
    const remaining = gating.filter(([n]) => !exempt(n));
    const used = [...new Set(gating.flatMap(([, v]) => (v.via || []).map(advisoryOf)).filter((a) => active.has(a)))];
    for (const e of expired) console.log(`   exemption for ${e.advisory} (${e.package || "?"}) expired on ${e.expires}: no longer applied`);
    if (gating.length > 0 && remaining.length === 0) {
      for (const a of used) console.log(`   exempted: ${a} (${active.get(a).package || "?"}) until ${active.get(a).expires}`);
      process.exit(3);
    }
    const v = d.metadata.vulnerabilities || {};
    const parts = Object.entries(v).filter(([, n]) => n).map(([k, n]) => `${n} ${k}`);
    console.log(`❌ vulnerabilities at or above the threshold: ${parts.join(", ") || "see report"}`);
    const shown = remaining.length > 0 ? remaining : Object.entries(vulns);
    for (const [name, x] of shown.slice(0, 15)) console.log(`   - ${name}: ${x.severity}${x.fixAvailable ? "  (fix available)" : ""}`);
    process.exit(1);
  ' <<<"$out"
  verdict=$?
  if (( verdict == 3 )); then
    summary "⚠️ ${label}: only EXEMPTED advisories found (scripts/audit-exemptions.json). Passing until each exemption expires."
    echo "::warning title=Dependency audit passed on an exemption::See scripts/audit-exemptions.json; every exemption has an expiry date."
    exit 0
  fi
  summary "❌ ${label}: vulnerabilities found (see job log)."
  exit 1
fi

# Unknown shape: fail closed and show everything.
summary "❌ ${label}: unexpected result (exit ${rc}); failing closed."
printf 'stdout:\n%s\nstderr:\n%s\n' "$out" "$err" | head -n 40 >&2
exit $(( rc == 0 ? 1 : rc ))
