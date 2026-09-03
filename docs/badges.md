# node9 badges

Drop-in Markdown for showing that a project's agent-security surface is checked by node9.

Two badges ship. One is for projects that use node9; the other is reserved for this repository.

## `scanned by node9`

Use this on any public project where the node9 Action runs in CI. It says that the repo's
committed agent configuration — CI workflows, agent settings, MCP servers, instruction files — is
inspected on every pull request, and it links readers back to node9 so they can judge what the
badge is worth.

![scanned by node9](https://img.shields.io/badge/scanned%20by-node9-a855f7?style=flat&labelColor=%231A1A2E&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNCAxNCI+PHBhdGggZmlsbD0iI0Y1RTlGRiIgZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik03IDAuNCAxLjYgMi41djQuMmMwIDMuMSAyLjMgNS42IDUuNCA2LjkgMy4xLTEuMyA1LjQtMy44IDUuNC02LjlWMi41TDcgMC40Wm0wIDEuNSAzLjkgMS41djMuM2MwIDIuMy0xLjYgNC4yLTMuOSA1LjMtMi4zLTEuMS0zLjktMy0zLjktNS4zVjMuNEw3IDEuOVptMCAyLjJhMS45IDEuOSAwIDAgMC0xIDMuNXYxLjZoMlY3LjZhMS45IDEuOSAwIDAgMC0xLTMuNVoiLz48L3N2Zz4K)

### Requirements

Only display this badge if the node9 Action genuinely runs on every pull request. The honest CI
wiring is the signal; the badge is only a surface for it. A badge on a repo that does not run the
check is misleading, and it devalues the badge for everyone who does.

The minimum is a job that runs `node9-ai/node9-proxy@v2` on `pull_request`:

```yaml
# .github/workflows/agent-security.yml
name: node9 agent-security
on: pull_request
permissions:
  contents: read
  pull-requests: write
  checks: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: node9-ai/node9-proxy@v2
        with:
          fail-on: high # 'never' to comment without gating
```

`fail-on: never` still counts as running the check: the badge claims the surface is _inspected_,
not that merges are blocked.

### Markdown

```markdown
[![scanned by node9](https://img.shields.io/badge/scanned%20by-node9-a855f7?style=flat&labelColor=%231A1A2E&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNCAxNCI+PHBhdGggZmlsbD0iI0Y1RTlGRiIgZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik03IDAuNCAxLjYgMi41djQuMmMwIDMuMSAyLjMgNS42IDUuNCA2LjkgMy4xLTEuMyA1LjQtMy44IDUuNC02LjlWMi41TDcgMC40Wm0wIDEuNSAzLjkgMS41djMuM2MwIDIuMy0xLjYgNC4yLTMuOSA1LjMtMi4zLTEuMS0zLjktMy0zLjktNS4zVjMuNEw3IDEuOVptMCAyLjJhMS45IDEuOSAwIDAgMC0xIDMuNXYxLjZoMlY3LjZhMS45IDEuOSAwIDAgMC0xLTMuNVoiLz48L3N2Zz4K)](https://github.com/node9-ai/node9-proxy)
```

### HTML

```html
<a href="https://github.com/node9-ai/node9-proxy">
  <img
    alt="scanned by node9"
    src="https://img.shields.io/badge/scanned%20by-node9-a855f7?style=flat&labelColor=%231A1A2E&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNCAxNCI+PHBhdGggZmlsbD0iI0Y1RTlGRiIgZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik03IDAuNCAxLjYgMi41djQuMmMwIDMuMSAyLjMgNS42IDUuNCA2LjkgMy4xLTEuMyA1LjQtMy44IDUuNC02LjlWMi41TDcgMC40Wm0wIDEuNSAzLjkgMS41djMuM2MwIDIuMy0xLjYgNC4yLTMuOSA1LjMtMi4zLTEuMS0zLjktMy0zLjktNS4zVjMuNEw3IDEuOVptMCAyLjJhMS45IDEuOSAwIDAgMC0xIDMuNXYxLjZoMlY3LjZhMS45IDEuOSAwIDAgMC0xLTMuNVoiLz48L3N2Zz4K"
  />
</a>
```

### Placement

Put it with the other status badges at the top of the README. It follows the standard shields.io
layout, so it sits cleanly next to CI, coverage, and license badges.

### Link target

Link the badge to `https://github.com/node9-ai/node9-proxy` so a reader can click through and find out what it asserts. Linking to
your own passing CI run instead is also fine.

## `node9 self-scanned`

**Reserved for this repository.** It says that node9 runs its own Action against its own source on
every pull request, and gates merges on the result — dogfooding in public. It links to the workflow
that does it, so the claim is checkable in one click.

![node9 self-scanned](https://img.shields.io/badge/node9-self--scanned-a855f7?style=flat&labelColor=%231A1A2E&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNCAxNCI+PHBhdGggZmlsbD0iI0Y1RTlGRiIgZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik03IDAuNCAxLjYgMi41djQuMmMwIDMuMSAyLjMgNS42IDUuNCA2LjkgMy4xLTEuMyA1LjQtMy44IDUuNC02LjlWMi41TDcgMC40Wm0wIDEuNSAzLjkgMS41djMuM2MwIDIuMy0xLjYgNC4yLTMuOSA1LjMtMi4zLTEuMS0zLjktMy0zLjktNS4zVjMuNEw3IDEuOVptMCAyLjJhMS45IDEuOSAwIDAgMC0xIDMuNXYxLjZoMlY3LjZhMS45IDEuOSAwIDAgMC0xLTMuNVoiLz48L3N2Zz4K)

```markdown
[![node9 self-scanned](https://img.shields.io/badge/node9-self--scanned-a855f7?style=flat&labelColor=%231A1A2E&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNCAxNCI+PHBhdGggZmlsbD0iI0Y1RTlGRiIgZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik03IDAuNCAxLjYgMi41djQuMmMwIDMuMSAyLjMgNS42IDUuNCA2LjkgMy4xLTEuMyA1LjQtMy44IDUuNC02LjlWMi41TDcgMC40Wm0wIDEuNSAzLjkgMS41djMuM2MwIDIuMy0xLjYgNC4yLTMuOSA1LjMtMi4zLTEuMS0zLjktMy0zLjktNS4zVjMuNEw3IDEuOVptMCAyLjJhMS45IDEuOSAwIDAgMC0xIDMuNXYxLjZoMlY3LjZhMS45IDEuOSAwIDAgMC0xLTMuNVoiLz48L3N2Zz4K)](https://github.com/node9-ai/node9-proxy/blob/main/.github/workflows/agent-security.yml)
```

On any other project, use `scanned by node9` above. This wording is only honest here.

## Brand

- Label background: `#1A1A2E`
- Message background: `#a855f7` (the node9 accent)
- Logo: `#F5E9FF`, a shield glyph inlined as an SVG data URI

shields.io renders an inlined SVG verbatim rather than tinting it, so the fill is baked into the
glyph. Do not change the colours or substitute a different logo. The consistency is the point: a
badge is only recognisable if it looks the same everywhere.

## Problems

If the badge renders oddly in your README, open an issue on
[node9-ai/node9-proxy](https://github.com/node9-ai/node9-proxy/issues) with the rendered image and your README source.
