# node9 documentation

These pages are the source of truth for how node9 behaves. They live next to the code so the tests
in this repository can check them: a page that names a command the CLI does not have, or a command
with no page at all, fails CI.

The site at [node9.ai/docs](https://node9.ai/docs) renders these same files.

## Protections

| Page                        | What it covers                                                                                                                           |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| [Egress Control](egress.md) | Which hosts an agent may reach, the always-on floor around cloud metadata and private ranges, and what a destination gate does not cover |

## Per agent

[One page per agent](agents/README.md): how node9 is wired in, what that covers, and what it does
not. Twelve agents, split by control model.

## Reference

| Page                        | What it covers                                                                                        |
| --------------------------- | ----------------------------------------------------------------------------------------------------- |
| [Comparison](comparison.md) | Where node9 sits among agent-security tools, on the axis of what a tool can read before an agent runs |
| [Badges](badges.md)         | The `scanned by node9` badge for your own README                                                      |

## Writing a page here

Every page starts with front matter:

```yaml
---
id: egress
label: Egress Control
description: One sentence. It becomes the page's search description.
group: Protections
order: 20
---
```

`id` becomes the URL (`/docs/egress`), `group` places it in the site's left navigation, and `order`
sorts it within that group. Use GitHub-flavoured Markdown plus GitHub alerts (`> [!NOTE]`,
`> [!WARNING]`), which render in both places.

Two rules the tests enforce:

- Every command a page names must exist. Check with `node9 <command> --help` before you write it.
- Every page must state what the feature does **not** do. A page that only sells is a page that
  will be wrong within a release.
