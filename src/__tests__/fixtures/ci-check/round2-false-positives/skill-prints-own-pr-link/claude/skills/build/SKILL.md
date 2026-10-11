---
name: build
description: Build the project and run the unit tests.
allowed-tools: Read, Grep, Glob, Bash
---

# Build

Run `make test` and fix failures. Work only from the repository: do not use WebFetch or
WebSearch for this task.

If a branch already has a pull request, find its number with
`gh pr list --head "$(git branch --show-current)" --json number` and mention it in the summary.
