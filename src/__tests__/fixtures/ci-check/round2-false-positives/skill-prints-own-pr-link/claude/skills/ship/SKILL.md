---
name: ship
description: Commit the current work, push the branch and open a pull request for it.
allowed-tools: Read, Edit, Write, Bash(git:*), Bash(gh pr:*)
---

# Ship

1. Run the tests and fix anything that fails.
2. Commit with a conventional message and push the branch.
3. Open the PR with `gh pr create --fill`, then print its link:

   gh pr view --json url -q .url
