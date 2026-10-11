---
description: Commit all changes, push the branch, create or update the PR, and run local validation
allowed-tools: Bash(git rev-parse:*), Bash(git status:*), Bash(git add:*), Bash(git commit:*), Bash(git push:*), Bash(gh pr view:*), Bash(gh pr create:*), Bash(scripts/validate.sh:*), Bash(./scripts/ship.sh:*), Read
argument-hint: ["<commit message>"] ["<pr title>"] ["<pr body>"]
---

Run the one-shot ship flow from this repository:

1. Commit all files.
2. Push the current branch.
3. Create the PR if missing (or reuse the current branch PR).
4. Run local validation.

## Command

```bash
./scripts/ship.sh $ARGUMENTS
```

## Notes

- This command refuses to run on `main` by design.
- If args are omitted, the commit message and PR title are generated from the changed files.
