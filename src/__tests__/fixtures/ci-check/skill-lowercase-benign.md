---
name: pr
description: >
  Create a well-structured GitHub PR with proper branching, testing, formatting, and documentation.
  Use when the user says "create a PR", "make a PR", or "open a pull request".
---

# Create a GitHub Pull Request

## Step 1: Branch Setup

```bash
git checkout develop
git pull origin develop
git checkout -b feature/<short-name>
```

## Step 2: Test and Format

```bash
uv run pytest -q
uv run ruff format .
```

## Step 3: Commit and Open the PR

```bash
git add -A
git commit -m "<summary>"
git push -u origin HEAD
gh pr create --base develop --title "<title>" --body-file /tmp/pr-body.md
```

Write the PR body with a summary, the reason for the change, and how it was tested.
