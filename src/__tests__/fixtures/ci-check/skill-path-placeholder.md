---
name: architecture-atlas
description: "Build an explorable architecture atlas as HTML."
version: 1.0.0
license: MIT
---

# Architecture Atlas Skill

## Procedure

1. Read the code and list the components and how they talk to each other.
2. Draft `SYSTEM.md` with one paragraph per component.
3. **First atlas.** Copy `assets/` into the atlas home, fill the data, build with `node`. **Where the atlas home is depends on the repo's docs policy**: ask before committing anything. Docs-friendly repos: `docs/<system>/atlas/` in-tree. Other repos: a git-ignored scratch dir.
