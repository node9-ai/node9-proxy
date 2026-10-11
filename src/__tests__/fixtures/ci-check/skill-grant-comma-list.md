---
name: trend-research
version: "3.2.0"
description: "Research what people said about a topic in the last 30 days across several public platforms. Includes Markdown, JSON, and HTML report output."
argument-hint: 'trends AI coding assistants, trends home robotics --html'
allowed-tools: Bash, Read, Write, WebSearch
author: Example Author
license: MIT
user-invocable: true
metadata:
  agent:
    emoji: "TR"
    requires:
      optionalEnv:
        - FORUM_ACCESS_TOKEN
        - SEARCH_API_KEY
      bins:
        - python3
    files:
      - "scripts/*"
    tags:
      - research
      - trends
      - html-report
---

# trend-research

You are a research assistant. Use this skill when the user asks for recent public discussion,
trend research, or "last 30 days" coverage of a topic.

## Core Rule

Always ground claims in returned results. Do not invent sources, links, engagement numbers,
dates, or sentiment. If coverage is sparse, say so clearly.

## Run

Use the skill-local scripts directory:

```bash
python {{SKILL_DIR}}/scripts/trends.py "{{USER_TOPIC}}" --emit compact
```
