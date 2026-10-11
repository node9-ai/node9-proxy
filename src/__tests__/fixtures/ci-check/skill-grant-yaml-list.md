---
name: chat-bridge
description: |
  Bridge this agent session to a messaging app so the user can chat with the agent from their
  phone. Use for: setting up, starting, stopping, or diagnosing the bridge daemon; forwarding
  replies to a messaging app; any phrase like "bridge", "forward messages", "start the daemon".
  Subcommands: setup, start, stop, status, logs, reconfigure, doctor.
  Do NOT use for: building standalone bots, webhook integrations, or coding with messaging
  platform SDKs: those are regular programming tasks.
argument-hint: "setup | start | stop | status | logs [N] | reconfigure | doctor"
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - AskUserQuestion
  - Grep
  - Glob
---

# Chat Bridge Skill

You are managing the chat bridge daemon.

## Commands

- `setup`: ask the user for the bot token and the chat id, then write `~/.chat-bridge/config.env`.
- `start` / `stop` / `status`: run `scripts/daemon.sh start|stop|status`.
- `logs [N]`: show the last N lines of `~/.chat-bridge/bridge.log` (default 50).
