# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Added

- **Smart Runner:** Node9 now intercepts the _initial_ command you pass to it (e.g., `node9 "rm -rf /"`) and checks it against your security policy before execution.
- **Improved Gemini CLI Integration:** Fully supports the latest Gemini CLI hook schema (array-based `BeforeTool`/`AfterTool`).
- **Verbose Policy Debugging:** Added `~/.node9/policy-debug.log` and `~/.node9/hook-debug.log` to help troubleshoot complex policy decisions and hook payloads.

### Fixed

- **Case-Insensitive Tool Matching:** Tool names like `Shell`, `shell`, and `run_shell_command` are now correctly identified and intercepted regardless of casing.
- **Robust Hook Setup:** `node9 addto gemini` now automatically detects and fixes outdated object-based hook configurations in `settings.json`.
- **Terminal Prompt in Hooks:** `node9 check` now correctly fallbacks to an interactive terminal prompt (y/N) even when running as a background hook, if no Node9 Cloud API key is configured.
- **Duplicate Interception:** Fixed a bug where `run_shell_command` was in the default `ignoredTools` list, preventing it from being properly inspected.

### Changed

- `node9 addto` now supports the new array-based hook structure for Gemini CLI.
- Updated internal `GeminiSettings` interfaces to match the latest CLI specifications.

## [0.1.0] - 2026-02-01

### Added

- Initial release
- `node9 proxy` — MCP JSON-RPC interceptor (wraps any MCP server or shell command)
- `node9 login` — saves API key to `~/.node9/credentials.json` for Slack routing
- `node9.config.json` — project-level policy configuration (`standard` / `strict` modes, `dangerousWords`, `ignoredTools`)
- Local terminal HITL approval via `@inquirer/prompts`
- Slack remote approval via Node9 Cloud API (Pro)
