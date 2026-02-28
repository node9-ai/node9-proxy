# Contributing to Node9 Proxy

Thank you for helping make AI agents safer. All contributions are welcome — bug reports, feature ideas, and code.

## Getting Started

```bash
git clone https://github.com/nadav-node9/node9-proxy.git
cd node9-proxy
npm install
npm run build
```

Run the demo to verify your setup:

```bash
npm run demo
```

## How to Contribute

### Reporting Bugs

Open an issue at https://github.com/nadav-node9/node9-proxy/issues with:

- Node.js version (`node --version`)
- What you ran and what you expected
- The full error output

### Suggesting Features

Open an issue with the label `enhancement`. Describe the use case, not just the feature.

### Submitting Code

1. Fork the repo and create a branch from `main`:
   ```bash
   git checkout -b fix/your-change
   ```
2. Make your changes in `src/`.
3. Build and verify:
   ```bash
   npm run build
   ```
4. Open a Pull Request against `main`. Keep PRs focused — one fix or feature per PR.

## Project Structure

```
src/
  core.ts    # Policy engine — authorizeAction(), config loading, cloud routing
  cli.ts     # node9 CLI — proxy and login commands
  index.ts   # SDK public API — protect() wrapper
examples/
  demo.ts    # Runnable demo showing the protect() SDK
```

## Security Issues

**Do not open a public issue for security vulnerabilities.**
See [SECURITY.md](./SECURITY.md) for the responsible disclosure process.

## Code Style

- TypeScript strict mode is enabled — no `any` in new code
- Keep functions small and single-purpose
- No external dependencies without discussion first (the dependency surface is intentionally small)
