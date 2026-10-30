# Node9 Firewall — Claude Code Rules

## Automated Enforcement

A pre-commit hook at `.git/hooks/pre-commit` runs these checks automatically before every `git commit`.
A pre-push hook at `.git/hooks/pre-push` runs the full checklist again before every `git push`, and requires interactive confirmation for any CI/CD workflow changes.
If it doesn't exist on your machine (hooks aren't tracked by git), recreate it from the pattern in
`node9-proxy/.git/hooks/pre-commit` or run the checks manually from the checklist below.

## PR Checklist (required before every commit)

Before committing or opening a PR, verify all of the following:

- [ ] New behavior has a test that **fails without the change**
- [ ] Backend: `npm test` passes inside `be/`
- [ ] Frontend: `npm test` passes inside `fe/`
- [ ] Backend: `npm run typecheck` passes inside `be/`
- [ ] Frontend: `npm run type-check` passes inside `fe/`
- [ ] Backend: `npm run lint` passes inside `be/`
- [ ] Frontend: `npm run lint` passes inside `fe/`
- [ ] Backend: `npm run format:check` passes inside `be/`

## Test Rules

**Every bug fix must ship with a regression test.**
Write the failing test first, then fix the code. This proves you understood the bug and prevents silent regressions.

**Tests must use the inputs the REAL caller produces.**
Confirm what the real request/component sends (payload shape, headers, props) before
asserting — a test green on synthetic inputs the caller never sends hides a dead feature.

**Anything that gates behavior (auth, membership, a managed decision) needs one real
end-to-end exercise before "done"** — a unit test is not proof it fires in production.

**Security-critical changes (auth/governance/enforcement): run the workflow `/code-review`**
and fix confirmed findings before reporting done.

**UI changes: flag for human visual QA before merge** — tests + review can't judge product
feel; a page can pass everything and still look wrong.

**Frontend tests live in `fe/src/__tests__/` and use Vitest + React Testing Library.**

- Test config: `fe/vitest.config.ts` (jsdom env, globals, setup file).
- Setup file: `fe/src/__tests__/setup.ts` (imports `@testing-library/jest-dom`).
- Use `vi.mock()` / `vi.fn()` / `vi.importActual()` — never `jest.mock()` / `jest.fn()`.
- Mock factories that call `vi.importActual` must be `async`.
- Smoke tests (renders without crashing) are the minimum bar for any new page or component.
- Do not write tests that check exact content strings — they break on every copy change.
  Test structure and behavior, not words.
- Node ≥ 20.19 is required by jsdom@29 (this project uses Node 22 — see `.nvmrc`).

**Backend tests live in `be/src/**/*.spec.ts` and use Jest.**

- Unit tests: mock external dependencies (DB, external APIs).
- For auth flows, write tests for both the happy path and the failure path.
- Always assert the HTTP status code, not just the response body.

**Auth/session changes always need integration coverage.**
Any change to `AuthContext`, `Login`, `Auth` (callback), `ProtectedRoute`, or the backend
`/auth/*` controllers must have a corresponding test that proves the flow works end-to-end.

## Language

**Code is English only. No exceptions.**
Source comments, identifiers, test names, log strings, commit messages, and every code
snippet inside a design or architecture write-up are English. Hebrew belongs in the chat,
never in a code block or a repository file.

## Code Rules — Frontend

**`isLoading` in `AuthContext` must not block the entire app after initialization.**
`App.tsx` gates the loading screen on `isLoading && !initialized`. Never change this to
`isLoading` alone — that would replace the running UI with a black screen during every
mid-session operation (login, token refresh, profile update).

**`initialized` is set only by `init()`, not by `login()`.**
`init()` is the sole initialization path. Setting `initialized=true` inside `login()` is
premature — the initial auth check may not have completed, which can expose protected routes.

**`login()` must roll back the token if profile fetch fails.**
`tokenStore.set(token)` is called at the start of `login()`. If `refreshUser()` returns
null (profile endpoint unreachable or errored), clear the token with `tokenStore.clear()`
and reset the auth header. Do not leave a stale token in storage with `isAuthenticated=false`.

**Do not re-enable submit buttons on a successful auth action.**
On login success, keep `isSubmitting=true` until the component unmounts via navigation.
Only reset `isSubmitting=false` on failure so the user can retry. This prevents
double-submission on security-sensitive flows.

**No `console.log` in AuthContext, API interceptor, or any auth path.**
These code paths run on every page load. Console noise makes debugging harder and can
leak token or user data in production logs.

**Never use `?? undefined` for optional path values from external sources.**
`??` only guards `null`/`undefined`. Use `|| undefined` which also guards empty string `""`.

```ts
// ❌ Bug: payload.cwd = "" passes the ?? check and joins relative to process.cwd()
const cwd = payload.cwd ?? undefined; // "" → path.join("", "config") = "config" (relative!)

// ✅ Fix: || also filters empty string
const cwd = payload.cwd || undefined; // "" → undefined → path is skipped
```

## Code Rules — Backend

**Auth cookies always use `secure: true, sameSite: 'none'`.**
The app runs behind a Cloudflare Tunnel (HTTPS). Do not weaken cookie security for local
development — use the same settings everywhere and ensure local dev also runs over HTTPS
via the tunnel or `vite-plugin-mkcert`.

**OAuth state cookies must be short-lived (5 min max) and verified before use.**
The CSRF state nonce must be read from a cookie (server-controlled), not from the URL
query param alone. Never trust the `state` param without comparing it to the stored nonce.

**Workspace membership must be verified before any workspace-scoped operation.**
Use `assertWorkspaceMember` / `assertWorkspaceAdmin` before reading or writing workspace
data. Never trust a `workspaceId` from the request body without a membership check.

**`workspaceId` for OAuth callbacks comes from the session, not the URL.**
Store it in `req.session.oauthSlackWorkspaceId` (server-controlled). Never read it from
the redirect state or URL params — those are attacker-controlled.

**Map internal errors to safe user messages before redirecting.**
Never reflect `error.message` directly into a URL parameter. Map to a safe string first;
log the real error server-side. This prevents leaking stack traces or DB errors into URLs.

## Architecture Notes

### Frontend (`fe/`)

- Auth state lives in `AuthContext` — single source of truth for `user`, `isAuthenticated`, `isLoading`, `initialized`
- `initialized`: set to `true` by `init()` once the initial auth check completes; never reset
- `isLoading`: `true` during initial load AND mid-session token operations; gate full-screen spinner on `isLoading && !initialized`
- Tokens stored in `tokenStore` (localStorage wrapper) — cleared on logout and on failed profile fetch
- Workspace state in `WorkspaceContext` — redirects to `/onboarding` if user has no workspaces
- Socket.io real-time updates via `useFirewallSocket` — connects only when `activeWorkspace` is set

### Backend (`be/`)

- NestJS + Prisma + PostgreSQL + Redis (sessions)
- `JWT_SECRET` signs access tokens (**15 minute** default via `JWT_ACCESS_EXPIRES_IN`); `JWT_REFRESH_SECRET` signs refresh tokens (7 day default via `JWT_REFRESH_EXPIRES_IN`)
- Access tokens must be short-lived; refresh tokens must outlive them. Never invert this.
- Refresh tokens are stored encrypted in the DB and rotated on every `/auth/refresh` call
- Session store uses Redis (`node9_sess:` prefix); session cookie is `httpOnly, secure, sameSite: none`
- Two Google OAuth flows: "Login" (email/profile scopes only) and "Connect" (workspace scopes, requires existing user)
- Cloudflare Tunnel exposes `dev-api.node9.ai` (dev) and `api.node9.ai` (prod)
