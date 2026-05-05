# Publishing @node9/policy-engine

Engine versions queued for publish:

- **1.1.0** — severity classifier (`classifyAuditEntry`, `computeSecurityScore`, `narrativeRuleLabel`)
- **1.2.0** — blast summarizer (`summarizeBlast`, `truncateBlastPath`)
- **1.3.0** — scan summarizer (`summarizeScan`, `computeScanScore`, `ScanFinding` types)

Currently on npm: only **1.0.0**. The backend's `package.json` references `^1.3.0` so deployment requires 1.3.0 to be published. Local dev works via the workspace `file:` link.

## Publish flow

```bash
cd packages/policy-engine

# 1. Verify the build is clean
npm run build
npm run typecheck
npm test

# 2. Verify what's about to ship
npm pack --dry-run

# 3. Confirm version + tag
node -p "require('./package.json').version"   # should print 1.3.0

# 4. Authenticate (if not already)
npm whoami                                    # confirms login
# npm login                                   # if needed

# 5. Publish (public scoped package)
npm publish --access public

# 6. Verify
npm view @node9/policy-engine version         # should print 1.3.0
```

## Catch-up versions

If you want to publish 1.1.0 and 1.2.0 historically (so consumers can pin to either), check out the relevant commits and publish from there. Otherwise, **publishing 1.3.0 alone is fine** — npm allows skipping versions, and consumers will resolve `^1.0.0` to `1.3.0` since it's the only version satisfying the range above 1.0.0.

## Rollback

`npm unpublish @node9/policy-engine@1.3.0` works for 72h after publish. After that you can only `npm deprecate` it. Best to test the dry-run output thoroughly before publishing.

## Backend-side after publish

Once 1.3.0 is on npm, the backend's `node_modules` can resolve cleanly:

```bash
cd be
# The package.json already references ^1.3.0, but local dev linked it
# via file:... — if a fresh install is needed:
rm -rf node_modules/@node9/policy-engine
npm install --package-lock-only @node9/policy-engine@^1.3.0
npm install
```

For production deploys this is automatic — `npm install` resolves the registry version.
