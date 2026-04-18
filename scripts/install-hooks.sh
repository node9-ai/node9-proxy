#!/bin/sh
# Install git hooks for node9-proxy development.
# Run once after cloning: sh scripts/install-hooks.sh

set -e
REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOK="$REPO_ROOT/.git/hooks/pre-commit"

cat > "$HOOK" << 'EOF'
#!/bin/sh
set -e

echo "Running pre-commit checks..."

echo "[1/4] Format..."
npm run format:check

echo "[2/4] Typecheck..."
npm run typecheck

echo "[3/4] Lint..."
npm run lint

echo "[4/4] Tests..."
npm test

echo "All checks passed."
EOF

chmod +x "$HOOK"
echo "✅ pre-commit hook installed at $HOOK"
