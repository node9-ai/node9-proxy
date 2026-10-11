#!/usr/bin/env bash
# Project rule: never delete a file without explicit permission.
# Blocks rm, sudo rm, xargs rm and absolute paths to rm (/bin/rm, /usr/bin/rm).
# Does not cover find -exec rm (rm as an argument, not a shell token).

. "$(dirname "$0")/_read_input.sh"

if echo "$cmd" | grep -qE '(^|[;&|])[[:space:]]*(sudo[[:space:]]+|xargs[[:space:]]+)?([^[:space:]]*/)?rm([[:space:]]|$)'; then
  echo '{"continue":false,"stopReason":"Project rule: ask before deleting any file (rm is blocked)."}'
fi
