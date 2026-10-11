#!/usr/bin/env bash
# readme-check.sh: mechanical red-flag detector for the /readme skill.
#
# Usage: readme-check.sh <path-to-README.md> [--chunks]
#
# Default: a findings report, one line per red flag, with the category and line number.
# --chunks: emit chunk boundaries, one per line, as "STARTLINE-ENDLINE TYPE FIRST50CHARS".
#
# Exit code: 0 if no STRONG findings; 1 if any (a Prerequisites heading, an em dash, etc.).

if [ $# -lt 1 ]; then
  echo "Usage: $0 <path-to-README.md> [--chunks]" >&2
  exit 2
fi

FILE="$1"
MODE="report"
shift || true
for arg in "$@"; do
  case "$arg" in
    --chunks) MODE="chunks" ;;
    *) echo "Unknown flag: $arg" >&2; exit 2 ;;
  esac
done

if [ ! -f "$FILE" ]; then
  echo "File not found: $FILE" >&2
  exit 2
fi

STRONG=0
emit() { printf "  [%s] L%s  %s\n" "$1" "$2" "$3"; }
emit_strong() { STRONG=$((STRONG + 1)); emit "$@"; }

if [ "$MODE" = "chunks" ]; then
  awk '
    BEGIN { chunk_start = 1; in_code = 0 }
    /^```/ { in_code = !in_code; next }
    in_code { next }
    /^## / {
      if (NR - 1 >= chunk_start) printf "%d-%d section  ...\n", chunk_start, NR - 1
      chunk_start = NR
    }
  ' "$FILE"
  exit 0
fi

while IFS=: read -r n line; do
  emit_strong "prerequisites" "$n" "$line"
done < <(grep -n '^#\+ Prerequisites' "$FILE")

while IFS=: read -r n line; do
  emit_strong "em-dash" "$n" "${line:0:60}"
done < <(grep -nP '\x{2014}' "$FILE")

[ "$STRONG" -eq 0 ]
