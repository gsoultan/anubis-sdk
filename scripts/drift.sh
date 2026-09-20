#!/usr/bin/env bash
#
# Is proto/ still the server's contract?
#
#   scripts/drift.sh [path-to-anubis-checkout]    # default ../anubis
#
# proto/anubis/v1/ is a vendored copy of a contract that lives in a private
# repository, and nothing here is generated from it — every client in this SDK
# is hand-written against the wire. That is what keeps the root module free of
# dependencies, and it is also why nothing detects that the copy has gone
# stale. This script is the detection: a diff, run by whoever has the server
# checked out.
#
# It cannot run in CI, and that is not an oversight. The server repository is
# private and CI has no checkout of it, so an absent checkout exits 0 with a
# note rather than failing — a check that cannot see the thing it compares
# against must not claim a verdict either way.
#
# Exit codes: 0 in sync or no checkout, 1 drifted, 2 misused.
set -uo pipefail

cd "$(dirname "$0")/.."
VENDORED=proto/anubis/v1

SERVER=${1:-${ANUBIS_SERVER:-../anubis}}
UPSTREAM=$SERVER/proto/anubis/v1

bold() { printf '\033[1m%s\033[0m\n' "$1"; }

if [ ! -d "$UPSTREAM" ]; then
  printf '   no server checkout at %s — nothing to diff against.\n' "$SERVER"
  printf '   Pass one: scripts/drift.sh /path/to/anubis (or set ANUBIS_SERVER).\n'
  exit 0
fi

bold "== Contract"

drifted=()
missing=()
added=()
for f in "$VENDORED"/*.proto; do
  name=$(basename "$f")
  if [ ! -f "$UPSTREAM/$name" ]; then
    missing+=("$name")
    printf '\033[33m   gone\033[0m %s — not in the server any more\n' "$name"
    continue
  fi
  if diff -q "$f" "$UPSTREAM/$name" >/dev/null 2>&1; then
    printf '\033[32m   ok\033[0m   %s\n' "$name"
  else
    drifted+=("$name")
    printf '\033[31m   DRIFT\033[0m %s (%s lines)\n' \
      "$name" "$(diff -u "$f" "$UPSTREAM/$name" | grep -c '^[+-][^+-]' || true)"
  fi
done

# A file the server has and we do not is a whole service the SDK cannot see.
for f in "$UPSTREAM"/*.proto; do
  name=$(basename "$f")
  [ -f "$VENDORED/$name" ] && continue
  added+=("$name")
  printf '\033[31m   NEW\033[0m   %s — the server has it and this SDK does not\n' "$name"
done

if [ ${#drifted[@]} -eq 0 ] && [ ${#missing[@]} -eq 0 ] && [ ${#added[@]} -eq 0 ]; then
  printf '\n   In sync with %s\n' "$SERVER"
  exit 0
fi

printf '\n'
bold "== What to do with this"
cat <<'NOTE'
   Read the diff before copying it. Every drifted field so far has been a live
   bug rather than paperwork — a new scalar on a message this SDK already
   decodes is the dangerous shape, because it compiles, it decodes, and the
   behaviour it was added to enable is silently absent.

   Ask what the client does with each field that changed, then re-vendor:
NOTE
for name in ${drifted[@]+"${drifted[@]}"}; do
  printf '     diff -u %s/%s %s/%s\n' "$VENDORED" "$name" "$UPSTREAM" "$name"
done
# A file this SDK does not have yet has no diff to read — it is read whole.
for name in ${added[@]+"${added[@]}"}; do
  printf '     cp %s/%s %s/\n' "$UPSTREAM" "$name" "$VENDORED"
done
exit 1
