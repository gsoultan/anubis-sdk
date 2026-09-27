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
# The files are half of it. A release can change what a procedure means
# without touching a .proto — v0.4.3 stopped an application's token managing
# a person's sessions, four procedures this SDK wraps, and no file moved — so
# proto/SYNCED names the release the copy was last checked against, and any
# release since counts as drift until somebody has read its CHANGELOG entry
# and moved SYNCED forward.
#
# Exit codes: 0 in sync or no checkout, 1 drifted, 2 misused.
set -uo pipefail

cd "$(dirname "$0")/.."
VENDORED=proto/anubis/v1
SYNCED_FILE=proto/SYNCED

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

printf '\n'
bold "== Releases"

# Releases since the one the copy was checked against. Only a git checkout
# has tags, and only one fetched recently has the newest; where they cannot be
# read, the releases are reported unchecked rather than passed for want of
# anything to compare.
releases=()
unchecked=""
synced=$(tr -d '[:space:]' < "$SYNCED_FILE" 2>/dev/null || true)
if [ -z "$synced" ]; then
  unchecked="$SYNCED_FILE names no release"
elif ! git -C "$SERVER" rev-parse --git-dir >/dev/null 2>&1; then
  unchecked="$SERVER is not a git checkout"
elif ! git -C "$SERVER" rev-parse -q --verify "refs/tags/$synced" >/dev/null; then
  unchecked="the server checkout has no tag $synced — fetch its tags"
else
  while IFS= read -r tag; do
    [ -n "$tag" ] && releases+=("$tag")
  done <<EOF
$(git -C "$SERVER" tag --list 'v*' --sort=v:refname | awk -v s="$synced" 'seen { print } $0 == s { seen = 1 }')
EOF
  if [ ${#releases[@]} -eq 0 ]; then
    printf '\033[32m   ok\033[0m   nothing released since %s\n' "$synced"
  fi
  for tag in ${releases[@]+"${releases[@]}"}; do
    printf '\033[31m   NEW\033[0m   %s — released since %s, not yet read\n' "$tag" "$synced"
  done
fi
if [ -n "$unchecked" ]; then
  printf '\033[33m   skip\033[0m %s\n' "$unchecked"
fi

contract_drifted=0
if [ ${#drifted[@]} -gt 0 ] || [ ${#missing[@]} -gt 0 ] || [ ${#added[@]} -gt 0 ]; then
  contract_drifted=1
fi

if [ $contract_drifted -eq 0 ] && [ ${#releases[@]} -eq 0 ]; then
  if [ -n "$unchecked" ]; then
    printf '\n   The files match %s; releases since %s not checked\n' "$SERVER" "${synced:-the last sync}"
  else
    printf '\n   In sync with %s\n' "$SERVER"
  fi
  exit 0
fi

printf '\n'
bold "== What to do with this"
if [ $contract_drifted -eq 1 ]; then
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
fi
if [ ${#releases[@]} -gt 0 ]; then
  newest=${releases[${#releases[@]}-1]}
  [ $contract_drifted -eq 1 ] && printf '\n'
  cat <<NOTE
   Read the server's CHANGELOG entry for every release listed above — the
   "Action required" lines first. A rule can change without a proto. When the
   SDK answers all of them, record where it now stands:
     echo $newest > $SYNCED_FILE
NOTE
fi
exit 1
