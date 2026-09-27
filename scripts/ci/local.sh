#!/usr/bin/env bash
#
# Every check in this repository, in one command: gofmt, vet and the race
# detector across both Go modules.
#
#   scripts/ci/local.sh
#
# A missing toolchain exits non-zero rather than passing quietly. A green tick
# that only means "go was not installed" is worse than no suite at all.
set -uo pipefail

cd "$(dirname "$0")/../.."
ROOT=$(pwd)

FAILED=()
PASSED=()
SKIPPED=()

say() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
ok() { PASSED+=("$1"); printf '\033[32m   ok\033[0m   %s\n' "$1"; }
bad() { FAILED+=("$1"); printf '\033[31m   FAIL\033[0m %s\n' "$1"; }
skip() { SKIPPED+=("$1"); printf '\033[33m   skip\033[0m %s — %s\n' "$1" "$2"; }

run() { # run <label> <command...>
  local label=$1
  shift
  if "$@" >/tmp/anubis-ci.$$ 2>&1; then
    ok "$label"
  else
    bad "$label"
    sed 's/^/     /' /tmp/anubis-ci.$$ | tail -30
  fi
  rm -f /tmp/anubis-ci.$$
}

say "Go"

if ! command -v go >/dev/null 2>&1; then
  printf '\033[31m   no go toolchain — nothing here can run\033[0m\n'
  exit 2
fi

# gofmt is checked rather than applied: this must not rewrite the tree.
unformatted=$(gofmt -l . anubiskit 2>/dev/null | grep -v '^$' || true)
if [ -n "$unformatted" ]; then
  bad "gofmt"
  echo "$unformatted" | sed 's/^/     /'
else
  ok "gofmt"
fi

# The root module's promise, and the kind of thing that erodes by accident.
if grep -qE '^\s*require' go.mod; then
  bad "root module has no dependencies"
  sed 's/^/     /' go.mod
else
  ok "root module has no dependencies"
fi

# The vendored contract, against the server it was copied from. This is the
# one check CI cannot run — the server repository is private — so it lives
# here, and skips rather than guesses when the checkout is not beside us.
# Every field that has ever drifted turned out to be a live bug.
SERVER=${ANUBIS_SERVER:-../anubis}
if [ -d "$SERVER/proto/anubis/v1" ]; then
  if drift=$(scripts/drift.sh "$SERVER" 2>&1); then
    ok "proto/ matches the server, and no release since is unread"
  else
    bad "proto/ matches the server, and no release since is unread"
    printf '%s\n' "$drift" | sed 's/^/  /'
  fi
else
  skip "proto/ matches the server, and no release since is unread" "no server checkout at $SERVER"
fi

run "go vet (root)" go vet ./...
# -race because the single-flight rotation in TokenSource is the one thing in
# this SDK a serial test cannot prove.
run "go test -race (root, keys, paseto, admin, examples)" go test -race -count=1 ./...

cd "$ROOT/anubiskit"
run "go vet (anubiskit)" go vet ./...
run "go test -race (anubiskit: http, grpc, amqp)" go test -race -count=1 ./...
cd "$ROOT"

say "Summary"
printf '   %d passed' "${#PASSED[@]}"
[ ${#SKIPPED[@]} -gt 0 ] && printf ', \033[33m%d skipped\033[0m' "${#SKIPPED[@]}"
[ ${#FAILED[@]} -gt 0 ] && printf ', \033[31m%d failed\033[0m' "${#FAILED[@]}"
printf '\n'

if [ ${#FAILED[@]} -gt 0 ]; then
  printf '\n   failed: %s\n' "${FAILED[*]}"
  exit 1
fi
printf '\n   All checks green.\n'
