#!/usr/bin/env bash
#
# Every suite in this repository, in one command.
#
#   scripts/ci/local.sh            everything the machine can run
#   scripts/ci/local.sh go         only the named languages
#
# A missing toolchain is reported as SKIPPED and makes the run exit non-zero at
# the end. A green tick that only means "php was not installed" is worse than
# no suite at all.
set -uo pipefail

cd "$(dirname "$0")/../.."
ROOT=$(pwd)

FAILED=()
SKIPPED=()
PASSED=()

say() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
ok() { PASSED+=("$1"); printf '\033[32m   ok\033[0m   %s\n' "$1"; }
bad() { FAILED+=("$1"); printf '\033[31m   FAIL\033[0m %s\n' "$1"; }
skip() { SKIPPED+=("$1"); printf '\033[33m   SKIP\033[0m %s (%s)\n' "$1" "$2"; }

have() { command -v "$1" >/dev/null 2>&1; }

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

want() { # want <language> — was it asked for?
  [ $# -eq 0 ] && return 0
  local lang=$1
  [ ${#TARGETS[@]} -eq 0 ] && return 0
  local t
  for t in "${TARGETS[@]}"; do [ "$t" = "$lang" ] && return 0; done
  return 1
}

TARGETS=("$@")

# ---- Go: two modules, one vocabulary --------------------------------------

if want go; then
  say "Go"
  if ! have go; then
    skip "go" "no go toolchain"
  else
    # gofmt is checked rather than applied: CI must not rewrite the tree.
    unformatted=$(gofmt -l . anubiskit 2>/dev/null | grep -v '^$' || true)
    if [ -n "$unformatted" ]; then
      bad "gofmt"
      echo "$unformatted" | sed 's/^/     /'
    else
      ok "gofmt"
    fi

    run "go vet (root)" go vet ./...
    # -race because the single-flight rotation in TokenSource is the one thing
    # in this SDK a serial test cannot prove.
    run "go test -race (root, admin, examples)" go test -race -count=1 ./...

    cd "$ROOT/anubiskit"
    run "go vet (anubiskit)" go vet ./...
    run "go test -race (anubiskit: http, grpc, amqp)" go test -race -count=1 ./...
    cd "$ROOT"
  fi
fi

# ---- PHP ------------------------------------------------------------------

if want php; then
  say "PHP"
  if ! have php; then
    skip "php" "no php"
  elif ! php -r 'exit(extension_loaded("sodium") ? 0 : 1);'; then
    skip "php" "ext-sodium missing — Ed25519 verification needs it"
  else
    cd "$ROOT/php"
    lint_failed=0
    for f in src/*.php src/Exception/*.php tests/*.php; do
      php -l "$f" >/dev/null 2>&1 || { bad "php -l $f"; lint_failed=1; }
    done
    [ $lint_failed -eq 0 ] && ok "php -l"
    run "php tests/run.php" php tests/run.php
    cd "$ROOT"
  fi
fi

# ---- verdict ---------------------------------------------------------------

say "Summary"
printf '   %d passed' "${#PASSED[@]}"
[ ${#SKIPPED[@]} -gt 0 ] && printf ', %d skipped' "${#SKIPPED[@]}"
[ ${#FAILED[@]} -gt 0 ] && printf ', \033[31m%d failed\033[0m' "${#FAILED[@]}"
printf '\n'

if [ ${#FAILED[@]} -gt 0 ]; then
  printf '\n   failed: %s\n' "${FAILED[*]}"
  exit 1
fi
if [ ${#SKIPPED[@]} -gt 0 ]; then
  printf '\n   skipped: %s\n' "${SKIPPED[*]}"
  printf '   Not a pass. Install the missing toolchains, or run CI.\n'
  exit 2
fi
printf '\n   All suites green.\n'
