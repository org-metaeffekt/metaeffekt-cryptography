#!/usr/bin/env bash
#
# On-demand consistency check for the metaeffekt-cryptography repository.
#
# Runs the mechanical integrity checks locally (the ae-pattern-validator
# submodule that holds the cr-*.yaml single source of truth is not part of the
# external repository, so these cannot run in cloud CI — see
# management/content-update-plan.md §8.4).
#
# Fast checks (always run):
#   1. scripts/validate_consistency.py        — 14 cross-file consistency checks
#   2. generate_status_tables_from_yaml.py     — autogen-freshness (--check)
#
# Slow check (opt-in with --tests / --all):
#   3. mvn test (ae-pattern-validator)         — validator test suite
#
# Usage:
#   scripts/check.sh            # fast checks only
#   scripts/check.sh --tests    # fast checks + mvn test
#   scripts/check.sh --all      # alias for --tests
#
# Exit status is non-zero if any selected check fails.

set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

RUN_TESTS=0
for arg in "$@"; do
  case "$arg" in
    --tests|--all) RUN_TESTS=1 ;;
    -h|--help)
      sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *)
      echo "Unknown argument: $arg (use --tests, --all, or --help)" >&2
      exit 2 ;;
  esac
done

FAILED=0

run_step() {
  local label="$1"; shift
  echo "==> $label"
  if "$@"; then
    echo "    OK: $label"
  else
    echo "    FAIL: $label" >&2
    FAILED=1
  fi
  echo
}

run_step "Consistency validator (16 checks)" \
  python3 scripts/validate_consistency.py

run_step "Autogen tables up to date" \
  python3 scripts/generate_status_tables_from_yaml.py --check

if [ "$RUN_TESTS" -eq 1 ]; then
  if [ -f ae-pattern-validator/pom.xml ]; then
    run_step "ae-pattern-validator test suite" \
      bash -c "cd ae-pattern-validator && mvn -B -q test"
  else
    echo "==> ae-pattern-validator test suite" >&2
    echo "    SKIP: submodule not checked out (ae-pattern-validator/pom.xml missing)" >&2
    echo
  fi
fi

if [ "$FAILED" -eq 0 ]; then
  echo "ALL CHECKS PASSED"
else
  echo "SOME CHECKS FAILED" >&2
fi
exit "$FAILED"
