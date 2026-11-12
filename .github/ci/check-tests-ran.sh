#!/usr/bin/env bash
# Reads the log of `cargo test` and fails unless the Send Secret interop
# and security tests ran and passed, and no test anywhere was ignored.
# Usage: check-tests-ran.sh LOG
set -euo pipefail

log=$1

# Minimum test count per suite. Raise it when you add tests.
declare -A want=(
    [send-secret/crates/cli/tests/interop.rs]=11
    [send-secret/crates/cli/tests/security.rs]=8
)

fail=0
for suite in "${!want[@]}"; do
    # cargo prints the path relative to the crate.
    short=${suite#send-secret/crates/cli/}
    if (($(grep -cF "Running $short " "$log" || true) > 1)); then
        echo "check-tests-ran: more than one $short ran; make the names unique" >&2
        fail=1
        continue
    fi
    result=$(awk -v s="Running $short " '
        index($0, s) { found = 1; next }
        found && /^ *(Running|Doc-tests) / { exit }
        found && /^test result:/ { print; exit }
    ' "$log")
    if [[ -z $result ]]; then
        echo "check-tests-ran: $suite did not run" >&2
        fail=1
        continue
    fi
    passed=$(sed -E 's/.* ([0-9]+) passed.*/\1/' <<<"$result")
    if [[ $result != "test result: ok."* ]] || ((passed < want[$suite])); then
        echo "check-tests-ran: $suite: want at least ${want[$suite]} passed: $result" >&2
        fail=1
    else
        echo "check-tests-ran: $suite: $passed passed"
    fi
done

if grep -E '^test result:' "$log" | grep -vqE ' 0 ignored;'; then
    echo "check-tests-ran: some tests were ignored:" >&2
    grep -E '^test result:' "$log" | grep -vE ' 0 ignored;' >&2
    fail=1
fi
exit "$fail"
