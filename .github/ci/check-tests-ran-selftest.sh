#!/usr/bin/env bash
# Self-test for check-tests-ran.sh with small made-up cargo test logs.
# Counts are 99, so raising the minimums there does not break it.
set -euo pipefail

check=$(dirname "$0")/check-tests-ran.sh
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT

suite() { # name passed ignored
    printf '     Running %s (target/debug/deps/x-0)\n\nrunning %s tests\n\n' "$1" "$2"
    printf 'test result: ok. %s passed; 0 failed; %s ignored; 0 measured; 0 filtered out; finished in 0.01s\n\n' "$2" "$3"
}

suite tests/interop.rs 99 0 >"$dir/good.log"
suite tests/security.rs 99 0 >>"$dir/good.log"

# security.rs prints no result line; the next binary's must not count.
{
    suite tests/interop.rs 99 0
    printf '     Running tests/security.rs (target/debug/deps/security-0)\n'
    suite tests/other.rs 76 0
} >"$dir/no-result.log"
{
    suite tests/interop.rs 99 0
    printf '     Running tests/security.rs (target/debug/deps/security-0)\n'
    printf '   Doc-tests cli\n\n'
    suite tests/x.rs 76 0 | tail -n +2
} >"$dir/doc-tests.log"

{ suite tests/interop.rs 3 0; suite tests/security.rs 99 0; } >"$dir/few.log"
{ cat "$dir/good.log"; suite tests/other.rs 2 1; } >"$dir/ignored.log"
suite tests/interop.rs 99 0 >"$dir/missing.log"
cat "$dir/good.log" "$dir/good.log" >"$dir/twice.log"

fail=0
expect() { # want-status log
    local got=0
    "$check" "$dir/$2" >/dev/null 2>&1 || got=$?
    if { [[ $1 == ok ]] && ((got != 0)); } || { [[ $1 == fail ]] && ((got == 0)); }; then
        echo "selftest: $2: want $1, got exit $got" >&2
        fail=1
    fi
}
expect ok good.log
expect fail no-result.log
expect fail doc-tests.log
expect fail few.log
expect fail ignored.log
expect fail missing.log
expect fail twice.log
((fail == 0)) && echo "check-tests-ran selftest: ok"
exit "$fail"
