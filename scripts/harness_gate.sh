# Shared post-merge test gate for the autonomous harnesses. Source it after cd'ing to the repo:
#   . scripts/harness_gate.sh
#
# One implementation, because the harnesses disagreeing about what "verified" means is how bad
# code reaches integration. Before 2026-08-06 only descent_night.sh ran the suite at all;
# seam/unblock/remediate merged on `cargo build --lib` alone, so a port that compiled and then
# failed or hung its tests merged clean.
#
# The two checks, and why each is shaped the way it is:
#
#  1. COMPILE via `--no-run`. It must NOT be a bare `cargo test`, because that RUNS the tests and
#     a passing test printing a line starting with "error" inflates `grep ^error` into a false
#     park (2026-07-21: six good ports parked on an identical "base 0 -> 2"). Baselined against
#     the caller's preflight count so pre-existing, not-yet-repaired drift cannot mass-park
#     otherwise-good ports; once the crate is clean the gate is strict.
#
#  2. RUNTIME. Park on `test result: FAILED` *and* on a timeout. The timeout half is the one that
#     matters: a deadlocked test never prints FAILED, it simply never finishes, `timeout` kills
#     it, and a gate that only greps for FAILED reads that silence as success. That is exactly
#     how the DataTypeDB set_name/get_name self-deadlock reached integration on 2026-08-05, after
#     burning 2x TEST_TIMEOUT per subsequent port. Silence is not success.
#
# Both checks retry once, to absorb transient incremental-compile errors and flaky parallel tests
# (2026-07-22: HighParamID/SpecExtension were false-parked on a flake and passed on re-run).
#
# TEST_GATE=0 disables; TEST_TIMEOUT bounds each cargo invocation.

# run_test_gate <label> [logfile] [baseline_compile_errors]
#   0 = pass, safe to keep the merge
#   1 = fail, the caller MUST undo the merge (reset to its pre-merge commit) and park
run_test_gate() {
  local label="$1" logf="${2:-/dev/null}" base="${3:-0}"
  local t="${TEST_TIMEOUT:-1800}"

  if [ "${TEST_GATE:-1}" != "1" ]; then
    echo "test gate skipped for ${label} (TEST_GATE=0)"
    return 0
  fi

  local terr
  terr=$(timeout "$t" cargo test --lib --no-run 2>>"$logf" | grep -cE '^error'); terr=${terr:-0}
  if [ "$terr" -gt "$base" ]; then
    terr=$(timeout "$t" cargo test --lib --no-run 2>>"$logf" | grep -cE '^error'); terr=${terr:-0}
  fi
  if [ "$terr" -gt "$base" ]; then
    echo "test gate FAIL: ${label} introduced $((terr - base)) test-compile error(s) (base ${base} -> ${terr}, confirmed on retry)"
    return 1
  fi

  local tout trc
  tout=$(timeout "$t" cargo test --lib --no-fail-fast 2>&1); trc=$?
  if [ "$trc" -eq 124 ] || printf '%s' "$tout" | grep -q 'test result: FAILED'; then
    tout=$(timeout "$t" cargo test --lib --no-fail-fast 2>&1); trc=$?
  fi

  if [ "$trc" -eq 124 ]; then
    local hung
    hung=$(printf '%s' "$tout" | grep -oP 'test \K\S+(?= has been running for over)' | head -3 | tr '\n' ' ')
    echo "test gate FAIL: ${label} -- suite TIMED OUT after ${t}s (hang/deadlock). Stuck: ${hung:-unknown}"
    return 1
  fi
  if printf '%s' "$tout" | grep -q 'test result: FAILED'; then
    echo "test gate FAIL: ${label} ($(printf '%s' "$tout" | grep -oE '[0-9]+ failed' | tail -1) in suite, confirmed on retry)"
    return 1
  fi

  echo "test gate OK: ${label} (test crate compiles, suite green)"
  return 0
}

# test_gate_preflight  -- establishes the baseline and proves the suite terminates at all.
# Echoes the baseline compile-error count on stdout; returns 1 if the suite already hangs, in
# which case the caller should abort rather than park every port against a broken baseline.
test_gate_preflight() {
  local t="${TEST_TIMEOUT:-1800}"
  local base
  base=$(timeout "$t" cargo test --lib --no-run 2>&1 | grep -cE '^error'); base=${base:-0}
  echo "$base"

  if [ "${TEST_GATE:-1}" = "1" ]; then
    timeout "$t" cargo test --lib --no-fail-fast >/dev/null 2>&1
    [ $? -eq 124 ] && return 1
  fi
  return 0
}
