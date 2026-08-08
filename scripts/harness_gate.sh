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
    local failed
    failed=$(printf '%s\n' "$tout" | awk '/^failures:$/{f=1;next} /^test result:/{f=0} f && /^ +[A-Za-z_]/{gsub(/^ +/,"");print}' | sort -u)
    if gate_failures_are_known_flaky "$label" "$failed"; then
      echo "test gate OK: ${label} (suite failure confined to known-flaky tests, port is not the cause)"
      return 0
    fi
    echo "test gate FAIL: ${label} ($(printf '%s' "$tout" | grep -oE '[0-9]+ failed' | tail -1) in suite, confirmed on retry)"
    return 1
  fi

  echo "test gate OK: ${label} (test crate compiles, suite green)"
  return 0
}

# Nondeterministic tests park innocent ports, and "confirmed on retry" does not save you: a
# test that fails 40% of the time fails twice in a row 16% of the time. That is not
# hypothetical -- `list_reg_names_..._in_order` asserted an order over a HashSet, landed at
# 23:26 on 2026-08-07, and every test-gate park for the rest of that run (six of roughly
# thirty-five attempts, ~17%) came after it. There were none before.
#
# So when the suite fails twice, ask whether the named tests are nondeterministic at all: run
# each in isolation and see if it ever passes. A test that both passes and fails on the same
# tree cannot confirm anything about this port.
#
# It still parks the FIRST port to hit a given flake, because a port that introduces a race
# looks exactly like this and must not merge on the strength of an intermittent pass. What it
# will not do is park the next twenty: the test is recorded in $FLAKY_TESTS and subsequent runs
# recognise it. That file is deliberately untracked -- like tick2.status and test_health.txt --
# so `git reset --hard` and `git clean -fd` (which spares ignored files) leave it alone.
FLAKY_TESTS="${FLAKY_TESTS:-FLAKY_TESTS.tsv}"

GATE_FLAKE_TRIES="${GATE_FLAKE_TRIES:-8}"

gate_failures_are_known_flaky() {
  local label="$1" failed="$2"
  [ -z "$failed" ] && return 1

  local t="${TEST_TIMEOUT:-1800}" name pass_seen known all_known=1 any=0
  [ -f "$FLAKY_TESTS" ] || printf 'ts\ttest\tfirst_seen_by\n' > "$FLAKY_TESTS"

  while IFS= read -r name; do
    [ -z "$name" ] && continue
    any=1
    grep -qF $'\t'"$name"$'\t' "$FLAKY_TESTS" 2>/dev/null && known=1 || known=0

    # Isolated re-runs. One pass is proof of nondeterminism; the retry count has to be
    # generous because the test only has to pass ~40% of the time to have produced the two
    # full-suite failures that got us here, and three attempts would then miss it 22% of the
    # time -- which is how the first draft of this check waved through a known flake and
    # parked the port anyway. A single test re-runs in about a second against the already
    # built binary, so 8 is cheap.
    pass_seen=0
    for _ in $(seq "$GATE_FLAKE_TRIES"); do
      if timeout "$t" cargo test --lib -- --exact "$name" >/dev/null 2>&1; then pass_seen=1; break; fi
    done

    # Never passes in isolation: a deterministic failure, whatever the registry says. A
    # known-flaky test can still be genuinely broken by a later port.
    [ "$pass_seen" = "0" ] && return 1

    if [ "$known" = "0" ]; then
      printf '%s\t%s\t%s\n' "$(date '+%Y-%m-%dT%H:%M')" "$name" "$label" >> "$FLAKY_TESTS"
      echo "test gate: NEW nondeterministic test recorded -- ${name} (passes and fails on the same tree; fix it, it parks ports until then)" >&2
      all_known=0
    fi
  done <<< "$failed"

  [ "$any" = "1" ] && [ "$all_known" = "1" ]
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
