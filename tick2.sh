#!/usr/bin/env bash
#
# Batch porting harness for ghidra-rs (v2) -- built to be kicked off and left
# running unattended for hours.
#
# Core loop: pick the next ready class from the manifest frontier, port it with a
# headless Claude, verify (manifest row DONE + crate builds), merge into
# `integration` so progress persists, close the per-class issue. Git is
# harness-controlled; the model only edits files, runs cargo, flips the manifest.
#
# Unattended-safety features:
#   * Per-step TIMEOUTS            -- a hung port/build can't eat the whole window.
#   * Graceful shutdown            -- SIGINT/SIGTERM finishes bookkeeping, returns
#                                     to integration, writes final status, exits.
#   * Crash recovery on startup    -- a killed prior run's dirty tree / stray
#                                     branch is reset before work resumes.
#   * Stop conditions              -- MAX_ITERS, TIME_BUDGET (sec), COST_BUDGET
#                                     (USD), and a consecutive-park circuit breaker.
#   * Post-merge build gate        -- re-build integration after each merge; if two
#                                     individually-OK ports combine badly, the merge
#                                     is auto-reverted and the class parked, so
#                                     integration is provably green the whole run.
#   * Periodic tests               -- cargo test every TEST_EVERY ports (+ at end),
#                                     not every iteration, to save wall-clock.
#   * Parked-set memory            -- unportable classes are recorded and skipped,
#                                     so a bad 0-dep class can't be re-picked forever.
#   * Live observability           -- tick2.status heartbeat + tick2_results.tsv.
#
# Usage:
#   MAX_ITERS=1   MODEL=sonnet ./tick2.sh                       # supervised single port
#   TIME_BUDGET=21600 COST_BUDGET=40 MODEL=sonnet ./tick2.sh    # ~6h / $40 cap, leave it
#   GH=0 MAX_ITERS=500 MODEL=sonnet ./tick2.sh                  # manifest-only, no GitHub
#
#   watch -n5 cat tick2.status        # check progress from another terminal
#
set -uo pipefail

# --- config (override via env) ---
REPO_DIR="${REPO_DIR:-$HOME/Projects/ghidra-rs}"
GH_REPO="${GH_REPO:-cyrex562/ghidra-rs}"
PY="${PY:-python3}"
MODEL="${MODEL:-sonnet}"
MAX_ITERS="${MAX_ITERS:-100}"
MANIFEST="PORT_MANIFEST.tsv"
PARKED="PORT_PARKED.tsv"
INTEGRATION="${INTEGRATION:-integration}"
GH="${GH:-1}"

# stop conditions (0 = disabled)
TIME_BUDGET="${TIME_BUDGET:-0}"            # seconds of wall-clock
COST_BUDGET="${COST_BUDGET:-0}"            # USD of Claude spend
MAX_CONSEC_PARK="${MAX_CONSEC_PARK:-10}"   # circuit breaker

# per-step timeouts (seconds)
CLAUDE_TIMEOUT="${CLAUDE_TIMEOUT:-1200}"
BUILD_TIMEOUT="${BUILD_TIMEOUT:-1800}"
TEST_TIMEOUT="${TEST_TIMEOUT:-1800}"

# behaviour
TEST_EVERY="${TEST_EVERY:-10}"             # run cargo test every N ports (+ at end)
POST_MERGE_BUILD="${POST_MERGE_BUILD:-1}"  # 1 = build integration after each merge, auto-revert on red

LOCK="/tmp/ghidra-tick.lock"
LOG_DIR="${LOG_DIR:-$HOME/agents/logs/ghidra}"
STATUS_FILE="${STATUS_FILE:-tick2.status}"
RESULTS_FILE="${RESULTS_FILE:-tick2_results.tsv}"
export GH GH_REPO
mkdir -p "$LOG_DIR"

# --- single-instance lock ---
exec 9>"$LOCK"
flock -n 9 || { echo "another tick is running; exiting"; exit 0; }

cd "$REPO_DIR" || { echo "no repo at $REPO_DIR"; exit 1; }
touch "$PARKED"
[ -f "$RESULTS_FILE" ] || printf 'ts\tclass\tresult\ttests\tdur_s\tcost_usd\tsrcpath\tnote\n' > "$RESULTS_FILE"

# --- run state ---
START_TS=$(date +%s)
ported=0; parked=0; consec_park=0; spent="0"; STOP=""

hms() { local s=$1; printf '%dh%02dm%02ds' $((s/3600)) $(((s%3600)/60)) $((s%60)); }
elapsed() { echo $(( $(date +%s) - START_TS )); }

# floating-point spend math without bc
add_cost() { spent=$(awk -v a="$spent" -v b="${1:-0}" 'BEGIN{printf "%.6f", a+b}'); }
cost_exceeded() { awk -v s="$spent" -v c="$COST_BUDGET" 'BEGIN{exit !(c>0 && s>=c)}'; }
time_exceeded() { [ "$TIME_BUDGET" -gt 0 ] && [ "$(elapsed)" -ge "$TIME_BUDGET" ]; }

write_status() {
  local cur="$1" last="$2" el; el=$(elapsed)
  local done_n; done_n=$(grep -c $'\tDONE\t' "$MANIFEST" 2>/dev/null || true); done_n=${done_n:-0}
  local rate="-"
  [ "$ported" -gt 0 ] && [ "$el" -gt 0 ] && rate=$(awk -v p="$ported" -v e="$el" 'BEGIN{printf "%.1f", p*3600/e}')
  local tmp="$STATUS_FILE.tmp"
  {
    echo "state:        ${STOP:+stopping (${STOP})}${STOP:-running}"
    echo "started:      $(date -d @"$START_TS" '+%Y-%m-%d %H:%M:%S')"
    echo "elapsed:      $(hms "$el")${TIME_BUDGET:+  / budget $( [ "$TIME_BUDGET" -gt 0 ] && hms "$TIME_BUDGET" || echo none)}"
    echo "model:        $MODEL    GH:$GH"
    echo "current:      ${cur:-(selecting)}"
    echo "ported(run):  $ported    parked(run): $parked    ports/hr: $rate"
    echo "manifest DONE total: $done_n"
    echo "spend:        \$$spent$( awk -v c="$COST_BUDGET" 'BEGIN{exit !(c>0)}' && echo "  / budget \$$COST_BUDGET" )"
    echo "consec_park:  $consec_park / $MAX_CONSEC_PARK"
    echo "last:         $last"
    echo "updated:      $(date '+%H:%M:%S')"
  } > "$tmp" && mv "$tmp" "$STATUS_FILE"
}

record_result() { # class result tests dur cost srcpath note
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$(date '+%Y-%m-%dT%H:%M:%S')" "$1" "$2" "$3" "$4" "$5" "$6" "${7:-}" >> "$RESULTS_FILE"
}

on_signal() { STOP="signal"; echo; echo "[signal] caught -- finishing current iteration, then stopping."; write_status "" "stopping on signal"; }
trap on_signal INT TERM

finish() {
  git switch "$INTEGRATION" >/dev/null 2>&1 || true
  local done_n park_n
  done_n=$(grep -c $'\tDONE\t' "$MANIFEST" 2>/dev/null || true); done_n=${done_n:-0}
  park_n=$(sort -u "$PARKED" 2>/dev/null | grep -c . || true); park_n=${park_n:-0}
  write_status "" "finished: ${ported} ported / ${parked} parked this run"
  echo "=================== batch done ==================="
  echo "this run:  ${ported} ported, ${parked} parked   spend: \$$spent   elapsed: $(hms "$(elapsed)")"
  echo "totals:    manifest DONE ${done_n}   parked ${park_n}"
  echo "status:    $STATUS_FILE      results: $RESULTS_FILE"
  echo "branches:  git branch --list 'port/auto-*'   (parked WIP left for inspection)"
}
trap finish EXIT

# --- startup: crash recovery + green-integration preflight ---
echo "--- startup recovery ---"
git merge --abort >/dev/null 2>&1 || true
git rebase --abort >/dev/null 2>&1 || true
git checkout -f "$INTEGRATION" >/dev/null 2>&1 || { echo "no '$INTEGRATION' branch -- create it first"; exit 1; }
git reset --hard >/dev/null 2>&1 || true          # drop tracked modifications from a killed run
# prune stray auto branches from prior runs (untracked user files are left untouched)
for b in $(git branch --list 'port/auto-*' --format='%(refname:short)'); do
  git branch -D "$b" >/dev/null 2>&1 || true
done
git pull --ff-only >/dev/null 2>&1 || true

echo "--- preflight: cargo build --lib on $INTEGRATION ---"
if ! timeout "$BUILD_TIMEOUT" cargo build --lib --quiet 2>/dev/null; then
  echo "integration does not build clean -- fix it first (every port build would fail)."
  exit 1
fi

echo "batch start: MAX_ITERS=$MAX_ITERS MODEL=$MODEL GH=$GH TIME_BUDGET=$TIME_BUDGET COST_BUDGET=$COST_BUDGET"
write_status "" "starting"

for ((i = 1; i <= MAX_ITERS; i++)); do
  [ -n "$STOP" ] && { echo "stopping: $STOP"; break; }
  time_exceeded && { STOP="time-budget"; echo "stopping: time budget reached"; break; }
  cost_exceeded && { STOP="cost-budget"; echo "stopping: cost budget reached"; break; }
  if [ "$consec_park" -ge "$MAX_CONSEC_PARK" ]; then
    STOP="circuit-breaker"; echo "stopping: ${consec_park} consecutive parks -- something is systemically wrong."; break
  fi

  echo "=================== iteration $i / $MAX_ITERS  (elapsed $(hms "$(elapsed)"), spend \$$spent) ==================="

  # 1. next ready, unparked class at the frontier, restricted to MAPPED areas
  #    (unmapped areas would be parked by the model -- skip them without spending).
  next=$("$PY" scripts/sync_check.py --root orig_src --manifest "$MANIFEST" --port-order 2>/dev/null \
        | awk -F'\t' '$1==0{print $2}' \
        | "$PY" scripts/portlib.py mapped \
        | grep -vxF -f <(sed 's#^orig_src/##' "$PARKED") \
        | head -1)
  if [ -z "$next" ]; then
    echo "no ready, unparked, mapped class at the frontier -- batch complete."
    echo "(unmapped areas remain; run '$PY scripts/portlib.py report' to see what needs mapping.)"
    break
  fi

  srcpath="orig_src/${next}"
  class=$(basename "$next" .java)
  hash=$(printf '%s' "$srcpath" | cksum | cut -d' ' -f1)
  branch="port/auto-${class}-${hash}"
  stamp=$(date +%s)
  log="$LOG_DIR/${class}.${hash}.${stamp}.log"
  jlog="$LOG_DIR/${class}.${hash}.${stamp}.json"
  iter_start=$stamp
  write_status "$srcpath" "porting (iter $i)"
  echo "next: $srcpath -> $branch"

  # 2. fresh feature branch off integration
  git checkout -f "$INTEGRATION" >/dev/null 2>&1
  git branch -D "$branch" >/dev/null 2>&1 || true
  git switch -c "$branch" >/dev/null 2>&1

  # 3. lazy-ensure the per-class issue
  iss=$("$PY" scripts/issuelib.py ensure "$srcpath" 2>>"$log")

  # 4. port exactly this one class (timeout-guarded, JSON output for cost)
  prompt="Port the single Java class located at: ${srcpath}

Follow AGENTS.md exactly:
- Place the Rust code in the module given by the target-layout map.
- Add focused unit tests; run \`cargo test\`.
- In ${MANIFEST}, find the row whose first column is exactly '${srcpath}' and change its
  second column from TODO to DONE.
Port ONLY this class -- nothing else. Do not run any git commands.
If you cannot finish within the rules (missing prereq, unmapped area, would need a stub),
do NOT force it: leave ${MANIFEST} unchanged and end your reply with the single line
PORT_RESULT: PARKED followed by a one-line reason."

  echo "--- claude ($MODEL, timeout ${CLAUDE_TIMEOUT}s) ---"
  timeout "$CLAUDE_TIMEOUT" claude -p "$prompt" \
    --model "$MODEL" \
    --permission-mode acceptEdits \
    --allowedTools "Read,Edit,Write,Bash(cargo test*),Bash(cargo build*),Bash(${PY} scripts/sync_check.py*)" \
    --output-format json >"$jlog" 2>>"$log"
  claude_rc=$?

  # extract cost + final text from the JSON envelope (best-effort)
  cost=$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1])).get("total_cost_usd",0))' "$jlog" 2>/dev/null || echo 0)
  "$PY" -c 'import json,sys; print(json.load(open(sys.argv[1])).get("result",""))' "$jlog" >>"$log" 2>/dev/null || true
  add_cost "$cost"
  [ "$claude_rc" -eq 124 ] && echo "claude TIMED OUT after ${CLAUDE_TIMEOUT}s" >>"$log"
  # the model's own park rationale, for triage (empty on success)
  preason=$(grep -m1 'PORT_RESULT:' "$log" 2>/dev/null | sed 's/.*PORT_RESULT:[[:space:]]*//' | tr '\t' ' ' | cut -c1-200)

  # 5. verify: manifest row DONE AND crate builds (the real gate -- not claude's say-so)
  status=$(grep -F "$srcpath"$'\t' "$MANIFEST" | head -1 | cut -f2 | tr -d '[:space:]')
  built=0
  if [ "$status" = "DONE" ]; then
    timeout "$BUILD_TIMEOUT" cargo build --lib --quiet 2>>"$log" && built=1
  fi

  if [ "$built" -eq 1 ]; then
    # periodic test (record only)
    if [ $(( (ported + 1) % TEST_EVERY )) -eq 0 ]; then
      if timeout "$TEST_TIMEOUT" cargo test --lib --quiet >>"$log" 2>&1; then tests="tests:PASS"; else tests="tests:FAIL"; fi
    else
      tests="tests:SKIP"
    fi

    git add -A
    git commit -q -m "port: ${class} [${tests}] (${srcpath})" || true

    # 6. merge to integration, with optional post-merge build gate + auto-revert
    git checkout -f "$INTEGRATION" >/dev/null 2>&1
    pre=$(git rev-parse HEAD)
    if git merge --no-ff "$branch" -m "merge port: ${class} [${tests}]" >>"$log" 2>&1; then
      gate_ok=1
      if [ "$POST_MERGE_BUILD" = "1" ]; then
        timeout "$BUILD_TIMEOUT" cargo build --lib --quiet 2>>"$log" || gate_ok=0
      fi
      if [ "$gate_ok" -eq 1 ]; then
        git branch -D "$branch" >/dev/null 2>&1 || true
        ported=$((ported + 1)); consec_park=0
        dur=$(( $(date +%s) - iter_start ))
        echo "OK: ${class} ported+merged [${tests}] in $(hms "$dur") (\$$cost)."
        record_result "$class" "PORTED" "$tests" "$dur" "$cost" "$srcpath"
        write_status "$srcpath" "OK ${class} [${tests}]"
        "$PY" scripts/issuelib.py close "$srcpath" \
          --comment "Ported and merged into \`${INTEGRATION}\`; ${tests}." >>"$log" 2>&1 || true
        continue
      fi
      # post-merge build broke -> revert the merge, park
      echo "POST-MERGE BUILD FAILED -- reverting merge of ${class}." >>"$log"
      git reset --hard "$pre" >>"$log" 2>&1 || true
      echo "$srcpath" >> "$PARKED"
      parked=$((parked + 1)); consec_park=$((consec_park + 1))
      dur=$(( $(date +%s) - iter_start ))
      echo "PARK: ${class} broke integration on merge -- reverted+parked. log: $log"
      record_result "$class" "PARK-MERGEBUILD" "$tests" "$dur" "$cost" "$srcpath" "post-merge build broke integration"
      write_status "$srcpath" "PARK ${class} (post-merge build)"
      "$PY" scripts/issuelib.py park "$srcpath" --comment "Combined build broke integration; reverted+parked." >>"$log" 2>&1 || true
      continue
    fi
    # merge conflict -> abort, park
    git merge --abort >/dev/null 2>&1 || true
    echo "$srcpath" >> "$PARKED"
    parked=$((parked + 1)); consec_park=$((consec_park + 1))
    dur=$(( $(date +%s) - iter_start ))
    echo "PARK: ${class} merge conflict -- aborted+parked. branch ${branch} left. log: $log"
    record_result "$class" "PARK-CONFLICT" "$tests" "$dur" "$cost" "$srcpath" "merge conflict against ${INTEGRATION}"
    write_status "$srcpath" "PARK ${class} (merge conflict)"
    "$PY" scripts/issuelib.py park "$srcpath" --comment "Merge conflict against ${INTEGRATION}; parked." >>"$log" 2>&1 || true
    continue
  fi

  # did not port cleanly -> keep WIP branch for inspection, park
  git add -A >/dev/null 2>&1 || true
  git commit -q -m "WIP/parked: ${class} (${srcpath})" >/dev/null 2>&1 || true
  git checkout -f "$INTEGRATION" >/dev/null 2>&1
  echo "$srcpath" >> "$PARKED"
  parked=$((parked + 1)); consec_park=$((consec_park + 1))
  dur=$(( $(date +%s) - iter_start ))
  reason="status='${status}'"; [ "$claude_rc" -eq 124 ] && reason="timeout"
  echo "PARK: ${class} did not complete (${reason}). branch ${branch} left. log: $log"
  record_result "$class" "PARK" "tests:NA" "$dur" "$cost" "$srcpath" "${preason:-$reason}"
  write_status "$srcpath" "PARK ${class} (${reason})"
  "$PY" scripts/issuelib.py park "$srcpath" --comment "Could not port cleanly (${reason}). See log." >>"$log" 2>&1 || true
done

# final test sweep on integration for the record (skipped on a manual Ctrl-C so stop is fast)
if [ "$STOP" != "signal" ]; then
  echo "--- final cargo test --lib on $INTEGRATION ---"
  git checkout -f "$INTEGRATION" >/dev/null 2>&1
  if timeout "$TEST_TIMEOUT" cargo test --lib --quiet >"$LOG_DIR/final-test.$(date +%s).log" 2>&1; then
    echo "final tests: PASS"
  else
    echo "final tests: FAIL (see $LOG_DIR/final-test.*.log)"
  fi
fi
# finish() runs on EXIT
