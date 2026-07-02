#!/usr/bin/env bash
#
# Supervisor for tick2.sh — kick off ONCE and leave it for days.
#
# Runs tick2.sh batches back-to-back. The binding constraint in practice is the
# Claude usage limit: when a batch stops with "stopping: api-error", this reads the
# reset time the model reported ("resets 5:50pm"), sleeps until then (+ buffer), and
# relaunches. Between windows it just keeps porting. It stops for good when:
#   * the mapped frontier is exhausted (all queued work ported), or
#   * no batch makes progress for MAX_NOPROGRESS runs in a row (avoid spinning), or
#   * an overall cap is reached (MAX_RUNS / OVERALL_HOURS / OVERALL_COST).
#
# tick2.sh keeps doing the real work (selection, port, build-gate, merge, issue
# close) and its own per-batch caps (TIME_BUDGET / COST_BUDGET) still apply.
#
# Usage:
#   MODEL=sonnet ./run_batches.sh                       # sensible defaults
#   OVERALL_HOURS=48 OVERALL_COST=300 ./run_batches.sh  # cap a long unattended run
#   watch -n10 tail -n20 ~/agents/logs/ghidra/supervisor.*.log
#
set -uo pipefail

REPO_DIR="${REPO_DIR:-$HOME/Projects/ghidra-rs}"
cd "$REPO_DIR" || { echo "no repo at $REPO_DIR"; exit 1; }
MANIFEST="PORT_MANIFEST.tsv"
RESULTS="${RESULTS_FILE:-tick2_results.tsv}"
PARKED_FILE="PORT_PARKED.tsv"
LOG_DIR="${LOG_DIR:-$HOME/agents/logs/ghidra}"
mkdir -p "$LOG_DIR"
SUP_LOG="$LOG_DIR/supervisor.$(date +%s).log"

# --- per-batch settings (passed through to tick2.sh) ---
export MODEL="${MODEL:-sonnet}"
export TIME_BUDGET="${TIME_BUDGET:-21600}"     # 6h per batch
export COST_BUDGET="${COST_BUDGET:-80}"        # $80 per batch
export MAX_ITERS="${MAX_ITERS:-100000}"
export TEST_EVERY="${TEST_EVERY:-1000000}"
export GH="${GH:-1}"

# --- supervisor caps / behaviour ---
MAX_RUNS="${MAX_RUNS:-100}"
OVERALL_HOURS="${OVERALL_HOURS:-72}"           # 0 = unlimited
OVERALL_COST="${OVERALL_COST:-0}"              # USD across this session; 0 = unlimited
MAX_NOPROGRESS="${MAX_NOPROGRESS:-3}"          # consecutive 0-progress batches -> stop
RESET_BUFFER="${RESET_BUFFER:-300}"            # extra seconds to wait past a stated reset
MAX_SLEEP="${MAX_SLEEP:-28800}"                # cap any single wait at 8h (safety)

# single supervisor instance (tick2 has its own lock)
exec 8>/tmp/ghidra-supervisor.lock
flock -n 8 || { echo "another supervisor is already running; exiting"; exit 0; }

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$SUP_LOG"; }
done_count() { local n; n=$(grep -c $'\tDONE\t' "$MANIFEST" 2>/dev/null || true); echo "${n:-0}"; }
spent_total() { awk -F'\t' 'NR>1{s+=$6} END{printf "%.4f", s+0}' "$RESULTS" 2>/dev/null || echo 0; }
over_cost() { awk -v s="$1" -v b="$2" -v c="$OVERALL_COST" 'BEGIN{exit !(c>0 && (s-b)>=c)}'; }

start_ts=$(date +%s)
base_cost=$(spent_total)
noprog=0
unparked=0   # self-heal: un-park accumulated parks once when the frontier looks dry
trap 'log "supervisor interrupted; exiting (tick2 may still be finishing its batch)."; exit 130' INT TERM

log "supervisor start: MODEL=$MODEL  per-batch TIME_BUDGET=${TIME_BUDGET}s COST_BUDGET=\$$COST_BUDGET"
log "caps: MAX_RUNS=$MAX_RUNS OVERALL_HOURS=$OVERALL_HOURS OVERALL_COST=\$$OVERALL_COST  (baseline spend \$$base_cost)"

for ((run = 1; run <= MAX_RUNS; run++)); do
  # overall caps
  el=$(( $(date +%s) - start_ts ))
  if [ "$OVERALL_HOURS" -gt 0 ] && [ "$el" -ge $((OVERALL_HOURS * 3600)) ]; then
    log "overall wall-clock cap (${OVERALL_HOURS}h) reached. stopping."; break
  fi
  now_cost=$(spent_total)
  if over_cost "$now_cost" "$base_cost"; then
    log "overall cost cap (\$$OVERALL_COST this session) reached. stopping."; break
  fi

  before=$(done_count)
  runlog="$LOG_DIR/batch.run${run}.$(date +%s).log"
  log "=== batch $run/$MAX_RUNS  (DONE=$before, session spend \$$(awk -v s="$now_cost" -v b="$base_cost" 'BEGIN{printf "%.2f", s-b}')) -> $runlog"
  ./tick2.sh > "$runlog" 2>&1
  rc=$?
  after=$(done_count)
  ported=$(( after - before ))
  reason=$(grep -oE "stopping: [a-z-]+" "$runlog" | tail -1 | sed 's/stopping: //')
  log "batch $run finished: rc=$rc  +$ported ported (DONE=$after)  stop='${reason:-none}'"

  # hard stops that should NOT retry
  if grep -q "does not build clean" "$runlog"; then
    log "preflight failed: integration does not build. fix it, then restart the supervisor. stopping."; break
  fi
  if grep -q "batch complete" "$runlog" && [ "$ported" -eq 0 ]; then
    # Frontier looks dry -- but classes parked earlier (when their deps were still
    # TODO) may be portable now that those deps are ported. Un-park all once and retry;
    # only repeat after an intervening progress batch, so truly-unportable work can't spin.
    parked_n=$(sort -u "$PARKED_FILE" 2>/dev/null | grep -c . || true); parked_n=${parked_n:-0}
    if [ "$parked_n" -gt 0 ] && [ "$unparked" -eq 0 ]; then
      cp "$PARKED_FILE" "$LOG_DIR/PORT_PARKED.$(date +%s).bak" 2>/dev/null || true
      : > "$PARKED_FILE"
      unparked=1
      log "frontier dry but $parked_n parked -> un-parked all and retrying (deps may now be ported)."
      continue
    fi
    log "mapped frontier exhausted — all queued work ported or genuinely blocked. DONE.";  break
  fi

  if [ "$ported" -gt 0 ]; then noprog=0; unparked=0; else noprog=$(( noprog + 1 )); fi

  # usage limit: wait for the reported reset, then resume
  if [ "$reason" = "api-error" ]; then
    rt=$(grep -oiE "resets [0-9]{1,2}:[0-9]{2} ?(am|pm)" "$runlog" | tail -1 | sed -E 's/^resets //I')
    target=""; [ -n "$rt" ] && target=$(date -d "$rt" +%s 2>/dev/null)
    now=$(date +%s)
    if [ -n "$target" ]; then
      [ "$target" -le "$now" ] && target=$(date -d "tomorrow $rt" +%s 2>/dev/null)
      wait=$(( target - now + RESET_BUFFER ))
    else
      wait=$MAX_SLEEP
    fi
    [ "$wait" -lt "$RESET_BUFFER" ] && wait=$RESET_BUFFER
    [ "$wait" -gt "$MAX_SLEEP" ] && wait=$MAX_SLEEP
    log "usage limit hit (reset '${rt:-unknown}'). sleeping $((wait / 60))m, then resuming."
    sleep "$wait"
    noprog=0   # a limit wait isn't a failure to make progress
    continue
  fi

  # circuit-breaker / budget stops: parked-memory means the next batch skips parked
  # work and advances, so just continue -- unless we keep making no progress.
  if [ "$noprog" -ge "$MAX_NOPROGRESS" ]; then
    log "no progress for $noprog batches in a row (last stop='${reason:-?}'). stopping to avoid a spin loop."; break
  fi
  log "continuing to next batch."
done

final=$(done_count)
log "supervisor done. manifest DONE=$final, session spend \$$(awk -v s="$(spent_total)" -v b="$base_cost" 'BEGIN{printf "%.2f", s-b}'). log: $SUP_LOG"
