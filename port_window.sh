#!/usr/bin/env bash
#
# Durable bounded porting window — for cron (nightly) or manual use, with NO Claude
# session needed. Sets a cron-safe environment, runs the run_batches.sh supervisor
# for ~N hours (it self-stops at the cap and sleeps through usage-limit windows),
# then appends a one-line summary and fires a desktop notification if available.
#
# Usage:
#   ./port_window.sh [HOURS]          # default 7h
#   crontab:  0 22 * * * /home/cyrex/Projects/ghidra-rs/port_window.sh 7
#
set -uo pipefail

# cron runs with a minimal environment — make the toolchain resolvable.
export HOME="${HOME:-/home/cyrex}"
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin:$PATH"

REPO="${REPO_DIR:-$HOME/Projects/ghidra-rs}"
cd "$REPO" || { echo "no repo at $REPO"; exit 1; }

HOURS="${1:-7}"
LOGDIR="${LOG_DIR:-$HOME/agents/logs/ghidra}"; mkdir -p "$LOGDIR"
SUMMARY="$LOGDIR/port-summary.log"
MANIFEST="PORT_MANIFEST.tsv"
RESULTS="tick2_results.tsv"

done_before=$(grep -c $'\tDONE\t' "$MANIFEST" 2>/dev/null || true); done_before=${done_before:-0}
spent_before=$(awk -F'\t' 'NR>1{s+=$6} END{printf "%.2f", s+0}' "$RESULTS" 2>/dev/null || echo 0)
start_hm=$(date '+%Y-%m-%d %H:%M')

# Run the supervisor, bounded to HOURS. Per-batch: sonnet, 20 ports, no test loop.
MODEL="${MODEL:-sonnet}" MAX_ITERS="${MAX_ITERS:-20}" TEST_EVERY=1000000 \
  COST_BUDGET=0 TIME_BUDGET=0 \
  OVERALL_HOURS="$HOURS" OVERALL_COST="${OVERALL_COST:-200}" MAX_NOPROGRESS="${MAX_NOPROGRESS:-5}" \
  ./run_batches.sh >> "$LOGDIR/cron-window.log" 2>&1

done_after=$(grep -c $'\tDONE\t' "$MANIFEST" 2>/dev/null || true); done_after=${done_after:-0}
spent_after=$(awk -F'\t' 'NR>1{s+=$6} END{printf "%.2f", s+0}' "$RESULTS" 2>/dev/null || echo 0)
delta=$(( done_after - done_before ))
spend=$(awk -v a="$spent_before" -v b="$spent_after" 'BEGIN{printf "%.2f", b-a}')

line="[$(date '+%Y-%m-%d %H:%M')] window ${start_hm} (+${HOURS}h cap): DONE ${done_before}->${done_after} (+${delta}), spend \$${spend}"
echo "$line" | tee -a "$SUMMARY"
command -v notify-send >/dev/null 2>&1 && notify-send "ghidra-rs porting" "$line" 2>/dev/null || true

# test-health: the mechanical porter gates on `cargo build --lib` only, which NEVER compiles
# test code -- so record test-crate compile drift here (once per window), the way seam_night.sh
# and unblock_night.sh already do. Without this the test crate silently rots (it reached 816
# undetected errors once this way, and +131 ports on 2026-07-10 re-drifted it 0->62). Visibility,
# not a hard gate: a single seam/port legitimately breaks mocks other files own, so we warn +
# record rather than fail the window.
terr=$(timeout 900 cargo test --lib --no-run 2>&1 | grep -cE '^error' || true)
printf '%s\t%s\n' "${terr:-?}" "$(date +%s)" > test_health.txt 2>/dev/null || true
if [ "${terr:-0}" != "0" ]; then
  hline="[$(date '+%Y-%m-%d %H:%M')] WARNING: test crate has ${terr} compile errors (drift accumulating) -- run a repair sweep soon"
  echo "$hline" | tee -a "$SUMMARY"
  command -v notify-send >/dev/null 2>&1 && notify-send "ghidra-rs test drift" "test crate: ${terr} compile errors" 2>/dev/null || true
else
  echo "[$(date '+%Y-%m-%d %H:%M')] test-health OK: test crate compiles clean" | tee -a "$SUMMARY"
fi
