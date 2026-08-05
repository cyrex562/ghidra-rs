#!/usr/bin/env bash
#
# Periodic Java-idiom pattern audit — detection only, no LLM calls, no branch/merge.
# Re-scans ghidra-rs/src with scripts/pattern_audit.py, diffs against the previous
# OWNERSHIP_DEBT.tsv snapshot to find files that got WORSE since the last audit (new
# Box<dyn>/Rc<RefCell<_>>/Arc<Mutex<_>>/get-set-pair/unwrap-density smells introduced
# by ordinary porting work), and commits the refreshed snapshot so OWNERSHIP_DEBT.tsv
# stays current between remediation runs.
#
# This is the fix for the gap described in OWNERSHIP_MIGRATION.md: ownership-pattern
# drift wasn't tripping any STOP condition in tick2.sh/seam_night.sh, so it accumulated
# invisibly. This script doesn't block anything -- it just stops the drift from being
# invisible, on a cadence independent of any porting run.
#
# Safe to cron directly (unlike remediate_ownership.sh): it only reads source and
# writes OWNERSHIP_DEBT.tsv + a log line, no code changes to the ported crate.
#
# Usage:  ./audit_night.sh
#         crontab:  0 6 * * 1 /home/cyrex/Projects/ghidra-rs/audit_night.sh   # weekly, Monday 06:00
#
set -uo pipefail
export HOME="${HOME:-/home/cyrex}"
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
REPO="${REPO_DIR:-$HOME/Projects/ghidra-rs}"; cd "$REPO" || exit 1

PY="${PY:-python3}"
DEBT="OWNERSHIP_DEBT.tsv"; PREV="/tmp/ownership_debt.prev.tsv"
INTEGRATION="${INTEGRATION:-integration}"
PUSH="${PUSH:-1}"; PUSH_REMOTE="${PUSH_REMOTE:-origin}"
LOG_DIR="${LOG_DIR:-$HOME/agents/logs/ghidra}"; mkdir -p "$LOG_DIR"

exec 6>/tmp/ghidra-audit.lock; flock -n 6 || { echo "another audit run active"; exit 0; }

log(){ echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
git checkout -f "$INTEGRATION" >/dev/null 2>&1 || { log "no $INTEGRATION branch"; exit 1; }
git pull --ff-only >/dev/null 2>&1 || true

[ -f "$DEBT" ] && cp "$DEBT" "$PREV" || : > "$PREV"

regressions=$("$PY" scripts/pattern_audit.py --root ghidra-rs/src --seam SEAM.tsv \
  --baseline "$PREV" --diff-new 2>>"$LOG_DIR/audit.log")

"$PY" scripts/pattern_audit.py --root ghidra-rs/src --seam SEAM.tsv --out "$DEBT" >>"$LOG_DIR/audit.log" 2>&1

n_regress=0
if [ -n "$regressions" ]; then
  n_regress=$(printf '%s\n' "$regressions" | grep -c . || true)
  log "NEW/WORSENED smells since last audit ($n_regress):"
  printf '%s\n' "$regressions" | tee -a "$LOG_DIR/audit.log"
else
  log "no new/worsened smells since last audit"
fi

if git diff --quiet -- "$DEBT"; then
  log "$DEBT unchanged"
else
  git add "$DEBT"
  git commit -q -m "audit: refresh OWNERSHIP_DEBT.tsv ($(grep -c $'^TODO\t' "$DEBT" 2>/dev/null || echo '?') TODO rows, ${n_regress} new/worsened)" || true
  if [ "$PUSH" = "1" ]; then
    git push "$PUSH_REMOTE" "$INTEGRATION" >/dev/null 2>&1 && log "pushed $PUSH_REMOTE/$INTEGRATION" || log "push FAILED (non-fatal; check SSH under cron)"
  fi
fi

line="[$(date '+%Y-%m-%d %H:%M')] pattern audit: ${n_regress} new/worsened files, $(grep -c $'^TODO\t' "$DEBT" 2>/dev/null || echo '?') total TODO in $DEBT"
echo "$line" | tee -a "$LOG_DIR/port-summary.log"
command -v notify-send >/dev/null 2>&1 && notify-send "ghidra-rs audit" "$line" 2>/dev/null || true
