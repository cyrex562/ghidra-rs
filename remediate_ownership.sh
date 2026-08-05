#!/usr/bin/env bash
#
# Ownership-remediation harness — works OWNERSHIP_DEBT.tsv top-down, replacing
# Java-idiom-in-Rust patterns (Box<dyn Trait> + Rc<RefCell<_>>/Arc<Mutex<_>> +
# .clone() sprawl on shared/graph types, Java-bean get_x/set_x pairs, etc.) with
# the arena+ID / enum-dispatch conventions in OWNERSHIP_MIGRATION.md.
#
# Mirrors seam_night.sh's structure (branch off integration -> claude remediates
# -> gate on cargo build --lib -> merge -> push), but targets already-DONE code
# with established callers, so it is HIGHER RISK than seam_night.sh's "new trait,
# no callers yet" case. See OWNERSHIP_MIGRATION.md Phase 2/3:
#   - Phase 2 (the top-5 highest-fan-in seam types: Listing, Function,
#     DataTypeManager, DataType, ProgramBasedDataTypeManager) is NOT meant to run
#     via this unattended harness -- do those by hand / with human-reviewed PRs
#     first, to validate the pattern on the highest-blast-radius types.
#   - Only run this harness (Phase 3: the long tail) after Phase 2 lands and the
#     convention has real worked examples for the model to follow.
#
# REMEDIATE_MAX defaults to 0 (no-op) so this script is inert until a human
# opts in -- do not cron-wire it until Phase 2 in OWNERSHIP_MIGRATION.md is done.
#
# Usage:  REMEDIATE_MAX=6 MODEL=sonnet ./remediate_ownership.sh
#         crontab (only after Phase 2 lands):
#           0 23 * * * REMEDIATE_MAX=6 /home/cyrex/Projects/ghidra-rs/remediate_ownership.sh
#
set -uo pipefail
export HOME="${HOME:-/home/cyrex}"
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
REPO="${REPO_DIR:-$HOME/Projects/ghidra-rs}"; cd "$REPO" || exit 1

MODEL="${MODEL:-sonnet}"
REMEDIATE_MAX="${REMEDIATE_MAX:-0}"   # inert by default; see header
# Fan-in ceiling for unattended work. Rows above it (the Phase 2 blast-radius types --
# Listing/Function/DataTypeManager/DataType/... all sit at 1000+) are skipped here and left
# for human-reviewed PRs. Raise deliberately, only once Phase 2 has landed by hand.
MAX_FANIN="${MAX_FANIN:-500}"
# Skip rows whose smell is dominated by dyn/Rc/Arc, i.e. the ones that need an ownership
# CONVENTION for some core type before they can be touched at all. 66% of the eligible
# frontier is in that state today, and a live proofing run parked three of them in a row
# (Trace -> DebuggerStaticMappingService -> DebuggerTraceManagerService, each blocked on the
# same undecided Trace convention). Until Phase 2 lands those decisions, this harness can only
# make real progress on the mechanical 34% (clone/unwrap/get-set density). Set to 0 after
# Phase 2 to let it work the dyn-dominated rows too.
MECHANICAL_ONLY="${MECHANICAL_ONLY:-1}"
DYN_BLOCK_THRESHOLD="${DYN_BLOCK_THRESHOLD:-5}"
DEBT="OWNERSHIP_DEBT.tsv"; DOC="OWNERSHIP_MIGRATION.md"
INTEGRATION="${INTEGRATION:-integration}"
PUSH="${PUSH:-1}"; PUSH_REMOTE="${PUSH_REMOTE:-origin}"
CLAUDE_TIMEOUT="${CLAUDE_TIMEOUT:-1800}"; BUILD_TIMEOUT="${BUILD_TIMEOUT:-1800}"
PY="${PY:-python3}"; LOG_DIR="${LOG_DIR:-$HOME/agents/logs/ghidra}"; mkdir -p "$LOG_DIR"

if [ "$REMEDIATE_MAX" -le 0 ]; then
  echo "REMEDIATE_MAX=0 (default) -- harness is inert. Read OWNERSHIP_MIGRATION.md Phase 2/3 before opting in."
  exit 0
fi

exec 7>/tmp/ghidra-remediate.lock; flock -n 7 || { echo "another remediation run active"; exit 0; }
[ -f "$DEBT" ] || { echo "no $DEBT -- run: python3 scripts/pattern_audit.py --root ghidra-rs/src --seam SEAM.tsv --out $DEBT"; exit 1; }

log(){ echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

# Set col-1 status for the row whose path column (col 7) equals $1. Field-exact, so it can't
# silently no-op the way a hand-counted sed pattern can (it did: the pattern had one field too
# few, so every PARK was a no-op and the loop re-picked the same row until REMEDIATE_MAX ran out).
set_status(){ # $1=path $2=new status
  "$PY" - "$DEBT" "$1" "$2" <<'PY'
import sys
tsv, target, status = sys.argv[1], sys.argv[2], sys.argv[3]
lines = open(tsv, encoding="utf-8").read().split("\n")
hit = 0
for i, ln in enumerate(lines):
    c = ln.split("\t")
    if len(c) > 6 and c[6] == target and c[0] == "TODO":
        c[0] = status; lines[i] = "\t".join(c); hit += 1
open(tsv, "w", encoding="utf-8").write("\n".join(lines))
sys.exit(0 if hit else 1)
PY
}
git merge --abort >/dev/null 2>&1||true; git rebase --abort >/dev/null 2>&1||true
git checkout -f "$INTEGRATION" >/dev/null 2>&1 || { log "no $INTEGRATION branch"; exit 1; }
git reset --hard >/dev/null 2>&1 || true
for b in $(git branch --list 'ownership/*' --format='%(refname:short)'); do git branch -D "$b" >/dev/null 2>&1||true; done
git pull --ff-only >/dev/null 2>&1 || true

log "remediate preflight: cargo build --lib"
timeout "$BUILD_TIMEOUT" cargo build --lib --quiet 2>/dev/null || { log "integration not green -- abort"; exit 1; }

fixed=0; parked=0
for ((i=1;i<=REMEDIATE_MAX;i++)); do
  # Highest-priority still-TODO row (priority = smell score * (1 + fan-in/100)), EXCLUDING
  # rows above MAX_FANIN. Without that filter this harness picks Listing/Function/DataType...
  # on iteration 1 -- precisely the Phase 2 types the header says must not run unattended.
  # The doc's constraint has to live in the code, not only in a comment above it.
  row=$(awk -F'\t' -v maxfan="$MAX_FANIN" -v mech="$MECHANICAL_ONLY" -v dynmax="$DYN_BLOCK_THRESHOLD" '
        $1=="TODO" && ($4+0)<=maxfan {
          if (mech=="1") {
            if ($8 ~ /rc_refcell=|arc_mutex=/) next
            if (match($8, /dyn=[0-9]+/) && substr($8, RSTART+4, RLENGTH-4)+0 >= dynmax) next
          }
          print
        }' "$DEBT" | sort -t$'\t' -k2,2 -rn | head -1)
  if [ -z "$row" ]; then
    skipped=$(awk -F'\t' -v maxfan="$MAX_FANIN" '$1=="TODO" && ($4+0)>maxfan' "$DEBT" | wc -l)
    log "no eligible TODO rows left in $DEBT (${skipped} above MAX_FANIN=${MAX_FANIN} held back for human-reviewed Phase 2; MECHANICAL_ONLY=${MECHANICAL_ONLY})."
    break
  fi
  path=$(printf '%s' "$row" | cut -f7); class=$(printf '%s' "$row" | cut -f5); signals=$(printf '%s' "$row" | cut -f8)
  hash=$(printf '%s' "$path" | cksum | cut -d' ' -f1); branch="ownership/${class}-${hash}"
  clog="$LOG_DIR/ownership.${class}.${hash}.$(date +%s).log"; jlog="${clog%.log}.json"

  log "remediate ${i}/${REMEDIATE_MAX}: $class ($path) -- $signals"
  git checkout -f "$INTEGRATION" >/dev/null 2>&1
  git branch -D "$branch" >/dev/null 2>&1 || true; git switch -c "$branch" >/dev/null 2>&1

  prompt="Remediate a Java-idiom-in-Rust smell in an already-ported file, per ${DOC}.
File: ${path}
Detected signals: ${signals}

Read ${DOC} first for the target conventions (arena+typed-ID for shared/graph types,
enum dispatch for closed hierarchies). Then:
- If this type is graph-shaped / referenced from many places and mutated over its
  lifetime (matches the arena convention in ${DOC}): introduce or extend the
  relevant arena/store and a Copy ID type; convert the flagged Box<dyn>/Rc<RefCell<_>>/
  Arc<Mutex<_>> usage to hold the ID instead, with methods on the ID taking
  '&Store'/'&mut Store'. Update EVERY call site the compiler flags -- do not leave
  integration red.
- If this type is a closed set of variants (matches the enum-dispatch convention):
  convert the Box<dyn Trait> hierarchy to an enum with one variant per concrete kind.
- Java-bean get_x()/set_x() pairs: collapse to a single accessor or a pub field per
  normal Rust convention, unless the getter/setter does real validation/side effects
  Java relied on (keep it in that case).
- .unwrap()/.expect() outside tests: propagate with '?' / Result unless the panic is
  genuinely an invariant violation (document why, briefly, if you keep it).
- Do NOT change externally-observed behavior. Do NOT weaken or delete tests.
- If the fix would require touching a type with no established convention yet
  (a genuinely new case OWNERSHIP_MIGRATION.md doesn't cover), STOP and end with:
  PORT_RESULT: PARKED <what convention decision is needed>.
- Verify with 'cargo build --lib' (do NOT run cargo test; do NOT run git).
- Set the row for '${path}' in ${DEBT} from TODO to DONE (col 1).
Change ONLY what's needed to fix the flagged smell in this file and its call sites."

  timeout "$CLAUDE_TIMEOUT" claude -p "$prompt" --model "$MODEL" --permission-mode acceptEdits \
    --allowedTools "Read,Edit,Write,Bash(cargo build*),Bash(cargo check*)" \
    --output-format json >"$jlog" 2>>"$clog"; rc=$?
  "$PY" -c 'import json,sys;print(json.load(open(sys.argv[1])).get("result",""))' "$jlog" >>"$clog" 2>/dev/null||true
  iserr=$("$PY" -c 'import json,sys;print(1 if json.load(open(sys.argv[1])).get("is_error") else 0)' "$jlog" 2>/dev/null||echo 1)

  status=$(grep -F "$path"$'\t' "$DEBT" | head -1 | cut -f1 | tr -d '[:space:]')
  if [ "$rc" -ne 124 ] && { [ "$rc" -ne 0 ] || [ "$iserr" = "1" ]; }; then
    log "API failure on $class -- stopping run (not parking)."; git checkout -f "$INTEGRATION" >/dev/null 2>&1
    git branch -D "$branch" >/dev/null 2>&1||true; break
  fi
  if [ "$status" = "DONE" ] && timeout "$BUILD_TIMEOUT" cargo build --lib --quiet 2>>"$clog"; then
    git add -A; git commit -q -m "ownership: remediate ${class} (${path})" || true
    git checkout -f "$INTEGRATION" >/dev/null 2>&1
    if git merge --no-ff "$branch" -m "merge ownership: ${class}" >>"$clog" 2>&1 && timeout "$BUILD_TIMEOUT" cargo build --lib --quiet 2>>"$clog"; then
      git branch -D "$branch" >/dev/null 2>&1||true
      fixed=$((fixed+1)); log "OK ownership: $class merged"
    else
      git merge --abort >/dev/null 2>&1||true; git reset --hard >/dev/null 2>&1||true
      set_status "$path" PARK || log "WARN: could not park row for $path in $DEBT"
      git add "$DEBT" >/dev/null 2>&1; git commit -q -m "ownership: park $class" >/dev/null 2>&1||true
      parked=$((parked+1)); log "PARK ownership: $class (post-merge build failed)"
    fi
  else
    git checkout -f "$INTEGRATION" >/dev/null 2>&1
    set_status "$path" PARK || log "WARN: could not park row for $path in $DEBT"
    git add "$DEBT" >/dev/null 2>&1; git commit -q -m "ownership: park $class" >/dev/null 2>&1||true
    parked=$((parked+1)); log "PARK ownership: $class (status=$status / build red). log: $clog"
  fi
done

git checkout -f "$INTEGRATION" >/dev/null 2>&1 || true
if [ "$PUSH" = "1" ] && [ "$fixed" -gt 0 ]; then
  git push "$PUSH_REMOTE" "$INTEGRATION" >/dev/null 2>&1 && log "pushed $PUSH_REMOTE/$INTEGRATION" || log "push FAILED (non-fatal; check SSH under cron)"
fi
line="[$(date '+%Y-%m-%d %H:%M')] ownership remediation run: +${fixed} fixed, ${parked} parked"
echo "$line" | tee -a "$LOG_DIR/port-summary.log"
command -v notify-send >/dev/null 2>&1 && notify-send "ghidra-rs ownership" "$line" 2>/dev/null || true
