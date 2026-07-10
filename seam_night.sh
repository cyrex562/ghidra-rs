#!/usr/bin/env bash
#
# Seam harness — breaks the ~8.9k-class keystone SCC by porting core Java interfaces
# to Rust TRAITS, stubbing any unported cross-referenced core type as a minimal
# placeholder trait (recorded in STUBS.tsv for a follow-up pass). Unlike tick2.sh it
# does NOT require 0 remaining deps -- entering the cycle is the whole point.
#
# Work-list: SEAM.tsv (col1 status TODO/DONE/PARK, col6 path), processed top-down.
# Per class: branch off integration -> claude ports the trait (+ stubs) -> gate on
# cargo build --lib -> merge -> push. Bounded by SEAM_MAX per run.
#
# Usage:  SEAM_MAX=6 MODEL=sonnet ./seam_night.sh
#         crontab:  0 22 * * * /home/cyrex/Projects/ghidra-rs/seam_night.sh   (via a wrapper that sets env)
#
set -uo pipefail
export HOME="${HOME:-/home/cyrex}"
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
REPO="${REPO_DIR:-$HOME/Projects/ghidra-rs}"; cd "$REPO" || exit 1

MODEL="${MODEL:-sonnet}"
SEAM_MAX="${SEAM_MAX:-6}"
MANIFEST="PORT_MANIFEST.tsv"; SEAM="SEAM.tsv"; STUBS="STUBS.tsv"; PARKED="PORT_PARKED.tsv"
INTEGRATION="${INTEGRATION:-integration}"
PUSH="${PUSH:-1}"; PUSH_REMOTE="${PUSH_REMOTE:-origin}"; GH="${GH:-0}"
CLAUDE_TIMEOUT="${CLAUDE_TIMEOUT:-1500}"; BUILD_TIMEOUT="${BUILD_TIMEOUT:-1800}"
PY="${PY:-python3}"; LOG_DIR="${LOG_DIR:-$HOME/agents/logs/ghidra}"; mkdir -p "$LOG_DIR"

exec 8>/tmp/ghidra-seam.lock; flock -n 8 || { echo "another seam run active"; exit 0; }
[ -f "$STUBS" ] || printf 'ts\tstub_class\treferenced_by\n' > "$STUBS"

log(){ echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
git merge --abort >/dev/null 2>&1||true; git rebase --abort >/dev/null 2>&1||true
git checkout -f "$INTEGRATION" >/dev/null 2>&1 || { log "no $INTEGRATION branch"; exit 1; }
git reset --hard >/dev/null 2>&1 || true
for b in $(git branch --list 'seam/*' --format='%(refname:short)'); do git branch -D "$b" >/dev/null 2>&1||true; done
git pull --ff-only >/dev/null 2>&1 || true

log "seam preflight: cargo build --lib"
timeout "$BUILD_TIMEOUT" cargo build --lib --quiet 2>/dev/null || { log "integration not green -- abort"; exit 1; }

ported=0; parked=0; reconciled=0
seam_done_before=$(grep -cP '^DONE\t' "$SEAM" 2>/dev/null || true)
log "seam start: MODEL=$MODEL SEAM_MAX=$SEAM_MAX (seam done so far: ${seam_done_before:-0})"

SEAM_ONLY="${SEAM_ONLY:-}"   # optional: space-separated class names; processed IN THE GIVEN ORDER
for ((i=1;i<=SEAM_MAX;i++)); do
  if [ -n "$SEAM_ONLY" ]; then
    # targeted mode: first still-TODO class in the requested order
    next=""
    for want in $SEAM_ONLY; do
      cand=$(awk -F'\t' -v w="$want" '$1=="TODO"{n=split($6,a,"/"); c=a[n]; sub(/\.java$/,"",c); if(c==w){print $6; exit}}' "$SEAM")
      [ -n "$cand" ] && { next="$cand"; break; }
    done
  else
    # pick the TODO seam interface with the FEWEST remaining unported deps (col4) -> fewest stubs
    next=$(awk -F'\t' '$1=="TODO"{print $4"\t"$6}' "$SEAM" | sort -n -k1,1 | head -1 | cut -f2)
  fi
  [ -z "$next" ] && { log "no TODO seam classes left."; break; }
  seampath="$next"; srcpath="orig_src/$next"; class=$(basename "$next" .java)
  hash=$(printf '%s' "$srcpath" | cksum | cut -d' ' -f1); branch="seam/${class}-${hash}"
  log="$LOG_DIR/seam.${class}.${hash}.$(date +%s).log"; jlog="${log%.log}.json"
  module=$("$PY" scripts/portlib.py module "${srcpath#orig_src/}" 2>/dev/null)

  # reconcile-skip: if a Rust impl already exists for this interface, it is effectively ported
  # (some keystones were ported early as concrete types). Mark DONE without an LLM turn.
  if grep -rqE --include='*.rs' --exclude='seam_stubs.rs' "\b(pub +)?(struct|trait|enum) +${class}\b" ghidra-rs/src 2>/dev/null; then
    esc=$(printf '%s' "$srcpath" | sed 's/[.[\*^$]/\\&/g')
    sed -i "s#^${esc}\tTODO\t#${esc}\tDONE\t#" "$MANIFEST"
    sed -i "s#^TODO\(\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t${seampath//\//\\/}\)\$#DONE\1#" "$SEAM"
    git add "$MANIFEST" "$SEAM" >/dev/null 2>&1
    git commit -q -m "seam reconcile: $class already ported -> DONE" >/dev/null 2>&1 || true
    reconciled=$((reconciled+1)); log "reconciled (already ported): $class -> DONE (no LLM turn)"; ((i--)); continue
  fi
  log "seam ${i}/${SEAM_MAX}: $class -> ${module}/ (trait)"

  git checkout -f "$INTEGRATION" >/dev/null 2>&1
  git branch -D "$branch" >/dev/null 2>&1 || true; git switch -c "$branch" >/dev/null 2>&1

  # is this class currently a PLACEHOLDER in a seam_stubs.rs? if so, this is a PROMOTE (replace it)
  promote=""
  if grep -rqE --include='seam_stubs.rs' "\b(pub +)?trait +${class}\b" ghidra-rs/src 2>/dev/null; then
    promote="PROMOTE MODE: a minimal placeholder 'trait ${class}' currently exists in a seam_stubs.rs.
You are REPLACING that placeholder with the real port. After creating the real trait: (1) update EVERY
importer -- replace each 'use ...seam_stubs::${class}' (and any 'seam_stubs::${class}' path) with the
real trait's path; if the placeholder had methods, the real trait must still provide them (keep them as
a superset) so existing impls/callers compile. (2) DELETE the placeholder 'trait ${class}' (and any
${class}-specific consts) from seam_stubs.rs. (3) Remove ${class}'s line(s) from STUBS.tsv. Then proceed
with the normal rules below.
"
  fi
  prompt="You are breaking a dependency CYCLE in a Java->Rust port. Port the Java INTERFACE at
${srcpath} to a Rust TRAIT.
${promote}
Destination: ghidra-rs/src/${module}/ -- mirror the remaining Java package path in snake_case;
create the file and wire it into mod.rs up the chain. Read sibling .rs files first for conventions.

Rules for breaking the cycle:
- Map the Java interface to a Rust trait (methods -> trait methods). Prefer object-safe traits
  (use &self, return owned/boxed types); where a method returns/takes another core type, use a
  trait object (Box<dyn T>/Arc<dyn T>) or a generic, NOT a concrete struct.
- For any in-repo core type this interface references that is NOT yet defined in the Rust crate,
  do NOT port that type here and do NOT fail: define a MINIMAL placeholder trait for it (e.g.
  'pub trait DataTypeManager {}' with only the methods THIS interface needs) in a shared stubs
  module ghidra-rs/src/${module}/seam_stubs.rs (create/extend it; wire into mod.rs), and append a
  line to STUBS.tsv: '<ISO-time>\t<PlaceholderName>\t${class}'. These placeholders get replaced by
  real traits as those classes are ported later.
- Add a #[cfg(test)] mod with at least one smoke test (e.g. a trivial mock impl of the trait to
  prove it is object-safe / usable).
- Verify locally with 'cargo build --lib' ONLY (do NOT run cargo test; do NOT run git).
- In ${MANIFEST}, set the row whose first column is exactly '${srcpath}' from TODO to DONE.
Port ONLY this interface (plus placeholder stubs for its references). No unrelated changes.
If truly impossible, leave ${MANIFEST} unchanged and end with: PORT_RESULT: PARKED <reason>."

  timeout "$CLAUDE_TIMEOUT" claude -p "$prompt" --model "$MODEL" --permission-mode acceptEdits \
    --allowedTools "Read,Edit,Write,Bash(cargo build*),Bash(cargo check*)" \
    --output-format json >"$jlog" 2>>"$log"; rc=$?
  "$PY" -c 'import json,sys;print(json.load(open(sys.argv[1])).get("result",""))' "$jlog" >>"$log" 2>/dev/null||true
  iserr=$("$PY" -c 'import json,sys;print(1 if json.load(open(sys.argv[1])).get("is_error") else 0)' "$jlog" 2>/dev/null||echo 1)

  status=$(grep -F "$srcpath"$'\t' "$MANIFEST" | head -1 | cut -f2 | tr -d '[:space:]')
  if [ "$rc" -ne 124 ] && { [ "$rc" -ne 0 ] || [ "$iserr" = "1" ]; }; then
    log "API failure on $class -- stopping run (not parking)."; git checkout -f "$INTEGRATION" >/dev/null 2>&1
    git branch -D "$branch" >/dev/null 2>&1||true; break
  fi
  if [ "$status" = "DONE" ] && timeout "$BUILD_TIMEOUT" cargo build --lib --quiet 2>>"$log"; then
    git add -A; git commit -q -m "seam: ${class} -> trait (${srcpath})" || true
    git checkout -f "$INTEGRATION" >/dev/null 2>&1
    if git merge --no-ff "$branch" -m "merge seam: ${class}" >>"$log" 2>&1 && timeout "$BUILD_TIMEOUT" cargo build --lib --quiet 2>>"$log"; then
      git branch -D "$branch" >/dev/null 2>&1||true
      sed -i "0,/^TODO\(\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t${seampath//\//\\/}\)$/s//DONE\1/" "$SEAM"
      git add "$SEAM" >/dev/null 2>&1; git commit -q -m "seam: mark $class DONE" >/dev/null 2>&1||true
      ported=$((ported+1)); log "OK seam: $class (trait) merged"
    else
      git merge --abort >/dev/null 2>&1||true; git reset --hard >/dev/null 2>&1||true
      sed -i "s#^TODO\(\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t${seampath//\//\\/}\)\$#PARK\1#" "$SEAM"
      git add "$SEAM" >/dev/null 2>&1; git commit -q -m "seam: park $class" >/dev/null 2>&1||true
      parked=$((parked+1)); log "PARK seam: $class (post-merge build failed)"
    fi
  else
    git add -A>/dev/null 2>&1||true; git commit -q -m "WIP seam park: $class" >/dev/null 2>&1||true
    git checkout -f "$INTEGRATION" >/dev/null 2>&1
    sed -i "s#^TODO\(\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t${seampath//\//\\/}\)\$#PARK\1#" "$SEAM"
    git add "$SEAM" >/dev/null 2>&1; git commit -q -m "seam: park $class" >/dev/null 2>&1||true
    parked=$((parked+1)); log "PARK seam: $class (status=$status / build red). log: $log"
  fi
done

git checkout -f "$INTEGRATION" >/dev/null 2>&1 || true
if [ "$PUSH" = "1" ] && [ $((ported+reconciled)) -gt 0 ]; then
  git push "$PUSH_REMOTE" "$INTEGRATION" >/dev/null 2>&1 && log "pushed $PUSH_REMOTE/$INTEGRATION" || log "push FAILED (non-fatal; check SSH under cron)"
fi
# test-health: report test-crate compile drift so it can never silently rot for days again
# (the seam campaign left 816 test-compile errors undetected because gates only ran build --lib).
if [ "$ported" -gt 0 ]; then
  terr=$(timeout "$BUILD_TIMEOUT" cargo test --lib --no-run 2>&1 | grep -cE '^error' || true)
  printf '%s\t%s\n' "${terr:-?}" "$(date +%s)" > test_health.txt 2>/dev/null || true
  if [ "${terr:-0}" -gt 0 ]; then
    log "WARNING: test crate has ${terr} compile errors (drift accumulating) -- run a repair sweep soon"
    command -v notify-send >/dev/null 2>&1 && notify-send "ghidra-rs test drift" "test crate: ${terr} compile errors" 2>/dev/null || true
  else
    log "test-health OK: test crate compiles clean"
  fi
fi
"$PY" scripts/dep_stats.py >/dev/null 2>&1 || true
line="[$(date '+%Y-%m-%d %H:%M')] seam run: +${ported} traits, ${reconciled} reconciled, ${parked} parked  (DONE $(grep -c $'\tDONE\t' "$MANIFEST"))"
echo "$line" | tee -a "$LOG_DIR/port-summary.log"
command -v notify-send >/dev/null 2>&1 && notify-send "ghidra-rs seam" "$line" 2>/dev/null || true
