#!/usr/bin/env bash
#
# Unblock harness — stub-tolerant porter for the CONCRETE frontier. The seam harness breaks the
# interface SCC; this breaks the "thin acyclic shell" wall the mechanical porter hits: it ports the
# highest-leverage BLOCKERS (types that are the sole remaining dep of many portable classes) even
# when they themselves have 1-4 unported deps, by stubbing those deps (recorded in STUBS.tsv).
# Each merged blocker flips its dependent need-1 classes to 0-dep-ready for the mechanical porter.
#
# Work-list: UNBLOCK.tsv (col1 status, col2 unblk-count, col3 rem, col4 kind class|interface, col6 path).
# Processed highest-unblk first. Gates on cargo build --lib; a WHOLE-RUN test gate (cargo test --lib)
# runs at the end and, if it regresses, the run is rolled back (stubs can compile yet break behavior).
# Bounded by UNBLOCK_MAX. Usage:  UNBLOCK_MAX=3 MODEL=sonnet ./unblock_night.sh
#
set -uo pipefail
export HOME="${HOME:-/home/cyrex}"
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
REPO="${REPO_DIR:-$HOME/Projects/ghidra-rs}"; cd "$REPO" || exit 1

MODEL="${MODEL:-sonnet}"
UNBLOCK_MAX="${UNBLOCK_MAX:-8}"
MANIFEST="PORT_MANIFEST.tsv"; WORK="UNBLOCK.tsv"; STUBS="STUBS.tsv"
INTEGRATION="${INTEGRATION:-integration}"
PUSH="${PUSH:-1}"; PUSH_REMOTE="${PUSH_REMOTE:-origin}"
TEST_GATE="${TEST_GATE:-0}"    # DISABLED: the test crate currently has ~816 pre-existing compile errors
                               # from the seam campaign (build --lib doesn't compile test code), so a
                               # full-suite gate always fails and can't attribute regressions. Re-enable
                               # (with a baseline error-count delta, not pass/fail) after the test-repair pass.
CLAUDE_TIMEOUT="${CLAUDE_TIMEOUT:-1500}"; BUILD_TIMEOUT="${BUILD_TIMEOUT:-1800}"; TEST_TIMEOUT="${TEST_TIMEOUT:-2400}"
PY="${PY:-python3}"; LOG_DIR="${LOG_DIR:-$HOME/agents/logs/ghidra}"; mkdir -p "$LOG_DIR"

exec 9>/tmp/ghidra-unblock.lock; flock -n 9 || { echo "another unblock run active"; exit 0; }
[ -f "$WORK" ] || { echo "no $WORK worklist"; exit 1; }
[ -f "$STUBS" ] || printf 'ts\tstub_class\treferenced_by\n' > "$STUBS"

log(){ echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
git merge --abort >/dev/null 2>&1||true; git rebase --abort >/dev/null 2>&1||true
git checkout -f "$INTEGRATION" >/dev/null 2>&1 || { log "no $INTEGRATION branch"; exit 1; }
git reset --hard >/dev/null 2>&1 || true
for b in $(git branch --list 'unblock/*' --format='%(refname:short)'); do git branch -D "$b" >/dev/null 2>&1||true; done
git pull --ff-only >/dev/null 2>&1 || true

log "unblock preflight: cargo build --lib"
timeout "$BUILD_TIMEOUT" cargo build --lib --quiet 2>/dev/null || { log "integration not green -- abort"; exit 1; }
START_COMMIT=$(git rev-parse HEAD)

ported=0; parked=0; reconciled=0
log "unblock start: MODEL=$MODEL UNBLOCK_MAX=$UNBLOCK_MAX TEST_GATE=$TEST_GATE"

for ((i=1;i<=UNBLOCK_MAX;i++)); do
  read -r unblk kind next < <(awk -F'\t' '$1=="TODO"{print $2"\t"$4"\t"$6}' "$WORK" | sort -rn -k1,1 | head -1)
  [ -z "${next:-}" ] && { log "no TODO unblock targets left."; break; }
  wpath="$next"; srcpath="orig_src/$next"; class=$(basename "$next" .java)
  hash=$(printf '%s' "$srcpath" | cksum | cut -d' ' -f1); branch="unblock/${class}-${hash}"
  log="$LOG_DIR/unblock.${class}.${hash}.$(date +%s).log"; jlog="${log%.log}.json"
  module=$("$PY" scripts/portlib.py module "${srcpath#orig_src/}" 2>/dev/null)

  # reconcile-skip: real impl already exists (not a placeholder) -> mark DONE, no LLM turn
  if grep -rqE --include='*.rs' --exclude='seam_stubs.rs' "\b(pub +)?(struct|trait|enum) +${class}\b" ghidra-rs/src 2>/dev/null; then
    esc=$(printf '%s' "$srcpath" | sed 's/[.[\*^$]/\\&/g')
    sed -i "s#^${esc}\tTODO\t#${esc}\tDONE\t#" "$MANIFEST"
    sed -i "s#^TODO\(\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t${wpath//\//\\/}\)\$#DONE\1#" "$WORK"
    git add "$MANIFEST" "$WORK" >/dev/null 2>&1; git commit -q -m "unblock reconcile: $class already ported" >/dev/null 2>&1||true
    reconciled=$((reconciled+1)); log "reconciled (already ported): $class"; ((i--)); continue
  fi
  log "unblock ${i}/${UNBLOCK_MAX}: $class ($kind, unblocks $unblk) -> ${module}/"

  git checkout -f "$INTEGRATION" >/dev/null 2>&1
  git branch -D "$branch" >/dev/null 2>&1 || true; git switch -c "$branch" >/dev/null 2>&1

  if [ "$kind" = "interface" ]; then shape="a Rust TRAIT (methods -> trait methods; object-safe, prefer Box<dyn T>/generics over concrete structs for cross-refs)"
  else shape="a Rust STRUCT (or enum if the Java type is an enum), porting fields + methods faithfully"; fi
  prompt="Port the Java ${kind} at ${srcpath} to ${shape}.

This is a high-leverage BLOCKER: many already-portable classes are waiting only on this type, so
porting it (even against stubbed deps) unblocks them. Destination: ghidra-rs/src/${module}/ -- mirror
the remaining Java package path in snake_case; create the file and wire it into mod.rs up the chain.
Read sibling .rs files first for conventions.

Rules:
- Port THIS type faithfully. For any in-repo type it references that is NOT yet defined in the Rust
  crate, do NOT port that type and do NOT fail: add a MINIMAL placeholder (a 'pub trait X {}' for an
  interface-shaped dep, or a minimal 'pub struct X;' with only the fields/methods THIS type needs for
  a concrete dep) in ghidra-rs/src/${module}/seam_stubs.rs (create/extend; wire into mod.rs), and
  append '<ISO-time>\t<PlaceholderName>\t${class}' to STUBS.tsv. Keep stubs as small as possible.
- Add a #[cfg(test)] mod with at least one smoke test exercising the real (non-stub) behavior you ported.
- Verify locally with 'cargo build --lib' ONLY (do NOT run cargo test; do NOT run git).
- In ${MANIFEST}, set the row whose first column is exactly '${srcpath}' from TODO to DONE.
Port ONLY this type (+ minimal stubs for its refs). No unrelated changes.
If truly impossible, leave ${MANIFEST} unchanged and end with: PORT_RESULT: PARKED <reason>."

  timeout "$CLAUDE_TIMEOUT" claude -p "$prompt" --model "$MODEL" --permission-mode acceptEdits \
    --allowedTools "Read,Edit,Write,Bash(cargo build*),Bash(cargo check*)" \
    --output-format json >"$jlog" 2>>"$log"; rc=$?
  "$PY" -c 'import json,sys;print(json.load(open(sys.argv[1])).get("result",""))' "$jlog" >>"$log" 2>/dev/null||true
  iserr=$("$PY" -c 'import json,sys;print(1 if json.load(open(sys.argv[1])).get("is_error") else 0)' "$jlog" 2>/dev/null||echo 1)

  status=$(grep -F "$srcpath"$'\t' "$MANIFEST" | head -1 | cut -f2 | tr -d '[:space:]')
  if [ "$rc" -ne 124 ] && { [ "$rc" -ne 0 ] || [ "$iserr" = "1" ]; }; then
    log "API failure on $class -- stopping run."; git checkout -f "$INTEGRATION" >/dev/null 2>&1
    git branch -D "$branch" >/dev/null 2>&1||true; break
  fi
  if [ "$status" = "DONE" ] && timeout "$BUILD_TIMEOUT" cargo build --lib --quiet 2>>"$log"; then
    git add -A; git commit -q -m "unblock: ${class} -> ${kind} (${srcpath})" || true
    git checkout -f "$INTEGRATION" >/dev/null 2>&1
    if git merge --no-ff "$branch" -m "merge unblock: ${class}" >>"$log" 2>&1 && timeout "$BUILD_TIMEOUT" cargo build --lib --quiet 2>>"$log"; then
      git branch -D "$branch" >/dev/null 2>&1||true
      sed -i "0,/^TODO\(\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t${wpath//\//\\/}\)$/s//DONE\1/" "$WORK"
      git add "$WORK" >/dev/null 2>&1; git commit -q -m "unblock: mark $class DONE" >/dev/null 2>&1||true
      ported=$((ported+1)); log "OK unblock: $class merged (unblocks ~$unblk)"
    else
      git merge --abort >/dev/null 2>&1||true; git reset --hard >/dev/null 2>&1||true
      sed -i "s#^TODO\(\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t${wpath//\//\\/}\)\$#PARK\1#" "$WORK"
      git add "$WORK">/dev/null 2>&1; git commit -q -m "unblock: park $class" >/dev/null 2>&1||true
      parked=$((parked+1)); log "PARK unblock: $class (post-merge build failed)"
    fi
  else
    git checkout -f "$INTEGRATION" >/dev/null 2>&1
    sed -i "s#^TODO\(\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t${wpath//\//\\/}\)\$#PARK\1#" "$WORK"
    git add "$WORK">/dev/null 2>&1; git commit -q -m "unblock: park $class" >/dev/null 2>&1||true
    parked=$((parked+1)); log "PARK unblock: $class (status=$status / build red). log: $log"
  fi
done

git checkout -f "$INTEGRATION" >/dev/null 2>&1 || true

# whole-run TEST GATE: stubs can compile yet break behavior. If tests regress, roll the run back.
if [ "$TEST_GATE" = "1" ] && [ "$ported" -gt 0 ]; then
  log "unblock test gate: cargo test --lib --test-threads=1 (may take a while)"
  if timeout "$TEST_TIMEOUT" cargo test --lib -- --test-threads=1 >>"$LOG_DIR/unblock.tests.$(date +%s).log" 2>&1; then
    log "test gate PASSED"
  else
    log "test gate FAILED -- rolling back this run to $START_COMMIT (stubs likely broke behavior)"
    git reset --hard "$START_COMMIT" >/dev/null 2>&1
    ported=0; ROLLED_BACK=1
  fi
fi

if [ "$PUSH" = "1" ] && [ $((ported+reconciled)) -gt 0 ]; then
  git push "$PUSH_REMOTE" "$INTEGRATION" >/dev/null 2>&1 && log "pushed $PUSH_REMOTE/$INTEGRATION" || log "push FAILED (non-fatal)"
fi
"$PY" scripts/dep_stats.py >/dev/null 2>&1 || true
line="[$(date '+%Y-%m-%d %H:%M')] unblock run: +${ported} blockers, ${reconciled} reconciled, ${parked} parked${ROLLED_BACK:+ (ROLLED BACK: test regression)}  (DONE $(grep -c $'\tDONE\t' "$MANIFEST"))"
echo "$line" | tee -a "$LOG_DIR/port-summary.log"
command -v notify-send >/dev/null 2>&1 && notify-send "ghidra-rs unblock" "$line" 2>/dev/null || true
