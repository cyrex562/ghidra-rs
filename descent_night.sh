#!/usr/bin/env bash
#
# Recursive-descent porting harness -- the unified driver. Replaces the two prior
# pickers (tick2.sh's 0-dep-leaf frontier; seam_night.sh's flat fanin-ranked trait
# list) with a single leaf-first order computed by scripts/desc_order.py:
#
#   DFS the unported in-scope dep graph from the highest-fanin node, descend to
#   leaves, emit POST-ORDER so every class is ported after its deps. Back-edges
#   (the giant SCC's cycle edges) are cut by porting that node as a Rust TRAIT;
#   everything else ports as a normal struct. Two-phase: traits declared first.
#
# Work-list: PORT_ORDER.tsv  (status  mode  depth  fanin  rem  module  path),
# processed STRICTLY top-down (the order is the whole point -- do NOT re-sort).
# Per row: branch off integration -> claude ports (trait path or struct path by
# mode) -> gate on cargo build --lib -> merge -> push. Bounded by DESCENT_MAX.
#
# Usage:  DESCENT_MAX=6 MODEL=sonnet ./descent_night.sh
#         DESCENT_ONLY=StructureDataType DESCENT_MAX=1 PUSH=0 ./descent_night.sh   # targeted test
#         crontab:  0 19 * * * DESCENT_MAX=40 MODEL=sonnet /home/cyrex/Projects/ghidra-rs/descent_night.sh
#
set -uo pipefail
export HOME="${HOME:-/home/cyrex}"
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
REPO="${REPO_DIR:-$HOME/Projects/ghidra-rs}"; cd "$REPO" || exit 1

MODEL="${MODEL:-sonnet}"
DESCENT_MAX="${DESCENT_MAX:-6}"
MANIFEST="PORT_MANIFEST.tsv"; ORDER="PORT_ORDER.tsv"; STUBS="STUBS.tsv"
DEBT="OWNERSHIP_DEBT.tsv"                                           # Java-idiom frontier (OWNERSHIP_MIGRATION.md)
AUDIT_STEP="${AUDIT_STEP:-1}"                                       # post-run idiom-drift scan; detection only, never blocks a port
DESCENT_PARKED="DESCENT_PARKED.tsv"   # durable park-list: classes too big for the nightly loop (timeouts);
                                      # excluded from the regenerated order, worked interactively in daytime
SHAPES_TSV="${SHAPES_TSV:-SHAPES.tsv}"  # Java declaration -> Rust shape, from scripts/shape_rules.py
INTEGRATION="${INTEGRATION:-integration}"
PUSH="${PUSH:-1}"; PUSH_REMOTE="${PUSH_REMOTE:-origin}"
REGEN="${REGEN:-1}"        # regenerate PORT_ORDER.tsv at start (stale rows reconcile harmlessly, but fresh is better)
TIMEOUT_RETRIES="${TIMEOUT_RETRIES:-2}"   # errored turns retried this many times before a durable park
CLAUDE_TIMEOUT="${CLAUDE_TIMEOUT:-1500}"; BUILD_TIMEOUT="${BUILD_TIMEOUT:-1800}"  # 25min: doomed classes durable-park faster (was 2400/40min)
TEST_GATE="${TEST_GATE:-1}"; TEST_TIMEOUT="${TEST_TIMEOUT:-1800}"   # backstop: verify test crate stays green after merge
API_RETRIES="${API_RETRIES:-2}"                                     # retry a class on TRANSIENT API failure before aborting the run
OVERALL_HOURS="${OVERALL_HOURS:-7}"                                 # wall-clock cap; loop stops after this many hours regardless of DESCENT_MAX
PY="${PY:-python3}"; LOG_DIR="${LOG_DIR:-$HOME/agents/logs/ghidra}"; mkdir -p "$LOG_DIR"
START_EPOCH=$(date +%s)

exec 7>/tmp/ghidra-descent.lock; flock -n 7 || { echo "another descent run active"; exit 0; }
[ -f "$STUBS" ] || printf 'ts\tstub_class\treferenced_by\n' > "$STUBS"
[ -f "$DESCENT_PARKED" ] || printf 'ts\treason\tpath\n' > "$DESCENT_PARKED"

log(){ echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
git merge --abort >/dev/null 2>&1||true; git rebase --abort >/dev/null 2>&1||true
# Preserve any uncommitted work before the checkout/reset below discards it.
. scripts/harness_guard.sh
. scripts/harness_gate.sh
guard_working_tree descent || exit 1
git checkout -f "$INTEGRATION" >/dev/null 2>&1 || { log "no $INTEGRATION branch"; exit 1; }
git reset --hard >/dev/null 2>&1 || true
for b in $(git branch --list 'descent/*' --format='%(refname:short)'); do git branch -D "$b" >/dev/null 2>&1||true; done
git pull --ff-only >/dev/null 2>&1 || true

log "descent preflight: cargo build --lib"
timeout "$BUILD_TIMEOUT" cargo build --lib --quiet 2>/dev/null || { log "integration not green -- abort"; exit 1; }
# baseline test-crate compile health -- the backstop parks any port that RAISES this count
TEST_ERR_BASE=$(timeout "$TEST_TIMEOUT" cargo test --lib --no-run 2>&1 | grep -cE '^error'); TEST_ERR_BASE=${TEST_ERR_BASE:-0}
log "preflight test-compile baseline: ${TEST_ERR_BASE} errors"
# A suite that already hangs makes the per-port runtime gate meaningless (every port would time
# out and park), so establish up front that it terminates at all.
if [ "$TEST_GATE" = "1" ]; then
  timeout "$TEST_TIMEOUT" cargo test --lib --no-fail-fast >/dev/null 2>&1; pre_rc=$?
  if [ "$pre_rc" -eq 124 ]; then
    log "preflight: suite HANGS on integration before any port -- fix the hang first; aborting."
    exit 1
  fi
  log "preflight: suite terminates (rc=${pre_rc})"
fi

# refresh the leaf-first order against the current manifest (unless disabled)
if [ "$REGEN" = "1" ] && [ -z "${DESCENT_ONLY:-}" ]; then
  log "regenerating $ORDER"
  "$PY" scripts/desc_order.py --write >/dev/null 2>>"$LOG_DIR/descent_night.log" || log "WARN: desc_order regen failed, using existing $ORDER"
  git add "$ORDER" >/dev/null 2>&1; git commit -q -m "descent: refresh PORT_ORDER.tsv" >/dev/null 2>&1||true
fi

# SHAPES.tsv answers "what Rust shape should this Java file become?", which is a different
# question from PORT_ORDER's `mode` ("is this file a dependency-cycle cut point?"). Conflating
# the two is what turned `sealed interface Lifespan` -- a closed set over a long range -- into
# `pub trait Lifespan` with 613 `dyn Lifespan` uses behind it. `mode` still decides ORDER;
# `shape` decides the TYPE. It is keyed by path rather than added as a PORT_ORDER column
# on purpose: the row-rewriting seds below match a fixed seven-column layout.
if [ "${SHAPE_RULES:-1}" = "1" ] && [ ! -s "$SHAPES_TSV" ]; then
  log "building $SHAPES_TSV (first run)"
  "$PY" scripts/shape_rules.py index >/dev/null 2>>"$LOG_DIR/descent_night.log" \
    || log "WARN: shape index failed -- falling back to mode-only prompts"
fi
[ -f "$ORDER" ] || { log "no $ORDER worklist -- run scripts/desc_order.py --write"; exit 1; }

ported=0; parked=0; reconciled=0
log "descent start: MODEL=$MODEL DESCENT_MAX=$DESCENT_MAX (DONE so far: $(grep -c $'\tDONE\t' "$MANIFEST"))"

DESCENT_ONLY="${DESCENT_ONLY:-}"   # optional: space-separated class names, processed in that order
for ((i=1;i<=DESCENT_MAX;i++)); do
  # wall-clock cap: the port-write-test-fix loop is slower per class, so bound the night
  elapsed_h=$(( ($(date +%s) - START_EPOCH) / 3600 ))
  if [ "$elapsed_h" -ge "$OVERALL_HOURS" ]; then log "OVERALL_HOURS=${OVERALL_HOURS} reached -- stopping."; break; fi
  if [ -n "$DESCENT_ONLY" ]; then
    next=""; mode=""
    for want in $DESCENT_ONLY; do
      read -r mode rem next < <(awk -F'\t' -v w="$want" '$1=="TODO"{n=split($7,a,"/"); c=a[n]; sub(/\.java$/,"",c); if(c==w){print $2"\t"$5"\t"$7; exit}}' "$ORDER")
      [ -n "$next" ] && break
    done
  else
    # STRICT top-down: first still-TODO row in file order (leaf-first). mode col2, rem col5.
    read -r mode rem next < <(awk -F'\t' '$1=="TODO"{print $2"\t"$5"\t"$7; exit}' "$ORDER")
  fi
  [ -z "$next" ] && { log "no TODO rows left in $ORDER."; break; }
  ordpath="$next"; srcpath="orig_src/$next"; class=$(basename "$next" .java)
  hash=$(printf '%s' "$srcpath" | cksum | cut -d' ' -f1); branch="descent/${class}-${hash}"
  log="$LOG_DIR/descent.${class}.${hash}.$(date +%s).log"; jlog="${log%.log}.json"
  module=$("$PY" scripts/portlib.py module "${srcpath#orig_src/}" 2>/dev/null)

  # #7 MODEL TIERING: route by difficulty (rem = stub surface, lines = size) to a per-class model.
  # Default no-op (all $MODEL). Enable via env: TIER_HARD_REM/LINES + MODEL_HARD (e.g. opus),
  # TIER_EASY_REM/LINES + MODEL_EASY (e.g. haiku). Cheap classes cheaper, hard classes more power.
  lines=$(wc -l < "$srcpath" 2>/dev/null | tr -d ' '); lines=${lines:-0}; rem=${rem:-0}
  portmodel="$MODEL"; tier="med"
  if [ "$rem" -gt "${TIER_HARD_REM:-99999}" ] || [ "$lines" -gt "${TIER_HARD_LINES:-999999}" ]; then
    portmodel="${MODEL_HARD:-$MODEL}"; tier="hard"
  elif [ "$rem" -le "${TIER_EASY_REM:--1}" ] && [ "$lines" -le "${TIER_EASY_LINES:--1}" ]; then
    portmodel="${MODEL_EASY:-$MODEL}"; tier="easy"
  fi

  # reconcile-skip: a Rust type for this class already exists (ported early / by another harness)
  if grep -rqE --include='*.rs' --exclude='seam_stubs.rs' "\b(pub +)?(struct|trait|enum) +${class}\b" ghidra-rs/src 2>/dev/null; then
    esc=$(printf '%s' "$srcpath" | sed 's/[.[\*^$]/\\&/g')
    sed -i "s#^${esc}\tTODO\t#${esc}\tDONE\t#" "$MANIFEST"
    sed -i "s#^TODO\(\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t${ordpath//\//\\/}\)\$#DONE\1#" "$ORDER"
    git add "$MANIFEST" "$ORDER" >/dev/null 2>&1
    git commit -q -m "descent reconcile: $class already ported -> DONE" >/dev/null 2>&1 || true
    reconciled=$((reconciled+1)); log "reconciled (already ported): $class -> DONE (no LLM turn)"; ((i--)); continue
  fi

  # SHAPE: what Rust construct this Java declaration should become, decided from the Java
  # source by scripts/shape_rules.py. Empty when the index is missing or the file is not in it.
  shape=""; shape_rule=""
  if [ "${SHAPE_RULES:-1}" = "1" ] && [ -s "$SHAPES_TSV" ]; then
    read -r shape shape_rule < <(awk -F'\t' -v p="$ordpath" '$1==p{print $4"\t"$5; exit}' "$SHAPES_TSV")
  fi

  # A shape the rules cannot decide (marker interfaces, constant-carrying type tags,
  # annotation types) is a question for a human, not a coin flip for the porter. Park it
  # WITHOUT an LLM turn -- at $3.26 per turn last run, guessing 169 of these is real money
  # spent producing code that would then have to be found and undone.
  if [ "$shape" = "park" ]; then
    why=$(awk -F'\t' -v p="$ordpath" '$1==p{print $8; exit}' "$SHAPES_TSV")
    printf '%s\tshape-undecided (%s)\t%s\n' "$(date '+%Y-%m-%dT%H:%M')" "${shape_rule}" "$next" >> "$DESCENT_PARKED"
    sed -i "s#^TODO\(\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t${ordpath//\//\\/}\)\$#PARK\1#" "$ORDER"
    git add "$DESCENT_PARKED" "$ORDER" >/dev/null 2>&1
    git commit -q -m "descent: park $class (shape undecided: ${shape_rule})" >/dev/null 2>&1||true
    log "PARK descent: $class (shape undecided, ${shape_rule}: ${why}) -- no LLM turn"
    parked=$((parked+1)); ((i--)); continue
  fi

  log "descent ${i}/${DESCENT_MAX}: $class -> ${module}/ (${mode}${shape:+, shape=$shape}, ${tier}/${portmodel}, rem=${rem} lines=${lines})"

  git checkout -f "$INTEGRATION" >/dev/null 2>&1
  git branch -D "$branch" >/dev/null 2>&1 || true; git switch -c "$branch" >/dev/null 2>&1

  # #3/#6 DEPENDENCY CONTEXT: real Rust APIs of already-ported deps (reuse, don't guess) + convention-
  # correct stub traits for unported deps (use, don't invent). Written to a FILE the model reads -- NOT
  # interpolated into the prompt string (that path caused the 2026-07-25 quoting break).
  depctx_file="$LOG_DIR/depctx.${class}.${hash}.txt"; depctx_note=""

  # OWNERSHIP STEERING: DB-backed domain objects must not inherit Java's cache/lock/refresh
  # scaffolding. Ported literally, each one brings cached fields + a modification-count staleness
  # check + a reentrant lock + refreshIfNeeded -- the pattern that produced the DataTypeDB
  # self-deadlock and a cache that survived its own invalidation. 345 of these are still queued,
  # so the default has to change before they land, not after.
  ownership_note=""
  case "$ordpath" in
    *ghidra/program/database/*)
      ownership_note="
OWNERSHIP CONVENTION (read OWNERSHIP_MIGRATION.md section 'Snapshot + transaction' FIRST):
This class is a DB-backed domain object. Do NOT port Java's staleness machinery:
- no cached name/category fields refreshed against a modification count;
- no 'needs_refreshing'/'refresh_if_needed'/'do_refresh' plumbing;
- no reentrant read/write lock guarding those fields.
Instead: reads take an atomic snapshot (an Arc of the store) and resolve Copy IDs against it --
a snapshot cannot be stale, so there is nothing to check; writes go through a transaction that
mutates and publishes a new version. If the surrounding types for that model do not exist yet,
port only this class's real behaviour (the DB record read/write and the domain logic), leave the
caching/locking OUT entirely rather than inventing it, and say so in your final message.
If you cannot do that without inventing a convention, STOP with: PORT_RESULT: PARKED <what is needed>."
      ;;
  esac
  if [ "${DEP_CONTEXT:-1}" = "1" ] && timeout 120 "$PY" scripts/dep_context.py "$ordpath" > "$depctx_file" 2>/dev/null && [ -s "$depctx_file" ]; then
    depctx_note="
DEPENDENCY CONTEXT (read this FILE first): ${depctx_file}
  It lists the REAL Rust paths + API of already-ported deps (reuse them verbatim; do NOT redefine or
  guess their signatures) and convention-correct stub traits for unported deps (paste these into
  seam_stubs.rs if needed; do NOT invent your own names/shapes)."
  fi

  # PROMOTE detection runs for BOTH modes. It used to sit inside the trait branch only, so a
  # class ported as a struct never learned that a placeholder for it already existed -- the stub
  # survived and SHADOWED the real type. 42 names ended up declared twice, with 113 files wired
  # to the empty placeholder (see STUB_DEBT.tsv / scripts/stub_audit.py).
  promote=""
  if grep -rqE --include='seam_stubs.rs' "\b(pub +)?(trait|struct|enum) +${class}\b" ghidra-rs/src 2>/dev/null; then
    promote="PROMOTE MODE: a minimal placeholder for '${class}' currently exists in a seam_stubs.rs.
You are REPLACING that placeholder with the real port. After creating the real type: (1) update EVERY
importer -- replace each 'use ...seam_stubs::${class}' with the real type's path; keep any placeholder
methods as a superset so existing impls/callers compile. (2) DELETE the placeholder from seam_stubs.rs.
(3) Remove ${class}'s line(s) from STUBS.tsv. Leaving the placeholder in place creates two types with
the same name, which compiles and silently cannot interoperate.
"
  fi

  # SHAPE DIRECTIVE. The single most expensive class of defect in this port has not been a
  # wrong method body -- it has been a correct method body hung off the wrong Rust construct,
  # because that mistake is contagious: every caller written afterwards is written against it.
  # The rules live in scripts/shape_rules.py, decided from the Java declaration alone.
  shape_note=""
  if [ -n "$shape" ]; then
    sd=$(timeout 60 "$PY" scripts/shape_rules.py directive "$ordpath" 2>/dev/null)
    [ -n "$sd" ] && shape_note="

REQUIRED SHAPE (rule ${shape_rule} -- this is not a suggestion; if you believe it is wrong for
this type, do NOT port it: end with PORT_RESULT: PARKED and say why):
${sd}"
  fi

  # A cycle cut-point is a fact about the dependency GRAPH, not about the type. It used to be
  # translated as "port this as a trait", which deformed value types into trait objects to
  # solve an ordering problem -- `sealed interface Lifespan` became `pub trait Lifespan` and
  # 613 `dyn Lifespan` uses followed it. Cut the cycle at the forward reference (a stub),
  # never by changing what this type is.
  cycle_note=""
  if [ "$mode" = "trait" ]; then
    cycle_note="
CYCLE NOTE: this file sits on a dependency cycle, which is why it comes up now. Break the cycle
by STUBBING the forward reference (see the placeholder rule below) -- not by changing this type's
shape. The required shape above already accounts for it."
  fi

  prompt="Port the Java type at ${srcpath} to idiomatic Rust.
${promote}
It was chosen by RECURSIVE-DESCENT order: its in-repo dependencies are already ported, so REUSE
the existing Rust types -- read them first; do not redefine them.

Destination: ghidra-rs/src/${module}/ -- mirror the remaining Java package path in snake_case;
create the file and wire it into mod.rs up the chain. Read sibling .rs files first for conventions.${depctx_note}${shape_note}${cycle_note}${ownership_note}

Rules:
- Map fields and methods faithfully, and implement any Rust trait corresponding to a Java interface
  this type implements (those traits are already ported).
- OWNERSHIP: reach for \`Box<dyn T>\`/\`Arc<dyn T>\`/\`Rc<RefCell<_>>\`/\`Arc<Mutex<_>>\` only when THIS
  call site genuinely needs runtime polymorphism or shared mutation. A Java interface is not by itself
  a reason for \`dyn\`, and a Java field with a getter is not a reason for a \`get_x\`/\`set_x\` pair.
  Prefer a generic \`impl T\` parameter over \`&dyn T\`, a concrete type over a trait object, and a
  public field or a single accessor over a bean pair. See OWNERSHIP_MIGRATION.md.
- Prefer reusing already-ported types by their real path. If a referenced in-repo core type is genuinely
  NOT yet in the crate (a forward cycle edge), define a MINIMAL placeholder for it in
  ghidra-rs/src/${module}/seam_stubs.rs (only the methods THIS type needs; wire into mod.rs) and append
  '<ISO-time>\t<PlaceholderName>\t${class}' to STUBS.tsv -- do NOT fail for a missing type.
- Add a #[cfg(test)] mod with at least one smoke test that compares against expected values from the
  Java behavior, not trivially-true asserts.
- MANDATORY test-green loop before finishing: (1) 'cargo build --lib' must pass; (2) 'cargo test --lib
  --no-run' must compile with ZERO errors -- if your change broke EXISTING test code elsewhere, update
  that test code to match; (3) run ONLY your class's OWN module tests (e.g. 'cargo test --lib the_module_path') and make them PASS
  -- do NOT run the full 'cargo test --lib' suite yourself; it is slow (18k tests) and the harness runs
  it as a final gate. Fast cycles = build + your module only. Iterate: build/test ->
  read failures -> fix -> repeat until BOTH compile clean AND all tests pass. Do NOT run git. Run cargo SYNCHRONOUSLY
  and wait for each command to finish -- this is a SINGLE-SHOT non-interactive session: never
  background a command, schedule a wakeup, or defer work to 'report back later'. Everything,
  including the final passing test run, must complete within this turn before you stop.
- In ${MANIFEST}, set the row whose first column is exactly '${srcpath}' from TODO to DONE.
Port this type and fix any test code your change breaks.
If truly impossible, leave ${MANIFEST} unchanged and end with: PORT_RESULT: PARKED <reason>."

  # Invoke the porter with bounded retry on TRANSIENT API failure (e.g. "connection closed
  # mid-response" cost ~1h of window 2026-07-23). rc=124 is a per-port TIMEOUT, not an API error --
  # let it fall through to the build/park path. Only a persistent failure (all attempts) aborts the run.
  api_fail=0
  for try in $(seq 0 "$API_RETRIES"); do
    if [ "$try" -gt 0 ]; then
      log "API retry ${try}/${API_RETRIES} for $class (transient failure)"
      git checkout -f "$INTEGRATION" >/dev/null 2>&1; git reset --hard >/dev/null 2>&1
      git clean -fdq >/dev/null 2>&1   # drop partial-port untracked files (target/ is ignored, kept)
      git branch -D "$branch" >/dev/null 2>&1||true; git switch -c "$branch" >/dev/null 2>&1
    fi
    timeout "$CLAUDE_TIMEOUT" claude -p "$prompt" --model "$portmodel" --permission-mode acceptEdits \
      --allowedTools "Read,Edit,Write,Bash(cargo build*),Bash(cargo check*),Bash(cargo test*)" \
      --output-format json >"$jlog" 2>>"$log"; rc=$?
    "$PY" -c 'import json,sys;print(json.load(open(sys.argv[1])).get("result",""))' "$jlog" >>"$log" 2>/dev/null||true
    iserr=$("$PY" -c 'import json,sys;print(1 if json.load(open(sys.argv[1])).get("is_error") else 0)' "$jlog" 2>/dev/null||echo 1)
    if [ "$rc" -eq 124 ] || { [ "$rc" -eq 0 ] && [ "$iserr" != "1" ]; }; then api_fail=0; break; fi
    api_fail=1
  done

  status=$(grep -F "$srcpath"$'\t' "$MANIFEST" | head -1 | cut -f2 | tr -d '[:space:]')
  if [ "$api_fail" = "1" ]; then
    log "API failure on $class after $((API_RETRIES+1)) attempts -- stopping run (not parking)."
    git checkout -f "$INTEGRATION" >/dev/null 2>&1; git branch -D "$branch" >/dev/null 2>&1||true; break
  fi
  # TIMEOUT (rc=124). Two different things end here and they want opposite treatment.
  #
  # A class genuinely too big for the nightly loop should DURABLE-park: recorded in
  # DESCENT_PARKED, excluded from every regenerated order, worked interactively later.
  #
  # But a turn whose CLI errored also runs to the wall clock, and durable-parking that
  # permanently drops a class on the strength of a tool failure. MemoryBytePatternSearcher
  # (172 lines, rem=3) and JitDataFlowUseropLibrary (281) were lost exactly that way; of the
  # 27 durable timeout-parks, 20 are under 400 lines. The turn JSON tells them apart -- an
  # errored turn records `"subtype": "error_during_execution"` with `"is_error": true`,
  # where a turn that simply ran out of time does not.
  #
  # A transient park is NOT durable: the row is written with reason `timeout-retry` (which
  # desc_order does not exclude) and PORT_ORDER is left TODO, so it comes back next run. The
  # retry is capped, because an error that reliably burns the full CLAUDE_TIMEOUT must not
  # cost 25 minutes every night forever -- after TIMEOUT_RETRIES attempts it durable-parks.
  if [ "$rc" -eq 124 ]; then
    transient=0
    if [ -s "$jlog" ] && "$PY" - "$jlog" <<'PYEOF' >/dev/null 2>&1
import json, sys
d = json.load(open(sys.argv[1]))
sys.exit(0 if (d.get("is_error") and d.get("subtype") == "error_during_execution") else 1)
PYEOF
    then transient=1; fi
    # `grep -c` already PRINTS 0 when nothing matches, and exits 1 doing it -- so a
    # `|| echo 0` fallback appends a second zero and $prior becomes "0\n0", which is not an
    # integer and blows up the comparison below. Take grep's number, default only if the
    # file is missing entirely.
    prior=$(grep -cP "\ttimeout-retry\t${next//\//\\/}$" "$DESCENT_PARKED" 2>/dev/null) || true
    [ -n "$prior" ] || prior=0
    git checkout -f "$INTEGRATION" >/dev/null 2>&1; git branch -D "$branch" >/dev/null 2>&1||true
    git clean -fdq >/dev/null 2>&1   # remove the timed-out port's partial untracked files (target/ is ignored)
    if [ "$transient" = "1" ] && [ "$prior" -lt "$TIMEOUT_RETRIES" ]; then
      log "TIMEOUT on $class (${CLAUDE_TIMEOUT}s) -- turn ERRORED (attempt $((prior+1))/${TIMEOUT_RETRIES}); retryable park, stays in the order."
      printf '%s\ttimeout-retry\t%s\n' "$(date '+%Y-%m-%dT%H:%M')" "$next" >> "$DESCENT_PARKED"
      git add "$DESCENT_PARKED" >/dev/null 2>&1
      git commit -q -m "descent: retryable-park $class (turn errored, attempt $((prior+1))/${TIMEOUT_RETRIES})" >/dev/null 2>&1||true
    else
      why="too big for the nightly loop"
      [ "$transient" = "1" ] && why="turn errored ${prior} time(s); retries exhausted"
      log "TIMEOUT on $class (${CLAUDE_TIMEOUT}s) -- durable-park (${why}) for interactive follow-up."
      printf '%s\ttimeout\t%s\n' "$(date '+%Y-%m-%dT%H:%M')" "$next" >> "$DESCENT_PARKED"
      sed -i "s#^TODO\(\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t${ordpath//\//\\/}\)\$#PARK\1#" "$ORDER"
      git add "$DESCENT_PARKED" "$ORDER" >/dev/null 2>&1
      git commit -q -m "descent: durable-park $class (timeout)" >/dev/null 2>&1||true
    fi
    parked=$((parked+1)); continue
  fi
  if [ "$status" = "DONE" ] && timeout "$BUILD_TIMEOUT" cargo build --lib --quiet 2>>"$log"; then
    harness_add; git commit -q -m "descent: ${class} -> ${mode} (${srcpath})" || true
    git checkout -f "$INTEGRATION" >/dev/null 2>&1
    pre_merge=$(git rev-parse HEAD)
    if git merge --no-ff "$branch" -m "merge descent: ${class}" >>"$log" 2>&1 && timeout "$BUILD_TIMEOUT" cargo build --lib --quiet 2>>"$log"; then
      # BACKSTOP test gate: the model is now responsible for leaving the WHOLE test crate green
      # (build + test --no-run clean + suite passing). This verifies it. It parks a port that:
      #   * RAISES the test-compile error count above the run's baseline (introduced drift), or
      #   * leaves any test FAILING.
      # Baselined against preflight (TEST_ERR_BASE) so pre-existing, not-yet-repaired drift can't
      # mass-park otherwise-good ports; once the crate is clean (base 0) the gate is strict.
      # BACKSTOP test gate (scripts/harness_gate.sh -- shared by all four harnesses, so they
      # cannot disagree about what "verified" means). Parks a port that raises the test-compile
      # error count above the run's baseline, leaves a test failing, or hangs the suite.
      gate_ok=1
      gate_msg=$(run_test_gate "$class" "$log" "$TEST_ERR_BASE") || gate_ok=0
      log "$gate_msg"

      # PLACEHOLDER RETIREMENT is part of "verified", not a footnote. PROMOTE MODE tells the
      # port to delete the seam_stubs.rs placeholder and repoint its importers; when that does
      # not happen the crate ends up with two types of the same name, which compiles and
      # silently cannot interoperate. That was reported as a WARN after the merge was already
      # committed, so it accumulated: BytesPcodeExecutorStatePiece did it on 2026-08-09.
      #
      # Only enforced when PROMOTE MODE actually ran ($promote non-empty) -- otherwise a class
      # whose name merely appears in some unrelated seam_stubs.rs would be parked for nothing.
      # And never for an ambiguous basename: `Processor` is a placeholder for
      # ghidra.program.model.lang.Processor AND a real enum ported from the PDB reader, two
      # unrelated Java classes, so a name match there is not a shadow at all.
      if [ "$gate_ok" = "1" ] && [ -n "$promote" ]; then
        njava=$(find orig_src -name "${class}.java" 2>/dev/null | wc -l)
        if [ "$njava" -le 1 ] && grep -rqE --include='seam_stubs.rs' \
             "\b(pub +)?(trait|struct|enum) +${class}\b" ghidra-rs/src 2>/dev/null; then
          gate_ok=0
          gate_msg="placeholder for ${class} SURVIVED the port -- it shadows the real type"
          log "gate FAIL: $gate_msg (PROMOTE MODE required deleting it and repointing importers)"
        fi
      fi

      if [ "$gate_ok" = "1" ]; then
        git branch -D "$branch" >/dev/null 2>&1||true
        sed -i "0,/^TODO\(\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t${ordpath//\//\\/}\)$/s//DONE\1/" "$ORDER"
        git add "$ORDER" >/dev/null 2>&1; git commit -q -m "descent: mark $class DONE" >/dev/null 2>&1||true
        ported=$((ported+1)); log "OK descent: $class (${mode}) merged"
      else
        git reset --hard "$pre_merge" >/dev/null 2>&1||true
        sed -i "s#^TODO\(\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t${ordpath//\//\\/}\)\$#PARK\1#" "$ORDER"
        git add "$ORDER" >/dev/null 2>&1; git commit -q -m "descent: park $class (test gate)" >/dev/null 2>&1||true
        parked=$((parked+1)); log "PARK descent: $class (${gate_msg})"
      fi
    else
      git merge --abort >/dev/null 2>&1||true; git reset --hard "$pre_merge" >/dev/null 2>&1||true
      sed -i "s#^TODO\(\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t${ordpath//\//\\/}\)\$#PARK\1#" "$ORDER"
      git add "$ORDER" >/dev/null 2>&1; git commit -q -m "descent: park $class" >/dev/null 2>&1||true
      parked=$((parked+1)); log "PARK descent: $class (post-merge build failed)"
    fi
  else
    harness_add >/dev/null 2>&1||true; git commit -q -m "WIP descent park: $class" >/dev/null 2>&1||true
    git checkout -f "$INTEGRATION" >/dev/null 2>&1
    sed -i "s#^TODO\(\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t${ordpath//\//\\/}\)\$#PARK\1#" "$ORDER"
    git add "$ORDER" >/dev/null 2>&1; git commit -q -m "descent: park $class" >/dev/null 2>&1||true
    parked=$((parked+1)); log "PARK descent: $class (status=$status / build red). log: $log"
  fi
done

git checkout -f "$INTEGRATION" >/dev/null 2>&1 || true

# Java-idiom drift audit. Detection only: it never fails a port, reverts a merge, or blocks
# the push -- it just stops new Rc<RefCell<_>>/Arc<Mutex<_>>/Box<dyn> debt from entering
# invisibly, which is the gap OWNERSHIP_MIGRATION.md describes. Runs before the push so the
# refreshed frontier file ships with the ports that caused it. --preserve-status is required:
# without it the refresh resets every DONE/PARK row in $DEBT back to TODO.
audit_new=0; audit_committed=0
if [ "$AUDIT_STEP" = "1" ] && [ -f "$DEBT" ] && [ $((ported+reconciled)) -gt 0 ]; then
  prev_debt=$(mktemp /tmp/ghidra-descent-debt.XXXXXX)
  cp "$DEBT" "$prev_debt"
  regress=$("$PY" scripts/pattern_audit.py --root ghidra-rs/src --seam SEAM.tsv \
              --baseline "$prev_debt" --diff-new 2>/dev/null)
  if [ -n "$regress" ]; then
    audit_new=$(printf '%s\n' "$regress" | grep -c .)
    log "ownership drift: ${audit_new} file(s) got smellier this run (see $DEBT / OWNERSHIP_MIGRATION.md):"
    printf '%s\n' "$regress" | head -20 | while IFS= read -r l; do log "  $l"; done
  fi
  "$PY" scripts/pattern_audit.py --root ghidra-rs/src --seam SEAM.tsv \
        --baseline "$prev_debt" --preserve-status --out "$DEBT" >/dev/null 2>&1
  "$PY" scripts/stub_audit.py --root ghidra-rs/src --manifest "$MANIFEST" --out STUB_DEBT.tsv >/dev/null 2>&1 || true
  rm -f "$prev_debt"
  if ! git diff --quiet -- "$DEBT" 2>/dev/null; then
    git add "$DEBT" STUB_DEBT.tsv >/dev/null 2>&1
    git commit -q -m "audit: refresh $DEBT after descent run (${audit_new} new/worsened)" >/dev/null 2>&1 \
      && audit_committed=1
  fi
fi

if [ "$PUSH" = "1" ] && [ $((ported+reconciled+audit_committed)) -gt 0 ]; then
  git push "$PUSH_REMOTE" "$INTEGRATION" >/dev/null 2>&1 && log "pushed $PUSH_REMOTE/$INTEGRATION" || log "push FAILED (non-fatal; check SSH under cron)"
fi
if [ "$ported" -gt 0 ]; then
  terr=$(timeout "$BUILD_TIMEOUT" cargo test --lib --no-run 2>&1 | grep -cE '^error' || true)
  printf '%s\t%s\n' "${terr:-?}" "$(date +%s)" > test_health.txt 2>/dev/null || true
  if [ "${terr:-0}" -gt 0 ]; then
    log "WARNING: test crate has ${terr} compile errors (drift) -- run a repair sweep soon"
  else
    log "test-health OK: test crate compiles clean"
  fi
fi
"$PY" scripts/dep_stats.py >/dev/null 2>&1 || true
line="[$(date '+%Y-%m-%d %H:%M')] descent run: +${ported} ported, ${reconciled} reconciled, ${parked} parked, ${audit_new} idiom-drift  (DONE $(grep -c $'\tDONE\t' "$MANIFEST"))"
echo "$line" | tee -a "$LOG_DIR/port-summary.log"
command -v notify-send >/dev/null 2>&1 && notify-send "ghidra-rs descent" "$line" 2>/dev/null || true
