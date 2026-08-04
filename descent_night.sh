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
DESCENT_PARKED="DESCENT_PARKED.tsv"   # durable park-list: classes too big for the nightly loop (timeouts);
                                      # excluded from the regenerated order, worked interactively in daytime
INTEGRATION="${INTEGRATION:-integration}"
PUSH="${PUSH:-1}"; PUSH_REMOTE="${PUSH_REMOTE:-origin}"
REGEN="${REGEN:-1}"        # regenerate PORT_ORDER.tsv at start (stale rows reconcile harmlessly, but fresh is better)
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
git checkout -f "$INTEGRATION" >/dev/null 2>&1 || { log "no $INTEGRATION branch"; exit 1; }
git reset --hard >/dev/null 2>&1 || true
for b in $(git branch --list 'descent/*' --format='%(refname:short)'); do git branch -D "$b" >/dev/null 2>&1||true; done
git pull --ff-only >/dev/null 2>&1 || true

log "descent preflight: cargo build --lib"
timeout "$BUILD_TIMEOUT" cargo build --lib --quiet 2>/dev/null || { log "integration not green -- abort"; exit 1; }
# baseline test-crate compile health -- the backstop parks any port that RAISES this count
TEST_ERR_BASE=$(timeout "$TEST_TIMEOUT" cargo test --lib --no-run 2>&1 | grep -cE '^error'); TEST_ERR_BASE=${TEST_ERR_BASE:-0}
log "preflight test-compile baseline: ${TEST_ERR_BASE} errors"

# refresh the leaf-first order against the current manifest (unless disabled)
if [ "$REGEN" = "1" ] && [ -z "${DESCENT_ONLY:-}" ]; then
  log "regenerating $ORDER"
  "$PY" scripts/desc_order.py --write >/dev/null 2>>"$LOG_DIR/descent_night.log" || log "WARN: desc_order regen failed, using existing $ORDER"
  git add "$ORDER" >/dev/null 2>&1; git commit -q -m "descent: refresh PORT_ORDER.tsv" >/dev/null 2>&1||true
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
  log "descent ${i}/${DESCENT_MAX}: $class -> ${module}/ (${mode}, ${tier}/${portmodel}, rem=${rem} lines=${lines})"

  git checkout -f "$INTEGRATION" >/dev/null 2>&1
  git branch -D "$branch" >/dev/null 2>&1 || true; git switch -c "$branch" >/dev/null 2>&1

  if [ "$mode" = "trait" ]; then
    promote=""
    if grep -rqE --include='seam_stubs.rs' "\b(pub +)?trait +${class}\b" ghidra-rs/src 2>/dev/null; then
      promote="PROMOTE MODE: a minimal placeholder 'trait ${class}' currently exists in a seam_stubs.rs.
You are REPLACING that placeholder with the real port. After creating the real trait: (1) update EVERY
importer -- replace each 'use ...seam_stubs::${class}' with the real trait's path; keep any placeholder
methods as a superset so existing impls/callers compile. (2) DELETE the placeholder from seam_stubs.rs.
(3) Remove ${class}'s line(s) from STUBS.tsv. Then proceed with the normal rules below.
"
    fi
    prompt="You are breaking a dependency CYCLE in a Java->Rust port. Port the Java type at
${srcpath} to a Rust TRAIT (it was selected as a cycle cut-point).
${promote}
Destination: ghidra-rs/src/${module}/ -- mirror the remaining Java package path in snake_case;
create the file and wire it into mod.rs up the chain. Read sibling .rs files first for conventions.

Rules for breaking the cycle:
- Map the Java type's public API to a Rust trait (methods -> trait methods). Prefer object-safe traits
  (&self, owned/boxed returns); where a method returns/takes another core type, use a trait object
  (Box<dyn T>/Arc<dyn T>) or a generic, NOT a concrete struct.
- For any in-repo core type this references that is NOT yet defined in the Rust crate, do NOT port it
  here and do NOT fail: define a MINIMAL placeholder trait for it (only the methods THIS type needs) in
  ghidra-rs/src/${module}/seam_stubs.rs (create/extend it; wire into mod.rs), and append a line to
  STUBS.tsv: '<ISO-time>\t<PlaceholderName>\t${class}'.
- Add a #[cfg(test)] mod with at least one smoke test (a mock impl proving object-safety) that
  exercises real behavior, not trivially-true asserts.
- MANDATORY test-green loop before finishing: (1) 'cargo build --lib' must pass; (2) 'cargo test --lib
  --no-run' must compile with ZERO errors -- if your trait/signature change broke EXISTING test code
  elsewhere (stale mocks, dyn-safety, ambiguous methods), you MUST update that test code to match;
  (3) run ONLY your class's OWN module tests (e.g. 'cargo test --lib the_module_path') and make them PASS
  -- do NOT run the full 'cargo test --lib' suite yourself; it is slow (18k tests) and the harness runs
  it as a final gate. Fast cycles = build + your module only. Iterate: build/test -> read failures -> fix ->
  repeat until BOTH compile clean AND all tests pass. Do NOT run git. Run cargo SYNCHRONOUSLY
  and wait for each command to finish -- this is a SINGLE-SHOT non-interactive session: never
  background a command, schedule a wakeup, or defer work to 'report back later'. Everything,
  including the final passing test run, must complete within this turn before you stop.
- In ${MANIFEST}, set the row whose first column is exactly '${srcpath}' from TODO to DONE.
Port this type (plus placeholder stubs for its references) and fix any test code your change breaks.
If truly impossible, leave ${MANIFEST} unchanged and end with: PORT_RESULT: PARKED <reason>."
  else
    prompt="Port the Java class at ${srcpath} to idiomatic Rust (struct + impl).
This class was chosen by RECURSIVE-DESCENT order: its in-repo dependencies have already been ported,
so REUSE the existing Rust types -- read them first; do not redefine them.

Destination: ghidra-rs/src/${module}/ -- mirror the remaining Java package path in snake_case;
create the file and wire it into mod.rs up the chain. Read sibling .rs files first for conventions.

Rules:
- Map the class to a Rust struct with an impl block; map fields and methods faithfully. Implement any
  Rust trait that corresponds to a Java interface this class implements (those traits are already ported).
- Prefer reusing already-ported types by their real path. If a referenced in-repo core type is genuinely
  NOT yet in the crate (a forward cycle edge), define a MINIMAL placeholder trait for it in
  ghidra-rs/src/${module}/seam_stubs.rs (only the methods THIS class needs; wire into mod.rs) and append
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
Port this class and fix any test code your change breaks.
If truly impossible, leave ${MANIFEST} unchanged and end with: PORT_RESULT: PARKED <reason>."
  fi

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
  # TIMEOUT (rc=124): too big for the nightly loop. DURABLE-park -> record in DESCENT_PARKED (excluded
  # from future regenerated orders) so it stops re-burning spend nightly; work it interactively later.
  if [ "$rc" -eq 124 ]; then
    log "TIMEOUT on $class (${CLAUDE_TIMEOUT}s) -- durable-park for interactive follow-up."
    git checkout -f "$INTEGRATION" >/dev/null 2>&1; git branch -D "$branch" >/dev/null 2>&1||true
    printf '%s\ttimeout\t%s\n' "$(date '+%Y-%m-%dT%H:%M')" "$next" >> "$DESCENT_PARKED"
    sed -i "s#^TODO\(\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t${ordpath//\//\\/}\)\$#PARK\1#" "$ORDER"
    git add "$DESCENT_PARKED" "$ORDER" >/dev/null 2>&1; git commit -q -m "descent: durable-park $class (timeout)" >/dev/null 2>&1||true
    parked=$((parked+1)); continue
  fi
  if [ "$status" = "DONE" ] && timeout "$BUILD_TIMEOUT" cargo build --lib --quiet 2>>"$log"; then
    git add -A; git commit -q -m "descent: ${class} -> ${mode} (${srcpath})" || true
    git checkout -f "$INTEGRATION" >/dev/null 2>&1
    pre_merge=$(git rev-parse HEAD)
    if git merge --no-ff "$branch" -m "merge descent: ${class}" >>"$log" 2>&1 && timeout "$BUILD_TIMEOUT" cargo build --lib --quiet 2>>"$log"; then
      # BACKSTOP test gate: the model is now responsible for leaving the WHOLE test crate green
      # (build + test --no-run clean + suite passing). This verifies it. It parks a port that:
      #   * RAISES the test-compile error count above the run's baseline (introduced drift), or
      #   * leaves any test FAILING.
      # Baselined against preflight (TEST_ERR_BASE) so pre-existing, not-yet-repaired drift can't
      # mass-park otherwise-good ports; once the crate is clean (base 0) the gate is strict.
      gate_ok=1
      if [ "$TEST_GATE" = "1" ]; then
        # 1) COMPILE check via --no-run (SAME command as TEST_ERR_BASE). Must not count runtime test
        #    output: `cargo test` RUNS tests, and a passing test that merely prints a line starting
        #    with "error" would inflate a bare `grep ^error` -> false park (this happened 2026-07-21:
        #    6 good ports parked with an identical "base 0 -> 2"). --no-run never runs tests.
        terr=$(timeout "$TEST_TIMEOUT" cargo test --lib --no-run 2>&1 | grep -cE '^error'); terr=${terr:-0}
        if [ "$terr" -gt "$TEST_ERR_BASE" ]; then    # retry once -- absorb transient incremental-compile errors
          terr=$(timeout "$TEST_TIMEOUT" cargo test --lib --no-run 2>&1 | grep -cE '^error'); terr=${terr:-0}
        fi
        if [ "$terr" -gt "$TEST_ERR_BASE" ]; then
          gate_ok=0; log "test gate FAIL: $class introduced $((terr-TEST_ERR_BASE)) test-compile error(s) (base ${TEST_ERR_BASE} -> ${terr}, confirmed on retry)"
        else
          # 2) RUNTIME check: run the suite; park only on a genuine 'test result: FAILED'.
          tout=$(timeout "$TEST_TIMEOUT" cargo test --lib --no-fail-fast 2>&1)
          if printf '%s' "$tout" | grep -q 'test result: FAILED'; then
            # retry once -- the full-suite gate can catch an unrelated FLAKY test (parallel global
            # state); a real regression fails again (2026-07-22: HighParamID/SpecExtension false-parked
            # on a flake -- their branches pass 0-failed on re-run).
            tout=$(timeout "$TEST_TIMEOUT" cargo test --lib --no-fail-fast 2>&1)
          fi
          if printf '%s' "$tout" | grep -q 'test result: FAILED'; then
            gate_ok=0; log "test gate FAIL: $class ($(printf '%s' "$tout" | grep -oE '[0-9]+ failed' | tail -1) in suite, confirmed on retry)"
          else
            log "test gate OK: $class (test crate compiles, suite green)"
          fi
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
        parked=$((parked+1)); log "PARK descent: $class (test gate: introduced test drift/failures)"
      fi
    else
      git merge --abort >/dev/null 2>&1||true; git reset --hard "$pre_merge" >/dev/null 2>&1||true
      sed -i "s#^TODO\(\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t${ordpath//\//\\/}\)\$#PARK\1#" "$ORDER"
      git add "$ORDER" >/dev/null 2>&1; git commit -q -m "descent: park $class" >/dev/null 2>&1||true
      parked=$((parked+1)); log "PARK descent: $class (post-merge build failed)"
    fi
  else
    git add -A>/dev/null 2>&1||true; git commit -q -m "WIP descent park: $class" >/dev/null 2>&1||true
    git checkout -f "$INTEGRATION" >/dev/null 2>&1
    sed -i "s#^TODO\(\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t${ordpath//\//\\/}\)\$#PARK\1#" "$ORDER"
    git add "$ORDER" >/dev/null 2>&1; git commit -q -m "descent: park $class" >/dev/null 2>&1||true
    parked=$((parked+1)); log "PARK descent: $class (status=$status / build red). log: $log"
  fi
done

git checkout -f "$INTEGRATION" >/dev/null 2>&1 || true
if [ "$PUSH" = "1" ] && [ $((ported+reconciled)) -gt 0 ]; then
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
line="[$(date '+%Y-%m-%d %H:%M')] descent run: +${ported} ported, ${reconciled} reconciled, ${parked} parked  (DONE $(grep -c $'\tDONE\t' "$MANIFEST"))"
echo "$line" | tee -a "$LOG_DIR/port-summary.log"
command -v notify-send >/dev/null 2>&1 && notify-send "ghidra-rs descent" "$line" 2>/dev/null || true
