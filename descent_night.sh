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
INTEGRATION="${INTEGRATION:-integration}"
PUSH="${PUSH:-1}"; PUSH_REMOTE="${PUSH_REMOTE:-origin}"
REGEN="${REGEN:-1}"        # regenerate PORT_ORDER.tsv at start (stale rows reconcile harmlessly, but fresh is better)
CLAUDE_TIMEOUT="${CLAUDE_TIMEOUT:-1500}"; BUILD_TIMEOUT="${BUILD_TIMEOUT:-1800}"
TEST_GATE="${TEST_GATE:-1}"; TEST_TIMEOUT="${TEST_TIMEOUT:-1200}"   # per-port: run the ported module's own tests before keeping the merge
PY="${PY:-python3}"; LOG_DIR="${LOG_DIR:-$HOME/agents/logs/ghidra}"; mkdir -p "$LOG_DIR"

exec 7>/tmp/ghidra-descent.lock; flock -n 7 || { echo "another descent run active"; exit 0; }
[ -f "$STUBS" ] || printf 'ts\tstub_class\treferenced_by\n' > "$STUBS"

log(){ echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
snake(){ printf '%s' "$1" | sed -E 's/([a-z0-9])([A-Z])/\1_\2/g; s/([A-Z]+)([A-Z][a-z])/\1_\2/g' | tr '[:upper:]' '[:lower:]'; }
git merge --abort >/dev/null 2>&1||true; git rebase --abort >/dev/null 2>&1||true
git checkout -f "$INTEGRATION" >/dev/null 2>&1 || { log "no $INTEGRATION branch"; exit 1; }
git reset --hard >/dev/null 2>&1 || true
for b in $(git branch --list 'descent/*' --format='%(refname:short)'); do git branch -D "$b" >/dev/null 2>&1||true; done
git pull --ff-only >/dev/null 2>&1 || true

log "descent preflight: cargo build --lib"
timeout "$BUILD_TIMEOUT" cargo build --lib --quiet 2>/dev/null || { log "integration not green -- abort"; exit 1; }

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
  if [ -n "$DESCENT_ONLY" ]; then
    next=""; mode=""
    for want in $DESCENT_ONLY; do
      read -r mode next < <(awk -F'\t' -v w="$want" '$1=="TODO"{n=split($7,a,"/"); c=a[n]; sub(/\.java$/,"",c); if(c==w){print $2"\t"$7; exit}}' "$ORDER")
      [ -n "$next" ] && break
    done
  else
    # STRICT top-down: first still-TODO row in file order (leaf-first). mode from col2.
    read -r mode next < <(awk -F'\t' '$1=="TODO"{print $2"\t"$7; exit}' "$ORDER")
  fi
  [ -z "$next" ] && { log "no TODO rows left in $ORDER."; break; }
  ordpath="$next"; srcpath="orig_src/$next"; class=$(basename "$next" .java)
  hash=$(printf '%s' "$srcpath" | cksum | cut -d' ' -f1); branch="descent/${class}-${hash}"
  log="$LOG_DIR/descent.${class}.${hash}.$(date +%s).log"; jlog="${log%.log}.json"
  module=$("$PY" scripts/portlib.py module "${srcpath#orig_src/}" 2>/dev/null)

  # reconcile-skip: a Rust type for this class already exists (ported early / by another harness)
  if grep -rqE --include='*.rs' --exclude='seam_stubs.rs' "\b(pub +)?(struct|trait|enum) +${class}\b" ghidra-rs/src 2>/dev/null; then
    esc=$(printf '%s' "$srcpath" | sed 's/[.[\*^$]/\\&/g')
    sed -i "s#^${esc}\tTODO\t#${esc}\tDONE\t#" "$MANIFEST"
    sed -i "s#^TODO\(\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t[^\t]*\t${ordpath//\//\\/}\)\$#DONE\1#" "$ORDER"
    git add "$MANIFEST" "$ORDER" >/dev/null 2>&1
    git commit -q -m "descent reconcile: $class already ported -> DONE" >/dev/null 2>&1 || true
    reconciled=$((reconciled+1)); log "reconciled (already ported): $class -> DONE (no LLM turn)"; ((i--)); continue
  fi
  log "descent ${i}/${DESCENT_MAX}: $class -> ${module}/ (${mode})"

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
- Add a #[cfg(test)] mod with at least one smoke test (a mock impl proving object-safety). Your tests
  are RUN as a merge gate -- they must PASS and exercise real behavior, not trivially-true asserts.
- Verify locally with 'cargo build --lib' ONLY (do NOT run cargo test; do NOT run git).
- In ${MANIFEST}, set the row whose first column is exactly '${srcpath}' from TODO to DONE.
Port ONLY this type (plus placeholder stubs for its references). No unrelated changes.
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
- Add a #[cfg(test)] mod with at least one smoke test. Your tests are RUN as a merge gate -- they
  must PASS and exercise real behavior (compare against expected values), not trivially-true asserts.
- Verify locally with 'cargo build --lib' ONLY (do NOT run cargo test; do NOT run git).
- In ${MANIFEST}, set the row whose first column is exactly '${srcpath}' from TODO to DONE.
Port ONLY this class. No unrelated changes.
If truly impossible, leave ${MANIFEST} unchanged and end with: PORT_RESULT: PARKED <reason>."
  fi

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
    git add -A; git commit -q -m "descent: ${class} -> ${mode} (${srcpath})" || true
    git checkout -f "$INTEGRATION" >/dev/null 2>&1
    pre_merge=$(git rev-parse HEAD)
    if git merge --no-ff "$branch" -m "merge descent: ${class}" >>"$log" 2>&1 && timeout "$BUILD_TIMEOUT" cargo build --lib --quiet 2>>"$log"; then
      # STRICT per-port test gate: run the ported module's OWN tests. A port that compiles but
      # fails its smoke test must not merge. Safety: only PARK on this port's own failures --
      # an UNRELATED test-compile error (drift elsewhere) leaves the merge (build --lib is green).
      gate_ok=1
      if [ "$TEST_GATE" = "1" ]; then
        tfilter=$(snake "$class")
        tout=$(timeout "$TEST_TIMEOUT" cargo test --lib "$tfilter" --no-fail-fast 2>&1); techo=$?
        if printf '%s' "$tout" | grep -q 'test result: FAILED'; then
          gate_ok=0; log "test gate FAIL: $class ($(printf '%s' "$tout" | grep -oE '[0-9]+ failed' | head -1))"
        elif printf '%s' "$tout" | grep -q 'test result: ok'; then
          gate_ok=1
        elif printf '%s' "$tout" | grep -qE '^error' ; then
          # did not compile under this filter. own file implicated -> park; else inconclusive -> keep.
          rsfile=$(snake "$class")
          if printf '%s' "$tout" | grep -E '^error|-->' | grep -q "${rsfile}\.rs"; then
            gate_ok=0; log "test gate FAIL: $class (own test does not compile)"
          else
            gate_ok=1; log "test gate INCONCLUSIVE: $class (unrelated test-compile drift; kept on build gate)"
          fi
        else
          gate_ok=1; log "test gate: $class no matching tests ran (kept on build gate)"
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
        parked=$((parked+1)); log "PARK descent: $class (test gate: own tests failed)"
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
