#!/usr/bin/env bash
# Trial porting harness for ghidra-rs.
# Picks the lowest-remaining-dependency TODO class, ports it with Claude headless,
# verifies (manifest flipped to DONE + cargo test passes), commits to a feature branch,
# and best-effort labels the matching GitHub issue. Git is harness-controlled; the model
# only edits files, runs tests, and updates the manifest.
#
# Usage:
#   MAX_ITERS=1  MODEL=haiku  ./tick.sh        # supervised single port (start here)
#   MAX_ITERS=30 MODEL=sonnet ./tick.sh        # longer run once the loop is proven
set -uo pipefail

# --- config (override via env) ---
REPO_DIR="${REPO_DIR:-$HOME/Projects/ghidra-rs}"
GH_REPO="${GH_REPO:-cyrex562/ghidra-rs}"
MODEL="${MODEL:-haiku}"                 # haiku = cheap plumbing test; sonnet = real ports
MAX_ITERS="${MAX_ITERS:-1}"
MANIFEST="PORT_MANIFEST.tsv"
INTEGRATION="${INTEGRATION:-integration}"
LOCK="/tmp/ghidra-tick.lock"
LOG_DIR="${LOG_DIR:-$HOME/agents/logs/ghidra}"
mkdir -p "$LOG_DIR"

# --- single-instance lock so overlapping runs can't collide ---
exec 9>"$LOCK"
flock -n 9 || { echo "another tick is running; exiting"; exit 0; }

cd "$REPO_DIR" || { echo "no repo at $REPO_DIR"; exit 1; }

# refuse to run on a dirty tree
if [ -n "$(git status --porcelain)" ]; then
  echo "working tree is dirty — commit/stash before running tick.sh"; exit 1
fi

ported=0; parked=0
for ((i=1; i<=MAX_ITERS; i++)); do
  echo "=================== iteration $i / $MAX_ITERS ==================="

  # 1. next class: top of the frontier (lowest remaining unported deps)
  top=$(python scripts/sync_check.py --root orig_src --manifest "$MANIFEST" --port-order 2>/dev/null | head -1)
  next=$(printf '%s' "$top" | cut -f2)
  remaining=$(printf '%s' "$top" | cut -f1)
  if [ -z "$next" ]; then echo "manifest complete — nothing TODO"; break; fi
  echo "next: $next  (remaining deps: $remaining)"

  # only port true frontier on autonomous runs; >0 means a prereq is unported
  if [ "$remaining" != "0" ]; then
    echo "top frontier item has $remaining unported deps — stopping (manifest may be stale)"; break
  fi

  class=$(basename "$next" .java)
  branch="port/trial-${class}"
  log="$LOG_DIR/${class}.$(date +%s).log"

  # 2. clean feature branch off integration
  git switch "$INTEGRATION" >/dev/null 2>&1 || { echo "no '$INTEGRATION' branch — create it first"; break; }
  git pull --ff-only >/dev/null 2>&1 || true
  git branch -D "$branch" >/dev/null 2>&1 || true
  git switch -c "$branch" >/dev/null 2>&1

  # 3. port exactly this one class
  prompt="Port the single Java class at this orig_src path: ${next}

Follow AGENTS.md exactly:
- Place the Rust code in the module given by the target-layout map.
- Add focused unit tests; run \`cargo test\`.
- Set THIS class's row in ${MANIFEST} to DONE.
Port ONLY this class — nothing else. Do not run any git commands.
If you cannot finish within the rules (missing prereq, unmapped area, would need a stub),
do NOT force it: leave ${MANIFEST} unchanged and end your reply with the single line
PORT_RESULT: PARKED followed by a one-line reason."

  echo "--- running claude ($MODEL) ---"
  claude -p "$prompt" \
    --model "$MODEL" \
    --permission-mode acceptEdits \
    --allowedTools "Read,Edit,Write,Bash(cargo test*),Bash(cargo build*),Bash(python scripts/sync_check.py*)" \
    --output-format text 2>&1 | tee "$log"

  # 4. verify success: manifest row flipped to DONE AND tests pass
  status=$(grep -F "$next" "$MANIFEST" | head -1 | cut -f2 | tr -d '[:space:]')
  if [ "$status" = "DONE" ] && cargo test --quiet >/dev/null 2>&1; then
    git add -A
    git commit -q -m "port: ${class} (trial)" || true
    echo "OK: ${class} ported on ${branch}; tests pass."
    ported=$((ported+1))
    # 5. best-effort: flag the matching issue for review
    iss=$(gh issue list --repo "$GH_REPO" --state open --search "${class} in:title" \
          --json number,title -q ".[] | select(.title|test(\"\`${class}\`\")) | .number" 2>/dev/null | head -1)
    if [ -n "${iss:-}" ]; then
      gh issue edit "$iss" --repo "$GH_REPO" --add-label review >/dev/null 2>&1 || true
      gh issue comment "$iss" --repo "$GH_REPO" \
        --body "Ported on branch \`${branch}\`; \`cargo test\` passes. Awaiting review." >/dev/null 2>&1 || true
      echo "   labeled issue #${iss} review"
    else
      echo "   no matching open issue found (ok — manifest is the source of truth)"
    fi
  else
    # preserve whatever was produced for morning inspection, but mark nothing done
    git add -A >/dev/null 2>&1 || true
    git commit -q -m "WIP/parked: ${class} (trial)" >/dev/null 2>&1 || true
    echo "PARK: ${class} did not complete cleanly (manifest status='${status}'). Branch ${branch} left for inspection; log: ${log}"
    parked=$((parked+1))
  fi
done

git switch "$INTEGRATION" >/dev/null 2>&1 || true
echo "=================== done: ${ported} ported, ${parked} parked ==================="
echo "review branches with:  git branch --list 'port/trial-*'"
