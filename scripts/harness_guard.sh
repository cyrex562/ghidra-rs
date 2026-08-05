# Shared working-tree guard for the autonomous harnesses. Source it from a script that has
# already cd'd to the repo root:  . scripts/harness_guard.sh
#
# Every harness here starts with `git checkout -f <integration>` (and usually `git reset
# --hard`) to get to a known state. Those commands DISCARD uncommitted changes to tracked
# files -- so a nightly run that fires while a human has work in progress silently destroys
# it, which AGENTS.md explicitly forbids ("uncommitted user changes were not reverted or
# overwritten"). Aborting instead would be safe but would also halt the loop for good the
# first time a crashed run left the tree dirty, so the default is to preserve the work in a
# labelled stash and keep going.
#
# DIRTY_POLICY=stash   (default) stash changes + untracked files, log the stash ref, proceed
#              abort            refuse to run; leave the tree exactly as-is
#              ignore           legacy behaviour: proceed and let checkout -f discard them

guard_working_tree() { # $1 = harness name, for the stash label
  local who="${1:-harness}" policy="${DIRTY_POLICY:-stash}" dirty stamp
  dirty=$(git status --porcelain 2>/dev/null)
  [ -z "$dirty" ] && return 0

  local n; n=$(printf '%s\n' "$dirty" | grep -c .)
  case "$policy" in
    ignore)
      echo "WARNING: working tree has ${n} uncommitted change(s); DIRTY_POLICY=ignore -- they will be DISCARDED."
      printf '%s\n' "$dirty" | head -10
      return 0
      ;;
    abort)
      echo "ABORT: working tree has ${n} uncommitted change(s) and DIRTY_POLICY=abort."
      printf '%s\n' "$dirty" | head -10
      echo "Commit, stash, or re-run with DIRTY_POLICY=stash."
      return 1
      ;;
    *)
      stamp="auto: pre-${who} $(date '+%Y-%m-%d %H:%M:%S')"
      if git stash push -u -m "$stamp" >/dev/null 2>&1; then
        echo "NOTE: stashed ${n} uncommitted change(s) before ${who} run -- '${stamp}' (git stash list / git stash pop)."
      else
        echo "WARNING: working tree dirty (${n} change(s)) and 'git stash push' FAILED; refusing to run so nothing is discarded."
        printf '%s\n' "$dirty" | head -10
        return 1
      fi
      return 0
      ;;
  esac
}
