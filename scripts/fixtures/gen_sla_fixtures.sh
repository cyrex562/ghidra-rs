#!/usr/bin/env bash
#
# Compile a curated set of .slaspec from orig_src into golden .sla fixtures, using the
# Ghidra install from setup_ghidra.sh. Output -> ghidra-rs/tests/fixtures/sla/, which the
# (future) Rust round-trip harness diffs the in-port Sleigh compiler against:
#     .slaspec --[in-port compiler]--> .sla --[existing Rust decoder]--> model
#                                   vs  golden .sla produced here (upstream Ghidra)
#
# The .slaspec inputs stay in orig_src (present locally, gitignored like all Java source);
# only the small golden .sla land in the tracked fixtures dir.
#
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIST="$REPO/tools/ghidra-dist"
install="$(find "$DIST" -maxdepth 1 -type d -name 'ghidra_*_PUBLIC' 2>/dev/null | head -1 || true)"
[ -n "$install" ] || { echo "no Ghidra install -- run scripts/fixtures/setup_ghidra.sh first."; exit 1; }
SLEIGH="$install/support/sleigh"
[ -x "$SLEIGH" ] || { echo "sleigh wrapper not found/executable: $SLEIGH"; exit 1; }

OUT="$REPO/ghidra-rs/tests/fixtures/sla"
mkdir -p "$OUT"

# Curated, small, representative specs. Extend as the front-end matures. Missing entries
# are skipped (processor set varies by Ghidra version).
SPECS=(
  "GhidraBuild/Skeleton/data/languages/skel.slaspec"
  "Ghidra/Processors/8085/data/languages/8085.slaspec"
  "Ghidra/Processors/Toy/data/languages/toy.slaspec"
)

ok=0; skip=0
for rel in "${SPECS[@]}"; do
  spec="$REPO/orig_src/$rel"
  name="$(basename "${spec%.slaspec}")"
  if [ ! -f "$spec" ]; then echo "SKIP (missing): $rel"; skip=$((skip+1)); continue; fi
  echo "=== compiling $name ==="
  # sleigh resolves @includes relative to the spec dir and writes <spec>.sla in place.
  if ! "$SLEIGH" "$spec"; then echo "  sleigh FAILED for $name"; skip=$((skip+1)); continue; fi
  sla="${spec%.slaspec}.sla"
  if [ -f "$sla" ]; then
    cp -f "$sla" "$OUT/$name.sla"
    rm -f "$sla"           # keep orig_src clean (it's gitignored anyway)
    echo "  -> $OUT/$name.sla"
    ok=$((ok+1))
  else
    echo "  no .sla produced for $name"; skip=$((skip+1))
  fi
done

echo "Done: $ok fixture(s) written, $skip skipped -> $OUT"
echo "Commit the .sla (root .gitignore does not ignore *.sla). Record the Ghidra"
echo "version used ($(basename "$install")) in a fixtures README so parity is reproducible."
