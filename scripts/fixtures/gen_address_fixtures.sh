#!/usr/bin/env bash
#
# Generates golden Address/AddressSpace values from a real Ghidra install into
# ghidra-rs/tests/fixtures/address/address_golden.json, for tests/address_golden.rs.
#
# This is the differential-testing half of the port's verification story: without it every test
# in the crate asserts only what its author believed Ghidra does. The fixture is COMMITTED, so
# contributors without a Ghidra install still run the comparison -- the same arrangement
# gen_sla_fixtures.sh uses.
#
# Requires: a Ghidra install (scripts/fixtures/setup_ghidra.sh) and a JDK 21+ on PATH
# (tools/jdk/bin if you used the repo-local one).
#
#   scripts/fixtures/gen_address_fixtures.sh
#
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIST="$REPO/tools/ghidra-dist"
install="$(find "$DIST" -maxdepth 1 -type d -name 'ghidra_*_PUBLIC' 2>/dev/null | head -1 || true)"
[ -n "$install" ] || { echo "no Ghidra install -- run scripts/fixtures/setup_ghidra.sh first."; exit 1; }

# Prefer the repo-local JDK if present, so this works without a system Java.
if [ -x "$REPO/tools/jdk/bin/javac" ]; then
  export PATH="$REPO/tools/jdk/bin:$PATH"
fi
command -v javac >/dev/null 2>&1 || { echo "no javac on PATH (JDK 21+ required)."; exit 1; }

# Ghidra's classes live across several module jars; the harness needs SoftwareModeling plus the
# Generic/Utility jars it depends on.
CP="$(find "$install/Ghidra/Framework" -name '*.jar' | tr '\n' ':')"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "Compiling harness against $(basename "$install") ..."
javac -nowarn -cp "$CP" -d "$work" "$REPO/scripts/fixtures/AddressGolden.java"

OUT="$REPO/ghidra-rs/tests/fixtures/address"
mkdir -p "$OUT"
echo "Generating golden values ..."
java -cp "$CP:$work" AddressGolden > "$OUT/address_golden.json"

records="$(grep -c '"kind"' "$OUT/address_golden.json" || echo 0)"
echo "Wrote $records records to $OUT/address_golden.json"
echo "Ghidra version: $(basename "$install")"
echo "Next: cargo test --test address_golden"
