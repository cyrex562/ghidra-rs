#!/usr/bin/env bash
#
# Download + unpack an official Ghidra release into tools/ghidra-dist/ (gitignored),
# used ONLY to generate golden .sla fixtures for the in-port SLA round-trip harness
# (see gen_sla_fixtures.sh). This is a SEPARATE task from the port itself -- the
# ghidra-rs runtime consumes pre-compiled .sla; this install exists so we can produce
# reference .sla to validate the in-port Sleigh compiler against.
#
# Requires: curl, unzip, and a JDK (Ghidra 11.x needs JDK 21+) for the sleigh compiler.
# Override the version by exporting GHIDRA_ZIP_URL=<url-to-a-ghidra_*_PUBLIC_*.zip>.
#
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIST="$REPO/tools/ghidra-dist"
mkdir -p "$DIST"

# Idempotent: if an install is already unpacked, stop.
existing="$(find "$DIST" -maxdepth 1 -type d -name 'ghidra_*_PUBLIC' 2>/dev/null | head -1 || true)"
if [ -n "$existing" ]; then
  echo "Ghidra already installed: $existing"
  echo "sleigh wrapper: $existing/support/sleigh"
  exit 0
fi

# JDK check (warn, don't fail -- download can proceed; compile step needs it).
if command -v java >/dev/null 2>&1; then
  echo "java: $(java -version 2>&1 | head -1)"
else
  echo "WARNING: no 'java' on PATH -- Ghidra's sleigh compiler needs a JDK 21+ to run."
fi

# Resolve the latest release asset via the GitHub API (avoids hardcoding a fragile
# URL/date/hash). Pin by exporting GHIDRA_ZIP_URL.
API="https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest"
URL="${GHIDRA_ZIP_URL:-$(curl -fsSL "$API" \
      | grep -oE 'https://[^"]+_PUBLIC_[0-9]+\.zip' | head -1 || true)}"
[ -n "$URL" ] || { echo "ERROR: could not resolve a Ghidra release URL; set GHIDRA_ZIP_URL."; exit 1; }

zip="$DIST/$(basename "$URL")"
echo "Downloading: $URL"
curl -fSL --retry 3 -o "$zip" "$URL"
echo "SHA-256 (spot-check against the GitHub release page):"
sha256sum "$zip"

echo "Unpacking into $DIST ..."
unzip -q "$zip" -d "$DIST"
rm -f "$zip"

install="$(find "$DIST" -maxdepth 1 -type d -name 'ghidra_*_PUBLIC' 2>/dev/null | head -1 || true)"
[ -n "$install" ] || { echo "ERROR: unpack produced no ghidra_*_PUBLIC dir."; exit 1; }
echo "Installed: $install"
echo "sleigh wrapper: $install/support/sleigh"
echo "Next: scripts/fixtures/gen_sla_fixtures.sh"
