#!/usr/bin/env bash
# Regenerates the checked-in prost code for the Trace RMI and ISF protocols.
# Run from anywhere; needs network access the first time to fetch prost-build/protox.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
run() {
    cargo run --quiet --release \
        --manifest-path "$ROOT/scripts/protogen/Cargo.toml" \
        --target-dir "$ROOT/target/protogen" -- "$@"
}
RMI="$ROOT/orig_src/Ghidra/Debug/Debugger-rmi-trace/src/main/proto"
ISF="$ROOT/orig_src/Ghidra/Debug/Debugger-isf/src/main/proto"
run "$ROOT/ghidra-rs/src/debug/rmi/proto" "$RMI" "$RMI/trace-rmi.proto"
run "$ROOT/ghidra-rs/src/debug/dbg/isf/protocol" "$ISF" "$ISF/isf.proto"
