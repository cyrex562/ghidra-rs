#!/usr/bin/env python3
"""
Target-layout area filter for the porting harness.

AGENTS.md maps only a handful of top-level Java package areas to Rust modules;
anything else must be parked ("do NOT invent a new top-level module"). Of ~15.6k
classes, ~10.5k are in unmapped areas. Letting the harness feed those to Claude
just to have it (correctly) park them wastes money and trips the consecutive-park
circuit breaker on big contiguous unmapped blocks (all of Ghidra/Debug, etc.).

This module filters the frontier to packages the map actually covers, so an
unattended run stays productive across the ~5k mapped classes. Mapping is by Java
PACKAGE, not file location (a class under Ghidra/Debug can still be package
ghidra.program.* -> program/).

Keep MAPPED_PREFIXES in sync with the AGENTS.md "Target layout" table.

Usage:
    ... | python3 scripts/portlib.py mapped       # stdin: paths; stdout: mapped only
    python3 scripts/portlib.py report             # breakdown of mapped vs unmapped TODO
"""

import sys
from collections import Counter

# Java package prefixes that have a Rust module per AGENTS.md target-layout table.
MAPPED_PREFIXES = [
    "ghidra.framework",
    "ghidra.program",
    "ghidra.util",
    "generic", "ghidra.generic",
    "ghidra.app.script",
    "ghidra.app.util.bin.format",
    "ghidra.app.util.demangler",
    # GPL filesystem modules
    "mobiledevices.dmg", "ext4", "squashfs",
]


def package_of(path: str) -> str:
    """Java package from a source path (port-order style, orig_src/ prefix optional)."""
    toks = path.strip().split("/")
    if "java" in toks:
        toks = toks[toks.index("java") + 1:-1]   # between .../java/ and the filename
    else:
        return ""                                 # can't determine -> treat as unmapped
    return ".".join(toks)


def is_mapped(pkg: str) -> bool:
    return any(pkg == p or pkg.startswith(p + ".") for p in MAPPED_PREFIXES)


def cmd_mapped() -> int:
    for line in sys.stdin:
        path = line.rstrip("\n")
        if path and is_mapped(package_of(path)):
            print(path)
    return 0


def cmd_report() -> int:
    area = Counter()
    mapped_n = unmapped_n = 0
    for raw in open("PORT_MANIFEST.tsv", encoding="utf-8"):
        cols = raw.rstrip("\n").split("\t")
        if len(cols) < 2 or cols[1] != "TODO":
            continue
        pkg = package_of(cols[0])
        if is_mapped(pkg):
            mapped_n += 1
        else:
            unmapped_n += 1
            top = ".".join(pkg.split(".")[:2]) if pkg.startswith("ghidra.") else (pkg.split(".")[0] or "(unknown)")
            area[top] += 1
    print(f"TODO total: {mapped_n + unmapped_n}")
    print(f"  MAPPED (portable now): {mapped_n}")
    print(f"  UNMAPPED (parked):     {unmapped_n}")
    print("\nTop unmapped areas (candidates to add to the AGENTS.md map):")
    for a, c in area.most_common(20):
        print(f"  {c:6}  {a}")
    return 0


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in ("mapped", "report"):
        print("usage: portlib.py {mapped|report}", file=sys.stderr)
        return 2
    return cmd_mapped() if sys.argv[1] == "mapped" else cmd_report()


if __name__ == "__main__":
    sys.exit(main())
