#!/usr/bin/env python3
"""
Target-layout area filter + placement lookup for the porting harness.

AGENTS.md maps Java package areas to Rust modules; any class whose package is not
in the map must be parked ("do NOT invent a new top-level module"). Feeding
unmapped classes to Claude just to have it (correctly) park them wastes spend and
trips the consecutive-park circuit breaker on big contiguous unmapped blocks.

This module loads the map from scripts/port_layout.tsv (the single source of truth,
shared with the AGENTS.md table) and:
  * filters the frontier to classes whose package is mapped (`mapped`), so an
    unattended run only attempts queueable work;
  * looks up the destination module for a class (`module`);
  * regenerates the AGENTS.md table (`gen-agents`);
  * reports mapped-vs-unmapped TODO counts (`report`).

Mapping is by Java PACKAGE, not file location. Longest matching prefix wins.

Usage:
    ... | python3 scripts/portlib.py mapped     # stdin: paths; stdout: mapped only
    python3 scripts/portlib.py module <path>     # print destination rust module
    python3 scripts/portlib.py report            # mapped vs unmapped breakdown
    python3 scripts/portlib.py gen-agents         # emit the AGENTS.md layout table
"""

import os
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
LAYOUT_PATH = os.path.join(HERE, "port_layout.tsv")


def load_layout():
    """Return [(prefix, module)] sorted longest-prefix-first (most specific wins)."""
    if not os.path.exists(LAYOUT_PATH):
        sys.exit(f"portlib: missing {LAYOUT_PATH}")
    pairs = []
    with open(LAYOUT_PATH, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 2 and parts[0] and parts[1]:
                pairs.append((parts[0].strip(), parts[1].strip()))
    # longest (most dotted, then longest string) first
    pairs.sort(key=lambda pm: (pm[0].count("."), len(pm[0])), reverse=True)
    return pairs


LAYOUT = load_layout()


def package_of(path: str) -> str:
    """Java package from a source path (port-order style, orig_src/ prefix optional)."""
    toks = path.strip().split("/")
    if "java" in toks:
        toks = toks[toks.index("java") + 1:-1]   # between .../java/ and the filename
    else:
        return ""                                 # no standard sourceset -> unmapped
    return ".".join(toks)


def module_for(pkg: str):
    """Destination Rust module for a package, or None if unmapped."""
    for prefix, module in LAYOUT:           # already longest-first
        if pkg == prefix or pkg.startswith(prefix + "."):
            return module
    return None


def is_mapped(pkg: str) -> bool:
    return module_for(pkg) is not None


def cmd_mapped() -> int:
    for line in sys.stdin:
        path = line.rstrip("\n")
        if path and is_mapped(package_of(path)):
            print(path)
    return 0


def cmd_module(argv) -> int:
    if not argv:
        print("usage: portlib.py module <path>", file=sys.stderr)
        return 2
    print(module_for(package_of(argv[0])) or "")
    return 0


def cmd_report() -> int:
    area = Counter()
    mapped_n = unmapped_n = 0
    by_module = Counter()
    for raw in open("PORT_MANIFEST.tsv", encoding="utf-8"):
        cols = raw.rstrip("\n").split("\t")
        if len(cols) < 2 or cols[1] != "TODO":
            continue
        pkg = package_of(cols[0])
        mod = module_for(pkg)
        if mod:
            mapped_n += 1
            by_module[mod] += 1
        else:
            unmapped_n += 1
            top = ".".join(pkg.split(".")[:2]) if pkg.startswith("ghidra.") else (pkg.split(".")[0] or "(no-package)")
            area[top] += 1
    print(f"TODO total: {mapped_n + unmapped_n}")
    print(f"  MAPPED (in queue):  {mapped_n}")
    print(f"  UNMAPPED (skipped): {unmapped_n}")
    print("\nMapped TODO by destination module:")
    for m, c in by_module.most_common():
        print(f"  {c:6}  {m}")
    if area:
        print("\nRemaining unmapped areas (intentionally out of queue):")
        for a, c in area.most_common(30):
            print(f"  {c:6}  {a}")
    return 0


def cmd_gen_agents() -> int:
    """Emit the markdown layout table for AGENTS.md (longest-prefix-first)."""
    w = max(len(p) for p, _ in LAYOUT)
    print(f"| {'Java package prefix'.ljust(w)} | Rust module (src/) |")
    print(f"| {'-' * w} | ------------------ |")
    for prefix, module in LAYOUT:
        print(f"| {prefix.ljust(w)} | {module + '/':<18} |")
    return 0


def main() -> int:
    cmds = {"mapped", "module", "report", "gen-agents"}
    if len(sys.argv) < 2 or sys.argv[1] not in cmds:
        print(f"usage: portlib.py {{{'|'.join(sorted(cmds))}}}", file=sys.stderr)
        return 2
    cmd = sys.argv[1]
    if cmd == "mapped":
        return cmd_mapped()
    if cmd == "module":
        return cmd_module(sys.argv[2:])
    if cmd == "report":
        return cmd_report()
    return cmd_gen_agents()


if __name__ == "__main__":
    sys.exit(main())
