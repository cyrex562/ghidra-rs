#!/usr/bin/env python3
"""Emit FANIN.tsv: reverse-dependency count for EVERY Java type in orig_src.

Why this exists
---------------
`pattern_audit.py` folds fan-in into its priority (`score * (1 + fanin/100)`), and took that
number from SEAM.tsv -- a 369-row worklist for the seam campaign, whose harness was disabled
on 2026-07-18. It was never an index of the whole graph and was not meant to be: it is the
top-fanin slice the campaign had queued.

The consequence is a ranking artefact. 1,139 of the 1,310 files on the debt frontier (87%)
resolved to fanin 0 and were ordered by raw score alone, while the 171 that happened to be in
the worklist got multipliers of up to 20x. A file's remediation priority depended on whether
its type had been queued for a campaign that no longer runs.

Fan-in is a property of the JAVA dependency graph, so it does not go stale as the port
progresses -- SEAM.tsv's DONE/TODO column being a month old never mattered here, because
load_seam_fanin discards it. What mattered was coverage.

Usage:
  python3 scripts/fanin_gen.py                 # write FANIN.tsv
  python3 scripts/fanin_gen.py --top 20        # preview the highest-leverage types
"""
import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
OUT = os.path.join(REPO, "FANIN.tsv")
COLS = ["class", "fanin", "path"]


def load_frontier(root="orig_src", manifest="PORT_MANIFEST.tsv"):
    out = subprocess.run(
        [sys.executable, os.path.join(HERE, "sync_check.py"),
         "--root", root, "--manifest", manifest, "--json"],
        capture_output=True, text=True, cwd=REPO).stdout
    return json.loads(out[out.index("["):])


def compute(data):
    """{java_rel_path: reverse-dependency count} across the whole graph."""
    fanin = {}
    for d in data:
        for dep in d["dependencies"]:
            fanin[dep] = fanin.get(dep, 0) + 1
    return fanin


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--top", type=int, default=0, help="preview only, do not write")
    args = ap.parse_args()

    data = load_frontier()
    fanin = compute(data)
    rows = []
    for path, n in fanin.items():
        cls = os.path.basename(path)
        if cls.endswith(".java"):
            cls = cls[:-5]
        rows.append((cls, n, path))
    # A basename can name several Java types; keep the largest, which is what the previous
    # loader did (`max(...)`) and what a leverage measure should do.
    best = {}
    for cls, n, path in rows:
        if cls not in best or n > best[cls][0]:
            best[cls] = (n, path)

    if args.top:
        for cls, (n, path) in sorted(best.items(), key=lambda kv: -kv[1][0])[:args.top]:
            print(f"{n:6d}  {cls:34s} {path}")
        return 0

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write("\t".join(COLS) + "\n")
        for cls, (n, path) in sorted(best.items(), key=lambda kv: (-kv[1][0], kv[0])):
            fh.write(f"{cls}\t{n}\t{path}\n")
    print(f"wrote {len(best)} types to {args.out} "
          f"(SEAM.tsv covered {369}); max fanin {max(n for n, _ in best.values())}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
