#!/usr/bin/env python3
"""
Triage the blocked porting frontier for the interactive "untangle" harness.

Takes the ready (0-remaining-dep) MAPPED classes that the autonomous harness parked,
classifies WHY each is blocked by reading the Java source + the last park reason from
tick2_results.tsv, and writes an ordered work-list (most tractable first, UI last) to
UNTANGLE.tsv. Prints a category summary.

Categories:
  needs-prereq  parked citing specific unported prerequisite classes
  needs-dep     needs an external library / Rust crate not yet present
  needs-stub    would require a stub/placeholder (needs approval)
  ui            Swing/AWT UI (renderer/editor/icon/JComponent) -> redesign
  unknown       parked for an unclassified reason -> investigate

Usage:  python3 scripts/triage_blocked.py
"""

import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import portlib  # noqa: E402

ORIG = os.path.join(REPO, "orig_src")
MANIFEST = os.path.join(REPO, "PORT_MANIFEST.tsv")
PARKED = os.path.join(REPO, "PORT_PARKED.tsv")
RESULTS = os.path.join(REPO, "tick2_results.tsv")
OUT = os.path.join(REPO, "UNTANGLE.tsv")

UI_IMPORT = re.compile(r"import\s+(javax\.swing|java\.awt)")
UI_EXTEND = re.compile(r"\b(extends|implements)\s+([A-Za-z0-9_.]*\b(?:J[A-Z]\w*|Icon|CellRenderer|CellEditor|GComponent|GTable|GTree|Renderer)\w*)")
THIRD_PARTY = re.compile(r"import\s+(org\.(?!junit)|com\.(?!google\.common\.annotations)|net\.)\w[\w.]+")

CAT_ORDER = {"needs-prereq": 0, "needs-dep": 1, "needs-stub": 2, "unknown": 3, "ui": 4}


def ready_mapped_parked():
    """Classes at the 0-dep frontier that are mapped AND currently parked."""
    po = subprocess.run(
        [sys.executable, os.path.join(HERE, "sync_check.py"),
         "--root", "orig_src", "--manifest", "PORT_MANIFEST.tsv", "--port-order"],
        capture_output=True, text=True, cwd=REPO).stdout
    frontier = [l.split("\t")[1] for l in po.splitlines() if l.startswith("0\t")]
    mapped = {f for f in frontier if portlib.module_for(portlib.package_of(f))}
    parked = set()
    if os.path.exists(PARKED):
        with open(PARKED, encoding="utf-8", errors="ignore") as fh:
            parked = {l.strip().removeprefix("orig_src/") for l in fh if l.strip()}
    return sorted(f for f in mapped if f in parked)


def last_park_reason():
    """rel_path (orig_src/...) -> most recent park note from results."""
    reason = {}
    if not os.path.exists(RESULTS):
        return reason
    with open(RESULTS, encoding="utf-8", errors="ignore") as fh:
        next(fh, None)
        for line in fh:
            c = line.rstrip("\n").split("\t")
            if len(c) >= 8 and c[2].startswith("PARK"):
                reason[c[6]] = c[7]
    return reason


def classify(rel, note):
    path = os.path.join(ORIG, rel)
    try:
        src = open(path, encoding="utf-8", errors="ignore").read()
    except OSError:
        src = ""
    low_note = (note or "").lower()

    # UI is a hard structural signal — check first.
    if UI_IMPORT.search(src) or UI_EXTEND.search(src) or re.search(r"/(gui|widgets)/|docking/widgets", rel):
        m = UI_EXTEND.search(src)
        return "ui", (m.group(2) if m else "swing/awt")
    if "stub" in low_note:
        return "needs-stub", note[:80]
    if any(w in low_note for w in ("library", "dependency", "crate", "commonmark")) or THIRD_PARTY.search(src):
        m = THIRD_PARTY.search(src)
        return "needs-dep", (m.group(1) if m else "external lib") if not low_note else note[:80]
    if "prerequisite" in low_note or ("todo" in low_note and "port" in low_note):
        pres = re.findall(r"`([A-Za-z][\w]+)`", note or "")
        return "needs-prereq", (", ".join(pres[:6]) if pres else note[:80])
    # fall back: if the model left a note, surface it; else unknown
    return ("unknown", note[:80]) if note else ("unknown", "no recorded reason")


def main():
    rows = []
    reasons = last_park_reason()
    for rel in ready_mapped_parked():
        src_rel = "orig_src/" + rel
        cat, detail = classify(rel, reasons.get(src_rel, ""))
        cls = os.path.splitext(os.path.basename(rel))[0]
        mod = portlib.module_for(portlib.package_of(rel))
        rows.append((cat, cls, mod, rel, detail))

    rows.sort(key=lambda r: (CAT_ORDER.get(r[0], 9), r[3]))
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write("status\tcategory\tclass\tmodule\tpath\tblocker\n")
        for cat, cls, mod, rel, detail in rows:
            fh.write(f"TODO\t{cat}\t{cls}\t{mod}\t{rel}\t{detail}\n")

    from collections import Counter
    counts = Counter(r[0] for r in rows)
    print(f"wrote {len(rows)} blocked classes -> {os.path.relpath(OUT, REPO)}\n")
    print("by category (most tractable first):")
    for cat in sorted(counts, key=lambda c: CAT_ORDER.get(c, 9)):
        print(f"  {counts[cat]:4}  {cat}")
    print("\nfirst tractable (non-UI) candidates:")
    shown = 0
    for cat, cls, mod, rel, detail in rows:
        if cat == "ui":
            continue
        print(f"  [{cat}] {cls} -> {mod}/   ({detail})")
        shown += 1
        if shown >= 12:
            break
    if shown == 0:
        print("  (none — the entire ready frontier is UI)")


if __name__ == "__main__":
    main()
