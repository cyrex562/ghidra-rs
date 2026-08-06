"""Finds placeholder stubs that SHADOW a real ported type, and who is wired to them.

The seam/descent harnesses let a port define a minimal placeholder (`seam_stubs.rs`) for a type
it references but that is not ported yet -- without that, cycles could never be broken. The
placeholder is supposed to be retired when the real port lands: replace the importers, delete
the stub, drop its STUBS.tsv row. That retirement is only ever *instructed*, never verified, and
it does not happen at all when the class is ported as a struct rather than a trait
(descent_night.sh gates PROMOTE MODE on `mode == trait`).

The result is silent fragmentation: two types with the same name, one real and one empty, and
call sites wired to whichever their port happened to import. They compile, they pass tests, and
they cannot interoperate. `PatternExpression` had 23 files on the placeholder while the real
type existed; `MemBuffer` 22.

Output is STUB_DEBT.tsv, the same shape as the other frontier files, ranked by how many files
are wired to the wrong type:

    status  importers  stubs  class  manifest  real_path  stub_paths

`manifest` is the ported status of the Java class of the same name; DONE means the real port
landed and the placeholder is pure debt. A `-` means no Java class of that name exists, so the
name is probably a synthetic helper and the collision may be coincidental -- those need a human
eye rather than a sweep.

    python scripts/stub_audit.py --out STUB_DEBT.tsv
    python scripts/stub_audit.py --top 20        # print, don't write
"""
import argparse
import csv
import os
import re
import sys
from collections import defaultdict

RE_DECL = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?(?:trait|struct|enum)\s+(\w+)", re.M
)
COLUMNS = ["status", "importers", "stubs", "class", "manifest", "real_path", "stub_paths"]


def scan_sources(root):
    """(text by path, stub declarations, real declarations)."""
    texts, stub_decl, real_decl = {}, defaultdict(list), defaultdict(list)
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            if not fn.endswith(".rs"):
                continue
            path = os.path.join(dirpath, fn)
            try:
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
            except OSError:
                continue
            texts[path] = text
            target = stub_decl if fn == "seam_stubs.rs" else real_decl
            for name in RE_DECL.findall(text):
                target[name].append(path)
    return texts, stub_decl, real_decl


def manifest_status(manifest):
    """Java class name -> TODO/DONE."""
    status = {}
    if not os.path.exists(manifest):
        return status
    with open(manifest, encoding="utf-8") as fh:
        for line in fh:
            cols = line.rstrip("\n").split("\t")
            if len(cols) > 1 and cols[0].endswith(".java"):
                status[os.path.basename(cols[0])[: -len(".java")]] = cols[1]
    return status


def importers_of_stub(texts, name):
    """Files importing `name` from a seam_stubs module -- i.e. wired to the placeholder."""
    pattern = re.compile(
        rf"use [^;]*seam_stubs::(?:\{{[^}}]*\b{re.escape(name)}\b[^}}]*\}}|{re.escape(name)})\b"
    )
    return [p for p, t in texts.items() if pattern.search(t)]


def load_prior_status(path):
    """class -> status, so regenerating never discards triage already done."""
    prior = {}
    if not path or not os.path.exists(path):
        return prior
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh, delimiter="\t"):
            cls = (row.get("class") or "").strip()
            if cls:
                prior[cls] = (row.get("status") or "TODO").strip()
    return prior


def build(root, manifest, out_path):
    texts, stub_decl, real_decl = scan_sources(root)
    status = manifest_status(manifest)
    prior = load_prior_status(out_path)

    rows = []
    for name, stub_paths in stub_decl.items():
        real_paths = real_decl.get(name)
        if not real_paths:
            continue  # a placeholder with no real counterpart yet is legitimate, not debt
        importers = importers_of_stub(texts, name)
        rows.append(
            {
                "status": prior.get(name, "TODO"),
                "importers": len(importers),
                "stubs": len(stub_paths),
                "class": name,
                "manifest": status.get(name, "-"),
                "real_path": os.path.relpath(real_paths[0], os.path.dirname(root) or "."),
                "stub_paths": ";".join(
                    os.path.relpath(p, os.path.dirname(root) or ".") for p in stub_paths
                ),
            }
        )
    rows.sort(key=lambda r: (-r["importers"], -r["stubs"], r["class"]))
    return rows, len(stub_decl)


def main():
    ap = argparse.ArgumentParser(description="Find placeholder stubs shadowing real ported types")
    ap.add_argument("--root", default="ghidra-rs/src")
    ap.add_argument("--manifest", default="PORT_MANIFEST.tsv")
    ap.add_argument("--out", help="Write STUB_DEBT.tsv here (preserves existing statuses)")
    ap.add_argument("--top", type=int, default=20, help="Rows to print when not writing")
    args = ap.parse_args()

    rows, total_stubs = build(args.root, args.manifest, args.out)
    wired = sum(r["importers"] for r in rows)
    confirmed = [r for r in rows if r["manifest"] == "DONE"]

    if args.out:
        with open(args.out, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=COLUMNS, delimiter="\t")
            writer.writeheader()
            writer.writerows(rows)
        print(
            f"wrote {len(rows)} shadowed stub(s) to {args.out} "
            f"({len(confirmed)} whose class is already DONE; {wired} file(s) wired to a placeholder; "
            f"{total_stubs} stub names in total)",
            file=sys.stderr,
        )
    else:
        print(
            f"{len(rows)} of {total_stubs} stub names shadow a real type; "
            f"{wired} file(s) import the placeholder\n"
        )
        print(f"  {'importers':>9} {'stubs':>5} {'manifest':<9} class")
        for r in rows[: args.top]:
            print(f"  {r['importers']:>9} {r['stubs']:>5} {r['manifest']:<9} {r['class']}")


if __name__ == "__main__":
    main()
