#!/usr/bin/env python3
"""Decide whether a `dyn T` in the Rust tree is justified, from T's Java hierarchy.

Why this exists
---------------
`pattern_audit.py` counts `dyn` occurrences and scores them uniformly, so
`OWNERSHIP_DEBT.tsv` treats every trait object as equally suspect. It is not:

  * `dyn DataType` has **192** concrete implementers in `orig_src`. `dyn TaskMonitor` has 21,
    `dyn AddressSetView` 21. Runtime polymorphism is exactly right for those.
  * `dyn Trace` has **one** (`DBTrace`). `dyn TraceThread` one (`DBTraceThread`). A Java
    interface with a single implementation is Java's header-file idiom -- a way to name an
    API separately from its class -- not a statement that callers dispatch over alternatives.
  * `dyn TokenPattern`, `dyn RegisterValue`, `dyn BinaryReader` name Java *classes*. There was
    never an interface to be polymorphic over.

Measured across the crate: of 28,475 non-std `dyn` mentions, 40.9% are genuine (P5) and
30.6% are on types that have at most one concrete implementation or are not interfaces at
all (P1+P2). A uniform count cannot tell those apart, so the nightly drift number has been
reporting justified and unjustified `dyn` as the same debt.

The patterns
------------
  P1  T is a Java class/enum -- there is no interface. Use the concrete type.
  P2  T is an interface with exactly ONE concrete implementer, and not an extension point.
      Java's header-file idiom. Use the concrete struct; keep a trait only as a seam for a
      dependency that is genuinely unported.
  P0  T is an interface with NO concrete implementer anywhere in orig_src. Unknown, not
      fixable: it may be implemented by anonymous classes or lambdas, by code outside the
      tree, or it may be an annotation. There is no concrete type to collapse to, so this
      reports rather than advises.
  P3  T is an interface with 2-3 concrete implementers. A closed set: enum if they are
      alternative representations of one thing, trait if they are independently extensible.
      Needs a human -- this is the call AGENTS.md records being got wrong.
  P4  T reaches an extension-point root (ExtensionPoint/Service/Plugin/...). `dyn` is right.
  P5  T is an interface with 4+ concrete implementers. `dyn` is right.

Ambiguous basenames are never classified: `PatternExpression` is two unrelated Java classes
and `Settings`/`Symbol` collide across packages.

Usage
-----
  dyn_rules.py audit [--out DYN_DEBT.tsv]   rank every `dyn T` by pattern
  dyn_rules.py explain <TypeName>           why one type is classified as it is
  dyn_rules.py guidance <TypeName>...       prompt block: per-type dyn advice for a porter
"""

from __future__ import annotations

import argparse
import collections
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import shape_rules as sr  # noqa: E402

REPO = sr.REPO
RUST = os.path.join(REPO, "ghidra-rs", "src")
DYN_DEBT = os.path.join(REPO, "DYN_DEBT.tsv")

# `dyn` over these is std/library polymorphism, nothing to do with the port.
STD_TRAITS = {
    "Any", "Error", "Iterator", "Fn", "FnMut", "FnOnce", "Send", "Sync", "Display", "Debug",
    "Read", "Write", "Seek", "BufRead", "Hash", "Ord", "PartialOrd", "Eq", "PartialEq",
}

PATTERNS = {
    "P0": "interface with no concrete implementer in orig_src -- anonymous/lambda/external, unknown",
    "P1": "Java is a {kind}, not an interface -- use the concrete type",
    "P2": "interface with exactly one concrete implementer -- Java's header-file idiom, use the struct",
    "P3": "interface with {n} concrete implementers -- closed set, enum or trait (investigate)",
    "P4": "extension point -- dyn is correct",
    "P5": "interface with {n} concrete implementers -- dyn is correct",
    "??": "ambiguous basename or no Java match -- do not guess",
}

VERDICT = {"P0": "unknown", "P1": "fix", "P2": "fix", "P3": "investigate",
           "P4": "ok", "P5": "ok", "??": "skip"}


def classify(name, facts, subtypes, cache):
    """Return (pattern, n_impls, kind) for a referenced type name."""
    if name in STD_TRAITS:
        return "??", -1, "std"
    e = facts.get(name)
    if not e or len(e) > 1:
        return "??", -1, "ambiguous" if e else "unmatched"
    kind = e[0]["kind"]
    if kind != "interface" and not e[0]["abstract"]:
        return "P1", 0, kind
    if sr.is_extension_point(name, facts):
        return "P4", len(sr.concrete_implementers(name, facts, subtypes, cache)), kind
    n = len(sr.concrete_implementers(name, facts, subtypes, cache))
    return ("P0" if n == 0 else "P2" if n == 1 else "P3" if n <= 3 else "P5"), n, kind


def scan_rust():
    """Count `dyn T` mentions per referenced type, and remember where they are."""
    counts = collections.Counter()
    where = collections.defaultdict(list)
    pat = re.compile(r"\bdyn\s+([A-Za-z_][\w:]*)")
    for root, _d, files in os.walk(RUST):
        for f in files:
            if not f.endswith(".rs"):
                continue
            p = os.path.join(root, f)
            for ln, line in enumerate(open(p, encoding="utf-8", errors="replace"), 1):
                for m in pat.finditer(line):
                    name = m.group(1).split("::")[-1]
                    counts[name] += 1
                    if len(where[name]) < 3:
                        where[name].append(f"{os.path.relpath(p, REPO)}:{ln}")
    return counts, where


COLS = ["verdict", "pattern", "dyn_uses", "class", "java_kind", "concrete_impls", "why", "sample_sites"]


def cmd_audit(args):
    facts, subtypes = sr.build_index()
    cache = {}
    counts, where = scan_rust()
    rows = []
    tally = collections.Counter()
    for name, n in counts.items():
        pat, impls, kind = classify(name, facts, subtypes, cache)
        tally[pat] += n
        if VERDICT[pat] == "skip":
            continue
        why = PATTERNS[pat].format(kind=kind, n=impls)
        rows.append([VERDICT[pat], pat, n, name, kind, impls, why, " ".join(where[name])])
    rows.sort(key=lambda r: (r[0] != "fix", r[0] != "investigate", -r[2]))
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write("\t".join(COLS) + "\n")
        for r in rows:
            fh.write("\t".join(str(c).replace("\t", " ") for c in r) + "\n")
    total = sum(counts.values())
    print(f"wrote {len(rows)} rows to {args.out}  (of {total} total `dyn` mentions)")
    for p in ("P0", "P1", "P2", "P3", "P4", "P5", "??"):
        if tally[p]:
            print(f"  {tally[p]:6d}  {100 * tally[p] / total:4.1f}%  {p}  {VERDICT[p]}")
    fixable = tally["P1"] + tally["P2"]
    print(f"\n  fixable now (P1+P2): {fixable} dyn mentions across "
          f"{sum(1 for r in rows if r[0] == 'fix')} types")
    return 0


def cmd_explain(args):
    facts, subtypes = sr.build_index()
    pat, impls, kind = classify(args.name, facts, subtypes, {})
    print(f"{args.name}: {pat} ({VERDICT[pat]}) -- {PATTERNS[pat].format(kind=kind, n=impls)}")
    if impls >= 0:
        ci = sorted(sr.concrete_implementers(args.name, facts, subtypes, {}))
        print(f"  concrete implementers ({len(ci)}): {', '.join(ci[:20]) or 'none'}"
              + (" ..." if len(ci) > 20 else ""))
        direct = sorted(subtypes.get(args.name, ()))
        print(f"  direct subtypes ({len(direct)}): {', '.join(direct[:20]) or 'none'}")
    return 0


def cmd_guidance(args):
    """Prompt block telling a porter, per referenced type, whether `dyn` is warranted."""
    facts, subtypes = sr.build_index()
    cache = {}
    fix, ok = [], []
    for name in args.names:
        pat, impls, kind = classify(name, facts, subtypes, cache)
        if pat in ("P1", "P2"):
            concrete = sorted(sr.concrete_implementers(name, facts, subtypes, cache))
            hint = concrete[0] if concrete else f"{name}'s own data"
            fix.append(f"  - {name}: {PATTERNS[pat].format(kind=kind, n=impls)}"
                       f" (the one implementation is {hint})")
        elif pat in ("P4", "P5"):
            ok.append(f"  - {name}: {impls} concrete implementers")
    if not fix and not ok:
        return 0
    print("DYN GUIDANCE (from each referenced type's Java hierarchy, not from the Rust tree):")
    if fix:
        print("Do NOT use `Box<dyn T>`/`Arc<dyn T>`/`&dyn T` for these -- there is nothing to")
        print("dispatch over. Take/return the concrete type:")
        print("\n".join(fix))
    if ok:
        print("These are genuinely polymorphic; `dyn` is appropriate:")
        print("\n".join(ok))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("audit"); p.add_argument("--out", default=DYN_DEBT); p.set_defaults(fn=cmd_audit)
    p = sub.add_parser("explain"); p.add_argument("name"); p.set_defaults(fn=cmd_explain)
    p = sub.add_parser("guidance"); p.add_argument("names", nargs="+"); p.set_defaults(fn=cmd_guidance)
    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
