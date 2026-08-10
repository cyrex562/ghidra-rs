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
  P2s A P2 whose one concrete implementer is NOT ported yet. The end state is the same, but
      there is no Rust type to use today, so the trait is a seam awaiting that port rather
      than a defect -- the same distinction AGENTS.md draws for shape debt. 177 of 224 P2
      types were in this state, and telling a porter to "use DBTrace" when DBTrace is a seam
      stub is advice it cannot follow.
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
import csv
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
    "PA": "Java annotation type -- not a runtime type; it should not appear as a Rust type at all",
    "P1": "Java is a {kind}, not an interface -- use the concrete type",
    "P2": "interface with exactly one concrete implementer -- Java's header-file idiom, use the struct",
    "P2s": "interface with one concrete implementer that is NOT ported yet -- a seam until it is",
    "P3": "interface with {n} concrete implementers -- closed set, enum or trait (investigate)",
    "P4": "extension point -- dyn is correct",
    "P5": "interface with {n} concrete implementers -- dyn is correct",
    "??": "ambiguous basename or no Java match -- do not guess",
}

VERDICT = {"P0": "unknown", "PA": "unknown", "P1": "fix", "P2": "fix", "P2s": "blocked",
           "P3": "investigate",
           "P4": "ok", "P5": "ok", "??": "skip"}

# A pattern is EVIDENCE about a type's Java hierarchy; CONVENTION_QUEUE.tsv is the DECISION
# about what it becomes in Rust. Re-deriving evidence and ignoring the decision made this
# worklist ask for 4,925 dyn-mentions' worth of types to be "investigated" that were already
# settled -- `Program` reported P3/investigate while the queue had said ARENA. Where a verdict
# has been decided, it wins, and it also says WHAT to build instead of just "not this".
CONVENTIONS = os.path.join(REPO, "CONVENTION_QUEUE.tsv")
DECIDED = {"ACCEPT", "ARENA", "ENUM", "ITER", "GRAPH", "STRUCT", "PARK"}

# convention -> (action, what the dyn becomes)
CONVENTION_ACTION = {
    "ACCEPT": ("ok", "`dyn` IS the decided convention -- a genuine open extension point"),
    "ARENA":  ("fix", "hold a Copy ID resolved against the store, not a trait object "
                      "(OWNERSHIP_MIGRATION.md convention 1)"),
    "ENUM":   ("fix", "becomes a variant of the enum for this hierarchy (convention 2)"),
    "GRAPH":  ("fix", "becomes a Kind tag plus an arena id (convention 4)"),
    "ITER":   ("fix", "becomes a type implementing std::iter::Iterator"),
    "STRUCT": ("fix", "becomes the concrete type; there is nothing to dispatch over"),
    "PARK":   ("unknown", "parked: no convention decided, and re-asking is not wanted"),
}

_RUST_DECLS = None


def rust_declarations():
    """{name: kind} for every `pub struct/enum/trait` in the crate."""
    global _RUST_DECLS
    if _RUST_DECLS is None:
        out = {}
        pat = re.compile(r"^\s*pub (struct|enum|trait) ([A-Za-z_]\w*)")
        for root, _d, files in os.walk(RUST):
            for f in files:
                if not f.endswith(".rs"):
                    continue
                try:
                    with open(os.path.join(root, f), encoding="utf-8", errors="replace") as fh:
                        for line in fh:
                            m = pat.match(line)
                            if m:
                                out.setdefault(m.group(2), m.group(1))
                except OSError:
                    pass
        _RUST_DECLS = out
    return _RUST_DECLS


def convention_target_exists(name, conv):
    """Is the thing the convention says to build actually there yet?

    Telling a port to "hold a Copy ID resolved against the store" for `Program` when no
    ProgramStore exists is the same unactionable advice as naming an unported concrete type:
    the porter cannot comply, and inventing an arena to comply is worse than the trait object
    it replaces. slotmap is a dependency and EquateStore exists, but the arenas for the big
    domain types do not.
    """
    decls = rust_declarations()
    if conv == "ARENA":
        return any(f"{name}{sfx}" in decls for sfx in ("Store", "Arena", "Id"))
    if conv in ("ENUM", "GRAPH"):
        return decls.get(name) == "enum" or f"{name}Kind" in decls
    if conv == "ITER":
        return True   # std::iter::Iterator always exists
    return True       # STRUCT is handled by the P2s/ported check


_CONV = None


def conventions():
    """{type: verdict} for DECIDED verdicts only. SUGGEST-* is a proposal, not a decision."""
    global _CONV
    if _CONV is None:
        out = {}
        try:
            with open(CONVENTIONS, newline="", encoding="utf-8") as fh:
                for r in csv.DictReader(fh, delimiter="\t"):
                    v = (r.get("verdict") or "").strip()
                    t = (r.get("type") or "").strip()
                    if t and v in DECIDED:
                        out[t] = v
        except OSError:
            pass
        _CONV = out
    return _CONV


def decide(name, pattern, n, kind, table=None):
    """(action, convention, why) -- the decision if there is one, else the evidence.

    An ambiguous basename is never resolved, whatever the queue says: `PatternExpression` is
    two unrelated Java classes and a verdict recorded against the bare name cannot say which.
    """
    if pattern == "??":
        return "skip", "", PATTERNS["??"]
    conv = conventions().get(name)
    if conv:
        action, what = CONVENTION_ACTION[conv]
        # A convention whose target has not been BUILT is not actionable either.
        if not convention_target_exists(name, conv):
            return "blocked", conv, (
                f"decided {conv}, but the {conv.lower()} for `{name}` does not exist yet -- "
                f"`dyn {name}` is the correct seam until it lands; do NOT invent one here")
        # A STRUCT verdict is still blocked when that concrete type is not ported yet.
        if conv == "STRUCT" and pattern == "P2s":
            impls = (table or {}).get(name, {}).get("concrete_implementers", [])
            who = f"`{impls[0]}`" if impls else "its single implementation"
            return "blocked", conv, (f"decided STRUCT, but {who} is not ported yet -- "
                                     f"`dyn {name}` is the correct seam until it is")
        return action, conv, f"decided {conv}: {what}"
    return VERDICT[pattern], "", PATTERNS[pattern].format(kind=kind, n=n)


_PORTED = None


def ported_classes():
    """Java class names marked DONE in PORT_MANIFEST.tsv."""
    global _PORTED
    if _PORTED is None:
        out = set()
        try:
            with open(os.path.join(REPO, "PORT_MANIFEST.tsv"), encoding="utf-8") as fh:
                for line in fh:
                    c = line.split("\t")
                    if len(c) > 1 and c[1].strip() == "DONE":
                        out.add(os.path.basename(c[0])[:-5])
        except OSError:
            pass
        _PORTED = out
    return _PORTED


def classify_from_table(name, table):
    """Same verdict as `classify`, from the precomputed IMPLEMENTERS.tsv table.

    Lets callers in the nightly loop (dep_context.py) answer without rebuilding the Java
    index, which costs ~14s a port.
    """
    if name in STD_TRAITS:
        return "??", -1, "std"
    e = table.get(name)
    if e is None:
        return "??", -1, "unmatched"      # absent = no Java match, or an ambiguous basename
    kind = e["kind"]
    if kind == "@interface":
        return "PA", -1, kind
    if kind != "interface":
        return "P1", 0, kind
    n = e["n_concrete"]
    if e["extension_point"]:
        return "P4", n, kind
    if n == 1:
        impls = e["concrete_implementers"]
        if impls and impls[0] not in ported_classes():
            return "P2s", n, kind
        return "P2", n, kind
    return ("P0" if n == 0 else "P3" if n <= 3 else "P5"), n, kind


def classify(name, facts, subtypes, cache):
    """Return (pattern, n_impls, kind) for a referenced type name."""
    if name in STD_TRAITS:
        return "??", -1, "std"
    e = facts.get(name)
    if not e or len(e) > 1:
        return "??", -1, "ambiguous" if e else "unmatched"
    kind = e[0]["kind"]
    if kind == "@interface":
        return "PA", -1, kind
    if kind != "interface" and not e[0]["abstract"]:
        return "P1", 0, kind
    if sr.is_extension_point(name, facts):
        return "P4", len(sr.concrete_implementers(name, facts, subtypes, cache)), kind
    impls = sr.concrete_implementers(name, facts, subtypes, cache)
    n = len(impls)
    if n == 1:
        return ("P2" if next(iter(impls)) in ported_classes() else "P2s"), n, kind
    return ("P0" if n == 0 else "P3" if n <= 3 else "P5"), n, kind


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


COLS = ["verdict", "convention", "pattern", "dyn_uses", "class", "java_kind", "concrete_impls",
        "why", "sample_sites"]


def cmd_audit(args):
    facts, subtypes = sr.build_index()
    cache = {}
    counts, where = scan_rust()
    table = sr.load_implementers() or {}
    rows = []
    tally = collections.Counter()
    decided_n = 0
    for name, n in counts.items():
        pat, impls, kind = classify(name, facts, subtypes, cache)
        action, conv, why = decide(name, pat, impls, kind, table)
        tally[action] += n
        if action == "skip":
            continue
        if conv:
            decided_n += n
        rows.append([action, conv, pat, n, name, kind, impls, why, " ".join(where[name])])
    rows.sort(key=lambda r: (r[0] != "fix", r[0] != "investigate", -r[3]))
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write("\t".join(COLS) + "\n")
        for r in rows:
            fh.write("\t".join(str(c).replace("\t", " ") for c in r) + "\n")
    total = sum(counts.values())
    print(f"wrote {len(rows)} rows to {args.out}  (of {total} total `dyn` mentions)")
    for a in ("fix", "blocked", "investigate", "ok", "unknown", "skip"):
        if tally[a]:
            print(f"  {tally[a]:6d}  {100 * tally[a] / total:4.1f}%  {a}")
    print(f"\n  {decided_n} of {total} carry a decided convention from CONVENTION_QUEUE.tsv")
    print(f"  needs a decision: {tally['investigate'] + tally['unknown']} dyn mentions across "
          f"{sum(1 for r in rows if r[0] in ('investigate', 'unknown'))} types")
    return 0


def cmd_explain(args):
    facts, subtypes = sr.build_index()
    table = sr.load_implementers() or {}
    pat, impls, kind = classify(args.name, facts, subtypes, {})
    action, conv, why = decide(args.name, pat, impls, kind, table)
    print(f"{args.name}: {action}"
          + (f" [convention {conv}]" if conv else f" [{pat}, no decision recorded]")
          + f" -- {why}")
    if conv:
        print(f"  evidence: {pat} -- {PATTERNS[pat].format(kind=kind, n=impls)}")
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
    table = sr.load_implementers() or {}
    fix, ok = [], []
    for name in args.names:
        pat, impls, kind = classify(name, facts, subtypes, cache)
        action, conv, why = decide(name, pat, impls, kind, table)
        if conv and action == "fix":
            fix.append(f"  - {name}: {why}")
            continue
        if conv and action == "ok":
            ok.append(f"  - {name}: {why}")
            continue
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
