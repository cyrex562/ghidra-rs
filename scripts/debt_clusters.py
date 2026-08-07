"""Type-level frontier for the ownership migration -- the work-list Phase 3 actually needs.

OWNERSHIP_DEBT.tsv ranks FILES, but an ownership decision is never about a file: it's about a
TYPE. Proofing the remediation harness showed why that matters. Three files parked in a row
(Trace -> DebuggerStaticMappingService -> DebuggerTraceManagerService), each on the same
undecided convention for `Trace`. File-at-a-time remediation re-asks the same question once
per file, pays an LLM call for each, and parks every time.

This script inverts the index: for every type reached through `dyn T` / `Rc<RefCell<T>>` /
`Arc<Mutex<T>>` in a convention-blocked file, count how many distinct files depend on that
decision. The result is a short queue -- ~20 verdicts cover well over half the blocked pile --
where each entry is answered ONCE and unblocks everything downstream of it.

Verdicts (col 1 of CONVENTION_QUEUE.tsv), per OWNERSHIP_MIGRATION.md's conventions:
  TODO    undecided -- files depending on it stay blocked
  ACCEPT  `dyn` is the RIGHT answer here (genuine open-ended extension point: a progress
          monitor, plugin-provided service, loader, listener). Not debt. pattern_audit.py
          stops counting it, so files whose only remaining smell is ACCEPTed types leave the
          frontier with no LLM call and no park.
  ARENA   shared/graph type -> arena + typed Copy ID (see group_tree.rs for the worked shape)
  ENUM    closed hierarchy -> enum dispatch
  ITER    Java iterator interface -> concrete Rust iterator implementing std::Iterator
  GRAPH   AST/IR node set -> tagged arena graph (a `Kind` tag enum + arena + Copy ids), for
          hierarchies a parser builds dynamically. Distinct from ENUM: the question is not
          whether the set is closed -- both are -- but whether values are constructed statically
          (ENUM) or built dynamically with operations accruing over time (GRAPH).
  STRUCT  shouldn't be a trait at all (a trait with 0-2 implementers is usually just a type)
  PARK    genuinely undecidable for now; keep it off the queue but don't keep re-asking

SUGGEST-<VERDICT> is a PROPOSAL, not a decision: --suggest writes them from structural
evidence, and nothing downstream acts on them -- pattern_audit.py honours a bare ACCEPT only,
never SUGGEST-ACCEPT. Review, then promote in bulk with --promote.

Hierarchies are sized from the JAVA sources, not from the port. Counting Rust implementers
measures how far the port has got: `CodeUnit` showed three non-mock impls only because
Instruction and Data are unported, and the proposer recommended "small closed set -> enum" off
that number. Reading `extends`/`implements` out of orig_src gives the real shape, and one
reading is worth calling out -- a count of ZERO means nothing in Java extends the type, so it is
a concrete class and a Rust trait is simply the wrong shape. 14 types are in that state,
`TokenPattern` (25 files) and `Lock` (19) among them.

Usage:
  python scripts/debt_clusters.py --out CONVENTION_QUEUE.tsv
  python scripts/debt_clusters.py --top 20            # print the queue, don't write
"""
import argparse
import csv
import os
import re
import sys
from collections import defaultdict

# Trait objects that are idiomatic Rust, not a Java interface translated too literally.
# `Box<dyn Error>`, `&dyn Any`, `Box<dyn Fn(..)>` are correct Rust and must never be scored
# as ownership debt or enqueued as convention decisions.
IDIOMATIC = {
    "Any", "Error", "Fn", "FnMut", "FnOnce", "Iterator", "DoubleEndedIterator",
    "ExactSizeIterator", "Send", "Sync", "Display", "Debug", "Write", "Read", "Seek",
    "BufRead", "Future", "Hash", "Ord", "PartialEq", "PartialOrd", "Eq", "Clone",
    "ToString", "Deref", "DerefMut", "Drop", "Default", "From", "Into", "AsRef", "AsMut",
}

# Name shapes that mark a genuine open-ended extension point -- an interface whose whole
# purpose is that callers/plugins supply their own implementation. `dyn` is the idiomatic
# Rust answer for these, so they are ACCEPT candidates rather than arena candidates.
# Above this many real implementers, "closed hierarchy -> enum" stops being credible.
ENUM_MAX_VARIANTS = 8

# Name shapes for AST/IR nodes -- hierarchies a parser or lowering pass builds dynamically. Above
# ENUM_MAX_VARIANTS these are the tagged-arena-graph case rather than an undecidable one; see
# OWNERSHIP_MIGRATION.md convention 4.
AST_NODE_SUFFIXES = (
    "Expression", "Equation", "Value", "Pattern", "Symbol", "Node", "Op", "Instruction",
    "Statement", "Term", "Operand",
)

OPEN_EXTENSION_SUFFIXES = (
    "Monitor", "Service", "Provider", "Listener", "Adapter", "Handler", "Callback",
    "Factory", "Plugin", "Loader", "Visitor", "Filter", "Comparator", "Consumer",
    "Supplier", "Predicate", "Analyzer", "Exporter", "Importer", "Formatter",
)

RE_DYN = re.compile(
    r"\bdyn\s+(?:(?:crate|std|core|alloc|self|super)::)?"
    r"(?:[A-Za-z_][A-Za-z0-9_]*::)*([A-Za-z_][A-Za-z0-9_]*)"
)
RE_CELL = re.compile(
    r"\b(?:Rc\s*<\s*RefCell|Arc\s*<\s*(?:Mutex|RwLock))\s*<\s*(?:dyn\s+)?"
    r"(?:(?:crate|std|core|alloc|self|super)::)?"
    r"(?:[A-Za-z_][A-Za-z0-9_]*::)*([A-Za-z_][A-Za-z0-9_]*)"
)
RE_LINE_COMMENT = re.compile(r"//.*$", re.MULTILINE)

QUEUE_COLS = ["verdict", "leverage", "occurrences", "fanin", "type", "category", "source", "note"]


def load_family_rules(path):
    """suffix -> (verdict, note) from CONVENTION_FAMILIES.tsv. Families are how this queue
    stays tractable: one rule decides a naming family at once (all *Iterator, all *Listener),
    instead of asking the same question 22 or 39 times. Per-type verdicts always win."""
    rules = []
    if not path or not os.path.exists(path):
        return rules
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f, delimiter="\t"):
            suffix = (r.get("suffix") or "").strip()
            verdict = (r.get("verdict") or "").strip()
            if suffix and verdict:
                rules.append((suffix, verdict, r.get("note") or ""))
    # longest suffix first, so a more specific family wins over a shorter one
    rules.sort(key=lambda t: -len(t[0]))
    return rules


def apply_family(name, rules):
    for suffix, verdict, note in rules:
        if name.endswith(suffix) and name != suffix:
            return verdict, f"[family:{suffix}] {note}"
    return None


RE_TRAIT_DECL = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?trait\s+([A-Za-z_]\w*)", re.M)
RE_TYPE_DECL = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum)\s+([A-Za-z_]\w*)", re.M)
RE_IMPL_FOR = re.compile(
    r"^\s*impl(?:\s*<[^>]*>)?\s+(?:[\w:]*::)?([A-Za-z_]\w*)(?:\s*<[^>]*>)?\s+for\s+"
    r"(?:&\s*)?(?:[\w:]*::)?([A-Za-z_]\w*)",
    re.M,
)

# Test doubles are not evidence about a type's real implementer set: a trait implemented by
# one real type and six mocks is not an open extension point.
MOCK_PREFIXES = ("Mock", "Stub", "Fake", "Dummy", "Test", "Minimal")

# A ported type whose doc names a JDK type of the SAME simple name is modelling that, not the
# Ghidra class the name matches in orig_src. `Lock` is the case that surfaced it: the Rust trait
# documents "Acquire/release contract of java.util.concurrent.locks.Lock", while orig_src holds
# ghidra.util.Lock, an unrelated concrete class. An orig_src-only scan cannot see that collision,
# so read the port's own doc comment for it.
RE_JDK_REF = re.compile(r"java\.(?:util|lang|io|nio|net|time|math|security)[\w.]*\.(\w+)")


RE_EXTENDS = re.compile(r"\b(?:class|interface)\s+\w+(?:<[^>]*>)?\s+extends\s+([\w.<>, ]+?)\s*(?:implements|\{)")
RE_IMPLEMENTS = re.compile(r"\bimplements\s+([\w.<>, ]+?)\s*\{")


RE_JAVA_DECL = re.compile(
    r"^\s*public\s+(?:final\s+|abstract\s+|sealed\s+|static\s+)*(class|interface|enum|record)\s+(\w+)",
    re.M,
)


def java_declarations(orig_src="orig_src"):
    """Java type name -> what Java declares it AS (class/interface/enum/record).

    The kind matters as much as the subtype count. "Nothing extends it" means one thing for a
    `class` -- there is no hierarchy, so a Rust trait is the wrong shape -- and something else
    entirely for an `interface`, where it may be an extension point, or its implementers may
    simply not be ported yet. And a name with no Java file at all is something the port invented
    (`MdMangLike`, `IteratorStl`, `RepositoryLike`), where the count says nothing.

    Checking this split the 112 "zero-subtype" candidates into a solid batch and two that would
    have been wrong to sweep.
    """
    decls = {}
    if not os.path.isdir(orig_src):
        return decls
    for dirpath, _dirs, files in os.walk(orig_src):
        for fn in files:
            if not fn.endswith(".java"):
                continue
            name = fn[: -len(".java")]
            if name in decls:
                continue
            try:
                with open(os.path.join(dirpath, fn), encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
            except OSError:
                continue
            for kind, decl_name in RE_JAVA_DECL.findall(text):
                if decl_name == name:
                    decls[name] = kind
                    break
    return decls


def java_subtype_counts(orig_src="orig_src"):
    """Java class/interface name -> how many Java types extend or implement it.

    This is the signal the proposer should have been using all along. Counting RUST implementers
    measures how far the port has got, not the shape of the hierarchy: `CodeUnit` shows 3
    non-mock impls today only because Instruction and Data are not ported, and `Settings` shows
    8 mostly-empty ones. Recommending "small closed set -> enum" off those numbers is
    recommending against the source.

    Two readings matter especially:
      * a count of ZERO means the Java type is a concrete class or a leaf interface -- there is
        no hierarchy to dispatch over at all, so a trait in Rust is simply wrong (`Lock` and
        `TokenPattern` are both this);
      * a large count means an enum was never viable, whatever the port currently shows.
    """
    counts = defaultdict(int)
    if not os.path.isdir(orig_src):
        return counts
    for dirpath, _dirs, files in os.walk(orig_src):
        for fn in files:
            if not fn.endswith(".java"):
                continue
            try:
                with open(os.path.join(dirpath, fn), encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
            except OSError:
                continue
            for rx in (RE_EXTENDS, RE_IMPLEMENTS):
                for group in rx.findall(text):
                    for name in group.split(","):
                        name = name.strip().split("<")[0].split(".")[-1]
                        if name:
                            counts[name] += 1
    return counts


def load_unported_classes(manifest):
    """Java class names still TODO in PORT_MANIFEST.tsv. A trait with no real implementers is
    NOT evidence that it should be a concrete type when its Java implementers simply haven't
    been ported yet -- that is the normal mid-port state, and 198 of these traits are literal
    seam_stubs.rs placeholders waiting for their port. Without this check the proposer
    confidently recommends collapsing traits whose implementations are still queued."""
    unported = set()
    if not manifest or not os.path.exists(manifest):
        return unported
    with open(manifest, encoding="utf-8") as f:
        for line in f:
            cols = line.rstrip("\n").split("\t")
            if len(cols) >= 2 and cols[1] == "TODO":
                cls = os.path.basename(cols[0])
                if cls.endswith(".java"):
                    unported.add(cls[: -len(".java")])
    return unported


def collect_declarations(root):
    """Structural evidence for suggesting verdicts: where each name is declared and how many
    implementers it has. A trait with many implementers is an open set; a trait with one or
    none is usually a type that should never have been a trait."""
    traits, types_, impls = defaultdict(int), defaultdict(int), defaultdict(int)
    mock_impls, stub_decl, jdk_modeled = defaultdict(int), set(), set()
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            if not fn.endswith(".rs"):
                continue
            try:
                with open(os.path.join(dirpath, fn), encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
            except OSError:
                continue
            for n in RE_TRAIT_DECL.findall(text):
                traits[n] += 1
            for n in RE_TYPE_DECL.findall(text):
                types_[n] += 1
            for trait_name, impl_target in RE_IMPL_FOR.findall(text):
                if impl_target.startswith(MOCK_PREFIXES):
                    mock_impls[trait_name] += 1
                else:
                    impls[trait_name] += 1
            if fn == "seam_stubs.rs":
                for n in RE_TRAIT_DECL.findall(text):
                    stub_decl.add(n)
            declared = set(RE_TRAIT_DECL.findall(text)) | set(RE_TYPE_DECL.findall(text))
            for jdk_name in RE_JDK_REF.findall(text):
                if jdk_name in declared:
                    jdk_modeled.add(jdk_name)
    return traits, types_, impls, mock_impls, stub_decl, jdk_modeled


def suggest_verdict(name, traits, types_, impls, unported, mock_impls, stub_decl,
                    java_subtypes=None, java_decls=None, jdk_modeled=frozenset()):
    """Propose a verdict from structural evidence. Deliberately conservative: anything the
    evidence doesn't speak to stays TODO rather than getting a confident-looking guess."""
    is_trait, is_type, n_impl = traits.get(name, 0), types_.get(name, 0), impls.get(name, 0)
    open_name = name.endswith(OPEN_EXTENSION_SUFFIXES)
    if not is_trait and not is_type:
        return "SUGGEST-PARK", "not declared in the crate (external type or unresolved stub)"
    if not is_trait:
        return None, ""                       # already a concrete type; `dyn` match is suspect
    if n_impl == 0 and name in stub_decl:
        # A seam_stubs.rs placeholder: the descent harness created it so a caller could compile
        # before the real type was ported. Says nothing about the right ownership shape.
        return None, "seam_stubs.rs placeholder -- revisit after the real port lands"
    if n_impl == 0 and mock_impls.get(name, 0) > 0:
        # Only test doubles implement it. That is the port being unfinished, not a design
        # signal: the real implementers are Java classes still in the queue.
        return None, (f"only {mock_impls[name]} mock implementer(s) and no real one -- the "
                      f"implementations are not ported yet; revisit then")
    # Prefer Java's hierarchy over the port's: the port's count measures progress, not shape.
    if name in jdk_modeled:
        return None, (
            f"this port models the JDK's {name}; the {name} in orig_src is an unrelated Ghidra "
            f"class of the same simple name, so Java's shape here says nothing")

    if java_subtypes is not None:
        j = java_subtypes.get(name, 0)
        if j == 0:
            kind = (java_decls or {}).get(name)
            if kind in ("class", "enum", "record"):
                return "SUGGEST-STRUCT", (
                    f"Java declares {name} as a {kind} and nothing extends it -- there is no "
                    f"hierarchy to dispatch over, so a trait is the wrong shape "
                    f"({n_impl} Rust impls notwithstanding)")
            if kind == "interface":
                return None, (
                    f"Java declares {name} as an interface with no in-tree implementers -- either "
                    f"an extension point (-> ACCEPT) or its implementers are unported; the count "
                    f"cannot tell which")
            return None, (
                f"no Java type named {name} -- an abstraction the port invented, so Java says "
                f"nothing about its shape")
        if open_name:
            return "SUGGEST-ACCEPT", f"{j} Java subtypes and an extension-point name -- open set"
        if j <= ENUM_MAX_VARIANTS:
            return "SUGGEST-ENUM", f"small closed set: {j} Java subtypes"
        if name.endswith(AST_NODE_SUFFIXES):
            return "SUGGEST-GRAPH", (f"{j} Java subtypes with an AST/IR node name -- too many for "
                                     f"an enum, but a tagged arena graph suits a node set this size")
        return None, (f"{j} Java subtypes -- too many for an enum; needs a human call "
                      f"(genuine open set -> ACCEPT, or graph type -> ARENA/GRAPH)")

    if n_impl <= 2 and name in unported:
        # Mid-port state, not a design signal: the Java implementers are still queued.
        return None, (f"only {n_impl} real implementer(s), but {name} is still TODO in "
                      f"PORT_MANIFEST.tsv -- revisit once the port lands")
    if n_impl == 0:
        return "SUGGEST-STRUCT", "declared a trait but nothing (non-mock) implements it -- not an extension point"
    if n_impl <= 2:
        return "SUGGEST-STRUCT", f"trait with only {n_impl} real implementer(s) -- usually just a concrete type"
    if n_impl <= ENUM_MAX_VARIANTS:
        if open_name:
            return "SUGGEST-ACCEPT", f"{n_impl} implementers and an extension-point name -- open set"
        return "SUGGEST-ENUM", f"small closed set: {n_impl} real implementers, all in-crate"
    if name.endswith(AST_NODE_SUFFIXES):
        return "SUGGEST-GRAPH", (f"{n_impl} implementers with an AST/IR node name -- too many for "
                                 f"an enum, but a tagged arena graph handles a node set of this size")
    # A large implementer set is evidence AGAINST a closed hierarchy, not for one: nobody
    # wants a 94-variant enum. Either it is a genuine open set, or it is a graph type wanting
    # an arena -- a call the evidence here cannot make, so say so instead of guessing.
    if open_name:
        return "SUGGEST-ACCEPT", f"{n_impl} implementers and an extension-point name -- open set"
    return None, (f"{n_impl} real implementers -- too many for an enum; needs a human call "
                  f"(genuine open set -> ACCEPT, or graph type -> ARENA)")


def categorize(name):
    """Best-effort first guess at what KIND of decision this type needs. A guess only --
    the verdict column is set by a human or a reviewing agent, not by this heuristic."""
    if name.endswith(OPEN_EXTENSION_SUFFIXES):
        return "open-extension"
    if name.startswith("Abstract") or name.endswith(("DataType", "Exception")):
        return "closed-hierarchy?"
    return "graph?"


def load_blocked_rows(debt_path, max_fanin, dyn_threshold):
    """The convention-blocked slice of OWNERSHIP_DEBT.tsv: rows the remediation harness
    cannot act on until some type gets a verdict."""
    blocked = []
    with open(debt_path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f, delimiter="\t"):
            if r.get("status") != "TODO":
                continue
            try:
                if int(r.get("fanin", 0)) > max_fanin:
                    continue
            except ValueError:
                continue
            sig = r.get("signals", "")
            m = re.search(r"dyn=(\d+)", sig)
            dyn = int(m.group(1)) if m else 0
            if dyn >= dyn_threshold or "rc_refcell=" in sig or "arc_mutex=" in sig:
                blocked.append(r)
    return blocked


def types_in_file(path):
    """Types reached via dyn / Rc<RefCell<>> / Arc<Mutex<>>, comments stripped, idiomatic
    trait objects excluded. Returns {name: occurrence_count}."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
    except OSError:
        return {}
    text = RE_LINE_COMMENT.sub("", text)
    counts = defaultdict(int)
    for rx in (RE_DYN, RE_CELL):
        for name in rx.findall(text):
            if name not in IDIOMATIC:
                counts[name] += 1
    return counts


def load_prior_verdicts(path):
    """type -> (verdict, source, note) from an existing queue, so regenerating never discards
    decisions already made. Same lesson as pattern_audit.py's --preserve-status. Rows whose
    source is 'family' are recomputed from the rules file; 'manual'/'seed' rows are kept
    verbatim, so editing CONVENTION_FAMILIES.tsv can never silently overwrite a hand verdict."""
    prior = {}
    if not path or not os.path.exists(path):
        return prior
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f, delimiter="\t"):
            name = (r.get("type") or "").strip()
            if name:
                prior[name] = (
                    (r.get("verdict") or "TODO").strip(),
                    (r.get("source") or "manual").strip(),
                    r.get("note") or "",
                )
    return prior


def load_seam_fanin(seam_path):
    fanin = {}
    if not seam_path or not os.path.exists(seam_path):
        return fanin
    with open(seam_path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f, delimiter="\t")
        next(reader, None)
        for row in reader:
            if len(row) < 6:
                continue
            cls = os.path.basename(row[5])
            if cls.endswith(".java"):
                cls = cls[: -len(".java")]
            try:
                fanin[cls] = max(fanin.get(cls, 0), int(row[2]))
            except ValueError:
                continue
    return fanin


def build_queue(debt, seam, src_root, out_path, max_fanin, dyn_threshold, families):
    blocked = load_blocked_rows(debt, max_fanin, dyn_threshold)
    fanin = load_seam_fanin(seam)
    prior = load_prior_verdicts(out_path)

    files_by_type = defaultdict(set)
    occ_by_type = defaultdict(int)
    for r in blocked:
        full = os.path.join(os.path.dirname(src_root.rstrip("/")) or ".", r["path"])
        if not os.path.exists(full):
            full = os.path.join(src_root, os.path.relpath(r["path"], "src"))
        for name, n in types_in_file(full).items():
            files_by_type[name].add(r["path"])
            occ_by_type[name] += n

    rules = load_family_rules(families)
    rows = []
    for name, files in files_by_type.items():
        prev = prior.get(name)
        if prev and prev[1] != "family" and prev[0] != "TODO":
            verdict, source, note = prev            # hand-made decision: never recompute
        else:
            fam = apply_family(name, rules)
            if fam:
                verdict, note, source = fam[0], fam[1], "family"
            elif prev:
                verdict, source, note = prev
            else:
                verdict, source, note = "TODO", "", ""
        rows.append(
            {
                "verdict": verdict,
                "leverage": len(files),
                "occurrences": occ_by_type[name],
                "fanin": fanin.get(name, 0),
                "type": name,
                "category": categorize(name),
                "source": source,
                "note": note,
            }
        )
    rows.sort(key=lambda r: (-r["leverage"], -r["occurrences"], r["type"]))
    return rows, blocked


def main():
    ap = argparse.ArgumentParser(description="Type-level convention frontier for Phase 3")
    ap.add_argument("--debt", default="OWNERSHIP_DEBT.tsv")
    ap.add_argument("--seam", default="SEAM.tsv")
    ap.add_argument("--root", default="ghidra-rs/src")
    ap.add_argument("--out", help="Write CONVENTION_QUEUE.tsv here (preserves existing verdicts)")
    ap.add_argument("--families", default="CONVENTION_FAMILIES.tsv",
                    help="Family rules: one verdict for a whole naming family (*Iterator, *Listener, ...)")
    ap.add_argument("--top", type=int, default=25, help="Rows to print when not writing")
    ap.add_argument("--max-fanin", type=int, default=500,
                    help="Match remediate_ownership.sh's MAX_FANIN: rows above it are Phase 2")
    ap.add_argument("--dyn-threshold", type=int, default=5)
    ap.add_argument("--orig-src", default="orig_src",
                    help="Java sources, read to size each hierarchy at its source rather than "
                         "by how far the port has got")
    ap.add_argument("--manifest", default="PORT_MANIFEST.tsv",
                    help="Port status, so a trait with no implementers YET isn't mistaken for "
                         "a trait that shouldn't exist")
    ap.add_argument("--suggest", action="store_true",
                    help="Fill undecided rows with SUGGEST-<VERDICT> proposals from structural "
                         "evidence. Proposals are inert until --promote.")
    ap.add_argument("--promote", metavar="VERDICT",
                    help="Promote SUGGEST-<VERDICT> rows to <VERDICT> (e.g. --promote ACCEPT), "
                         "or ALL for every suggestion. This is the review gate.")
    args = ap.parse_args()

    rows, blocked = build_queue(
        args.debt, args.seam, args.root, args.out, args.max_fanin, args.dyn_threshold,
        args.families,
    )
    if not rows:
        print("no convention-blocked rows -- nothing to queue", file=sys.stderr)
        return

    if args.suggest:
        traits, types_, impls, mock_impls, stub_decl, jdk_modeled = collect_declarations(args.root)
        unported = load_unported_classes(args.manifest)
        java_subtypes = java_subtype_counts(args.orig_src)
        java_decls = java_declarations(args.orig_src)
        print(f"read {len(java_subtypes)} Java supertypes and {len(java_decls)} declarations "
              f"from {args.orig_src}", file=sys.stderr)
        n = 0
        for r in rows:
            if r["verdict"] != "TODO":
                continue
            v, why = suggest_verdict(r["type"], traits, types_, impls, unported,
                                     mock_impls, stub_decl, java_subtypes, java_decls,
                                     jdk_modeled)
            if v:
                r["verdict"], r["source"], r["note"] = v, "suggest", why
                n += 1
            elif why:
                r["source"], r["note"] = "evidence", why
        print(f"proposed {n} verdicts (inert until --promote)", file=sys.stderr)

    if args.promote:
        want = args.promote.strip().upper()
        n = 0
        for r in rows:
            v = r["verdict"]
            if v.startswith("SUGGEST-") and (want == "ALL" or v == f"SUGGEST-{want}"):
                r["verdict"], r["source"] = v[len("SUGGEST-"):], "promoted"
                n += 1
        print(f"promoted {n} suggestion(s) matching {want}", file=sys.stderr)

    decided = [r for r in rows if r["verdict"] != "TODO"]
    seen, cumulative = set(), []
    for r in rows:
        cumulative.append(r)

    if args.out:
        with open(args.out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=QUEUE_COLS, delimiter="\t")
            w.writeheader()
            for r in rows:
                w.writerow(r)
        print(
            f"wrote {len(rows)} type decisions to {args.out} "
            f"({len(decided)} already decided, {len(rows) - len(decided)} TODO) "
            f"covering {len(blocked)} blocked files",
            file=sys.stderr,
        )
    else:
        print(f"{len(blocked)} convention-blocked files depend on {len(rows)} type decisions\n")
        print(f"{'verdict':<8}{'files':>6}{'occ':>7}{'fanin':>7}  {'type':<32}category")
        for r in rows[: args.top]:
            print(
                f"{r['verdict']:<8}{r['leverage']:>6}{r['occurrences']:>7}{r['fanin']:>7}  "
                f"{r['type']:<32}{r['category']}"
            )


if __name__ == "__main__":
    main()
