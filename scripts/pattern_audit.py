"""Ghidra-rs "Java-in-Rust" pattern auditor.

Scans the ported crate for signals that a Java idiom was translated too literally
instead of being redesigned into idiomatic Rust -- the same class of problem that
produced the current Rc<RefCell<_>>/Arc<Mutex<_>>/Box<dyn Trait>/.clone() sprawl on
the high-fan-in "seam" types (Address, Program, DataTypeManager, Function, ...).

This is a heuristic, regex-based scanner (no rustc AST), matching the style of
sync_check.py -- fast, dependency-free, good enough to rank/triage, not a proof.

Signals (see SIGNAL_WEIGHTS below):
  dyn_trait        `dyn Trait` / `Box<dyn Trait>` usage -- Java-interface-as-trait-object
  rc_refcell       `Rc<RefCell<` -- single-threaded GC-style shared mutability
  arc_mutex        `Arc<Mutex<` / `Arc<RwLock<` -- multi-threaded GC-style shared mutability
  clone_density    `.clone()` calls per 100 lines -- borrow-checker-dodging via copying
  getter_setter    `fn get_x`/`fn set_x` pairs where a pub field would do
  unwrap_density   `.unwrap()`/`.expect(` per 100 lines outside #[cfg(test)] -- Java
                    checked-exception-as-panic thinking instead of Result propagation
  lazy_static_mut  `static` `Lazy<Mutex<` / `OnceCell<Mutex<` -- Java singleton/manager
                    statics instead of owned state threaded through the call graph

Usage:
  python scripts/pattern_audit.py --root ghidra-rs/src --seam SEAM.tsv \
      --out OWNERSHIP_DEBT.tsv
  python scripts/pattern_audit.py --root ghidra-rs/src --baseline OWNERSHIP_DEBT.tsv \
      --diff-new   # periodic-audit mode: only print files that got WORSE since baseline
"""
import argparse
import csv
import os
import re
import sys
from collections import defaultdict

SIGNAL_WEIGHTS = {
    "dyn_trait": 2,
    "rc_refcell": 3,
    "arc_mutex": 3,
    "clone_density": 1,     # per unit (per 100 lines)
    "getter_setter": 1,     # per pair
    "unwrap_density": 1,    # per unit (per 100 lines)
    "lazy_static_mut": 3,
}

# Trait objects that are idiomatic Rust rather than a Java interface translated too
# literally. `Box<dyn Error>`, `&dyn Any` and `Box<dyn Fn(..)>` are correct Rust; counting
# them as ownership debt inflates scores and pushes files onto the remediation frontier that
# have nothing to remediate. 1,745 such occurrences were scored as debt before this landed.
IDIOMATIC_DYN = {
    "Any", "Error", "Fn", "FnMut", "FnOnce", "Iterator", "DoubleEndedIterator",
    "ExactSizeIterator", "Send", "Sync", "Display", "Debug", "Write", "Read", "Seek",
    "BufRead", "Future", "Hash", "Ord", "PartialEq", "PartialOrd", "Eq", "Clone",
    "ToString", "Deref", "DerefMut", "Drop", "Default", "From", "Into", "AsRef", "AsMut",
}

# Captures the type name behind `dyn`, resolving `dyn crate::foo::Bar` to `Bar`.
RE_DYN = re.compile(
    r"\bdyn\s+(?:(?:crate|std|core|alloc|self|super)::)?"
    r"(?:[A-Za-z_][A-Za-z0-9_]*::)*([A-Za-z_][A-Za-z0-9_]*)"
)
RE_RC_REFCELL = re.compile(r"\bRc\s*<\s*RefCell\s*<")
# `Arc<Mutex<T>>`/`Arc<RwLock<T>>` is the multi-threaded GC-style sharing this migration
# targets -- EXCEPT when the payload is `()`. `Arc<RwLock<()>>` carries no data at all: it is a
# bare lock handle (the shape Java's ReadWriteLock takes when ported), which
# OWNERSHIP_MIGRATION.md explicitly lists as a legitimate use. Counting it kept
# db_synchronized_iterator.rs on the frontier after its actual debt was remediated.
RE_ARC_MUTEX = re.compile(r"\bArc\s*<\s*(?:Mutex|RwLock)\s*<\s*(?!\(\s*\)\s*>)")
RE_CLONE = re.compile(r"\.clone\(\)")
RE_GETTER = re.compile(r"\bfn\s+get_([A-Za-z0-9_]+)\s*\(")
RE_SETTER = re.compile(r"\bfn\s+set_([A-Za-z0-9_]+)\s*\(")
RE_UNWRAP = re.compile(r"\.unwrap\(\)|\.expect\(")
RE_LAZY_STATIC_MUT = re.compile(
    r"static\s+[A-Z0-9_]+\s*:\s*.*(Lazy|OnceCell|OnceLock)\s*<\s*.*(Mutex|RwLock)\s*<"
)
RE_TEST_CFG = re.compile(r"#\[cfg\(test\)\]")
RE_MOD_TESTS = re.compile(r"\bmod\s+tests\b")


def camel_to_snake(name):
    """Mirror AGENTS.md's class -> file convention: BTreeTypes -> b_tree_types."""
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    s2 = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1)
    return s2.lower()


def strip_test_modules(text):
    """Best-effort: drop from the first `#[cfg(test)]` or `mod tests` onward, so
    unwrap()/expect() inside test code doesn't inflate the production signal."""
    for rx in (RE_TEST_CFG, RE_MOD_TESTS):
        m = rx.search(text)
        if m:
            text = text[: m.start()]
    return text


RE_LINE_COMMENT = re.compile(r"//.*$", re.MULTILINE)


def strip_comments(text):
    """Best-effort: blank out `//`/`///`/`//!` line comments before signal-matching, so prose
    that *names* `dyn`/`Rc<RefCell<`/etc. while explaining what a file replaces (exactly what
    this module's own doc comments do) doesn't count as a real usage. Line-oriented and doesn't
    understand string literals containing `//` -- a known, accepted limitation, same tradeoff as
    the rest of this heuristic scanner."""
    return RE_LINE_COMMENT.sub("", text)


def load_seam_fanin(seam_path):
    """java_class_name (basename, no .java) -> fan-in count, from SEAM.tsv."""
    fanin = {}
    if not seam_path or not os.path.exists(seam_path):
        return fanin
    with open(seam_path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f, delimiter="\t")
        header = next(reader, None)
        for row in reader:
            if len(row) < 6:
                continue
            _status, _kind, fan, _rem, _module, path = row[:6]
            cls = os.path.basename(path)
            if cls.endswith(".java"):
                cls = cls[: -len(".java")]
            try:
                fanin[cls] = max(fanin.get(cls, 0), int(fan))
            except ValueError:
                continue
    return fanin


def load_prior_status(tsv_path):
    """path -> (status, score) from a previous audit snapshot. Empty if unreadable."""
    prior = {}
    if not tsv_path or not os.path.exists(tsv_path):
        return prior
    with open(tsv_path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f, delimiter="\t"):
            path = (r.get("path") or "").strip()
            if not path:
                continue
            try:
                score = float(r.get("score") or 0)
            except ValueError:
                score = 0.0
            prior[path] = ((r.get("status") or "TODO").strip(), score)
    return prior


def load_accepted_types(queue_path):
    """Types whose CONVENTION_QUEUE.tsv verdict is ACCEPT -- `dyn` is the right answer for
    them (genuine open-ended extension points), so they must stop counting as debt. This is
    what makes a convention decision actually retire files from the frontier instead of
    leaving them to be re-asked and re-parked once per file. A SUGGEST-ACCEPT proposal is
    deliberately NOT honoured: proposals are inert until promoted."""
    accepted = set()
    if not queue_path or not os.path.exists(queue_path):
        return accepted
    with open(queue_path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f, delimiter="\t"):
            if (r.get("verdict") or "").strip() == "ACCEPT":
                name = (r.get("type") or "").strip()
                if name:
                    accepted.add(name)
    return accepted


def load_justified_dyn_types(debt_path=None):
    """Types a port CANNOT avoid writing `dyn` for today.

    This file's number is the nightly DRIFT signal: did last night's ports add avoidable
    smells? Avoidable means an alternative exists right now. Three things do not qualify and
    must not be scored, or the signal measures the migration's size instead of the run's:

      * `dyn` that is CORRECT -- an extension point, or a genuinely polymorphic interface
        (dyn_rules ok);
      * a SEAM -- the one concrete implementation is not ported yet, so there is nothing else
        to write (dyn_rules blocked);
      * a decided convention whose TARGET has not been built -- `DataType` is decided ENUM
        with 1,513 `dyn` uses, but no `DataType` enum exists, and a port cannot hold a Copy ID
        into an arena that is not there. dyn_rules marks those `blocked`, so they arrive here
        already excluded; counting them tripled the score (34,296 -> 49,380) with work no
        nightly run could have done differently.

    What remains scored is the avoidable case: a Java class or a single-implementation
    interface whose concrete Rust type exists today.

    Reads the committed DYN_DEBT.tsv when it is present -- that file already holds the
    verdicts and costs milliseconds, where recomputing walks 15,601 Java files. Falls back
    to computing, and to the manual list alone if orig_src is unavailable, rather than
    failing the audit.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    debt = debt_path or os.path.join(os.path.dirname(here), "DYN_DEBT.tsv")
    if os.path.exists(debt):
        try:
            with open(debt, newline="", encoding="utf-8") as f:
                # Exactly the rows dyn_rules did NOT mark `fix` -- it already accounts for
                # whether a decided convention is buildable, so a second rule keyed on the
                # convention NAME would wrongly exempt the ones that are (EquateStore exists,
                # so `dyn Equate` is avoidable today).
                out = {r["class"] for r in csv.DictReader(f, delimiter="\t")
                       if (r.get("verdict") or "").strip() != "fix"}
            if out:
                return out
        except Exception:
            pass
    try:
        sys.path.insert(0, here)
        import dyn_rules
        import shape_rules
        facts, subtypes = shape_rules.build_index()
    except Exception:
        return set()
    cache, out = {}, set()
    for name in facts:
        try:
            pat, _n, _kind = dyn_rules.classify(name, facts, subtypes, cache)
        except Exception:
            continue
        if pat in ("P4", "P5", "P2s"):
            out.add(name)
    return out


def count_dyn(text, accepted):
    """`dyn T` occurrences that represent Java-interface-as-trait-object debt: excludes
    idiomatic Rust trait objects, any type with an ACCEPT verdict, and any type whose Java
    hierarchy shows genuine polymorphism."""
    skip = IDIOMATIC_DYN | (accepted or set())
    return sum(1 for name in RE_DYN.findall(text) if name not in skip)


def scan_file(path, accepted=None):
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        text = fh.read()
    prod_text = strip_test_modules(text)
    lines = max(1, text.count("\n") + 1)
    prod_lines = max(1, prod_text.count("\n") + 1)

    # Signals below should reflect real code, not doc/line comments *describing* a pattern
    # (e.g. a migration note that says "replaces Box<dyn Trait>" isn't a `dyn` usage).
    code_text = strip_comments(text)
    code_prod_text = strip_comments(prod_text)

    dyn_count = count_dyn(code_text, accepted)
    rc_refcell = len(RE_RC_REFCELL.findall(code_text))
    arc_mutex = len(RE_ARC_MUTEX.findall(code_text))
    clone_count = len(RE_CLONE.findall(code_text))
    getters = set(RE_GETTER.findall(code_text))
    setters = set(RE_SETTER.findall(code_text))
    getter_setter_pairs = len(getters & setters)
    unwrap_count = len(RE_UNWRAP.findall(code_prod_text))
    lazy_static_mut = len(RE_LAZY_STATIC_MUT.findall(code_text))

    clone_density = clone_count / lines * 100.0
    unwrap_density = unwrap_count / prod_lines * 100.0

    score = (
        dyn_count * SIGNAL_WEIGHTS["dyn_trait"]
        + rc_refcell * SIGNAL_WEIGHTS["rc_refcell"]
        + arc_mutex * SIGNAL_WEIGHTS["arc_mutex"]
        + clone_density * SIGNAL_WEIGHTS["clone_density"]
        + getter_setter_pairs * SIGNAL_WEIGHTS["getter_setter"]
        + unwrap_density * SIGNAL_WEIGHTS["unwrap_density"]
        + lazy_static_mut * SIGNAL_WEIGHTS["lazy_static_mut"]
    )

    signals = []
    if dyn_count:
        signals.append(f"dyn={dyn_count}")
    if rc_refcell:
        signals.append(f"rc_refcell={rc_refcell}")
    if arc_mutex:
        signals.append(f"arc_mutex={arc_mutex}")
    if clone_density >= 1.0:
        signals.append(f"clone/100L={clone_density:.1f}")
    if getter_setter_pairs:
        signals.append(f"getset_pairs={getter_setter_pairs}")
    if unwrap_density >= 1.0:
        signals.append(f"unwrap/100L={unwrap_density:.1f}")
    if lazy_static_mut:
        signals.append(f"lazy_static_mut={lazy_static_mut}")

    return round(score, 1), signals


def module_of(root, path):
    rel = os.path.relpath(path, root)
    parts = rel.split(os.sep)
    return parts[0] if len(parts) > 1 else ""


def main():
    ap = argparse.ArgumentParser(description="Audit ported Rust for Java-idiom smells")
    ap.add_argument("--root", default="ghidra-rs/src", help="Rust source root to scan")
    ap.add_argument("--seam", default="SEAM.tsv", help="SEAM.tsv, for fan-in cross-reference")
    ap.add_argument("--out", help="Write TSV (status/score/fanin/class/module/path/signals) here")
    ap.add_argument("--min-score", type=float, default=3.0, help="Ignore files below this score")
    ap.add_argument("--top", type=int, default=0, help="Only print/write the top N by priority")
    ap.add_argument(
        "--accepted",
        default="CONVENTION_QUEUE.tsv",
        help="Type-level verdict file (scripts/debt_clusters.py). Types marked ACCEPT there "
        "stop counting as dyn debt. Missing file = no accepted types.",
    )
    ap.add_argument(
        "--no-justified-dyn",
        action="store_true",
        help="Score every `dyn T` as debt, instead of exempting types whose Java hierarchy "
        "shows genuine polymorphism (scripts/dyn_rules.py P4/P5: an extension-point "
        "supertype, or 4+ concrete implementers in orig_src). Use to reproduce pre-2026-08-09 "
        "scores; the exemption is on by default because counting `dyn DataType` (192 "
        "implementers) the same as `dyn Trace` (one) makes the drift number unactionable.",
    )
    ap.add_argument("--baseline", help="Previous audit TSV, for --diff-new / --preserve-status")
    ap.add_argument(
        "--diff-new",
        action="store_true",
        help="Periodic-audit mode: only report files whose score regressed vs --baseline "
        "(new smells introduced since the last audit), not the whole backlog.",
    )
    ap.add_argument(
        "--preserve-status",
        action="store_true",
        help="When writing --out, carry DONE/PARK statuses over from the previous snapshot "
        "(--baseline, else the existing --out file) instead of resetting every row to TODO. "
        "A DONE/PARK row whose score regressed by >0.5 is reopened as TODO. Required for any "
        "refresh that runs after remediation has started, or the frontier file is wiped.",
    )
    args = ap.parse_args()

    if not os.path.isdir(args.root):
        print(f"error: {args.root} not found", file=sys.stderr)
        sys.exit(1)

    fanin = load_seam_fanin(args.seam)
    accepted = load_accepted_types(args.accepted)
    if accepted:
        print(f"honouring {len(accepted)} ACCEPT verdict(s) from {args.accepted}", file=sys.stderr)
    if not args.no_justified_dyn:
        justified = load_justified_dyn_types()
        if justified:
            print(f"treating {len(justified)} type(s) with 4+ concrete Java implementers (or an "
                  f"extension-point supertype) as justified `dyn`", file=sys.stderr)
            accepted = accepted | justified

    rows = []
    for dirpath, _dirs, files in os.walk(args.root):
        for fn in files:
            if not fn.endswith(".rs"):
                continue
            path = os.path.join(dirpath, fn)
            score, signals = scan_file(path, accepted)
            if score < args.min_score:
                continue
            stem = fn[: -len(".rs")]
            class_guess = "".join(p.capitalize() for p in stem.split("_"))
            fan = fanin.get(class_guess, 0)
            # priority folds fan-in in: a smelly high-fan-in seam type outranks a
            # smelly leaf file with the same raw score.
            priority = round(score * (1 + fan / 100.0), 1)
            rows.append(
                {
                    "status": "TODO",
                    "priority": priority,
                    "score": score,
                    "fanin": fan,
                    "class": class_guess,
                    "module": module_of(args.root, dirpath),
                    "path": os.path.relpath(path, os.path.dirname(args.root) or "."),
                    "signals": ",".join(signals),
                }
            )

    rows.sort(key=lambda r: (-r["priority"], r["path"]))
    if args.top:
        rows = rows[: args.top]

    if args.diff_new:
        baseline = {}
        if args.baseline and os.path.exists(args.baseline):
            with open(args.baseline, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f, delimiter="\t")
                for r in reader:
                    baseline[r["path"]] = float(r.get("score", 0) or 0)
        new_or_worse = [
            r for r in rows if r["score"] > baseline.get(r["path"], 0.0) + 0.5
        ]
        for r in new_or_worse:
            prev = baseline.get(r["path"], 0.0)
            print(f"{r['path']}\tscore {prev:.1f} -> {r['score']:.1f}\t{r['signals']}")
        if not new_or_worse:
            print("no new/worsened Java-idiom smells since baseline", file=sys.stderr)
        return

    out = args.out
    fieldnames = ["status", "priority", "score", "fanin", "class", "module", "path", "signals"]

    if args.preserve_status:
        # A plain rescan writes status=TODO for every row, which silently un-does every
        # DONE/PARK a remediation run (or a human) recorded -- the frontier file loses its
        # memory and already-handled files get picked up again. Carry those statuses over,
        # except where the file got measurably worse since the snapshot, which is exactly
        # the case worth reopening.
        prior = load_prior_status(args.baseline or out)
        kept = reopened = 0
        for r in rows:
            prev = prior.get(r["path"])
            if not prev or prev[0] not in ("DONE", "PARK"):
                continue
            if r["score"] > prev[1] + 0.5:
                reopened += 1
                print(
                    f"reopened {prev[0]} -> TODO (score {prev[1]:.1f} -> {r['score']:.1f}): "
                    f"{r['path']}",
                    file=sys.stderr,
                )
            else:
                r["status"] = prev[0]
                kept += 1
        print(f"preserved {kept} DONE/PARK rows, reopened {reopened}", file=sys.stderr)

    if out:
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames, delimiter="\t")
            w.writeheader()
            for r in rows:
                w.writerow(r)
        print(f"wrote {len(rows)} rows to {out}", file=sys.stderr)
    else:
        for r in rows:
            print(
                f"{r['priority']:6} pri | score {r['score']:5} | fanin {r['fanin']:4} | "
                f"{r['path']} | {r['signals']}"
            )


if __name__ == "__main__":
    main()
