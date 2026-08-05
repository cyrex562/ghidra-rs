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

RE_DYN = re.compile(r"\bdyn\s+[A-Za-z_]")
RE_RC_REFCELL = re.compile(r"\bRc\s*<\s*RefCell\s*<")
RE_ARC_MUTEX = re.compile(r"\bArc\s*<\s*(Mutex|RwLock)\s*<")
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


def scan_file(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        text = fh.read()
    prod_text = strip_test_modules(text)
    lines = max(1, text.count("\n") + 1)
    prod_lines = max(1, prod_text.count("\n") + 1)

    # Signals below should reflect real code, not doc/line comments *describing* a pattern
    # (e.g. a migration note that says "replaces Box<dyn Trait>" isn't a `dyn` usage).
    code_text = strip_comments(text)
    code_prod_text = strip_comments(prod_text)

    dyn_count = len(RE_DYN.findall(code_text))
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
    ap.add_argument("--baseline", help="Previous audit TSV, for --diff-new")
    ap.add_argument(
        "--diff-new",
        action="store_true",
        help="Periodic-audit mode: only report files whose score regressed vs --baseline "
        "(new smells introduced since the last audit), not the whole backlog.",
    )
    args = ap.parse_args()

    if not os.path.isdir(args.root):
        print(f"error: {args.root} not found", file=sys.stderr)
        sys.exit(1)

    fanin = load_seam_fanin(args.seam)

    rows = []
    for dirpath, _dirs, files in os.walk(args.root):
        for fn in files:
            if not fn.endswith(".rs"):
                continue
            path = os.path.join(dirpath, fn)
            score, signals = scan_file(path)
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
