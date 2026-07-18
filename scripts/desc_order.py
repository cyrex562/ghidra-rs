#!/usr/bin/env python3
"""
Recursive-descent port-order generator (unified driver, phase 1: the ORDER).

Replaces the two existing pickers' *ordering* logic:
  * tick2.sh          -- strictly 0-dep leaves, bottom-up (exhausts inside the SCC)
  * seam_night.sh     -- flat fanin-ranked trait list (breadth-first, over-stubs)

Instead: a DFS forest over the unported in-scope dependency graph, rooted at the
highest-fanin node (the keystone to break next), descending into dependencies until
a leaf, emitting POST-ORDER (leaf-first) so each class is ported after its deps.

Cycle handling -- the whole point. The remaining graph is ~1 giant SCC, so a pure
descent never reaches a leaf: it hits a dep already on the recursion stack (a
back-edge). That back-edge's TARGET (a DFS ancestor) is marked as a CUT -> it is
ported as a Rust TRAIT so its cyclic dependents can reference it abstractly and the
cycle breaks. Everything else ports as a normal struct. This is demand-driven: we
only trait-cut the edges actually on the path, not every unported reference.

Emits PORT_ORDER.tsv:  status  mode  depth  fanin  rem  module  path
  mode  = trait (back-edge cut point) | struct (normal port)
  depth = DFS depth at first visit (informational)
Order is leaf-first: a runner consumes it top-down and every dep is already queued.

Usage:
  python3 scripts/desc_order.py                # preview: stats + first 30 to port
  python3 scripts/desc_order.py --show 60       # preview first 60
  python3 scripts/desc_order.py --write         # (re)write PORT_ORDER.tsv
"""
import argparse, json, os, re, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__)); REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE); import portlib

OUT = os.path.join(REPO, "PORT_ORDER.tsv")


def load_frontier():
    raw = subprocess.run(
        [sys.executable, os.path.join(HERE, "sync_check.py"), "--root", "orig_src",
         "--manifest", "PORT_MANIFEST.tsv", "--json"],
        capture_output=True, text=True, cwd=REPO).stdout
    return json.loads(raw[raw.index("["):])


_ui = {}
def is_ui(rel):
    if rel in _ui:
        return _ui[rel]
    try:
        s = open(os.path.join(REPO, "orig_src", rel), encoding="utf-8", errors="ignore").read(4000)
    except OSError:
        s = ""
    r = bool(re.search(r"import\s+(javax\.swing|java\.awt)", s)
             or re.search(r"/(gui|widgets)/|docking/", rel)
             or re.search(r"\b(extends|implements)\s+[A-Za-z0-9_.]*(J[A-Z]\w*|Renderer|CellEditor|Icon|GComponent|GTable|GTree)", s))
    _ui[rel] = r
    return r


def kind_is_interface(rel):
    try:
        s = open(os.path.join(REPO, "orig_src", rel), encoding="utf-8", errors="ignore").read(8000)
    except OSError:
        return False
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.S)
    s = re.sub(r"//[^\n]*", "", s)
    m = re.search(r"\b(public|abstract|final|sealed|strictfp|\s)*\b(interface|class|enum|record)\b", s)
    return bool(m and m.group(2) == "interface")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--show", type=int, default=30, help="rows to preview (default 30)")
    ap.add_argument("--write", action="store_true", help="write PORT_ORDER.tsv")
    args = ap.parse_args()

    data = load_frontier()
    by = {d["file"]: d for d in data}

    fanin = {}
    for d in data:
        for dep in d["dependencies"]:
            fanin[dep] = fanin.get(dep, 0) + 1

    def in_scope(f):
        d = by.get(f)
        return bool(d and not d["done"]
                    and portlib.module_for(portlib.package_of(f)) and not is_ui(f))

    nodes = [d["file"] for d in data if in_scope(d["file"])]
    nset = set(nodes)
    adj = {v: [w for w in by[v]["dependencies"] if w in nset] for v in nodes}

    WHITE, GREY, BLACK = 0, 1, 2
    color = {v: WHITE for v in nodes}
    depth_at = {}
    order = []          # post-order (leaf-first)
    cut = set()         # back-edge targets -> port as trait

    # roots in descending fanin -> DFS forest; iterative to survive deep chains
    roots = sorted(nodes, key=lambda v: (-fanin.get(v, 0), v))
    for root in roots:
        if color[root] != WHITE:
            continue
        stack = [(root, 0)]
        color[root] = GREY; depth_at[root] = 0
        while stack:
            v, pi = stack[-1]
            advanced = False
            for i in range(pi, len(adj[v])):
                w = adj[v][i]
                if color[w] == WHITE:
                    stack[-1] = (v, i + 1)
                    color[w] = GREY; depth_at[w] = len(stack)
                    stack.append((w, 0))
                    advanced = True
                    break
                elif color[w] == GREY:
                    cut.add(w)             # back-edge target (DFS ancestor) -> trait cut
                    stack[-1] = (v, i + 1)
            if advanced:
                continue
            color[v] = BLACK
            order.append(v)
            stack.pop()

    def mode_of(v):
        return "trait" if (v in cut or kind_is_interface(v)) else "struct"

    def row(v):
        return (f"TODO\t{mode_of(v)}\t{depth_at.get(v, 0)}\t{fanin.get(v, 0)}\t"
                f"{by[v]['remaining_dep_count']}\t{portlib.module_for(portlib.package_of(v))}\t{v}")

    # TWO-PHASE emit: all trait DECLARATIONS first (their signatures use trait objects, not
    # concrete structs, so they have no struct deps), then struct impls -- each in leaf-first
    # (post-order) sequence. Guarantees every struct's trait deps are declared before it.
    trait_order = [v for v in order if mode_of(v) == "trait"]
    struct_order = [v for v in order if mode_of(v) == "struct"]
    emit = trait_order + struct_order
    rows = [row(v) for v in emit]
    traits = len(trait_order)

    print(f"# nodes in-scope unported (non-UI, mapped): {len(nodes)}")
    print(f"# leaf-first order length:                  {len(order)}")
    print(f"# trait cut points (back-edge / interface):  {len(cut)} cuts + interfaces = {traits} trait-mode")
    print(f"# phase-1 traits: {len(trait_order)}   phase-2 structs: {len(struct_order)}")
    print(f"# root (highest fanin): {roots[0]}  (fanin {fanin.get(roots[0],0)})")
    print(f"\n# first {min(args.show, len(rows))} to port (two-phase: traits then structs):")
    print("status\tmode\tdepth\tfanin\trem\tmodule\tpath")
    for r in rows[:args.show]:
        print(r)

    if args.write:
        with open(OUT, "w", encoding="utf-8") as fh:
            fh.write("status\tmode\tdepth\tfanin\trem\tmodule\tpath\n")
            for r in rows:
                fh.write(r + "\n")
        print(f"\nwrote {len(rows)} rows to PORT_ORDER.tsv ({traits} trait, {len(rows)-traits} struct)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
