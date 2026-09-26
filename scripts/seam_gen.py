#!/usr/bin/env python3
"""
Refill SEAM.tsv with the next batch of seam targets.

The seam campaign (seam_night.sh) breaks the keystone SCC by porting the highest-
leverage core Java interfaces/classes to Rust TRAITS. SEAM.tsv is a finite worklist;
when it drains (all rows DONE) the 19:00 cron no-ops. This regenerates the next batch.

Selection (mirrors dep_stats.py so the two agree on scope/SCC/UI):
  * frontier from sync_check.py --json (done flag + dependency edges)
  * in-scope only            -- portlib.module_for(package) is not None
  * unported only            -- not done
  * keystone-SCC members only -- the cyclic cluster the seam pass exists to break
  * non-UI only              -- Swing/AWT/docking types aren't trait seams
  * skip paths already in SEAM.tsv (any status)
  * rank by FANIN (reverse-dependency count) desc -- most leverage first

Emits SEAM.tsv rows: status<TAB>kind<TAB>fanin<TAB>rem<TAB>module<TAB>path
  kind  = interface|class  (detected from the source declaration)
  fanin = how many files depend on this type (leverage)
  rem   = remaining unported direct deps (informational; seam is stub-tolerant)

Usage:
  python3 scripts/seam_gen.py                 # preview top 20 (dry run, no write)
  python3 scripts/seam_gen.py -n 150          # preview top 150
  python3 scripts/seam_gen.py -n 150 --write  # append 150 TODO rows to SEAM.tsv
"""
import argparse, json, os, re, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__)); REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE); import portlib

SEAM = os.path.join(REPO, "SEAM.tsv")


def load_frontier():
    raw = subprocess.run(
        [sys.executable, os.path.join(HERE, "sync_check.py"), "--root", "orig_src",
         "--manifest", "PORT_MANIFEST.tsv", "--json"],
        capture_output=True, text=True, cwd=REPO).stdout
    return json.loads(raw[raw.index("["):])


_ui_cache = {}
def is_ui(rel):
    if rel in _ui_cache:
        return _ui_cache[rel]
    try:
        s = open(os.path.join(REPO, "orig_src", rel), encoding="utf-8", errors="ignore").read(4000)
    except OSError:
        s = ""
    r = bool(re.search(r"import\s+(javax\.swing|java\.awt)", s)
             or re.search(r"/(gui|widgets)/|docking/", rel)
             or re.search(r"\b(extends|implements)\s+[A-Za-z0-9_.]*(J[A-Z]\w*|Renderer|CellEditor|Icon|GComponent|GTable|GTree)", s))
    _ui_cache[rel] = r
    return r


def kind_of(rel):
    """interface|class from the primary type declaration."""
    try:
        s = open(os.path.join(REPO, "orig_src", rel), encoding="utf-8", errors="ignore").read(8000)
    except OSError:
        return "class"
    # strip block/line comments cheaply to avoid matching commented decls
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.S)
    s = re.sub(r"//[^\n]*", "", s)
    m = re.search(r"\b(public|abstract|final|sealed|strictfp|\s)*\b(interface|class|enum|record)\b", s)
    if m and m.group(2) == "interface":
        return "interface"
    return "class"


def keystone_scc(data, by):
    """Return the set of files in the largest cyclic cluster of unported in-scope nodes."""
    nodes = [d["file"] for d in data
             if not d["done"] and portlib.module_for(portlib.package_of(d["file"]))]
    nset = set(nodes)
    adj = {u: [v for v in by[u]["dependencies"] if v in nset] for u in nodes}
    idx = {}; low = {}; on = {}; stk = []; cnt = [0]
    biggest = set()
    def sc(root):
        wk = [(root, 0)]
        while wk:
            v, pi = wk[-1]
            if pi == 0:
                idx[v] = low[v] = cnt[0]; cnt[0] += 1; stk.append(v); on[v] = True
            rec = False
            for i in range(pi, len(adj[v])):
                w = adj[v][i]
                if w not in idx:
                    wk[-1] = (v, i + 1); wk.append((w, 0)); rec = True; break
                elif on.get(w):
                    low[v] = min(low[v], idx[w])
            if rec:
                continue
            for w in adj[v]:
                if w in low and on.get(w):
                    low[v] = min(low[v], low[w])
            if low[v] == idx[v]:
                comp = []
                while True:
                    w = stk.pop(); on[w] = False; comp.append(w)
                    if w == v:
                        break
                nonlocal biggest
                if len(comp) > len(biggest):
                    biggest = set(comp)
            wk.pop()
    for v in nodes:
        if v not in idx:
            sc(v)
    return biggest


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", "--count", type=int, default=20, help="number of targets (default 20)")
    ap.add_argument("--write", action="store_true", help="append rows to SEAM.tsv (default: dry-run preview)")
    args = ap.parse_args()

    data = load_frontier()
    by = {d["file"]: d for d in data}

    # fanin = reverse-dependency count across the WHOLE graph (leverage measure)
    fanin = {}
    for d in data:
        for dep in d["dependencies"]:
            fanin[dep] = fanin.get(dep, 0) + 1

    scc = keystone_scc(data, by)
    existing = set()
    if os.path.exists(SEAM):
        for i, l in enumerate(open(SEAM, encoding="utf-8")):
            if i == 0:
                continue
            c = l.rstrip("\n").split("\t")
            if len(c) >= 6:
                existing.add(c[5])

    cands = []
    for d in data:
        f = d["file"]
        if d["done"] or f in existing or f not in scc:
            continue
        mod = portlib.module_for(portlib.package_of(f))
        if not mod or is_ui(f):
            continue
        cands.append((fanin.get(f, 0), d["remaining_dep_count"], mod, f))
    cands.sort(key=lambda t: (-t[0], t[1], t[3]))
    picks = cands[:args.count]

    rows = [f"{'TODO'}\t{kind_of(f)}\t{fi}\t{rem}\t{mod}\t{f}" for fi, rem, mod, f in picks]

    if not args.write:
        print(f"# dry-run: {len(cands)} eligible seam candidates in SCC; showing top {len(picks)}")
        print("status\tkind\tfanin\trem\tmodule\tpath")
        print("\n".join(rows))
        print(f"\n# re-run with --write to append these {len(picks)} rows to SEAM.tsv", file=sys.stderr)
        return 0

    need_header = not os.path.exists(SEAM) or os.path.getsize(SEAM) == 0
    with open(SEAM, "a", encoding="utf-8") as fh:
        if need_header:
            fh.write("status\tkind\tfanin\trem\tmodule\tpath\n")
        for r in rows:
            fh.write(r + "\n")
    print(f"appended {len(rows)} TODO rows to SEAM.tsv "
          f"(interfaces={sum(1 for r in rows if r.split(chr(9))[1]=='interface')}, "
          f"classes={sum(1 for r in rows if r.split(chr(9))[1]=='class')})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
