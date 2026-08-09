#!/usr/bin/env python3
"""
Per-class dependency CONTEXT for the Java->Rust port prompt.

The porting harness (descent_night.sh) feeds one Java class at a time to an LLM.
Two of the costliest iteration failures we measured are:

  (a) the model GUESSES the API of an already-ported dependency and gets it wrong,
      forcing a compile/fix cycle; and
  (b) the model HAND-WRITES a stub trait for an unported dependency, inventing a
      name/shape that doesn't match repo convention.

This script kills both by emitting, for a target Java class, a compact context
block with two sections:

  ## Reuse (already ported)       -- #6: for each in-repo dep that is DONE, the
                                     REAL Rust path + verbatim public API surface
                                     (type decl + public method signatures), so the
                                     model calls the real thing instead of guessing.

  ## Suggested stubs (unported deps) -- #3: for each in-repo dep that is TODO and
                                     in-scope, a MINIMAL, deterministically generated
                                     Rust stub `trait` (from the Java public method
                                     signatures) plus ready-to-append STUBS.tsv lines,
                                     matching the repo's seam_stubs.rs convention.

Usage:
    python3 scripts/dep_context.py <orig_src/....java>        # human text block
    python3 scripts/dep_context.py <orig_src/....java> --json # structured JSON

Only the Python stdlib is used. Reuses:
    scripts/sync_check.py   -- in-repo dependency edges + DONE flags (cached JSON)
    scripts/portlib.py      -- package -> Rust module, is-in-scope test
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
# Repo root: the script's parent by default, overridable so a git worktree that is
# missing orig_src / some src dirs (the known `.gitignore debug/` defect) can point at
# the full checkout for validation. Production runs from the real checkout and need
# not set it.
REPO = os.environ.get("GHIDRA_RS_REPO") or os.path.dirname(HERE)
RUST_SRC = os.path.join(REPO, "ghidra-rs", "src")

sys.path.insert(0, HERE)
import portlib  # noqa: E402


# --------------------------------------------------------------------------- #
# sync_check reuse (cached)                                                    #
# --------------------------------------------------------------------------- #
_SYNC_CACHE = None


def load_sync(root="orig_src", manifest="PORT_MANIFEST.tsv"):
    """Run scripts/sync_check.py --json once and cache {rel_path: record}."""
    global _SYNC_CACHE
    if _SYNC_CACHE is not None:
        return _SYNC_CACHE
    out = subprocess.run(
        [sys.executable, os.path.join(HERE, "sync_check.py"),
         "--root", root, "--manifest", manifest, "--json"],
        capture_output=True, text=True, cwd=REPO,
    ).stdout
    # sync_check prints a progress line to stderr but JSON to stdout; be defensive.
    data = json.loads(out[out.index("["):])
    _SYNC_CACHE = {d["file"]: d for d in data}
    return _SYNC_CACHE


def class_name_of(rel_path):
    """Java simple class name from a source path (file stem)."""
    return os.path.splitext(os.path.basename(rel_path))[0]


# --------------------------------------------------------------------------- #
# identifier casing helpers                                                    #
# --------------------------------------------------------------------------- #
def to_snake(name):
    """camelCase / PascalCase Java identifier -> Rust snake_case."""
    # Split runs of caps, digits, and lower; matches BTree->b_tree, getID->get_id.
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)
    s = s.replace("__", "_")
    out = s.lower()
    if out in _RUST_KEYWORDS:
        out += "_"
    return out


_RUST_KEYWORDS = {
    "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false",
    "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut",
    "pub", "ref", "return", "self", "static", "struct", "super", "trait", "true",
    "type", "unsafe", "use", "where", "while", "async", "await", "dyn", "box",
    "final", "override", "abstract", "become", "do", "macro", "priv", "typeof",
    "unsized", "virtual", "yield", "try",
}


# --------------------------------------------------------------------------- #
# Java type -> Rust type mapping                                               #
# --------------------------------------------------------------------------- #
# Primitives + boxed forms. (return/param positions handled by caller.)
_PRIMITIVE = {
    "int": "i32", "long": "i64", "short": "i16", "byte": "i8",
    "boolean": "bool", "double": "f64", "float": "f32", "char": "char",
    "void": "()",
    "Integer": "i32", "Long": "i64", "Short": "i16", "Byte": "i8",
    "Boolean": "bool", "Double": "f64", "Float": "f32", "Character": "char",
}
# Java collection generics -> Rust container templates ({0}=elem, {1}=val).
_CONTAINERS = {
    "List": "Vec<{0}>", "ArrayList": "Vec<{0}>", "LinkedList": "Vec<{0}>",
    "Collection": "Vec<{0}>", "Set": "Vec<{0}>", "HashSet": "Vec<{0}>",
    "VectorSTL": "Vec<{0}>", "Vector": "Vec<{0}>",
    "Map": "std::collections::HashMap<{0}, {1}>",
    "HashMap": "std::collections::HashMap<{0}, {1}>",
    "Optional": "Option<{0}>",
}


def _split_top_commas(s):
    """Split on commas that are not nested inside <...> or (...) or [...]."""
    parts, depth, cur = [], 0, ""
    for ch in s:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    return [p.strip() for p in parts if p.strip()]


def map_java_type(java, position="return", known=None):
    """Map a Java type string to a plausible Rust type.

    position: "return" or "param" -- affects String (&str vs String), arrays
              (&[T] vs Vec<T>) and unknown in-repo types (&dyn T vs Box<dyn T>).
    known:    optional set of in-repo class names (used only for annotation).
    Returns a Rust type string.
    """
    t = java.strip().replace("final ", "").strip()
    if not t:
        return "()"

    # Java wildcards: `? extends Foo` / `? super Foo` -> the bound; bare `?` -> Any.
    wm = re.match(r"\?\s*(?:extends|super)\s+(.+)$", t)
    if wm:
        return map_java_type(wm.group(1), position, known)
    if t == "?":
        return ("&dyn std::any::Any" if position == "param"
                else "Box<dyn std::any::Any>")

    # Varargs / arrays -> slice (param) or Vec (return).
    m = re.match(r"(.+?)\s*(\.\.\.|(?:\[\s*\])+)\s*$", t)
    if m:
        elem = map_java_type(m.group(1), "elem", known)
        return f"&[{elem}]" if position == "param" else f"Vec<{elem}>"

    # Generic container: Name<args>
    gm = re.match(r"([A-Za-z_][\w.]*)\s*<(.+)>\s*$", t)
    if gm:
        base = gm.group(1).split(".")[-1]
        args = _split_top_commas(gm.group(2))
        rust_args = [map_java_type(a, "elem", known) for a in args]
        tmpl = _CONTAINERS.get(base)
        if tmpl:
            while len(rust_args) < 2:
                rust_args.append("()")
            return tmpl.format(*rust_args)
        # Unknown generic in-repo type: fall back to a trait object of the base.
        return _unknown_type(base, position)

    base = t.split(".")[-1]
    if base in _PRIMITIVE:
        return _PRIMITIVE[base]
    if base in ("String", "CharSequence"):
        return "&str" if position == "param" else "String"
    if base == "Object":
        return "&dyn std::any::Any" if position == "param" else "Box<dyn std::any::Any>"
    # Anything else is treated as an (unported) in-repo reference type.
    return _unknown_type(base, position)


def _unknown_type(base, position):
    """Trait-object mapping for an unknown/in-repo type, per repo seam convention."""
    if not re.fullmatch(r"[A-Za-z_]\w*", base):
        base = "std::any::Any"          # not a bare identifier -> fall back to Any
    if position in ("return", "elem"):
        return f"Box<dyn {base}>"
    return f"&dyn {base}"


# --------------------------------------------------------------------------- #
# Java public-method parser (targeted, not a full grammar)                     #
# --------------------------------------------------------------------------- #
def strip_java_comments(src):
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    src = re.sub(r"//[^\n]*", "", src)
    return src


def java_primary_type(src):
    """Return (name, is_interface) for the file's primary declared type."""
    m = re.search(r"\b(?:public\s+|abstract\s+|final\s+|sealed\s+|strictfp\s+)*"
                  r"(interface|class|enum|record)\s+(\w+)", src)
    if not m:
        return None, False
    return m.group(2), m.group(1) == "interface"


_MOD = r"(?:static|final|abstract|synchronized|native|default|strictfp|protected|public)"
_SIG_RE = re.compile(
    r"\bpublic\b"                                   # visibility
    r"(?P<mods>(?:\s+" + _MOD + r")*)"              # other modifiers, any order-ish
    r"\s+(?P<sig>[^;{}()=]*?)"                      # generic-decl + return type + name
    r"\(\s*(?P<params>[^)]*)\)"                     # (params)  -- no nested parens
    r"(?P<throws>[^;{]*)"                           # optional throws clause
    r"\s*[;{]",                                     # abstract ';' or body '{'
    re.S,
)


def parse_java_public_methods(src, class_name):
    """Extract public (non-constructor) methods as structured dicts.

    Returns list of {name, ret, params:[(type,name)], throws:bool, raw}.
    Constructors (return type == class name / empty) are skipped.
    """
    src = strip_java_comments(src)
    methods = []
    seen = set()
    for m in _SIG_RE.finditer(src):
        sig = m.group("sig").strip()
        # drop a leading method-level generic declaration: <T> / <T extends X>
        sig = re.sub(r"^\s*<[^<>]*(?:<[^<>]*>[^<>]*)*>\s*", "", sig)
        nm = re.search(r"(\w+)\s*$", sig)
        if not nm:
            continue
        name = nm.group(1)
        ret = sig[:nm.start()].strip()
        if not ret:
            continue                     # constructor (no return type)
        if name == class_name:
            continue                     # defensive: constructor
        params = []
        for p in _split_top_commas(m.group("params")):
            p = re.sub(r"@\w+(\([^)]*\))?\s*", "", p).strip()  # drop annotations
            pm = re.search(r"(\w+)\s*$", p)
            if not pm:
                continue
            pname = pm.group(1)
            ptype = p[:pm.start()].strip()
            if not ptype:                 # single-token param -> it was the type
                ptype, pname = pm.group(1), ""
            params.append((ptype, pname))
        throws = "throws" in m.group("throws")
        # Collapse Java overloads by NAME: Rust traits can't have two methods with the
        # same name, so keep the first occurrence (most stubs only need the shape hint).
        if name in seen:
            continue
        seen.add(name)
        methods.append({"name": name, "ret": ret, "params": params,
                        "throws": throws, "raw": m.group(0).strip()})
    return methods


def render_stub_method(meth, referenced):
    """Render one Java method dict as a Rust trait method signature line."""
    args = ["&self"]
    for i, (ptype, pname) in enumerate(meth["params"]):
        rname = to_snake(pname) if pname else f"arg{i}"
        rty = map_java_type(ptype, "param")
        args.append(f"{rname}: {rty}")
    ret = map_java_type(meth["ret"], "return")
    if meth["throws"]:
        inner = "()" if ret == "()" else ret
        ret = f"std::io::Result<{inner}>"
    ret_s = "" if ret == "()" else f" -> {ret}"
    tag = "  // [referenced in target]" if meth["name"] in referenced else ""
    return f"    fn {to_snake(meth['name'])}({', '.join(args)}){ret_s};{tag}"


def build_stub_trait(dep_class, target_class, methods, referenced, restricted):
    """Assemble the Rust stub-trait text for one unported dep."""
    lines = [
        f"/// Placeholder for the unported Java type `{dep_class}`, referenced by "
        f"`{target_class}`.",
        f"/// Generated stub: only a shape hint. Receivers default to `&self` (some may need "
        f"`&mut self`);",
        f"/// unknown in-repo types map to trait objects. Replace with the real port when "
        f"available.",
        f"pub trait {dep_class}: Send + Sync {{",
    ]
    if not methods:
        lines.append("    // (no public methods parsed from the Java source)")
    for meth in methods:
        lines.append(render_stub_method(meth, referenced))
    lines.append("}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Rust public-API skimmer (for already-ported deps)                           #
# --------------------------------------------------------------------------- #
_DECL_INDEX = None
_DECL_INDEX_NORM = None


def _norm_key(name):
    """Case/underscore-insensitive key so VectorSTL~VectorStl, symbol_type~SymbolType."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


def rust_decl_index():
    """Map every declared type name -> [(rel_file, kind)] across ghidra-rs/src.

    Built once via a single grep for speed. Also builds a normalized-key index so a
    Java class name that was cased/underscored differently in Rust still resolves.
    """
    global _DECL_INDEX, _DECL_INDEX_NORM
    if _DECL_INDEX is not None:
        return _DECL_INDEX
    idx = {}
    norm = {}
    out = subprocess.run(
        ["grep", "-rnE",
         r"^[[:space:]]*(pub[[:space:]]+)?(struct|trait|enum|type)[[:space:]]+[A-Za-z_][A-Za-z0-9_]*",
         RUST_SRC, "--include=*.rs"],
        capture_output=True, text=True,
    ).stdout
    pat = re.compile(r"^(.*?):(\d+):\s*(?:pub\s+(?:\([^)]*\)\s+)?)?(struct|trait|enum|type)\s+(\w+)")
    for line in out.splitlines():
        m = pat.match(line)
        if not m:
            continue
        path, _ln, kind, name = m.groups()
        idx.setdefault(name, []).append((path, kind, name))
        norm.setdefault(_norm_key(name), []).append((path, kind, name))
    _DECL_INDEX = idx
    _DECL_INDEX_NORM = norm
    return idx


def _module_hint(rel_java):
    """Rust module a Java class should live in (or None)."""
    return portlib.module_for(portlib.package_of(rel_java))


def _rust_path_to_use(abs_path):
    """Turn ghidra-rs/src/a/b/c.rs into a crate::a::b::c path prefix (best-effort)."""
    rel = os.path.relpath(abs_path, RUST_SRC).replace(os.sep, "/")
    rel = re.sub(r"\.rs$", "", rel)
    parts = [p for p in rel.split("/") if p != "mod"]
    return "crate::" + "::".join(parts)


def _match_paren(text, open_idx):
    """Return index just past the matching ')' for the '(' at open_idx."""
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i + 1
    return len(text)


def _match_brace(text, open_idx):
    """Return index just past the matching '}' for the '{' at open_idx."""
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    return len(text)


def _extract_fn_sig(text, fn_idx):
    """Verbatim Rust fn signature starting at fn_idx, terminated with ';'."""
    paren = text.find("(", fn_idx)
    if paren < 0:
        return None
    end = _match_paren(text, paren)
    # capture return type / where-clause up to the body '{' or a ';'
    depth = 0
    i = end
    while i < len(text):
        c = text[i]
        if c in "<([":
            depth += 1
        elif c in ">)]":
            depth = max(0, depth - 1)
        elif depth == 0 and c in "{;":
            break
        i += 1
    sig = (text[fn_idx:i]).strip()
    sig = re.sub(r"\s+", " ", sig)
    return sig + ";"


def choose_rust_file(dep_class, rel_java):
    """Pick the best Rust file declaring dep_class.

    Returns (abs_path, rust_name) -- rust_name may differ in casing from dep_class
    (found via the normalized fallback). Prefers a decl in the mapped module.
    """
    idx = rust_decl_index()
    hits = idx.get(dep_class)
    if not hits:
        # normalized fallback: VectorSTL->VectorStl, symbol_type->SymbolType, etc.
        hits = _DECL_INDEX_NORM.get(_norm_key(dep_class))
    if not hits:
        return None, None
    mod = _module_hint(rel_java)
    if mod:
        pref = [h for h in hits if f"/src/{mod}/" in h[0].replace(os.sep, "/")]
        if pref:
            return pref[0][0], pref[0][2]
    return hits[0][0], hits[0][2]


def skim_rust_api(abs_path, name):
    """Return (kind, decl_header, [signature_lines]) for `name` from a Rust file."""
    try:
        text = open(abs_path, encoding="utf-8", errors="ignore").read()
    except OSError:
        return None, None, []

    # Locate the declaration of `name`.
    decl = re.search(
        r"(pub\s+(?:\([^)]*\)\s+)?)?(struct|trait|enum|type)\s+" + re.escape(name) + r"\b",
        text,
    )
    if not decl:
        return None, None, []
    kind = decl.group(2)
    line_start = text.rfind("\n", 0, decl.start()) + 1
    # header = from line start to the first '{' or ';'
    hdr_end = len(text)
    for term in ("{", ";"):
        p = text.find(term, decl.start())
        if p >= 0:
            hdr_end = min(hdr_end, p)
    header = re.sub(r"\s+", " ", text[line_start:hdr_end].strip())

    sigs = []
    if kind == "trait":
        brace = text.find("{", decl.start())
        if brace >= 0:
            body_end = _match_brace(text, brace)
            body = text[brace:body_end]
            for m in re.finditer(r"\bfn\s+\w+", body):
                sig = _extract_fn_sig(body, m.start())
                if sig:
                    sigs.append(sig)
    else:
        # inherent impl blocks: `impl Name` / `impl<...> Name` (not `impl Trait for`)
        for im in re.finditer(r"\bimpl\b(?:\s*<[^>]*>)?\s+" + re.escape(name) + r"\b", text):
            after = text[im.end():im.end() + 40]
            if re.match(r"\s*(<[^>]*>\s*)?for\b", after):
                continue  # this is `impl Name<..> for X` -- skip trait impls
            brace = text.find("{", im.start())
            if brace < 0:
                continue
            body_end = _match_brace(text, brace)
            body = text[brace:body_end]
            for m in re.finditer(r"\bpub\s+(?:async\s+)?fn\s+\w+", body):
                sig = _extract_fn_sig(body, m.start())
                if sig:
                    sigs.append(sig)
    return kind, header, sigs


# --------------------------------------------------------------------------- #
# Orchestration                                                               #
# --------------------------------------------------------------------------- #
def build_context(target_rel):
    sync = load_sync()
    if target_rel not in sync:
        # tolerate a bare/partial path
        matches = [k for k in sync if k.endswith(target_rel)]
        if len(matches) == 1:
            target_rel = matches[0]
        elif len(matches) > 1:
            raise SystemExit(f"ambiguous target; matches: {matches[:5]}")
        else:
            raise SystemExit(f"target not found in sync graph: {target_rel}")

    rec = sync[target_rel]
    target_class = class_name_of(target_rel)

    try:
        target_src = open(os.path.join(REPO, "orig_src", target_rel),
                          encoding="utf-8", errors="ignore").read()
    except OSError:
        target_src = ""
    referenced = set(re.findall(r"\b(\w+)\s*\(", strip_java_comments(target_src)))

    reuse, stubs = [], []
    for dep in sorted(rec["dependencies"]):
        drec = sync.get(dep, {})
        dep_class = class_name_of(dep)
        if drec.get("done"):
            abs_path, rust_name = choose_rust_file(dep_class, dep)
            entry = {"dep_class": dep_class, "java": dep}
            if abs_path:
                kind, header, sigs = skim_rust_api(abs_path, rust_name)
                entry.update({
                    "rust_path": _rust_path_to_use(abs_path),
                    "rust_file": os.path.relpath(abs_path, REPO),
                    "rust_name": rust_name,
                    "kind": kind, "header": header, "signatures": sigs,
                })
            else:
                entry.update({"rust_path": None, "note": "Rust decl not located by grep"})
            reuse.append(entry)
        else:
            mod = _module_hint(dep)
            if not mod:
                continue  # out of scope: model will (correctly) park; nothing to stub
            try:
                dep_src = open(os.path.join(REPO, "orig_src", dep),
                              encoding="utf-8", errors="ignore").read()
            except OSError:
                dep_src = ""
            methods = parse_java_public_methods(dep_src, dep_class)
            code = build_stub_trait(dep_class, target_class, methods, referenced, False)
            stubs.append({
                "dep_class": dep_class, "java": dep, "module": mod,
                "method_count": len(methods), "code": code,
                "stubs_tsv": f"{datetime.now(timezone.utc).isoformat()}\t{dep_class}\t{target_class}",
            })

    return {"target": target_rel, "target_class": target_class,
            "reuse": reuse, "stubs": stubs}


def render_text(ctx):
    out = []
    out.append(f"# Dependency context for {ctx['target_class']}  ({ctx['target']})")
    out.append("")
    out.append("## Reuse (already ported)")
    out.append("These deps are already ported. Call these REAL types/paths; do NOT redefine "
               "them and do NOT guess their API.")
    out.append("")
    if not ctx["reuse"]:
        out.append("_(none)_")
    for e in ctx["reuse"]:
        if not e.get("rust_path"):
            out.append(f"- `{e['dep_class']}` ({e['java']}): {e.get('note', 'not located')}")
            continue
        out.append(f"### {e['dep_class']}  ->  {e['rust_path']}")
        out.append(f"<!-- {e['rust_file']} -->")
        out.append("```rust")
        if e.get("header"):
            out.append(e["header"] + (" { ... }" if e["kind"] != "type" else ""))
        for s in e.get("signatures", []):
            out.append("    " + s)
        if not e.get("signatures"):
            out.append("    // (no public methods extracted)")
        out.append("```")
        out.append("")
    out.append("## Suggested stubs (unported deps)")
    out.append("These in-scope deps are NOT ported yet. If you need them, write these stub "
               "traits into `ghidra-rs/src/<module>/seam_stubs.rs` (do not invent your own) "
               "and append the STUBS.tsv line. Signatures are the FULL public surface (could "
               "not cheaply restrict to only-referenced); methods used by the target are "
               "tagged `[referenced in target]`.")
    out.append("")
    if not ctx["stubs"]:
        out.append("_(none)_")
    for s in ctx["stubs"]:
        out.append(f"### {s['dep_class']}  (module: {s['module']}, {s['method_count']} methods)")
        out.append(f"<!-- from {s['java']} -->")
        out.append("```rust")
        out.append(s["code"])
        out.append("```")
        out.append(f"STUBS.tsv: `{s['stubs_tsv']}`")
        out.append("")
    out.extend(render_dyn_guidance(ctx))
    return "\n".join(out)


def render_dyn_guidance(ctx):
    """Per-dependency: is a trait object warranted for this type, or not?

    Ownership guidance in the prompt has been generic ("don't reach for dyn by default"),
    which is advice without evidence and loses to the concrete pressure of writing a
    signature. This answers the question per referenced type, from that type's own Java
    hierarchy: `dyn DataType` is right (192 concrete implementers), `dyn Trace` is not
    (one, DBTrace). Measured across the crate, 30.6% of non-std `dyn` mentions are on
    types with at most one concrete implementation or on Java classes that never had an
    interface at all.
    """
    try:
        import dyn_rules
        import shape_rules
    except ImportError:
        return []
    names = [e["dep_class"] for e in ctx["reuse"]] + [s["dep_class"] for s in ctx["stubs"]]
    if not names:
        return []
    # Precomputed table, so this costs milliseconds inside the nightly loop rather than the
    # ~14s a full index walk takes. Absent table = stay silent rather than pay it per port.
    table = shape_rules.load_implementers()
    if not table:
        return []
    avoid, fine = [], []
    for name in dict.fromkeys(names):
        pat, n, kind = dyn_rules.classify_from_table(name, table)
        if pat == "PA":
            avoid.append(f"- `{name}`: a Java annotation type. It is metadata, not a runtime "
                         f"type -- do not model it as a Rust type at all.")
        elif pat == "P1":
            avoid.append(f"- `{name}`: Java is a {kind}, not an interface. Use the concrete type.")
        elif pat == "P2":
            impls = table[name]["concrete_implementers"]
            who = f"`{impls[0]}`" if impls else "its single implementation"
            avoid.append(f"- `{name}`: interface whose only concrete implementation is "
                         f"{who}. Use that type.")
        elif pat in ("P4", "P5"):
            fine.append(f"- `{name}`: {n} concrete implementations")
    if not avoid and not fine:
        return []
    out = ["## Trait objects: where `dyn` is and is not warranted",
           "Decided from each type's Java hierarchy (concrete implementers, transitively, "
           "excluding abstract bases and test doubles) -- NOT from the Rust tree.", ""]
    if avoid:
        out.append("**Do NOT write `Box<dyn T>` / `Arc<dyn T>` / `&dyn T` for these.** There is "
                   "nothing to dispatch over; a trait object here costs a vtable and an "
                   "allocation to model a choice that does not exist:")
        out.extend(avoid)
        out.append("")
    if fine:
        out.append("These are genuinely polymorphic -- `dyn` is the right tool:")
        out.extend(fine)
        out.append("")
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="orig_src/....java path of the class about to be ported")
    ap.add_argument("--json", action="store_true", help="structured JSON output")
    args = ap.parse_args(argv)

    ctx = build_context(args.target)
    if args.json:
        print(json.dumps(ctx, indent=2))
    else:
        print(render_text(ctx))
    return 0


if __name__ == "__main__":
    sys.exit(main())
