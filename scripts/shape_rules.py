#!/usr/bin/env python3
"""Decide the Rust SHAPE a Java source file should port to, from the Java source.

Why this exists
---------------
`desc_order.py` emits a binary `mode` column: `trait` if the class is a DFS back-edge
cut-point or a Java `interface`, else `struct`. Java has more than two shapes, so that
column has been wrong in bulk:

  * 133 queued Java `enum`s and 121 `record`s were told "map the class to a Rust struct
    with an impl block";
  * 405 queued Java classes/records/enums were told to become traits because they sat on
    a dependency cycle;
  * `Lifespan` -- `public sealed interface Lifespan`, a closed set over a long range --
    became `pub trait Lifespan`, and the crate now carries 613 `dyn Lifespan` uses.

A cycle cut-point is a statement about the dependency graph, not about the type. This
module answers the type question separately, from `orig_src` only -- never from the Rust
tree, which measures how far the port got rather than how code should be shaped
(AGENTS.md, "Diagnosing the Port").

Shapes
------
  enum         Rust `enum` + `match`. Closed set of alternatives.
  struct       Rust `struct` + `impl`.
  module       Module of `pub const` items / free `pub fn`s and NO type of that name.
  trait        Rust `trait`. Genuine open extension point.
  struct_trait Shared-state `struct` + `trait` for the abstract operations.
  error        `struct`/`enum` implementing `std::error::Error` + `Display`.
  iterator     A type implementing `std::iter::Iterator`.
  park         Cannot be decided mechanically -- stop and ask.

Usage
-----
  shape_rules.py index [--out SHAPES.tsv]      build/refresh the shape table
  shape_rules.py classify <rel-java-path>      one file, JSON to stdout
  shape_rules.py directive <rel-java-path>     prompt block for the porting harness
  shape_rules.py audit [--out SHAPE_DEBT.tsv]  shipped Rust decls vs. the rules
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
ORIG = os.path.join(REPO, "orig_src")
SHAPES = os.path.join(REPO, "SHAPES.tsv")

# ---------------------------------------------------------------------------
# Java surface parsing
#
# This is a scanner, not a parser. It only has to be right about the *primary*
# declaration in a file (the type whose name matches the file stem), which Java
# guarantees is public and top-level. Everything nested is deliberately ignored.
# ---------------------------------------------------------------------------

_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_LINE_COMMENT = re.compile(r"//[^\n]*")
_STRING = re.compile(r'"(?:\\.|[^"\\])*"')
_CHAR = re.compile(r"'(?:\\.|[^'\\])'")

MODS = r"(?:public|protected|private|abstract|final|static|sealed|non-sealed|strictfp|@\w+(?:\([^)]*\))?|\s)*"

THROWABLE_SUFFIXES = ("Exception", "Error", "Throwable")

# Java cursor supertypes: the type IS a position in a sequence. Porting these literally is
# what produced the `while it.has_next() { push(it.next()) }` double-consume bug in AGENTS.md.
CURSOR_SUPERS = {"Iterator", "ListIterator", "Enumeration"}

# `Iterable` is NOT a cursor -- it means "you can iterate me", which any collection says. A
# rich interface that happens to be Iterable is still that interface: `AddressSetView` extends
# `Iterable<AddressRange>` and declares 28 other abstract methods, and 833 `dyn AddressSetView`
# uses hang off it. Treating it as a cursor would have been a far worse instruction than the
# one it replaced. Only an Iterable with essentially no other API is really a sequence.
ITERABLE_SUPERS = {"Iterable", "Collection"}
ITERABLE_API_CUTOFF = 1


def strip_java(src: str) -> str:
    """Remove comments and literal contents so brace/keyword scanning is safe."""
    src = _BLOCK_COMMENT.sub(" ", src)
    src = _LINE_COMMENT.sub(" ", src)
    src = _STRING.sub('""', src)
    src = _CHAR.sub("' '", src)
    return src


def find_primary(src: str, name: str):
    """Locate the top-level declaration named `name`. Returns (kind, mods, header_end)."""
    # `@interface` must be tried before `interface`, and `interface` must be forbidden from
    # matching the tail of `@interface`. There is a word boundary between `@` and `i`, so a
    # bare `\b(interface)` happily matches inside `@interface Foo` with empty modifiers --
    # which classified all 39 annotation types in the tree as plain interfaces and meant
    # rule R4 never once fired.
    pat = re.compile(
        r"(?P<mods>" + MODS + r")"
        r"(?P<kind>@interface\b|(?<!@)\b(?:class|interface|enum|record)\b)\s+"
        + re.escape(name)
        + r"\b"
    )
    for m in pat.finditer(src):
        # Reject matches nested inside another type body by checking brace depth.
        if src.count("{", 0, m.start()) == src.count("}", 0, m.start()):
            return m.group("kind"), m.group("mods") or "", m.end()
    return None, "", -1


def header_and_body(src: str, start: int):
    """Split the declaration header (up to `{`) from its brace-matched body."""
    open_at = src.find("{", start)
    if open_at < 0:
        return src[start:].strip(), ""
    header = src[start:open_at]
    depth, i = 0, open_at
    while i < len(src):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return header, src[open_at + 1 : i]
        i += 1
    return header, src[open_at + 1 :]


def split_types(clause: str):
    """Split an extends/implements clause on top-level commas (generics-aware)."""
    out, depth, cur = [], 0, ""
    for ch in clause:
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return [re.sub(r"<.*", "", t).strip().split(".")[-1] for t in out if t.strip()]


def strip_type_params(header: str) -> str:
    """Drop the generic parameter list a declaration header opens with.

    `class AbstractAssemblyGrammar<NT extends AssemblyNonTerminal, P extends ...>` puts an
    `extends` INSIDE the type parameters, and a regex looking for the first `extends` in the
    header reads the bound as a supertype. That invented an edge saying AssemblyGrammar
    implements AssemblyNonTerminal -- a grammar is not a non-terminal -- and 354 Java files
    declare a bounded type parameter, so it inflated implementer counts across the tree.
    """
    i = 0
    while i < len(header) and header[i].isspace():
        i += 1
    if i >= len(header) or header[i] != "<":
        return header
    depth = 0
    while i < len(header):
        if header[i] == "<":
            depth += 1
        elif header[i] == ">":
            depth -= 1
            if depth == 0:
                return header[i + 1:]
        i += 1
    return header  # unbalanced -- leave it alone rather than truncate


def parse_header(header: str):
    """Pull extends / implements / permits lists out of a declaration header."""
    header = strip_type_params(header)
    ext = re.search(r"\bextends\b(.*?)(?=\bimplements\b|\bpermits\b|$)", header, re.S)
    imp = re.search(r"\bimplements\b(.*?)(?=\bpermits\b|$)", header, re.S)
    per = re.search(r"\bpermits\b(.*)$", header, re.S)
    return (
        split_types(ext.group(1)) if ext else [],
        split_types(imp.group(1)) if imp else [],
        split_types(per.group(1)) if per else [],
    )


def enum_constants(body: str):
    """Enum constant names, and whether any constant carries a class body."""
    head = body.split(";", 1)[0] if ";" in body else body
    consts, depth, cur = [], 0, ""
    for ch in head:
        if ch in "({<":
            depth += 1
        elif ch in ")}>":
            depth -= 1
        if ch == "," and depth == 0:
            consts.append(cur)
            cur = ""
        else:
            cur += ch
    consts.append(cur)
    names, bodies = [], False
    for c in consts:
        m = re.match(r"\s*(?:@\w+\s*)*([A-Z_][A-Za-z0-9_]*)", c)
        if m:
            names.append(m.group(1))
            if "{" in c:
                bodies = True
    return names, bodies


def _top_level_members(body: str):
    """Yield member declarations at brace depth 0 of a type body."""
    depth, cur = 0, ""
    for ch in body:
        if ch == "{":
            depth += 1
            if depth == 1:
                # Method/initialiser body -- emit the signature, skip the body.
                yield cur
                cur = ""
                continue
        elif ch == "}":
            depth -= 1
            continue
        if depth == 0:
            if ch == ";":
                yield cur
                cur = ""
            else:
                cur += ch
    if cur.strip():
        yield cur


def analyse_body(kind: str, body: str, name: str):
    """Count the members that decide a shape."""
    static_fields = instance_fields = 0
    abstract_methods = concrete_methods = static_methods = 0
    private_ctor = public_ctor = False
    has_instance_singleton = False

    for decl in _top_level_members(body):
        d = decl.strip()
        if not d or d.startswith("@") and "\n" not in d and "(" not in d:
            continue
        is_static = re.search(r"\bstatic\b", d) is not None
        is_abstract = re.search(r"\babstract\b", d) is not None
        # A constructor: the type's own name opening the declaration, after modifiers
        # only. Anchoring matters -- an unanchored search also matches the `new
        # Registry()` inside `static final Registry INSTANCE = new Registry()`, which
        # read the singleton's field as a public constructor and hid rule R13.
        ctor = re.match(
            r"\s*(?:(?:public|protected|private|static|final|abstract|synchronized"
            r"|native|@\w+(?:\([^)]*\))?|<[^<>]*>)\s+)*" + re.escape(name) + r"\s*\(",
            d,
        )
        if ctor and not re.search(r"\b(class|interface|enum|record)\b", d):
            if re.search(r"\bprivate\b", d):
                private_ctor = True
            else:
                public_ctor = True
            continue
        # A `=` ahead of any `(` means an initialised field, not a method -- otherwise
        # `static final Registry INSTANCE = new Registry()` reads as a method signature
        # (it does end in `)`) and the singleton rule never fires.
        eq, par = d.find("="), d.find("(")
        initialised_field = eq >= 0 and (par < 0 or eq < par)
        if not initialised_field and "(" in d and re.search(r"\)\s*(throws[\w\s,.]*)?$", d):
            # Method signature.
            if is_static:
                static_methods += 1
            elif is_abstract or (kind == "interface" and not re.search(r"\bdefault\b", d)):
                abstract_methods += 1
            else:
                concrete_methods += 1
            continue
        if initialised_field or re.search(r"[\w\]>]\s+\w+\s*(=|$)", d):
            # Interface fields are implicitly public static final; the keyword is almost
            # never written, so trusting `is_static` here counts every interface constant
            # as instance state and hides R8a behind R8b.
            if is_static or kind == "interface":
                static_fields += 1
                if re.search(r"\b(INSTANCE|DEFAULT)\b", d) and re.search(r"\bfinal\b", d):
                    has_instance_singleton = True
            else:
                instance_fields += 1

    return dict(
        static_fields=static_fields,
        instance_fields=instance_fields,
        abstract_methods=abstract_methods,
        concrete_methods=concrete_methods,
        static_methods=static_methods,
        private_ctor=private_ctor,
        public_ctor=public_ctor,
        singleton=private_ctor and has_instance_singleton,
    )


def parse_file(path: str, name: str):
    """Parse one Java file into the facts the rules consume. None if unparseable."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    except OSError:
        return None
    src = strip_java(raw)
    kind, mods, end = find_primary(src, name)
    if kind is None:
        return None
    header, body = header_and_body(src, end)
    extends, implements, permits = parse_header(header)
    facts = dict(
        name=name,
        kind=kind,
        sealed="sealed" in mods and "non-sealed" not in mods,
        abstract="abstract" in mods,
        final=re.search(r"\bfinal\b", mods) is not None,
        extends=extends,
        implements=implements,
        permits=permits,
        annotations=re.findall(r"@(\w+)", mods),
    )
    if kind == "enum":
        consts, bodies = enum_constants(body)
        facts["enum_constants"] = consts
        facts["enum_constant_bodies"] = bodies
    facts.update(analyse_body(kind, body, name))
    return facts


# ---------------------------------------------------------------------------
# Subtype index -- "how many things extend/implement this?", answered from
# orig_src. Counting implementers in the Rust tree is the mistake AGENTS.md
# documents four times over; orig_src is the authority.
# ---------------------------------------------------------------------------


# Ghidra is a plugin architecture and says so in the type system: an extension point reaches
# one of these in its supertype closure. Those are the interfaces where runtime polymorphism
# over unknown implementers is the actual requirement.
EXTENSION_POINT_ROOTS = {
    "ExtensionPoint", "Service", "Plugin", "Analyzer", "Loader", "Exporter", "FileSystem",
}

# Names that mark a test double rather than a real alternative representation. Counting
# `StubProgram` as an implementation of `Program` is what makes a single-implementation
# interface look like a closed set of two -- AGENTS.md records the same mistake being made
# from the Rust side ("Are the only implementers test doubles? Then you are looking at an
# unfinished port"). Deliberately does NOT include `*Adapter`: in this codebase that suffix
# usually marks a real implementation (`BufferFileAdapter`), not a double.
_DOUBLE_RE = re.compile(r"^(Stub|Mock|Dummy|Fake|TestDouble|TestDummy)|(Stub|Mock|Dummy|Fake)$")


_PLACEHOLDER_FQN = re.compile(
    r"Placeholder for `((?:[a-z][\w]*\.)+[A-Z]\w*)`", re.S)


def placeholder_target(name, rust_path):
    """The fully-qualified Java name a seam_stubs.rs placeholder says it stands for.

    A stub does not sit in the package path of the class it replaces, so path agreement
    cannot resolve it -- but the stub says so itself: "Placeholder for
    `ghidra.program.model.lang.Processor`". That doc comment is the authoritative answer and
    it is already written on 369 of them.
    """
    try:
        with open(rust_path, encoding="utf-8", errors="replace") as fh:
            src = fh.read()
    except OSError:
        return None
    m = re.search(r"(?m)^\s*pub (?:trait|struct|enum) " + re.escape(name) + r"\b", src)
    if not m:
        return None
    # the doc block immediately above the declaration
    head = src[:m.start()]
    block = []
    for line in reversed(head.rstrip().split("\n")):
        if line.lstrip().startswith("///") or line.lstrip().startswith("//"):
            block.append(line)
        else:
            break
    fq = _PLACEHOLDER_FQN.search("\n".join(reversed(block)))
    return fq.group(1) if fq else None


def resolve_by_path(name, rust_path, facts):
    """Pick which Java class a Rust declaration models, from where it sits.

    A bare name cannot say: `PatternExpression` is the sleigh runtime expression AND the
    pcodeCPort AST node. But the Rust tree already answers it by placement -- the pcodeCPort
    one is at decompiler/slghpatexpress/, and its own doc comment says "Models
    ghidra.pcodeCPort.slghpatexpress.PatternValue". Scoring candidates by how many trailing
    package segments their Java path shares with the Rust path recovers that, and it is what
    turns 32 "ask a human" rows into a handful.

    Returns the winning facts dict, or None when it is genuinely undecidable (no overlap, or a
    tie).
    """
    cands = facts.get(name) or []
    if len(cands) <= 1:
        return cands[0] if cands else None

    # A placeholder names its target outright; trust that over any path heuristic.
    fq = placeholder_target(name, rust_path)
    if fq:
        want = fq.replace(".", "/") + ".java"
        for e in cands:
            if e["rel"].replace("\\", "/").endswith(want):
                return e
        return None       # it names something not among the candidates -- do not guess

    rust_segs = [x for x in os.path.dirname(rust_path).split(os.sep) if x not in ("ghidra-rs", "src", "")]

    def score(e):
        java_segs = [x for x in os.path.dirname(e["rel"]).split("/")
                     if x not in ("Ghidra", "src", "main", "java", "ghidra")]
        # longest common suffix of package segments, compared case-insensitively because the
        # Rust tree is snake_case (slghpatexpress -> slghpatexpress, pdb2/pdbreader -> pdb2/pdbreader)
        n = 0
        for a, b in zip(reversed([x.lower() for x in java_segs]),
                        reversed([x.replace("_", "").lower() for x in rust_segs])):
            if a.replace("_", "").lower() == b:
                n += 1
            else:
                break
        return n

    scored = sorted(((score(e), e) for e in cands), key=lambda t: -t[0])
    if scored[0][0] and not (len(scored) > 1 and scored[0][0] == scored[1][0]):
        return scored[0][1]

    # Fallback: a package segment appearing ANYWHERE in the Rust path, for the cases where the
    # module tree reorganises rather than mirrors -- db/buffers/DataBuffer.java lives at
    # framework/db/buffer.rs, and app/plugin/processors/sleigh/Constructor.java at
    # program/model/lang/sleigh/constructor/. Strict suffix alignment scores both zero.
    rust_set = {x.replace("_", "").lower() for x in rust_segs}

    def overlap(e):
        java_segs = [x for x in os.path.dirname(e["rel"]).split("/")
                     if x not in ("Ghidra", "src", "main", "java", "ghidra")]
        return len({x.replace("_", "").lower() for x in java_segs} & rust_set)

    ov = sorted(((overlap(e), e) for e in cands), key=lambda t: -t[0])
    if ov[0][0] and not (len(ov) > 1 and ov[0][0] == ov[1][0]):
        return ov[0][1]
    return None


def is_extension_point(name, facts):
    """True if `name` reaches an extension-point root through its supertypes."""
    seen, stack = set(), [name]
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        if n in EXTENSION_POINT_ROOTS:
            return True
        for e in facts.get(n, []):
            stack.extend(e["extends"] + e["implements"])
    return False


def concrete_implementers(name, facts, subtypes, _cache=None):
    """Transitive CONCRETE class implementers of `name`, excluding test doubles.

    Transitive because Java hierarchies interpose sub-interfaces: `TraceCodeUnit`'s direct
    subtypes are `TraceData` and `TraceInstruction`, both interfaces, so a direct count says
    zero implementations when the truth is "whatever implements those". Concrete because an
    abstract base is not an alternative representation either. Both corrections move types
    between "collapse this" and "leave it alone", so neither is optional.
    """
    if _cache is None:
        _cache = {}
    if name in _cache:
        return _cache[name]
    _cache[name] = set()  # cycle guard
    out, seen, stack = set(), set(), [name]
    while stack:
        x = stack.pop()
        if x in seen:
            continue
        seen.add(x)
        for sub in subtypes.get(x, ()):
            e = facts.get(sub)
            if not e:
                continue
            if e[0]["kind"] == "class" and not e[0]["abstract"] and not _DOUBLE_RE.search(sub):
                out.add(sub)
            stack.append(sub)
    _cache[name] = out
    return out


# Java sourcesets that are not production code. `desc_order.py` already keeps the porting
# frontier off these ("test-fixture classes exercise Java internals; production Rust never
# depends on them"), but the shape index was reading all 15,613 files, so 1,944 test-sourceset
# classes and 10 bundled example scripts counted as implementers. That is how `Util`, from
# Extensions/bundle_examples/scripts_lib, became an implementer of `Library` -- and every test
# double implementing a production interface inflated that interface's implementer count,
# which is the number every verdict in CONVENTION_QUEUE.tsv turns on.
def is_non_production(rel: str) -> bool:
    return (
        "/src/test/" in rel
        or "/src/test." in rel
        or "/bundle_examples/" in rel
        or "/GhidraDocs/" in rel
    )


def build_index(verbose=False):
    files, facts = [], {}
    for root, _dirs, names in os.walk(ORIG):
        for f in names:
            if not f.endswith(".java"):
                continue
            p = os.path.join(root, f)
            if is_non_production(os.path.relpath(p, ORIG)):
                continue
            files.append(p)
    subtypes: dict[str, set] = {}
    for i, p in enumerate(sorted(files)):
        name = os.path.basename(p)[:-5]
        rel = os.path.relpath(p, ORIG)
        fa = parse_file(p, name)
        if fa is None:
            continue
        fa["rel"] = rel
        facts.setdefault(name, []).append(fa)
        for sup in fa["extends"] + fa["implements"]:
            subtypes.setdefault(sup, set()).add(name)
        if verbose and i % 2000 == 0:
            print(f"  indexed {i}/{len(files)}", file=sys.stderr)
    return facts, subtypes


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

# shape -> the directive injected into the porting prompt. Kept terse on purpose:
# every one of these is paid for on every port.
DIRECTIVES = {
    "enum": """SHAPE: Rust `enum`. This Java type is a CLOSED set of alternatives ({why}).
Emit `pub enum {name}` with one variant per alternative and implement its methods with
`match self`. Do NOT emit a trait: a trait would reopen a set the Java source deliberately
closed, and every caller would then take `&dyn {name}` for what is a plain value.""",
    "struct": """SHAPE: Rust `struct` + `impl`. This Java type is a concrete data type ({why}).
Emit `pub struct {name}` and take/return it BY VALUE or by `&`/`&mut` reference. Do NOT emit a
trait and do NOT let it appear as `Box<dyn {name}>`/`Arc<dyn {name}>` anywhere.""",
    "module": """SHAPE: a plain module -- `pub const` items and/or free `pub fn`s, and NO type
named `{name}` at all ({why}).
Java needs a class to hang statics off; Rust does not. Emit the constants and functions directly
in the module. A field-less struct that is never instantiated is not the port of a statics holder,
and it drags an unnecessary `impl` block and receiver argument through every call site.""",
    "trait": """SHAPE: Rust `trait`. This is a genuine open extension point ({why}).
Emit `pub trait {name}`. Use `&dyn {name}`/`Box<dyn {name}>` ONLY where the call site really is
polymorphic over unknown implementers; prefer a generic `impl {name}` parameter otherwise.""",
    "struct_trait": """SHAPE: shared-state `struct` + `trait` for the abstract operations ({why}).
Java abstract classes carry BOTH state and behaviour. Split them: `pub struct {name}Base` (or
give the shared fields to each concrete type) holds the fields and the concrete methods; `pub
trait {name}` declares ONLY the abstract methods. Do not emit a bare trait -- the shared state
has to live somewhere, and a trait cannot hold it.""",
    "error": """SHAPE: an error type ({why}). Emit a `struct`/`enum` implementing
`std::fmt::Display` and `std::error::Error`, returned as `Err(...)` from `Result`. Do NOT model
the Java exception hierarchy as a Rust trait hierarchy, and do NOT panic where Java throws.""",
    "iterator": """SHAPE: implement `std::iter::Iterator` ({why}).
Emit a type whose `Iterator::next` returns `Option<Item>`. Do NOT port `hasNext()`/`next()` as a
pair of Rust methods: `while it.has_next() {{ v.push(it.next()) }}` advanced the cursor twice per
turn and silently dropped every other element (AGENTS.md, "Compiling is not evidence").""",
    "park": """SHAPE: UNDECIDED. {why}
Do not guess. Port nothing and end with: PORT_RESULT: PARKED shape undecided -- {why}""",
}


def classify(facts: dict, subtype_count: int, permits_resolved=None) -> dict:
    """Apply the shape rules. Returns {shape, rule, why, confidence}."""
    name, kind = facts["name"], facts["kind"]
    all_supers = facts["extends"] + facts["implements"]

    # A rich interface that also happens to be Iterable keeps its own shape, but the porter
    # still needs telling how to carry the iteration across -- otherwise `iterator()` comes
    # over as a has_next/next pair, which is the double-consume bug all over again.
    iterable_note = ""
    if any(s in ITERABLE_SUPERS for s in all_supers) and not any(
        s in CURSOR_SUPERS for s in all_supers
    ):
        iterable_note = (
            "\nALSO: the Java type is `Iterable`. Implement `IntoIterator` (and/or an `iter()` "
            "returning a concrete iterator) for it. Do NOT port `iterator()`/`hasNext()`/`next()` "
            "as a pair of Rust methods -- `while it.has_next() { v.push(it.next()) }` advanced "
            "the cursor twice per turn and silently dropped every other element."
        )

    def r(rule, shape, why, conf="hard"):
        return dict(shape=shape, rule=rule, why=why, confidence=conf, name=name,
                    extra=iterable_note)

    # R1 -- Java enum. Always a Rust enum, constant bodies or not.
    if kind == "enum":
        n = len(facts.get("enum_constants", []))
        extra = " with constant-specific bodies -> `match self` in each method" if facts.get(
            "enum_constant_bodies"
        ) else ""
        return r("R1-java-enum", "enum", f"Java `enum` with {n} constants{extra}")

    # R2 -- sealed type. `permits` IS the variant list; this is the Lifespan case.
    if facts["sealed"]:
        p = permits_resolved or facts["permits"]
        listed = ", ".join(p) if p else "its nested implementors"
        return r(
            "R2-sealed",
            "enum",
            f"Java `sealed {kind}` -- the permitted set is closed: {listed}",
        )

    # R3 -- record. An immutable value; accessors are field reads.
    if kind == "record":
        return r("R3-record", "struct", "Java `record` -- an immutable value type")

    # R4 -- annotation type. Not a runtime type at all.
    if kind == "@interface":
        return r(
            "R4-annotation",
            "park",
            "Java annotation type -- has no direct Rust equivalent; decide with a human",
            "ambiguous",
        )

    # R5 -- exception. Decided by supertype/name before any structural rule.
    supers = all_supers
    if any(s.endswith(THROWABLE_SUFFIXES) for s in supers) or name.endswith(THROWABLE_SUFFIXES):
        return r("R5-exception", "error", f"extends/names a Java throwable ({', '.join(supers) or name})")

    # R6a -- a cursor. Must become a real Iterator, never a has_next/next pair.
    cursors = [s for s in supers if s in CURSOR_SUPERS]
    if cursors:
        return r("R6a-cursor", "iterator", f"extends {', '.join(cursors)}")

    # R6b -- iterable with essentially no other API: also a sequence.
    iterables = [s for s in supers if s in ITERABLE_SUPERS]
    if iterables and facts["abstract_methods"] <= ITERABLE_API_CUTOFF:
        return r(
            "R6b-bare-iterable",
            "iterator",
            f"extends {', '.join(iterables)} and declares no other API "
            f"({facts['abstract_methods']} abstract method(s))",
        )

    # R7 -- statics holder: a class that exists only because Java has nowhere else to put
    # constants and free functions. No instance state, no instance methods.
    if (
        kind == "class"
        and facts["instance_fields"] == 0
        and facts["concrete_methods"] == 0
        and facts["abstract_methods"] == 0
        and (facts["static_fields"] > 0 or facts["static_methods"] > 0)
        and not facts["public_ctor"]
    ):
        bits = []
        if facts["static_fields"]:
            bits.append(f"{facts['static_fields']} static field(s)")
        if facts["static_methods"]:
            bits.append(f"{facts['static_methods']} static method(s)")
        return r(
            "R7-statics-holder",
            "module",
            f"{' and '.join(bits)}, no instance state and no instance methods",
        )

    if kind == "interface":
        if facts["abstract_methods"] == 0 and facts["concrete_methods"] == 0:
            # R8a -- an interface whose only members are constants (implicitly
            # public static final). It is part constants module, part type tag, and
            # which half matters depends on whether anything dispatches on the tag --
            # which the Java source alone does not say.
            if facts["static_fields"] > 0:
                return r(
                    "R8a-constants-interface",
                    "park",
                    f"interface with {facts['static_fields']} constant(s) and no methods: "
                    f"the constants want a plain module, but "
                    f"{'the ' + ', '.join(facts['extends']) + ' supertype means' if facts['extends'] else 'it may mean'}"
                    " something dispatches on it as a type tag -- decide with a human",
                    "ambiguous",
                )
            # R8b -- a true marker interface: no members at all.
            return r(
                "R8b-marker",
                "park",
                "marker interface -- no methods, no constants; Rust has no equivalent "
                "and the right seam depends on what tests the marker",
                "ambiguous",
            )
        # R9 -- open interface. The one case a trait is unambiguously right.
        return r(
            "R9-open-interface",
            "trait",
            f"Java `interface` with {facts['abstract_methods']} abstract method(s), "
            f"{subtype_count} in-repo implementor(s)",
        )

    # kind == class from here.
    if facts["abstract"]:
        # R10 -- abstract base with no subclasses left in-repo: nothing to abstract over.
        if subtype_count == 0:
            return r("R10-abstract-orphan", "struct", "abstract class with no in-repo subclasses")
        # R11 -- abstract base carrying state: needs the struct half.
        if facts["instance_fields"] > 0:
            return r(
                "R11-abstract-stateful",
                "struct_trait",
                f"abstract class with {facts['instance_fields']} instance field(s) and "
                f"{subtype_count} in-repo subclass(es)",
            )
        # R12 -- pure abstract base: behaves as an interface.
        return r(
            "R12-abstract-pure",
            "trait",
            f"abstract class with no instance state and {subtype_count} in-repo subclass(es)",
        )

    # R13 -- singleton. Concrete, but its instance identity is the point.
    if facts["singleton"]:
        return r(
            "R13-singleton",
            "struct",
            "singleton (private constructor + static INSTANCE) -- expose a `fn` or a "
            "`OnceLock`, not a global `Arc<Mutex<_>>`",
        )

    # R14 -- concrete class. The default, and the largest bucket.
    return r("R14-concrete-class", "struct", f"concrete Java `class` ({subtype_count} in-repo subclass(es))")


def directive_for(res: dict) -> str:
    return DIRECTIVES[res["shape"]].format(name=res["name"], why=res["why"]) + res.get("extra", "")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

COLS = ["path", "class", "kind", "shape", "rule", "confidence", "subtypes", "why"]


IMPLEMENTERS = os.path.join(REPO, "IMPLEMENTERS.tsv")
IMPL_COLS = ["class", "kind", "n_concrete", "extension_point", "concrete_implementers"]


def write_implementers(facts, subtypes, out=IMPLEMENTERS, cap=40):
    """Materialise the concrete-implementer closure so callers need not rebuild the index.

    `build_index` walks 15,601 Java files and costs ~14s. `dep_context.py` runs once per
    port inside the nightly loop, so recomputing there would burn a quarter-hour a night to
    re-derive something `orig_src` fixes for good. Written alongside SHAPES.tsv and tracked
    for the same reason: the harnesses run `git reset --hard`, and untracked state would be
    thrown away mid-run.
    """
    cache = {}
    rows = []
    for name in facts:
        if len(facts[name]) > 1:
            continue  # ambiguous basename -- callers must not resolve it
        impls = sorted(concrete_implementers(name, facts, subtypes, cache))
        rows.append([
            name,
            facts[name][0]["kind"],
            str(len(impls)),
            "1" if is_extension_point(name, facts) else "0",
            ",".join(impls[:cap]),
        ])
    rows.sort()
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("\t".join(IMPL_COLS) + "\n")
        for r in rows:
            fh.write("\t".join(c.replace("\t", " ") for c in r) + "\n")
    return len(rows)


def load_implementers(path=IMPLEMENTERS):
    """{class: {kind, n_concrete, extension_point, concrete_implementers}} or None."""
    if not os.path.exists(path):
        return None
    out = {}
    try:
        with open(path, encoding="utf-8") as fh:
            next(fh, None)
            for line in fh:
                c = line.rstrip("\n").split("\t")
                if len(c) != len(IMPL_COLS):
                    continue
                out[c[0]] = dict(kind=c[1], n_concrete=int(c[2]),
                                 extension_point=c[3] == "1",
                                 concrete_implementers=[x for x in c[4].split(",") if x])
    except Exception:
        return None
    return out or None


def cmd_index(args):
    facts, subtypes = build_index(verbose=True)
    n = write_implementers(facts, subtypes)
    print(f"wrote {n} rows to {IMPLEMENTERS}")
    rows = []
    for name, entries in facts.items():
        for fa in entries:
            res = classify(fa, len(subtypes.get(name, ())))
            rows.append(
                [
                    fa["rel"],
                    name,
                    fa["kind"] + ("/sealed" if fa["sealed"] else "") + ("/abstract" if fa["abstract"] else ""),
                    res["shape"],
                    res["rule"],
                    res["confidence"],
                    str(len(subtypes.get(name, ()))),
                    res["why"],
                ]
            )
    rows.sort(key=lambda r: r[0])
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write("\t".join(COLS) + "\n")
        for r in rows:
            fh.write("\t".join(c.replace("\t", " ").replace("\n", " ") for c in r) + "\n")
    counts: dict[str, int] = {}
    for r in rows:
        counts[r[3]] = counts.get(r[3], 0) + 1
    print(f"wrote {len(rows)} rows to {args.out}")
    for k, v in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {v:6d}  {k}")
    return 0


def _lookup(rel: str):
    """Shape row for a path, from SHAPES.tsv when present, else parsed live."""
    rel = rel[len("orig_src/") :] if rel.startswith("orig_src/") else rel
    if os.path.exists(SHAPES):
        with open(SHAPES, encoding="utf-8") as fh:
            next(fh, None)
            for line in fh:
                c = line.rstrip("\n").split("\t")
                if c and c[0] == rel:
                    return dict(zip(COLS, c)) | {"name": c[1]}
    name = os.path.basename(rel)[:-5]
    fa = parse_file(os.path.join(ORIG, rel), name)
    if fa is None:
        return None
    _facts, subtypes = build_index()
    res = classify(fa, len(subtypes.get(name, ())))
    return dict(path=rel, **{k: res[k] for k in ("shape", "rule", "confidence", "why", "name")})


def cmd_classify(args):
    row = _lookup(args.path)
    if row is None:
        print(json.dumps({"shape": "park", "why": "could not parse the Java declaration"}))
        return 1
    print(json.dumps(row, indent=2))
    return 0


def cmd_directive(args):
    row = _lookup(args.path)
    if row is None:
        return 1
    print(DIRECTIVES[row["shape"]].format(name=row["name"], why=row["why"]))
    return 0


def cmd_audit(args):
    """Compare shipped Rust declarations against the rules.

    A trait standing in for a still-TODO Java class is a deliberate seam, not a defect
    (AGENTS.md), so those are excluded. So are ambiguous basenames: `PatternExpression`
    is two unrelated Java classes, and pairing by basename has produced confident wrong
    answers before.
    """
    if not os.path.exists(SHAPES):
        print(f"{SHAPES} missing -- run `shape_rules.py index` first", file=sys.stderr)
        return 1
    shapes: dict[str, list] = {}
    with open(SHAPES, encoding="utf-8") as fh:
        next(fh, None)
        for line in fh:
            c = line.rstrip("\n").split("\t")
            if len(c) == len(COLS):
                shapes.setdefault(c[1], []).append(dict(zip(COLS, c)))
    status = {}
    with open(os.path.join(REPO, "PORT_MANIFEST.tsv"), encoding="utf-8") as fh:
        for line in fh:
            c = line.split("\t")
            if len(c) > 1:
                status[c[0]] = c[1].strip()

    decl = re.compile(r"^\s*pub (trait|struct|enum) ([A-Za-z0-9_]+)(.*)$")
    rust: dict[str, list] = {}
    for root, _d, files in os.walk(os.path.join(REPO, "ghidra-rs", "src")):
        for f in files:
            if not f.endswith(".rs") or f == "seam_stubs.rs":
                continue
            p = os.path.join(root, f)
            for i, line in enumerate(open(p, encoding="utf-8", errors="replace"), 1):
                m = decl.match(line)
                if not m:
                    continue
                kind = m.group(1)
                # `pub trait FunctionIterator: Iterator<Item = Arc<dyn Function>> {}` is the
                # established way this crate names an iterator without giving up the domain
                # vocabulary: a marker supertrait plus a blanket impl. It IS an iterator, so
                # counting it as a trait/iterator mismatch is a false positive -- and it flagged
                # four already-correct types before this check existed.
                if kind == "trait" and re.search(r":\s*[^{]*\bIterator\b", m.group(3)):
                    kind = "iterator_trait"
                rust.setdefault(m.group(2), []).append((kind, os.path.relpath(p, REPO), i))

    want = {"enum": "enum", "struct": "struct", "trait": ("trait", "iterator_trait"),
            "iterator": ("struct", "enum", "iterator_trait"),
            "error": ("struct", "enum"), "struct_trait": ("struct", "trait")}
    rows = []
    for name, decls in sorted(rust.items()):
        cand = shapes.get(name)
        if not cand or len(cand) > 1:
            continue  # unmatched, or an ambiguous basename -- do not guess
        sh = cand[0]
        if sh["shape"] not in want:
            continue
        if status.get("orig_src/" + sh["path"]) != "DONE":
            continue  # trait standing in for an unported class = deliberate seam
        ok = want[sh["shape"]]
        ok = (ok,) if isinstance(ok, str) else ok
        kinds = {d[0] for d in decls}
        if kinds & set(ok):
            continue
        for k, p, ln in decls:
            rows.append([name, k, sh["shape"], sh["rule"], sh["kind"], f"{p}:{ln}", sh["why"]])

    hdr = ["class", "rust_is", "should_be", "rule", "java_kind", "location", "why"]
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write("\t".join(hdr) + "\n")
        for r in rows:
            fh.write("\t".join(str(c).replace("\t", " ") for c in r) + "\n")
    print(f"wrote {len(rows)} shape mismatches to {args.out}")
    by: dict[str, int] = {}
    for r in rows:
        by[f"{r[1]} -> {r[2]} ({r[3]})"] = by.get(f"{r[1]} -> {r[2]} ({r[3]})", 0) + 1
    for k, v in sorted(by.items(), key=lambda x: -x[1])[:12]:
        print(f"  {v:5d}  {k}")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("index"); p.add_argument("--out", default=SHAPES); p.set_defaults(fn=cmd_index)
    p = sub.add_parser("classify"); p.add_argument("path"); p.set_defaults(fn=cmd_classify)
    p = sub.add_parser("directive"); p.add_argument("path"); p.set_defaults(fn=cmd_directive)
    p = sub.add_parser("audit"); p.add_argument("--out", default=os.path.join(REPO, "SHAPE_DEBT.tsv"))
    p.set_defaults(fn=cmd_audit)
    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
