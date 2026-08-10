#!/usr/bin/env python3
"""Unit tests for shape_rules.py -- the Java-declaration -> Rust-shape classifier.

The cases here are the ones that have already cost the port real money:

  * `sealed interface Lifespan` became `pub trait Lifespan` and the crate now carries
    613 `dyn Lifespan` uses. R2 exists to make that impossible.
  * 133 queued Java `enum`s and 121 `record`s were being handed a prompt that said
    "map the class to a Rust struct with an impl block".
  * A `hasNext()`/`next()` pair ported literally consumed two items per loop turn and
    dropped every other element (AGENTS.md, "Compiling is not evidence"); R6 routes
    those to `std::iter::Iterator` instead.

    python3 scripts/test_shape_rules.py
"""
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import shape_rules as sr


def shape(src: str, name: str, subtypes: int = 0):
    """Classify a Java snippet the way the indexer would."""
    s = sr.strip_java(src)
    kind, mods, end = sr.find_primary(s, name)
    assert kind is not None, f"could not find declaration of {name}"
    header, body = sr.header_and_body(s, end)
    ext, imp, per = sr.parse_header(header)
    f = dict(
        name=name,
        kind=kind,
        sealed="sealed" in mods and "non-sealed" not in mods,
        abstract="abstract" in mods,
        final="final" in mods,
        extends=ext,
        implements=imp,
        permits=per,
        annotations=[],
    )
    if kind == "enum":
        c, b = sr.enum_constants(body)
        f["enum_constants"], f["enum_constant_bodies"] = c, b
    f.update(sr.analyse_body(kind, body, name))
    return sr.classify(f, subtypes), f


class TestClosedSets(unittest.TestCase):
    def test_sealed_interface_is_an_enum_not_a_trait(self):
        """The Lifespan regression: `permits` is a variant list, not an extension point."""
        res, _ = shape(
            """
            public sealed interface Lifespan extends Span<Long, Lifespan>
                    permits Lifespan.Impl, Lifespan.Empty {
                long lmin();
                long lmax();
            }
            """,
            "Lifespan",
            subtypes=2,
        )
        self.assertEqual(res["shape"], "enum")
        self.assertEqual(res["rule"], "R2-sealed")
        self.assertIn("Impl", res["why"])
        # And the directive has to say why, or the porter reopens the set anyway.
        self.assertIn("Do NOT emit a trait", sr.directive_for(res))

    def test_sealed_abstract_class_is_also_closed(self):
        res, _ = shape(
            "public sealed abstract class Node permits Leaf, Branch { abstract int size(); }",
            "Node",
            subtypes=2,
        )
        self.assertEqual(res["shape"], "enum")

    def test_non_sealed_is_not_treated_as_closed(self):
        res, _ = shape(
            "public non-sealed class Middle extends Node { int size() { return 1; } }",
            "Middle",
        )
        self.assertEqual(res["shape"], "struct")

    def test_java_enum_maps_to_rust_enum(self):
        res, f = shape(
            "public enum RefType { READ, WRITE, EXECUTE; public boolean isRead() { return true; } }",
            "RefType",
        )
        self.assertEqual(res["shape"], "enum")
        self.assertEqual(f["enum_constants"], ["READ", "WRITE", "EXECUTE"])

    def test_enum_with_constant_bodies_still_enum(self):
        res, _ = shape(
            """
            public enum Op {
                ADD { int apply(int a, int b) { return a + b; } },
                SUB { int apply(int a, int b) { return a - b; } };
                abstract int apply(int a, int b);
            }
            """,
            "Op",
        )
        self.assertEqual(res["shape"], "enum")
        self.assertIn("match self", res["why"])


class TestValueTypes(unittest.TestCase):
    def test_record_is_a_struct(self):
        res, _ = shape("public record ElementId(String name, int id) {}", "ElementId")
        self.assertEqual(res["shape"], "struct")
        self.assertEqual(res["rule"], "R3-record")

    def test_constants_only_class_has_no_rust_type(self):
        """SquashConstants-style holders port to `const` items, not an empty struct."""
        res, _ = shape(
            """
            public final class SquashConstants {
                public static final int MAGIC = 0x73717368;
                public static final int MAX_UNIT = 8192;
                private SquashConstants() {}
            }
            """,
            "SquashConstants",
        )
        self.assertEqual(res["shape"], "module")
        self.assertIn("NO type\nnamed `SquashConstants` at all", sr.directive_for(res))

    def test_static_utility_class_is_also_a_module(self):
        """A class holding only static methods exists because Java has no free functions."""
        res, _ = shape(
            """
            public class ReflectionUtilities {
                public static Class<?> locateClass(String n) { return null; }
                public static String getName(Object o) { return ""; }
            }
            """,
            "ReflectionUtilities",
        )
        self.assertEqual(res["shape"], "module")
        self.assertEqual(res["rule"], "R7-statics-holder")

    def test_constants_carrying_interface_parks_with_a_specific_reason(self):
        """TraceEventScope-style: constants plus a type tag. Which half matters is not
        answerable from the Java source, so it must not be guessed."""
        res, _ = shape(
            """
            public interface TraceEventScope extends TraceObjectInterface {
                String KEY_EVENT_THREAD = "_event_thread";
                String KEY_TIME_SUPPORT = "_time_support";
            }
            """,
            "TraceEventScope",
            subtypes=2,
        )
        self.assertEqual(res["shape"], "park")
        self.assertEqual(res["rule"], "R8a-constants-interface")
        self.assertIn("TraceObjectInterface", res["why"])

    def test_class_with_instance_state_is_not_a_constants_module(self):
        res, _ = shape(
            """
            public class Holder {
                public static final int MAGIC = 1;
                private int value;
                public int getValue() { return value; }
            }
            """,
            "Holder",
        )
        self.assertEqual(res["shape"], "struct")

    def test_singleton_is_a_struct_with_a_note(self):
        res, _ = shape(
            """
            public class Registry {
                public static final Registry INSTANCE = new Registry();
                private java.util.Map<String, String> map;
                private Registry() {}
                public String get(String k) { return map.get(k); }
            }
            """,
            "Registry",
        )
        self.assertEqual(res["shape"], "struct")
        self.assertEqual(res["rule"], "R13-singleton")
        self.assertIn("OnceLock", res["why"])


class TestInterfacesAndAbstracts(unittest.TestCase):
    def test_open_interface_is_a_trait(self):
        res, _ = shape(
            "public interface Analyzer { void added(Program p); boolean canAnalyze(Program p); }",
            "Analyzer",
            subtypes=17,
        )
        self.assertEqual(res["shape"], "trait")
        self.assertEqual(res["rule"], "R9-open-interface")

    def test_marker_interface_parks(self):
        res, _ = shape("public interface ExtensionPoint {}", "ExtensionPoint")
        self.assertEqual(res["shape"], "park")
        self.assertEqual(res["confidence"], "ambiguous")

    def test_abstract_class_with_state_needs_the_struct_half(self):
        """A bare trait cannot hold the fields an abstract base declares."""
        res, _ = shape(
            """
            public abstract class AbstractCodeUnit {
                protected Address address;
                protected int length;
                public Address getAddress() { return address; }
                public abstract byte[] getBytes();
            }
            """,
            "AbstractCodeUnit",
            subtypes=6,
        )
        self.assertEqual(res["shape"], "struct_trait")
        self.assertIn("a trait cannot hold it", sr.directive_for(res))

    def test_stateless_abstract_class_is_a_trait(self):
        res, _ = shape(
            "public abstract class AbstractVisitor { public abstract void visit(Node n); }",
            "AbstractVisitor",
            subtypes=4,
        )
        self.assertEqual(res["shape"], "trait")

    def test_abstract_class_with_no_subclasses_is_a_struct(self):
        res, _ = shape(
            "public abstract class Orphan { protected int x; public abstract int f(); }",
            "Orphan",
            subtypes=0,
        )
        self.assertEqual(res["shape"], "struct")
        self.assertEqual(res["rule"], "R10-abstract-orphan")


class TestSpecialSupertypes(unittest.TestCase):
    def test_iterator_becomes_a_real_iterator(self):
        res, _ = shape(
            "public interface CodeUnitIterator extends Iterator<CodeUnit> { boolean hasNext(); }",
            "CodeUnitIterator",
            subtypes=3,
        )
        self.assertEqual(res["shape"], "iterator")
        self.assertIn("dropped every other element", sr.directive_for(res))

    def test_rich_iterable_keeps_its_own_shape(self):
        """`Iterable` means "you can iterate me", which any collection says.

        `AddressSetView extends Iterable<AddressRange>` and declares 28 other abstract
        methods, with 833 `dyn AddressSetView` uses behind it. An earlier draft of R6 fired
        on any `Iterable` supertype and would have told the porter to make it -- and
        `Project`, and `ProjectData` -- a cursor type.
        """
        res, _ = shape(
            """
            public interface AddressSetView extends Iterable<AddressRange> {
                boolean contains(Address addr);
                Address getMinAddress();
                Address getMaxAddress();
                int getNumAddressRanges();
                boolean isEmpty();
            }
            """,
            "AddressSetView",
            subtypes=30,
        )
        self.assertEqual(res["shape"], "trait")
        self.assertEqual(res["rule"], "R9-open-interface")
        # ...but the iteration still has to cross over correctly.
        d = sr.directive_for(res)
        self.assertIn("IntoIterator", d)
        self.assertIn("dropped every other element", d)

    def test_bare_iterable_with_no_other_api_is_a_sequence(self):
        res, _ = shape(
            "public interface AddressRangeIterable extends Iterable<AddressRange> {}",
            "AddressRangeIterable",
            subtypes=2,
        )
        self.assertEqual(res["shape"], "iterator")
        self.assertEqual(res["rule"], "R6b-bare-iterable")

    def test_cursor_supertype_still_wins_over_iterable(self):
        res, _ = shape(
            "public interface CodeUnitIterator extends Iterator<CodeUnit>, Iterable<CodeUnit> {}",
            "CodeUnitIterator",
            subtypes=3,
        )
        self.assertEqual(res["rule"], "R6a-cursor")
        # The Iterable note would be redundant noise on something that is already a cursor.
        self.assertNotIn("IntoIterator", sr.directive_for(res))

    def test_exception_becomes_an_error_type(self):
        res, _ = shape(
            "public class InvalidInputException extends UsrException { public InvalidInputException(String m) { super(m); } }",
            "InvalidInputException",
        )
        self.assertEqual(res["shape"], "error")

    def test_exception_by_name_when_supertype_is_unhelpful(self):
        res, _ = shape("public class CancelledException extends Foo {}", "CancelledException")
        self.assertEqual(res["shape"], "error")

    def test_exception_rule_beats_the_abstract_rule(self):
        res, _ = shape(
            "public abstract class UsrException extends Exception { protected int code; }",
            "UsrException",
            subtypes=40,
        )
        self.assertEqual(res["shape"], "error")


class TestParsing(unittest.TestCase):
    def test_nested_type_does_not_shadow_the_primary(self):
        src = """
            public class Outer {
                private int f;
                public interface Inner { void go(); }
                public int get() { return f; }
            }
        """
        res, _ = shape(src, "Outer")
        self.assertEqual(res["shape"], "struct")

    def test_declaration_keyword_inside_a_comment_is_ignored(self):
        src = """
            /* public interface Outer { } */
            // public enum Outer { A }
            public final class Outer { private int f; public int get() { return f; } }
        """
        res, _ = shape(src, "Outer")
        self.assertEqual(res["shape"], "struct")

    def test_generic_supertypes_are_split_on_top_level_commas(self):
        self.assertEqual(
            sr.split_types("Span<Long, Lifespan>, Iterable<Long>"), ["Span", "Iterable"]
        )

    def test_generic_bounds_are_not_supertypes(self):
        """`class X<T extends Bound>` does not make X a subtype of Bound.

        A regex for the first `extends` in the header read the type-parameter bound as a
        supertype, inventing an edge saying AssemblyGrammar implements AssemblyNonTerminal.
        354 Java files in the tree declare a bounded type parameter.
        """
        ext, imp, per = sr.parse_header(
            "<NT extends AssemblyNonTerminal, P extends AbstractAssemblyProduction<NT>> ")
        self.assertEqual((ext, imp, per), ([], [], []))

    def test_generic_bounds_do_not_hide_a_real_supertype(self):
        ext, imp, _ = sr.parse_header(
            "<T extends Comparable<T>> extends AbstractThing<T> implements Serializable ")
        self.assertEqual(ext, ["AbstractThing"])
        self.assertEqual(imp, ["Serializable"])

    def test_declaration_without_type_params_is_unchanged(self):
        ext, imp, _ = sr.parse_header(" extends Base implements Foo ")
        self.assertEqual((ext, imp), (["Base"], ["Foo"]))

    def test_implements_and_permits_are_separated(self):
        ext, imp, per = sr.parse_header(
            " extends Base<T> implements Foo, Bar<Baz> permits A, B "
        )
        self.assertEqual((ext, imp, per), (["Base"], ["Foo", "Bar"], ["A", "B"]))


class TestDirectiveCoverage(unittest.TestCase):
    def test_every_shape_has_a_directive(self):
        shapes = {"enum", "struct", "module", "trait", "struct_trait", "error",
                  "iterator", "park"}
        self.assertEqual(set(sr.DIRECTIVES), shapes)

    def test_directives_format_without_stray_placeholders(self):
        """Every `{...}` must be either a known field or an escaped literal brace.

        The iterator directive quotes Rust code containing real braces, so a blanket
        "no `{` in the output" check is wrong; what must not survive is a placeholder.
        """
        for s in sr.DIRECTIVES:
            out = sr.DIRECTIVES[s].format(name="Foo", why="because")
            for leftover in re.findall(r"\{(\w+)\}", out):
                self.fail(f"unfilled placeholder {{{leftover}}} in the {s} directive")


class TestNonProductionSources(unittest.TestCase):
    """Test sourcesets and bundled examples are not evidence about a type's shape.

    1,944 of the tree's 15,613 Java files are under src/test. desc_order.py already keeps the
    porting frontier off them; the shape index was reading them, so test doubles counted as
    implementers -- and the implementer count is what every CONVENTION_QUEUE verdict turns on.
    `Util`, from Extensions/bundle_examples/scripts_lib, was an implementer of `Library`.
    """

    def test_test_sourcesets_are_excluded(self):
        for rel in ("Ghidra/Framework/DB/src/test/java/db/FooTest.java",
                    "Ghidra/Framework/DB/src/test.slow/java/db/BarTest.java"):
            self.assertTrue(sr.is_non_production(rel), rel)

    def test_bundled_examples_are_excluded(self):
        self.assertTrue(sr.is_non_production(
            "Ghidra/Extensions/bundle_examples/scripts_lib/org/other/lib/Util.java"))

    def test_production_paths_are_kept(self):
        for rel in ("Ghidra/Framework/DB/src/main/java/db/DBHandle.java",
                    "Ghidra/Features/Base/src/main/java/ghidra/app/nav/Navigatable.java",
                    "Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/test/TestUtils.java"):
            self.assertFalse(sr.is_non_production(rel), rel)


class TestShapeTableIsPathKeyed(unittest.TestCase):
    def test_nested_entries_are_excluded_from_the_path_table(self):
        """SHAPES.tsv is read by path, first match wins.

        A nested type shares its parent file's path, so including them gave 1,850 duplicate
        paths and could hand descent_night.sh the shape of a nested action class for the whole
        file. They stay in the name index; they are not written here.
        """
        import csv as _csv
        path = os.path.join(sr.REPO, "SHAPES.tsv")
        if not os.path.exists(path):
            self.skipTest("SHAPES.tsv not built")
        seen = set()
        with open(path, newline="", encoding="utf-8") as f:
            dups = [r["path"] for r in _csv.DictReader(f, delimiter="\t")
                    if r["path"] in seen or seen.add(r["path"])]
        self.assertEqual(dups, [], f"{len(dups)} duplicate path(s) in SHAPES.tsv")


class TestNameLookup(unittest.TestCase):
    """The port renames systematically; a basename index sees none of it."""

    FACTS = {"MDMang": [{"rel": "mdemangler/MDMang.java"}],
             "FSRL": [{"rel": "ghidra/formats/gfilesystem/FSRL.java"}],
             "AddressKeyIterator": [{"rel": "a/AddressKeyIterator.java"}],
             "FooLike": [{"rel": "b/FooLike.java"}],
             "Foo": [{"rel": "b/Foo.java"}]}

    def test_exact_name_wins(self):
        self.assertEqual(sr.lookup("MDMang", self.FACTS)[0]["rel"], "mdemangler/MDMang.java")

    def test_acronym_case_is_tolerated(self):
        """Ghidra writes MDMang and FSRL; the Rust port writes MdMang and Fsrl."""
        self.assertIsNotNone(sr.lookup("MdMang", self.FACTS))
        self.assertIsNotNone(sr.lookup("Fsrl", self.FACTS))

    def test_seam_suffix_is_stripped(self):
        """MdMangLike is a seam trait standing in for MDMang."""
        self.assertEqual(sr.lookup("AddressKeyIteratorLike", self.FACTS)[0]["rel"],
                         "a/AddressKeyIterator.java")

    def test_a_real_Like_class_is_not_shadowed(self):
        """Exact match first, so a genuine `FooLike` never resolves to `Foo`."""
        self.assertEqual(sr.lookup("FooLike", self.FACTS)[0]["rel"], "b/FooLike.java")

    def test_unknown_stays_unknown(self):
        self.assertIsNone(sr.lookup("NoSuchThingAnywhere", self.FACTS))


class TestRealSources(unittest.TestCase):
    """Guard the two live cases the rules were written for, if orig_src is present."""

    def setUp(self):
        if not os.path.isdir(sr.ORIG):
            self.skipTest("orig_src not present")

    def test_lifespan_classifies_as_enum(self):
        p = os.path.join(
            sr.ORIG,
            "Ghidra/Debug/Framework-TraceModeling/src/main/java/ghidra/trace/model/Lifespan.java",
        )
        if not os.path.exists(p):
            self.skipTest("Lifespan.java not present")
        facts = sr.parse_file(p, "Lifespan")
        self.assertIsNotNone(facts)
        self.assertTrue(facts["sealed"])
        self.assertEqual(sr.classify(facts, 3)["shape"], "enum")


if __name__ == "__main__":
    unittest.main(verbosity=2)
