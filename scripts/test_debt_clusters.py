#!/usr/bin/env python3
"""Unit tests for debt_clusters.py -- the type-level convention frontier.

The proposer is the risky part: an over-confident suggestion is worse than none, because it
looks like a decision. Three of its rules exist only because earlier versions got them wrong
on real data, so each has a test here:

  * mocks are not implementers   -- counting them made `Namespace` look like a 52-variant enum
  * many implementers != closed  -- it proposed a 94-variant enum for `MemBuffer`
  * no implementers != wrong shape -- 198 of those traits are seam_stubs.rs placeholders
    waiting for their port, and mock-only traits are simply mid-port

    python3 scripts/test_debt_clusters.py
"""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import debt_clusters as dc


def write(path, body):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(body)


class TestFamilyRules(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.rules = os.path.join(self.d, "fam.tsv")
        write(self.rules,
              "suffix\tverdict\tnote\n"
              "Iterator\tITER\titerators are concrete\n"
              "Listener\tACCEPT\tcallback\n"
              "Monitor\tACCEPT\tcallback\n")

    def test_family_applies_by_suffix(self):
        rules = dc.load_family_rules(self.rules)
        self.assertEqual(dc.apply_family("AddressIterator", rules)[0], "ITER")
        self.assertEqual(dc.apply_family("CancelledListener", rules)[0], "ACCEPT")
        self.assertIsNone(dc.apply_family("Program", rules))

    def test_bare_family_name_is_not_matched(self):
        """`Iterator` itself is std's trait, not a Ghidra family member."""
        rules = dc.load_family_rules(self.rules)
        self.assertIsNone(dc.apply_family("Iterator", rules))

    def test_note_records_which_family_decided_it(self):
        rules = dc.load_family_rules(self.rules)
        self.assertIn("[family:Iterator]", dc.apply_family("CodeUnitIterator", rules)[1])


class TestSuggestVerdict(unittest.TestCase):
    def call(self, name, traits=1, impls=0, mocks=0, unported=(), stubs=()):
        return dc.suggest_verdict(
            name,
            {name: traits} if traits else {},
            {},
            {name: impls} if impls else {},
            set(unported),
            {name: mocks} if mocks else {},
            set(stubs),
        )

    def test_small_closed_set_suggests_enum(self):
        v, _why = self.call("PatternKind", impls=4)
        self.assertEqual(v, "SUGGEST-ENUM")

    def test_large_implementer_set_refuses_to_guess(self):
        """94 implementers is evidence AGAINST a closed hierarchy. It must decline, not
        propose a 94-variant enum."""
        v, why = self.call("MemBuffer", impls=94)
        self.assertIsNone(v)
        self.assertIn("too many for an enum", why)

    def test_extension_point_name_with_many_impls_suggests_accept(self):
        v, _why = self.call("ScriptProvider", impls=20)
        self.assertEqual(v, "SUGGEST-ACCEPT")

    def test_single_implementer_suggests_struct(self):
        v, _why = self.call("InstructionPrototype", impls=1)
        self.assertEqual(v, "SUGGEST-STRUCT")

    def test_mock_only_trait_is_deferred_not_collapsed(self):
        """Only test doubles implement it -> the port is unfinished, not a design signal."""
        v, why = self.call("Namespace", impls=0, mocks=51)
        self.assertIsNone(v)
        self.assertIn("not ported yet", why)

    def test_seam_stub_placeholder_is_deferred(self):
        v, why = self.call("SomeStub", impls=0, stubs=("SomeStub",))
        self.assertIsNone(v)
        self.assertIn("placeholder", why)

    def test_unported_class_with_few_impls_is_deferred(self):
        v, why = self.call("HalfPorted", impls=1, unported=("HalfPorted",))
        self.assertIsNone(v)
        self.assertIn("PORT_MANIFEST", why)

    def test_undeclared_type_suggests_park(self):
        v, _why = self.call("NotHere", traits=0)
        self.assertEqual(v, "SUGGEST-PARK")


class TestCollectDeclarations(unittest.TestCase):
    def test_mock_impls_counted_separately_and_stubs_recorded(self):
        d = tempfile.mkdtemp()
        write(os.path.join(d, "src", "thing.rs"),
              "pub trait Thing {}\n"
              "impl Thing for RealThing {}\n"
              "impl Thing for MockThing {}\n"
              "impl Thing for StubThing {}\n")
        write(os.path.join(d, "src", "seam_stubs.rs"), "pub trait Placeholder {}\n")
        traits, _types, impls, mocks, stubs, _jdk = dc.collect_declarations(os.path.join(d, "src"))
        self.assertEqual(traits["Thing"], 1)
        self.assertEqual(impls["Thing"], 1)      # RealThing only
        self.assertEqual(mocks["Thing"], 2)      # Mock + Stub
        self.assertIn("Placeholder", stubs)


class TestIdiomaticExclusion(unittest.TestCase):
    def test_idiomatic_trait_objects_never_enter_the_queue(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "x.rs")
        write(p, "fn f(a: &dyn Error, b: Box<dyn Fn(u32)>, c: &dyn Any, d: &dyn Program) {}\n")
        found = dc.types_in_file(p)
        self.assertEqual(set(found), {"Program"})

    def test_path_qualified_dyn_resolves_to_final_segment(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "x.rs")
        write(p, "fn f(a: &dyn crate::program::model::listing::Function) {}\n")
        self.assertEqual(set(dc.types_in_file(p)), {"Function"})

    def test_comments_are_not_usages(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "x.rs")
        write(p, "// replaces Box<dyn Group> and Rc<RefCell<dyn Group>>\npub struct A;\n")
        self.assertEqual(dc.types_in_file(p), {})



class TestGraphVerdict(unittest.TestCase):
    """Convention 4: a large AST/IR node set is the tagged-arena-graph case, not an undecidable
    one. Before this the proposer declined on anything above ENUM_MAX_VARIANTS, which left the
    sleigh compiler's 30-odd expression nodes with no verdict at all."""

    def call(self, name, impls):
        return dc.suggest_verdict(name, {name: 1}, {}, {name: impls}, set(), {}, set())

    def test_large_ast_node_set_suggests_graph(self):
        v, why = self.call("PatternExpression", 32)
        self.assertEqual(v, "SUGGEST-GRAPH")
        self.assertIn("tagged arena graph", why)

    def test_small_ast_node_set_still_suggests_enum(self):
        """Few variants, statically built -- a plain data-carrying enum is simpler."""
        v, _why = self.call("PatternExpression", 5)
        self.assertEqual(v, "SUGGEST-ENUM")

    def test_a_large_non_ast_hierarchy_still_declines(self):
        v, why = self.call("MemBuffer", 100)
        self.assertIsNone(v)
        self.assertIn("too many for an enum", why)

    def test_extension_point_name_still_wins_over_graph(self):
        v, _why = self.call("ScriptProvider", 40)
        self.assertEqual(v, "SUGGEST-ACCEPT")



class TestJavaSizedVerdicts(unittest.TestCase):
    """The proposer sizes hierarchies from Java, not from how far the port has got.

    Counting Rust implementers in a 22%-complete port mostly measures what is missing: `CodeUnit`
    showed 3 non-mock impls only because Instruction and Data are unported, and the proposer
    happily recommended "small closed set -> enum" off that. These pin the corrected rules.
    """

    def call(self, name, rust_impls, java, decls=None, jdk=frozenset()):
        return dc.suggest_verdict(name, {name: 1}, {}, {name: rust_impls}, set(), {}, set(),
                                  java, decls or {}, jdk)

    def test_an_unported_concrete_class_is_a_seam_not_a_defect(self):
        """A trait standing in for a class that is not ported yet is a deliberate seam letting
        callers compile ahead of it -- TokenPattern's own doc comment says exactly that. A
        concrete type is still the right end state, but the work is to PORT the class, and
        calling it a shape defect would misdirect whoever picks it up."""
        v, why = dc.suggest_verdict(
            "Later", {"Later": 1}, {}, {"Later": 20}, {"Later"}, {}, set(),
            {"Later": 0}, {"Later": "class"}, frozenset())
        self.assertIsNone(v)
        self.assertIn("seam awaiting that port", why)

    def test_a_java_class_nothing_extends_should_not_be_a_trait(self):
        """`TokenPattern` is a concrete class in Java; nothing extends it, so a trait is wrong."""
        v, why = self.call("TokenPattern", 24, {"TokenPattern": 0}, {"TokenPattern": "class"})
        self.assertEqual(v, "SUGGEST-STRUCT")
        self.assertIn("no hierarchy to dispatch over", why)

    def test_an_enum_counts_as_concrete_too(self):
        v, _why = self.call("CheckoutType", 5, {"CheckoutType": 0}, {"CheckoutType": "enum"})
        self.assertEqual(v, "SUGGEST-STRUCT")

    def test_an_interface_with_no_in_tree_implementers_is_not_swept(self):
        """It may be an extension point, or its implementers may be unported. The count cannot
        tell which, so the proposer must decline rather than call it concrete."""
        v, why = self.call("ToolSet", 2, {"ToolSet": 0}, {"ToolSet": "interface"})
        self.assertIsNone(v)
        self.assertIn("cannot tell which", why)

    def test_a_name_java_never_declares_is_not_swept(self):
        """`IteratorStl`, `RepositoryLike`, `C13SectionLike` -- abstractions the port invented."""
        v, why = self.call("IteratorStl", 4, {"IteratorStl": 0}, {})
        self.assertIsNone(v)
        self.assertIn("the port invented", why)

    def test_a_port_modelling_a_jdk_type_is_not_paired_with_ghidras_class(self):
        """The Rust `Lock` trait documents java.util.concurrent.locks.Lock, while orig_src holds
        an unrelated ghidra.util.Lock class. An orig_src-only scan cannot see that collision."""
        v, why = self.call("Lock", 11, {"Lock": 0}, {"Lock": "class"}, jdk={"Lock"})
        self.assertIsNone(v)
        self.assertIn("models the JDK", why)

    def test_java_count_beats_a_misleading_rust_count(self):
        # 3 Rust impls would have said "small closed set"; Java says otherwise.
        v, why = self.call("BigHierarchy", 3, {"BigHierarchy": 40})
        self.assertIsNone(v)
        self.assertIn("40 Java subtypes", why)

    def test_small_java_hierarchy_suggests_enum(self):
        v, why = self.call("Decoder2", 16, {"Decoder2": 2})
        self.assertEqual(v, "SUGGEST-ENUM")
        self.assertIn("2 Java subtypes", why)

    def test_large_java_ast_hierarchy_suggests_graph(self):
        v, _why = self.call("PatternValue", 11, {"PatternValue": 14})
        self.assertEqual(v, "SUGGEST-GRAPH")

    def test_extension_point_name_still_wins_regardless_of_size(self):
        v, _why = self.call("ScriptProvider", 2, {"ScriptProvider": 30})
        self.assertEqual(v, "SUGGEST-ACCEPT")

    def test_falls_back_to_rust_counts_when_java_is_unavailable(self):
        v, why = self.call("Thing", 4, None)
        self.assertEqual(v, "SUGGEST-ENUM")
        self.assertIn("real implementers", why)


class TestJavaSubtypeScan(unittest.TestCase):
    def test_counts_extends_and_implements_including_lists(self):
        d = tempfile.mkdtemp()
        files = {
            "A.java": "public class A extends Base {}",
            "B.java": "public interface B extends Base {}",
            "C.java": "public class C implements Iface1, Iface2 {}",
            "D.java": "public class D extends pkg.Base implements Iface1 {}",
        }
        for name, body in files.items():
            write(os.path.join(d, name), body + chr(10))
        counts = dc.java_subtype_counts(d)
        self.assertEqual(counts["Base"], 3, "qualified names count too")
        self.assertEqual(counts["Iface1"], 2)
        self.assertEqual(counts["Iface2"], 1)
        self.assertEqual(counts["Nothing"], 0)


class TestSmallClosedSetFamilies(unittest.TestCase):
    """"Small closed set" is several questions with different answers (decided 2026-08-09).

    Classifying the 214 undecided 2-3-implementer types by what their implementers ARE, rather
    than how many there are, splits them into families the generic ENUM suggestion got wrong.
    """

    def test_storage_split_is_one_type_not_an_enum(self):
        v, note = dc.suggest_by_family("FunctionTag", ["FunctionTagDB", "InMemoryFunctionTag"])
        self.assertEqual(v, "SUGGEST-ARENA")
        self.assertIn("where the object was read from", note)

    def test_db_and_trace_backings_are_still_one_type(self):
        v, _ = dc.suggest_by_family("Instruction",
                                    ["DBTraceInstruction", "InstructionDB", "PseudoInstruction"])
        self.assertEqual(v, "SUGGEST-ARENA")

    def test_null_object_becomes_option_not_a_variant(self):
        v, note = dc.suggest_by_family("InstructionPrototype",
                                       ["InvalidPrototype", "SleighInstructionPrototype"])
        self.assertEqual(v, "SUGGEST-STRUCT")
        self.assertIn("Option<InstructionPrototype>", note)
        self.assertIn("SleighInstructionPrototype", note)

    def test_wrapper_needs_real_polymorphism(self):
        v, note = dc.suggest_by_family(
            "GDirectedGraph",
            ["JungDirectedGraph", "JungToGDirectedGraphAdapter", "MutableGDirectedGraphWrapper"])
        self.assertEqual(v, "SUGGEST-ACCEPT")
        self.assertIn("hold something polymorphic", note)

    def test_plain_siblings_fall_through_to_enum(self):
        """Language = OldLanguage + SleighLanguage has no storage/null/wrapper marker."""
        self.assertIsNone(dc.suggest_by_family("Language", ["OldLanguage", "SleighLanguage"]))

    def test_single_implementer_is_not_a_family_question(self):
        self.assertIsNone(dc.suggest_by_family("Trace", ["DBTrace"]))

    def test_all_backings_storage_still_counts_as_a_storage_split(self):
        """ProgramModule = ModuleDB + DBTraceProgramViewRootModule: both are DB-backed.

        An earlier draft required at least one NON-storage implementer, which dropped exactly
        the pairs where both sides are persistent.
        """
        v, _ = dc.suggest_by_family("ProgramModule",
                                    ["DBTraceProgramViewRootModule", "ModuleDB"])
        self.assertEqual(v, "SUGGEST-ARENA")


if __name__ == "__main__":
    unittest.main(verbosity=2)
