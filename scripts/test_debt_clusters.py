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
import csv
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
        """A name with no Java counterpart under ANY of the port's renaming conventions.

        The original example here was `IteratorStl` -- which turned out to be
        generic/stl/IteratorSTL.java, differing only in acronym case. 142 of 197 rows called
        "abstractions the port invented" were that kind of near-miss, so this test now uses a
        name that really is absent.
        """
        v, why = self.call("ErasedPcodeThread", 4, {"ErasedPcodeThread": 0}, {})
        self.assertIsNone(v)
        self.assertIn("the port invented", why)

    def test_a_renamed_java_type_is_recognised_not_called_invented(self):
        """IteratorStl is IteratorSTL; MdMang is MDMang; MdMangLike is a seam for it."""
        for rust_name in ("IteratorStl", "MdMang", "MdMangLike"):
            v, why = self.call(rust_name, 4, {rust_name: 0}, {})
            self.assertNotIn("the port invented", why,
                             f"{rust_name} has a Java counterpart: {why}")
            # and it is answered from Java's own shape, not merely acknowledged
            self.assertTrue(v or "Java declares" in why or "Java subtypes" in why,
                            f"{rust_name} resolved but produced no evidence: {why}")

    def test_a_nested_java_type_is_recognised(self):
        """Lifespan.LifeSet has no file of its own, so a basename index cannot see it."""
        v, why = self.call("LifeSet", 4, {"LifeSet": 0}, {})
        self.assertNotIn("the port invented", why, why)

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


class TestPromotionValidation(unittest.TestCase):
    """A promotion is only as good as the evidence it was made on, and that evidence moves.

    The index changed under promoted verdicts three times: direct -> transitive subtype counts,
    test sourcesets excluded, nested implementations counted. OpBehaviorOther was promoted
    STRUCT as "one concrete implementer" and has 62 -- it is the per-processor CALLOTHER
    extension point.
    """

    def _queue(self, d, rows):
        p = os.path.join(d, "q.tsv")
        with open(p, "w", encoding="utf-8") as f:
            f.write("\t".join(dc.QUEUE_COLS) + "\n")
            for r in rows:
                f.write("\t".join(r) + "\n")
        return p

    def test_reset_when_the_claim_no_longer_holds(self):
        with tempfile.TemporaryDirectory() as d:
            q = self._queue(d, [
                ["STRUCT", "1", "1", "0", "Stale", "", "x", "promoted",
                 "one concrete Java implementer (Foo)"],
                ["STRUCT", "1", "1", "0", "Fine", "", "x", "promoted",
                 "one concrete Java implementer (Bar)"],
                ["ACCEPT", "1", "1", "0", "Handmade", "", "x", "manual",
                 "one concrete Java implementer (Baz)"],
            ])
            import shape_rules
            real = shape_rules.load_implementers
            shape_rules.load_implementers = lambda *a, **k: {
                "Stale": {"n_concrete": 62}, "Fine": {"n_concrete": 1},
                "Handmade": {"n_concrete": 62}}
            try:
                n = dc.validate_promotions(q)
            finally:
                shape_rules.load_implementers = real
            self.assertEqual(n, 1)
            got = {r["type"]: r["verdict"] for r in
                   csv.DictReader(open(q, newline="", encoding="utf-8"), delimiter="\t")}
            self.assertEqual(got["Stale"], "TODO", "claim broke -- must reset")
            self.assertEqual(got["Fine"], "STRUCT", "claim still holds")
            self.assertEqual(got["Handmade"], "ACCEPT",
                             "a hand-made decision is not a promotion and is never reset")


class TestDecisionsOutliveTheFrontier(unittest.TestCase):
    """A decided verdict must survive its type leaving the blocked set.

    Rows are built from types reached through convention-blocked files, so when the frontier
    shrinks a type stops being emitted and its verdict goes with it. That dropped 96 decided
    rows the day pattern_audit's exemption was tightened.
    """

    def test_decided_rows_are_carried_when_no_longer_reached(self):
        with tempfile.TemporaryDirectory() as d:
            prior = os.path.join(d, "q.tsv")
            with open(prior, "w", encoding="utf-8") as f:
                f.write("\t".join(dc.QUEUE_COLS) + "\n")
                f.write("ACCEPT\t5\t5\t0\tGoneButDecided\t\tx\tmanual\twhy\n")
                f.write("TODO\t5\t5\t0\tGoneUndecided\t\tx\t\t\n")
                f.write("SUGGEST-ENUM\t5\t5\t0\tGoneProposal\t\tx\tsuggest\t\n")
            got = dc.load_prior_verdicts(prior)
            self.assertIn(("GoneButDecided", ""), got)
            keep = [n for (n, _jc), (v, _s, _no) in got.items()
                    if v != "TODO" and not str(v).startswith("SUGGEST-")]
            self.assertEqual(keep, ["GoneButDecided"],
                             "only decisions are carried -- not TODOs or proposals")

    def test_prior_verdicts_key_on_type_AND_java_class(self):
        """Two rows for one basename must not collide -- that is the whole point of the split."""
        with tempfile.TemporaryDirectory() as d:
            prior = os.path.join(d, "q.tsv")
            with open(prior, "w", encoding="utf-8") as f:
                f.write("\t".join(dc.QUEUE_COLS) + "\n")
                f.write("STRUCT\t5\t5\t0\tPatternExpression\ta/sleigh/PatternExpression.java"
                        "\tx\tmanual\trt\n")
                f.write("GRAPH\t5\t5\t0\tPatternExpression\tb/pcodeCPort/PatternExpression.java"
                        "\tx\tmanual\tc\n")
            got = dc.load_prior_verdicts(prior)
            self.assertEqual(len(got), 2, "one row per Java class, not one per name")
            self.assertEqual(got[("PatternExpression", "a/sleigh/PatternExpression.java")][0],
                             "STRUCT")
            self.assertEqual(got[("PatternExpression", "b/pcodeCPort/PatternExpression.java")][0],
                             "GRAPH")


class TestQueueContents(unittest.TestCase):
    def test_rust_builtins_are_not_convention_decisions(self):
        """`Rc<RefCell<Vec<Foo>>>` makes the cell regex capture Vec, not Foo.

        The queue was carrying rows for Vec (leverage 31), bool, usize, HashMap, Box, String,
        Option and Self, all proposed PARK -- which reads as "undecidable" when the truth is
        "not a question".
        """
        for n in ("Vec", "Box", "HashMap", "Option", "String", "Self", "bool", "usize", "i32", "r"):
            self.assertFalse(dc.is_domain_type(n), n)

    def test_real_types_are_kept(self):
        for n in ("Trace", "DataType", "AddressSetView", "DBTraceCodeUnitAdapter"):
            self.assertTrue(dc.is_domain_type(n), n)

    def test_import_aliases_resolve_to_the_real_type(self):
        """`dyn StubRefType` is `RefType` under an alias, not a type of its own.

        Each unresolved alias grew a phantom queue row -- undeclared anywhere, proposed PARK
        as "not declared in the crate" -- while the real type lost those occurrences.
        """
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.rs")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write("use crate::program::seam_stubs::{RefType as StubRefType, "
                         "Reference as StubReference};\n"
                         "use crate::a::b::InstructionContext as LangInstructionContext;\n"
                         "fn f(a: &dyn StubRefType, b: Box<dyn StubReference>, "
                         "c: &dyn LangInstructionContext) {}\n")
            got = dc.types_in_file(p)
            self.assertIn("RefType", got)
            self.assertIn("Reference", got)
            self.assertIn("InstructionContext", got)
            for phantom in ("StubRefType", "StubReference", "LangInstructionContext"):
                self.assertNotIn(phantom, got)

    def test_unaliased_imports_are_untouched(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "y.rs")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write("use crate::a::Trace;\nfn f(t: &dyn Trace) {}\n")
            self.assertIn("Trace", dc.types_in_file(p))

    def test_types_in_file_drops_the_container(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.rs")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write("struct S { a: Rc<RefCell<Vec<Foo>>>, b: Arc<Mutex<bool>>, "
                         "c: Box<dyn Bar> }\n")
            got = dc.types_in_file(p)
            self.assertNotIn("Vec", got)
            self.assertNotIn("bool", got)
            self.assertIn("Bar", got)


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

    def test_null_object_needs_exactly_one_real_implementation(self):
        """Archive has four real implementers alongside InvalidFileArchive.

        "Delete the placeholder and port the concrete type" only makes sense when there IS a
        single concrete type; here it would have named four.
        """
        v = dc.suggest_by_family(
            "Archive",
            ["BuiltInArchive", "FileArchive", "InvalidFileArchive", "ProjectArchive",
             "LibraryArchive"],
            impl_table={n: {"concrete_implementers": []} for n in
                        ["BuiltInArchive", "FileArchive", "InvalidFileArchive",
                         "ProjectArchive", "LibraryArchive"]})
        self.assertIsNone(v, "a 5-member hierarchy is not a null-object pairing")

    def test_wrapper_needs_real_polymorphism(self):
        v, note = dc.suggest_by_family(
            "GDirectedGraph",
            ["JungDirectedGraph", "JungToGDirectedGraphAdapter", "MutableGDirectedGraphWrapper"])
        self.assertEqual(v, "SUGGEST-ACCEPT")
        self.assertIn("hold something polymorphic", note)

    def test_inheritance_chain_is_composition_not_an_enum(self):
        """AddressFactory's three implementers are a chain, not three alternatives.

        Program- and TraceAddressFactory both extend DefaultAddressFactory. An enum would
        model base/derived as siblings and duplicate the base behaviour across arms.
        """
        table = {
            "DefaultAddressFactory": {"concrete_implementers":
                                      ["ProgramAddressFactory", "TraceAddressFactory"]},
            "ProgramAddressFactory": {"concrete_implementers": []},
            "TraceAddressFactory": {"concrete_implementers": []},
        }
        v, note = dc.suggest_by_family(
            "AddressFactory",
            ["DefaultAddressFactory", "ProgramAddressFactory", "TraceAddressFactory"],
            impl_table=table)
        self.assertEqual(v, "SUGGEST-STRUCT")
        self.assertIn("extend(s) DefaultAddressFactory", note)
        self.assertIn("embed it", note)

    def test_versioned_db_adapters_are_not_wrappers(self):
        """ModuleDBAdapterV0 extends ModuleDBAdapter -- a schema version, not a wrapper.

        The implementer inherits "Adapter" from the family name, so testing the raw name
        ACCEPTed ten versioned DB adapter families and exempted them from debt scoring.
        """
        impls = ["ModuleDBAdapterV0", "ModuleDBAdapterV1"]
        v = dc.suggest_by_family("ModuleDBAdapter", impls,
                                 impl_table={i: {"concrete_implementers": []} for i in impls})
        self.assertIsNone(v, "a version suffix is not a wrapper")

    def test_wrapper_named_for_what_it_does_still_counts(self):
        v, note = dc.suggest_by_family("DomainFile", ["DomainFileProxy", "GhidraFile"],
                                       impl_table={"DomainFileProxy": {"concrete_implementers": []},
                                                   "GhidraFile": {"concrete_implementers": []}})
        self.assertEqual(v, "SUGGEST-ACCEPT")
        self.assertIn("DomainFileProxy", note)

    def test_plain_siblings_fall_through_to_enum(self):
        """Language = OldLanguage + SleighLanguage has no storage/null/wrapper marker."""
        self.assertIsNone(dc.suggest_by_family(
            "Language", ["OldLanguage", "SleighLanguage"],
            impl_table={"OldLanguage": {"concrete_implementers": []},
                        "SleighLanguage": {"concrete_implementers": []}}))

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



class TestEvidenceOrdering(unittest.TestCase):
    """Java's hierarchy outranks the port's progress (fixed 2026-08-09).

    The "only mock implementers" and "seam_stubs placeholder" deferrals used to run first and
    short-circuit, so 555 of 748 TODO rows were parked as "revisit once the port lands"
    without Java being asked -- and Java answered 417 of them.
    """

    def _call(self, name, **kw):
        base = dict(traits={name: 1}, types_={}, impls={}, unported=set(),
                    mock_impls={}, stub_decl=set(), java_subtypes={}, java_decls={},
                    jdk_modeled=frozenset(), java_impl_names={}, java_ext_points=set(),
                    java_ambiguous=set())
        base.update(kw)
        return dc.suggest_verdict(name, base["traits"], base["types_"], base["impls"],
                                  base["unported"], base["mock_impls"], base["stub_decl"],
                                  base["java_subtypes"], base["java_decls"],
                                  base["jdk_modeled"], base["java_impl_names"],
                                  base["java_ext_points"], None, base["java_ambiguous"])

    def test_java_answer_beats_only_mock_implementers(self):
        """19 Java implementers is still a human call -- but the REASON must be Java's.

        Previously this returned "only 68 mock implementer(s) ... revisit then", which sends
        the reader to wait for a port that would not have answered the question anyway.
        """
        v, note = self._call("Namespace", mock_impls={"Namespace": 68},
                             java_subtypes={"Namespace": 19}, java_decls={"Namespace": "interface"})
        self.assertNotIn("mock implementer", note)
        self.assertIn("19 Java subtypes", note)

    def test_java_answer_beats_mocks_when_java_is_decisive(self):
        v, note = self._call("ExternalLocation", mock_impls={"ExternalLocation": 12},
                             java_subtypes={"ExternalLocation": 1},
                             java_decls={"ExternalLocation": "interface"},
                             java_impl_names={"ExternalLocation": ["ExternalLocationDB"]})
        self.assertEqual(v, "SUGGEST-STRUCT")
        self.assertIn("ExternalLocationDB", note)

    def test_java_answer_beats_seam_stub_placeholder(self):
        v, note = self._call("TraceThread", stub_decl={"TraceThread"},
                             java_subtypes={"TraceThread": 1},
                             java_decls={"TraceThread": "interface"},
                             java_impl_names={"TraceThread": ["DBTraceThread"]})
        self.assertEqual(v, "SUGGEST-STRUCT")
        self.assertIn("DBTraceThread", note)

    def test_rust_deferral_still_applies_when_java_is_silent(self):
        """No Java entry at all -- the port-side evidence is all there is."""
        v, note = self._call("PortInvented", mock_impls={"PortInvented": 3},
                             java_subtypes={}, java_decls={})
        self.assertIsNone(v)
        self.assertIn("no Java type named", note)

    def test_ambiguous_basename_is_not_answered_from_the_name(self):
        """PatternExpression is two unrelated Java classes.

        Still refused -- but the refusal now says WHY and what to do, because the Rust tree
        already separates them (the runtime form under program/model/lang/sleigh/expression,
        the pcodeCPort AST node in decompiler/seam_stubs.rs). One queue row covering two
        types cannot be answered; splitting it can.
        """
        v, note = self._call("PatternExpression",
                             java_subtypes={"PatternExpression": 0},
                             java_decls={"PatternExpression": "class"},
                             java_ambiguous={"PatternExpression"})
        self.assertIsNone(v)
        self.assertIn("distinct Java classes", note)
        self.assertIn("Split the row", note)
        self.assertIn("pcodeCPort", note)

    def test_ambiguous_name_the_rust_tree_places_consistently_is_answerable(self):
        """If every Rust declaration of the name resolves to the SAME Java class, the shared
        basename is a tooling artefact, not a question."""
        dc._RESOLVE_CACHE["OnlyOnePlace"] = {"*": "a/b/OnlyOnePlace.java"}
        try:
            v, note = self._call("OnlyOnePlace",
                                 java_subtypes={"OnlyOnePlace": 1},
                                 java_decls={"OnlyOnePlace": "interface"},
                                 java_impl_names={"OnlyOnePlace": ["OnlyOnePlaceImpl"]},
                                 java_ambiguous={"OnlyOnePlace"})
            self.assertEqual(v, "SUGGEST-STRUCT")
        finally:
            dc._RESOLVE_CACHE.pop("OnlyOnePlace", None)

    def test_ambiguous_name_with_no_placeable_declaration_still_refuses(self):
        dc._RESOLVE_CACHE["Nowhere"] = None
        try:
            v, note = self._call("Nowhere", java_subtypes={"Nowhere": 0},
                                 java_decls={"Nowhere": "class"},
                                 java_ambiguous={"Nowhere"})
            self.assertIsNone(v)
            self.assertIn("cannot be placed", note)
        finally:
            dc._RESOLVE_CACHE.pop("Nowhere", None)

    def test_java_declarations_reports_duplicate_basenames(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            for sub, body in (("a", "public class Dup {}"), ("b", "public interface Dup {}"),
                              ("a", "public class Uniq {}")):
                os.makedirs(os.path.join(d, sub), exist_ok=True)
                nm = "Dup" if "Dup" in body else "Uniq"
                with open(os.path.join(d, sub, nm + ".java"), "w", encoding="utf-8") as fh:
                    fh.write(body)
            dc.java_declarations(d)
            self.assertIn("Dup", dc.java_declarations.ambiguous)
            self.assertNotIn("Uniq", dc.java_declarations.ambiguous)

    def test_jdk_collision_still_wins_over_java(self):
        """The orig_src type of that name is a different type entirely."""
        v, note = self._call("Lock", jdk_modeled=frozenset({"Lock"}),
                             java_subtypes={"Lock": 4}, java_decls={"Lock": "class"})
        self.assertIsNone(v)
        self.assertIn("models the JDK", note)

    def test_single_implementer_is_a_struct_not_a_one_variant_enum(self):
        v, note = self._call("Trace", java_subtypes={"Trace": 1},
                             java_decls={"Trace": "interface"},
                             java_impl_names={"Trace": ["DBTrace"]})
        self.assertEqual(v, "SUGGEST-STRUCT")
        self.assertIn("DBTrace", note)
        self.assertNotIn("closed set", note)

    def test_single_subclass_of_a_CLASS_says_composition_not_header_file(self):
        """BinaryReader is a Java class with one subclass, not an interface with one impl.

        Both answer STRUCT, but the reason differs and the note has to say which -- the first
        draft called every j==1 case "an interface naming a single implementation", which is
        simply false for a class.
        """
        v, note = self._call("BinaryReader", java_subtypes={"BinaryReader": 1},
                             java_decls={"BinaryReader": "class"},
                             java_impl_names={"BinaryReader": ["DumpFileReader"]})
        self.assertEqual(v, "SUGGEST-STRUCT")
        self.assertNotIn("an interface naming", note)
        self.assertIn("inheritance for reuse", note)
        self.assertIn("embed it", note)

    def test_extension_point_name_alone_does_not_earn_ACCEPT(self):
        """AddressFactory ends in "Factory" but is not an extension point.

        Its three implementers are DefaultAddressFactory and two subclasses of it. Accepting
        on the suffix would have exempted it -- and 37 others -- from debt scoring because of
        how they are spelled. 38 of 42 name-based ACCEPTs were in this state.
        """
        v, note = self._call("AddressFactory", java_subtypes={"AddressFactory": 3},
                             java_decls={"AddressFactory": "interface"},
                             java_impl_names={"AddressFactory": ["DefaultAddressFactory",
                                                                "ProgramAddressFactory",
                                                                "TraceAddressFactory"]},
                             java_ext_points=set())
        self.assertNotEqual(v, "SUGGEST-ACCEPT", f"name-only ACCEPT: {note}")

    def test_structural_extension_point_earns_ACCEPT(self):
        v, note = self._call("Analyzer", java_subtypes={"Analyzer": 2},
                             java_decls={"Analyzer": "interface"},
                             java_ext_points={"Analyzer"})
        self.assertEqual(v, "SUGGEST-ACCEPT")
        self.assertIn("extension-point supertype", note)

    def test_many_implementers_with_an_open_name_is_still_open(self):
        """ErrorHandler has 47 implementers -- open by count, whatever the name suggests."""
        v, note = self._call("ErrorHandler", java_subtypes={"ErrorHandler": 47},
                             java_decls={"ErrorHandler": "interface"}, java_ext_points=set())
        self.assertEqual(v, "SUGGEST-ACCEPT")

    def test_unported_concrete_class_is_still_a_seam_not_a_defect(self):
        """The work is to port the class, not to 'fix' the trait standing in for it."""
        v, note = self._call("TokenPattern", unported={"TokenPattern"},
                             java_subtypes={"TokenPattern": 0},
                             java_decls={"TokenPattern": "class"})
        self.assertIsNone(v)
        self.assertIn("seam awaiting that port", note)


if __name__ == "__main__":
    unittest.main(verbosity=2)
