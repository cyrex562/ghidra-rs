#!/usr/bin/env python3
"""Unit tests for dyn_rules.py -- deciding whether a `dyn T` is justified.

The cases here are the ones that made the first three drafts of this classifier wrong:

  * counting DIRECT subtypes says `TraceCodeUnit` has no implementations, because its
    subtypes are the sub-interfaces `TraceData` and `TraceInstruction`;
  * counting sub-interfaces and abstract bases as implementations says `DataType` has 12
    when it has 192, and inflates single-implementation interfaces into "closed sets";
  * counting test doubles and sub-interfaces says `Program` is implemented by StubProgram
    and by TraceProgramView, which is an interface -- the same mistake AGENTS.md records
    being made from the Rust side. Its real implementations are ProgramDB and the two
    concrete trace views reached through TraceProgramView.

    python3 scripts/test_dyn_rules.py
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import dyn_rules as dr
import shape_rules as sr


def facts_for(spec):
    """Build a fake index. spec: name -> (kind, abstract, [supertypes])."""
    facts, subtypes = {}, {}
    for name, (kind, is_abstract, supers) in spec.items():
        facts[name] = [dict(name=name, kind=kind, abstract=is_abstract, sealed=False,
                            extends=supers, implements=[], permits=[], rel=f"{name}.java")]
        for s in supers:
            subtypes.setdefault(s, set()).add(name)
    return facts, subtypes


class TestImplementerCounting(unittest.TestCase):
    def test_transitive_through_sub_interfaces(self):
        """TraceCodeUnit's subtypes are interfaces; the classes are one level further down."""
        facts, subtypes = facts_for({
            "TraceCodeUnit": ("interface", False, []),
            "TraceData": ("interface", False, ["TraceCodeUnit"]),
            "TraceInstruction": ("interface", False, ["TraceCodeUnit"]),
            "DBTraceData": ("class", False, ["TraceData"]),
            "DBTraceInstruction": ("class", False, ["TraceInstruction"]),
        })
        impls = sr.concrete_implementers("TraceCodeUnit", facts, subtypes, {})
        self.assertEqual(impls, {"DBTraceData", "DBTraceInstruction"})

    def test_abstract_bases_are_not_implementations(self):
        facts, subtypes = facts_for({
            "DataType": ("interface", False, []),
            "AbstractDataType": ("class", True, ["DataType"]),
            "ByteDataType": ("class", False, ["AbstractDataType"]),
        })
        self.assertEqual(sr.concrete_implementers("DataType", facts, subtypes, {}), {"ByteDataType"})

    def test_test_doubles_are_not_implementations(self):
        """StubProgram must not make a one-implementation interface look like a closed set."""
        facts, subtypes = facts_for({
            "Program": ("interface", False, []),
            "ProgramDB": ("class", False, ["Program"]),
            "StubProgram": ("class", False, ["Program"]),
            "MockProgram": ("class", False, ["Program"]),
        })
        self.assertEqual(sr.concrete_implementers("Program", facts, subtypes, {}), {"ProgramDB"})

    def test_adapter_suffix_is_not_treated_as_a_double(self):
        """In this codebase `*Adapter` usually names a real implementation."""
        facts, subtypes = facts_for({
            "BufferFile": ("interface", False, []),
            "BufferFileAdapter": ("class", False, ["BufferFile"]),
        })
        self.assertEqual(sr.concrete_implementers("BufferFile", facts, subtypes, {}),
                         {"BufferFileAdapter"})

    def test_cycles_do_not_hang(self):
        facts, subtypes = facts_for({
            "A": ("interface", False, ["B"]),
            "B": ("interface", False, ["A"]),
            "C": ("class", False, ["A"]),
        })
        self.assertEqual(sr.concrete_implementers("A", facts, subtypes, {}), {"C"})


class TestClassification(unittest.TestCase):
    def setUp(self):
        self.facts, self.subtypes = facts_for({
            "Trace": ("interface", False, []),
            "DBTrace": ("class", False, ["Trace"]),
            "TokenPattern": ("class", False, []),
            "Language": ("interface", False, []),
            "OldLanguage": ("class", False, ["Language"]),
            "SleighLanguage": ("class", False, ["Language"]),
            "Analyzer": ("interface", False, ["ExtensionPoint"]),
            "OneAnalyzer": ("class", False, ["Analyzer"]),
            "DataType": ("interface", False, []),
            **{f"D{i}": ("class", False, ["DataType"]) for i in range(9)},
        })

    def c(self, name):
        return dr.classify(name, self.facts, self.subtypes, {})

    def test_java_class_is_p1(self):
        self.assertEqual(self.c("TokenPattern")[0], "P1")

    def test_single_implementation_is_p2_when_that_type_is_ported(self):
        dr._PORTED = {"DBTrace"}
        try:
            pat, n, _ = self.c("Trace")
            self.assertEqual((pat, n), ("P2", 1))
            self.assertEqual(dr.VERDICT[pat], "fix")
        finally:
            dr._PORTED = None

    def test_single_implementation_is_a_SEAM_when_that_type_is_not_ported(self):
        """"Use DBTrace" is not advice a porter can follow when DBTrace is a seam stub.

        177 of 224 single-implementer types are in this state, and pattern_audit was charging
        the port for `dyn` it had no way to avoid.
        """
        dr._PORTED = set()
        try:
            pat, n, _ = self.c("Trace")
            self.assertEqual((pat, n), ("P2s", 1))
            self.assertEqual(dr.VERDICT[pat], "blocked")
        finally:
            dr._PORTED = None

    def test_two_implementations_is_p3_investigate(self):
        pat, n, _ = self.c("Language")
        self.assertEqual((pat, n), ("P3", 2))
        self.assertEqual(dr.VERDICT[pat], "investigate")

    def test_many_implementations_is_p5_ok(self):
        pat, n, _ = self.c("DataType")
        self.assertEqual(pat, "P5")
        self.assertEqual(dr.VERDICT[pat], "ok")

    def test_extension_point_is_ok_even_with_one_implementation(self):
        """A plugin interface is polymorphic over code that does not exist yet."""
        pat, n, _ = self.c("Analyzer")
        self.assertEqual((pat, n), ("P4", 1))
        self.assertEqual(dr.VERDICT[pat], "ok")

    def test_std_traits_are_skipped(self):
        for name in ("Any", "Error", "Iterator", "Fn"):
            self.assertEqual(dr.classify(name, self.facts, self.subtypes, {})[0], "??")

    def test_unknown_name_is_skipped_not_guessed(self):
        self.assertEqual(self.c("NoSuchThing")[0], "??")

    def test_ambiguous_basename_is_skipped(self):
        """PatternExpression is two unrelated Java classes; pairing by basename has been wrong."""
        facts = dict(self.facts)
        facts["PatternExpression"] = [
            dict(name="PatternExpression", kind="class", abstract=False, sealed=False,
                 extends=[], implements=[], permits=[], rel="a/PatternExpression.java"),
            dict(name="PatternExpression", kind="class", abstract=False, sealed=False,
                 extends=[], implements=[], permits=[], rel="b/PatternExpression.java"),
        ]
        self.assertEqual(dr.classify("PatternExpression", facts, self.subtypes, {})[0], "??")


class TestRealTree(unittest.TestCase):
    """Guard the live numbers the patterns were derived from."""

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(sr.ORIG):
            raise unittest.SkipTest("orig_src not present")
        cls.facts, cls.subtypes = sr.build_index()
        cls.cache = {}

    def c(self, name):
        return dr.classify(name, self.facts, self.subtypes, self.cache)

    def test_data_type_is_genuinely_polymorphic(self):
        pat, n, _ = self.c("DataType")
        self.assertEqual(pat, "P5")
        self.assertGreater(n, 100)

    def test_trace_has_a_single_implementation(self):
        """DBTrace is that implementation and is not ported, so Trace is a seam (P2s)."""
        pat, n, _ = self.c("Trace")
        self.assertEqual((pat, n), ("P2s", 1))
        self.assertNotIn("DBTrace", dr.ported_classes())

    def test_program_counts_only_real_implementations(self):
        """StubProgram is a test double and TraceProgramView is a sub-interface.

        Asserts WHAT is counted rather than which bucket that lands in: the bucket moved
        legitimately when test sourcesets were excluded from the index (StubProgram dropped
        out), and an assertion on the bucket would have failed for the right change.
        """
        impls = sr.concrete_implementers("Program", self.facts, self.subtypes, {})
        self.assertIn("ProgramDB", impls)
        self.assertNotIn("StubProgram", impls, "test double must not count")
        self.assertNotIn("TraceProgramView", impls, "a sub-interface is not an implementation")

    def test_token_pattern_is_a_class(self):
        self.assertEqual(self.c("TokenPattern")[0], "P1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
