#!/usr/bin/env python3
"""Unit tests for stub_audit.py.

Every case here is a bug this tool actually shipped, which is why it has tests now:

  * it counted only `use` statements, missing inline `crate::..::seam_stubs::Name` references,
    and so understated the backlog roughly 4x (MemBuffer: 23 reported, 116 real);
  * it paired a stub with a "real" type of the same BARE NAME, so `PatternExpression` -- two
    unrelated Java classes, the sleigh runtime expression and the pcodeCPort compiler's AST node
    -- was reported as an ENUM-vs-dyn design conflict. It is not a conflict at all;
  * it overloaded `status` with the ambiguity, so a preserved triage value hid it.

    python3 scripts/test_stub_audit.py
"""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import stub_audit as sa


def write(path, body):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(body)


class Fixture:
    """A throwaway crate root plus manifest."""

    def __init__(self):
        self.dir = tempfile.mkdtemp()
        self.root = os.path.join(self.dir, "src")
        os.makedirs(self.root, exist_ok=True)
        self.manifest = os.path.join(self.dir, "PORT_MANIFEST.tsv")
        self.java = []

    def rs(self, rel, body):
        write(os.path.join(self.root, rel), body)

    def java_class(self, path, status="DONE"):
        self.java.append(f"{path}\t{status}\tpkg\n")
        with open(self.manifest, "w", encoding="utf-8") as f:
            f.writelines(self.java)

    def build(self):
        return sa.build(self.root, self.manifest, None)


class TestShadowDetection(unittest.TestCase):
    def test_stub_without_a_real_counterpart_is_not_debt(self):
        f = Fixture()
        f.rs("seam_stubs.rs", "pub trait Widget {}\n")
        f.java_class("orig_src/x/Widget.java")
        rows, _ = f.build()
        self.assertEqual(rows, [], "a placeholder awaiting its port is legitimate")

    def test_stub_shadowing_a_real_type_is_reported(self):
        f = Fixture()
        f.rs("seam_stubs.rs", "pub trait Widget {}\n")
        f.rs("widget.rs", "pub trait Widget { fn go(&self); }\n")
        f.rs("user.rs", "use crate::seam_stubs::Widget;\n")
        f.java_class("orig_src/x/Widget.java")
        rows, _ = f.build()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["class"], "Widget")
        self.assertEqual(rows[0]["pairing"], "unique")
        self.assertEqual(rows[0]["importers"], 1)


class TestImporterCounting(unittest.TestCase):
    """The undercount bug: `use` statements are not the only way to name a stub."""

    def rows_for(self, user_body):
        f = Fixture()
        f.rs("seam_stubs.rs", "pub trait Widget {}\n")
        f.rs("widget.rs", "pub trait Widget {}\n")
        f.rs("user.rs", user_body)
        f.java_class("orig_src/x/Widget.java")
        return f.build()[0]

    def test_counts_a_plain_use(self):
        self.assertEqual(self.rows_for("use crate::seam_stubs::Widget;\n")[0]["importers"], 1)

    def test_counts_a_braced_use(self):
        self.assertEqual(
            self.rows_for("use crate::seam_stubs::{Other, Widget};\n")[0]["importers"], 1
        )

    def test_counts_a_multiline_braced_use(self):
        self.assertEqual(
            self.rows_for("use crate::seam_stubs::{\n    Other,\n    Widget,\n};\n")[0]["importers"],
            1,
        )

    def test_counts_a_fully_qualified_reference_with_no_use(self):
        """`impl crate::..::seam_stubs::Widget for X` -- the form that was invisible, and the
        exact form that had to be hand-fixed when retiring DataTypeManagerOwner."""
        self.assertEqual(
            self.rows_for("impl crate::seam_stubs::Widget for Thing {}\n")[0]["importers"], 1
        )


class TestAmbiguousPairing(unittest.TestCase):
    """Ghidra reuses simple names across packages; the tool must not invent a conflict."""

    def two_class_fixture(self):
        f = Fixture()
        f.rs("seam_stubs.rs", "pub trait PatternExpression {}\n")
        f.rs("expression.rs", "pub enum PatternExpression { A }\n")
        f.rs("user.rs", "use crate::seam_stubs::PatternExpression;\n")
        f.java_class("orig_src/x/ghidra/app/plugin/processors/sleigh/expression/PatternExpression.java")
        f.java_class("orig_src/x/ghidra/pcodeCPort/slghpatexpress/PatternExpression.java")
        return f

    def test_a_name_shared_by_two_java_classes_is_marked_ambiguous(self):
        rows, _ = self.two_class_fixture().build()
        self.assertEqual(rows[0]["pairing"], "ambiguous(2)")

    def test_both_java_classes_are_named_so_a_human_can_decide(self):
        rows, _ = self.two_class_fixture().build()
        self.assertIn("sleigh/expression/PatternExpression.java", rows[0]["java_classes"])
        self.assertIn("pcodeCPort/slghpatexpress/PatternExpression.java", rows[0]["java_classes"])

    def test_ambiguity_is_reported_even_when_triage_status_is_preserved(self):
        """It lives in its own column precisely because overloading `status` hid it: a row
        already triaged PARK still has to show that its pairing is unreliable."""
        f = self.two_class_fixture()
        out = os.path.join(f.dir, "STUB_DEBT.tsv")
        rows, _ = sa.build(f.root, f.manifest, out)
        rows[0]["status"] = "PARK"
        with open(out, "w", encoding="utf-8") as fh:
            fh.write("\t".join(sa.COLUMNS) + "\n")
            fh.write("\t".join(str(rows[0][c]) for c in sa.COLUMNS) + "\n")

        again, _ = sa.build(f.root, f.manifest, out)
        self.assertEqual(again[0]["status"], "PARK", "triage is preserved")
        self.assertEqual(again[0]["pairing"], "ambiguous(2)", "...and ambiguity still shows")

    def test_a_unique_name_is_not_marked_ambiguous(self):
        f = Fixture()
        f.rs("seam_stubs.rs", "pub trait Widget {}\n")
        f.rs("widget.rs", "pub trait Widget {}\n")
        f.java_class("orig_src/x/Widget.java")
        rows, _ = f.build()
        self.assertEqual(rows[0]["pairing"], "unique")


class TestOrdering(unittest.TestCase):
    def test_ambiguous_rows_sort_below_actionable_ones(self):
        f = Fixture()
        f.rs("seam_stubs.rs", "pub trait Amb {}\npub trait Solo {}\n")
        f.rs("amb.rs", "pub trait Amb {}\n")
        f.rs("solo.rs", "pub trait Solo {}\n")
        # Amb has more importers, but is not actionable
        f.rs("u1.rs", "use crate::seam_stubs::Amb;\n")
        f.rs("u2.rs", "use crate::seam_stubs::Amb;\n")
        f.rs("u3.rs", "use crate::seam_stubs::Solo;\n")
        f.java_class("orig_src/a/Amb.java")
        f.java_class("orig_src/b/Amb.java")
        f.java_class("orig_src/c/Solo.java")
        rows, _ = f.build()
        self.assertEqual(rows[0]["class"], "Solo", "actionable rows come first")
        self.assertEqual(rows[1]["pairing"], "ambiguous(2)")


if __name__ == "__main__":
    unittest.main(verbosity=2)
