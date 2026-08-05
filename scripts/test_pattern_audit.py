#!/usr/bin/env python3
"""Unit tests for pattern_audit.py -- the Java-idiom scanner behind OWNERSHIP_DEBT.tsv.

Covers the signal scanner, and the two frontier-file behaviours that are easy to break
silently and expensive when broken: --diff-new regression reporting, and --preserve-status
(without which a periodic refresh resets every DONE/PARK row to TODO and the migration
loses track of what it already handled).

    python3 scripts/test_pattern_audit.py
"""
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import pattern_audit as pa

AUDIT = os.path.join(HERE, "pattern_audit.py")
COLS = ["status", "priority", "score", "fanin", "class", "module", "path", "signals"]

SMELLY = """\
use std::rc::Rc;
pub struct Widget { inner: Rc<RefCell<dyn Foo>>, other: Arc<Mutex<dyn Bar>> }
impl Widget {
    pub fn get_name(&self) -> String { self.name.clone() }
    pub fn set_name(&mut self, n: String) { self.name = n; }
    pub fn boom(&self) -> u32 { self.v.unwrap() }
}
"""

CLEAN = """\
//! Replaces the old `Box<dyn Group>` / `Rc<RefCell<dyn Group>>` shape with an arena.
pub struct Tree { nodes: SlotMap<NodeId, Node> }
impl NodeId {
    pub fn name(self, t: &Tree) -> &str { &t.nodes[self].name }
}
"""


def write_file(path, body):
    with open(path, "w", encoding="utf-8") as f:
        f.write(body)


def write_tsv(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        f.write("\t".join(COLS) + "\n")
        for r in rows:
            f.write("\t".join(str(r.get(c, "")) for c in COLS) + "\n")


def read_tsv(path):
    with open(path, encoding="utf-8") as f:
        lines = [l.rstrip("\n") for l in f if l.strip()]
    return [dict(zip(COLS, l.split("\t"))) for l in lines[1:]]


def run_audit(*args):
    p = subprocess.run(
        [sys.executable, AUDIT, *args], capture_output=True, text=True, check=False
    )
    return p.stdout, p.stderr, p.returncode


class TestScanFile(unittest.TestCase):
    def test_smelly_file_scores_and_names_signals(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "widget.rs")
            write_file(p, SMELLY)
            score, signals = pa.scan_file(p)
            self.assertGreater(score, 3.0)
            joined = ",".join(signals)
            for expected in ("rc_refcell=", "arc_mutex=", "dyn=", "getset_pairs=1"):
                self.assertIn(expected, joined)

    def test_comments_naming_a_pattern_are_not_usages(self):
        """The pilot's own doc comment names Box<dyn>/Rc<RefCell<> in prose; that must not
        score as real usage -- this exact false positive is called out in the plan doc."""
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "group_tree.rs")
            write_file(p, CLEAN)
            score, signals = pa.scan_file(p)
            self.assertEqual(signals, [])
            self.assertEqual(score, 0.0)

    def test_unwrap_in_test_module_is_not_production_signal(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.rs")
            write_file(
                p,
                "pub fn f() -> u32 { 1 }\n#[cfg(test)]\nmod tests {\n"
                + "".join("    let _ = q.unwrap();\n" for _ in range(20))
                + "}\n",
            )
            _score, signals = pa.scan_file(p)
            self.assertFalse([s for s in signals if s.startswith("unwrap")])


class TestDiffNew(unittest.TestCase):
    def _root(self, d, body):
        root = os.path.join(d, "src")
        os.makedirs(root, exist_ok=True)
        write_file(os.path.join(root, "widget.rs"), body)
        return root

    def test_worsened_file_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            root = self._root(d, SMELLY)
            base = os.path.join(d, "base.tsv")
            run_audit("--root", root, "--seam", "/nonexistent", "--out", base)
            self._root(d, SMELLY + "pub struct B { a: Arc<Mutex<dyn Z>>, b: Box<dyn Y> }\n")
            out, _err, _rc = run_audit(
                "--root", root, "--seam", "/nonexistent", "--baseline", base, "--diff-new"
            )
            self.assertIn("widget.rs", out)
            self.assertIn("->", out)

    def test_unchanged_tree_reports_nothing_on_stdout(self):
        """audit_night.sh captures stdout and treats non-empty as 'regressions found', so a
        quiet run must put its status message on stderr, not stdout."""
        with tempfile.TemporaryDirectory() as d:
            root = self._root(d, SMELLY)
            base = os.path.join(d, "base.tsv")
            run_audit("--root", root, "--seam", "/nonexistent", "--out", base)
            out, err, _rc = run_audit(
                "--root", root, "--seam", "/nonexistent", "--baseline", base, "--diff-new"
            )
            self.assertEqual(out.strip(), "")
            self.assertIn("no new/worsened", err)


class TestPreserveStatus(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.root = os.path.join(self.d, "src")
        os.makedirs(self.root)
        write_file(os.path.join(self.root, "widget.rs"), SMELLY)
        self.out = os.path.join(self.d, "debt.tsv")
        run_audit("--root", self.root, "--seam", "/nonexistent", "--out", self.out)
        self.path = read_tsv(self.out)[0]["path"]

    def _mark(self, status, score=None):
        rows = read_tsv(self.out)
        rows[0]["status"] = status
        if score is not None:
            rows[0]["score"] = score
        write_tsv(self.out, rows)

    def test_plain_refresh_resets_status(self):
        """Documents the trap --preserve-status exists to avoid: without it, a refresh
        silently reopens every already-remediated row."""
        self._mark("DONE")
        run_audit("--root", self.root, "--seam", "/nonexistent", "--out", self.out)
        self.assertEqual(read_tsv(self.out)[0]["status"], "TODO")

    def test_preserve_keeps_done_and_park(self):
        for status in ("DONE", "PARK"):
            self._mark(status)
            run_audit(
                "--root", self.root, "--seam", "/nonexistent",
                "--preserve-status", "--out", self.out,
            )
            self.assertEqual(read_tsv(self.out)[0]["status"], status)

    def test_regressed_done_row_is_reopened(self):
        self._mark("DONE", score="1.0")  # pretend it was remediated down to ~nothing
        _out, err, _rc = run_audit(
            "--root", self.root, "--seam", "/nonexistent",
            "--preserve-status", "--out", self.out,
        )
        self.assertEqual(read_tsv(self.out)[0]["status"], "TODO")
        self.assertIn("reopened", err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
