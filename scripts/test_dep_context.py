#!/usr/bin/env python3
"""Unit tests for the Java-signature parser and Java->Rust type mapper in
dep_context.py. Pure functions only -- no repo I/O -- so these run anywhere.

    python3 scripts/test_dep_context.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dep_context as dc


class TestSnake(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(dc.to_snake("getToken"), "get_token")
        self.assertEqual(dc.to_snake("BTreeHeaderRecord"), "b_tree_header_record")
        self.assertEqual(dc.to_snake("getID"), "get_id")
        self.assertEqual(dc.to_snake("findSymbol"), "find_symbol")
        self.assertEqual(dc.to_snake("addGlobalSymbol"), "add_global_symbol")

    def test_keyword_escaped(self):
        self.assertEqual(dc.to_snake("type"), "type_")
        self.assertEqual(dc.to_snake("match"), "match_")


class TestTypeMap(unittest.TestCase):
    def test_primitives(self):
        self.assertEqual(dc.map_java_type("int"), "i32")
        self.assertEqual(dc.map_java_type("long"), "i64")
        self.assertEqual(dc.map_java_type("boolean"), "bool")
        self.assertEqual(dc.map_java_type("byte"), "i8")
        self.assertEqual(dc.map_java_type("double"), "f64")
        self.assertEqual(dc.map_java_type("char"), "char")
        self.assertEqual(dc.map_java_type("short"), "i16")
        self.assertEqual(dc.map_java_type("float"), "f32")

    def test_void(self):
        self.assertEqual(dc.map_java_type("void"), "()")

    def test_boxed(self):
        self.assertEqual(dc.map_java_type("Integer"), "i32")
        self.assertEqual(dc.map_java_type("Boolean"), "bool")

    def test_string_position(self):
        self.assertEqual(dc.map_java_type("String", "param"), "&str")
        self.assertEqual(dc.map_java_type("String", "return"), "String")

    def test_arrays(self):
        self.assertEqual(dc.map_java_type("byte[]", "param"), "&[i8]")
        self.assertEqual(dc.map_java_type("byte[]", "return"), "Vec<i8>")
        self.assertEqual(dc.map_java_type("int[]", "return"), "Vec<i32>")

    def test_varargs(self):
        # slice elements use owned types (&[String], not &[&str])
        self.assertEqual(dc.map_java_type("String...", "param"), "&[String]")
        self.assertEqual(dc.map_java_type("SleighSymbol...", "param"),
                         "&[Box<dyn SleighSymbol>]")

    def test_object(self):
        self.assertEqual(dc.map_java_type("Object", "param"), "&dyn std::any::Any")
        self.assertEqual(dc.map_java_type("Object", "return"), "Box<dyn std::any::Any>")

    def test_collections(self):
        self.assertEqual(dc.map_java_type("List<String>", "return"), "Vec<String>")
        self.assertEqual(dc.map_java_type("VectorSTL<SleighSymbol>", "return"),
                         "Vec<Box<dyn SleighSymbol>>")
        self.assertEqual(dc.map_java_type("Map<String,Integer>", "return"),
                         "std::collections::HashMap<String, i32>")

    def test_unknown_in_repo(self):
        self.assertEqual(dc.map_java_type("SleighSymbol", "param"), "&dyn SleighSymbol")
        self.assertEqual(dc.map_java_type("SleighSymbol", "return"), "Box<dyn SleighSymbol>")

    def test_qualified_name_stripped(self):
        self.assertEqual(dc.map_java_type("java.lang.String", "return"), "String")
        self.assertEqual(dc.map_java_type("ghidra.foo.Bar", "return"), "Box<dyn Bar>")

    def test_wildcards(self):
        # bare wildcard -> Any; bounded wildcard -> the bound; never invalid `dyn ?`
        self.assertEqual(dc.map_java_type("?", "return"), "Box<dyn std::any::Any>")
        self.assertEqual(dc.map_java_type("? extends Foo", "return"), "Box<dyn Foo>")
        self.assertEqual(dc.map_java_type("List<? extends Class>", "return"),
                         "Vec<Box<dyn Class>>")
        self.assertNotIn("?", dc.map_java_type("List<?>", "return"))

    def test_no_invalid_trait_object(self):
        # a garbage base can never yield `Box<dyn <non-ident>>`
        self.assertEqual(dc.map_java_type("a b c", "return"),
                         "Box<dyn std::any::Any>")


class TestSplitCommas(unittest.TestCase):
    def test_nested_generics(self):
        self.assertEqual(dc._split_top_commas("Map<String,Integer>, int x"),
                         ["Map<String,Integer>", "int x"])

    def test_empty(self):
        self.assertEqual(dc._split_top_commas(""), [])


class TestJavaParser(unittest.TestCase):
    def test_simple_class(self):
        src = """
        package p;
        public class TokenSymbol extends SleighSymbol {
            private Token tok;
            public TokenSymbol(Location location, Token t) { }
            public Token getToken() { return tok; }
            public symbol_type getType() { return null; }
        }
        """
        ms = dc.parse_java_public_methods(src, "TokenSymbol")
        names = {m["name"] for m in ms}
        self.assertEqual(names, {"getToken", "getType"})  # constructor excluded
        gt = next(m for m in ms if m["name"] == "getToken")
        self.assertEqual(gt["ret"], "Token")
        self.assertEqual(gt["params"], [])

    def test_params_and_throws(self):
        src = """
        public class X {
            public void encode(Encoder encoder) throws IOException { }
            public int addSymbol(SleighSymbol a) { return 0; }
            public SleighSymbol findSymbol(String nm, int skip) { return null; }
        }
        """
        ms = {m["name"]: m for m in dc.parse_java_public_methods(src, "X")}
        self.assertTrue(ms["encode"]["throws"])
        self.assertEqual(ms["encode"]["params"], [("Encoder", "encoder")])
        self.assertEqual(ms["addSymbol"]["ret"], "int")
        self.assertEqual(ms["findSymbol"]["params"],
                         [("String", "nm"), ("int", "skip")])

    def test_multiline_signature(self):
        src = """
        public class X {
            public VarnodeListSymbol(Location location, String nm, PatternValue pv,
                    int n) { }
            public VectorSTL<SleighSymbol> getUnsoughtSymbols() { return null; }
        }
        """
        ms = {m["name"]: m for m in dc.parse_java_public_methods(src, "X")}
        # constructor with wrapped params must NOT appear
        self.assertNotIn("VarnodeListSymbol", ms)
        self.assertEqual(ms["getUnsoughtSymbols"]["ret"], "VectorSTL<SleighSymbol>")

    def test_generic_method_decl_stripped(self):
        src = """
        public interface X {
            public <T> T cast(Object o);
        }
        """
        ms = dc.parse_java_public_methods(src, "X")
        self.assertEqual(ms[0]["name"], "cast")
        self.assertEqual(ms[0]["ret"], "T")

    def test_comments_ignored(self):
        src = """
        public class X {
            // public int commentedOut() {}
            /* public int alsoOut() {} */
            public int real() { return 0; }
        }
        """
        ms = dc.parse_java_public_methods(src, "X")
        self.assertEqual({m["name"] for m in ms}, {"real"})

    def test_overloads_collapsed_by_name(self):
        src = """
        public class X {
            public SleighSymbol findSymbol(String nm) { return null; }
            public SleighSymbol findSymbol(String nm, int skip) { return null; }
            public SleighSymbol findSymbol(int id) { return null; }
        }
        """
        ms = dc.parse_java_public_methods(src, "X")
        self.assertEqual(len([m for m in ms if m["name"] == "findSymbol"]), 1)


class TestStubRendering(unittest.TestCase):
    def test_stub_method_line(self):
        meth = {"name": "encode", "ret": "void",
                "params": [("Encoder", "encoder")], "throws": True}
        line = dc.render_stub_method(meth, referenced=set())
        self.assertEqual(
            line, "    fn encode(&self, encoder: &dyn Encoder) -> std::io::Result<()>;")

    def test_referenced_tag(self):
        meth = {"name": "getSize", "ret": "int", "params": [], "throws": False}
        line = dc.render_stub_method(meth, referenced={"getSize"})
        self.assertIn("[referenced in target]", line)
        self.assertIn("fn get_size(&self) -> i32;", line)

    def test_trait_has_unique_method_names(self):
        src = """
        public class X {
            public int findSymbol(String nm) { return 0; }
            public int findSymbol(String nm, int s) { return 0; }
        }
        """
        ms = dc.parse_java_public_methods(src, "X")
        code = dc.build_stub_trait("X", "Target", ms, set(), False)
        # exactly one fn find_symbol -> valid Rust (no duplicate method names)
        self.assertEqual(code.count("fn find_symbol("), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
