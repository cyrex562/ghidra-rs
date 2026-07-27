//! Mirrors `ghidra.app.plugin.assembler.sleigh.grammars.AssemblySentential`.

use std::sync::Arc;

use crate::app::seam_stubs::AssemblySymbol;

/// A "string" of symbols.
///
/// To avoid overloading the word "string", Java calls this a "sentential". Technically, to be a
/// "sentential" in the classic sense, it must be a possible element in the derivation of a
/// sentence in the grammar starting with the start symbol; Java's own doc comment notes it
/// ignores that nuance for the sake of naming, and this port follows suit.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.grammars.AssemblySentential<NT extends
/// AssemblyNonTerminal>`, a concrete class chosen as the cut-point for a dependency cycle running
/// through the grammar, production, and symbol types (the placeholder this replaces was
/// referenced by [`AssemblyGrammar`](crate::app::plugin::assembler::sleigh::grammars::AssemblyGrammar)
/// and [`AssemblyExtendedGrammar`](
/// crate::app::plugin::assembler::sleigh::grammars::AssemblyExtendedGrammar)). Java's `NT`
/// generic parameter is dropped -- it never appears in the class body except as a compile-time
/// bound on `compareTo`/`sub`'s return type, so it carries no runtime data for this trait to
/// model.
///
/// Unlike the other cut-point traits in this cycle, `AssemblySentential.java`'s public methods
/// are almost entirely *self-contained*: `addWS`, `addCommaWS`, `addSeparatorPart`,
/// `addSeparators`, `toString`, and `compareTo` are pure functions of the symbol list itself, so
/// they're ported as default methods built on a small required core:
/// [`add_symbol`](Self::add_symbol), [`get_symbols`](Self::get_symbols),
/// [`finish`](Self::finish), and [`sub`](Self::sub) (storage-dependent, since this trait has no
/// field of its own) plus two construction hooks, [`white_space_symbol`](Self::white_space_symbol)
/// and [`make_string_terminal`](Self::make_string_terminal), standing in for `new
/// AssemblyStringTerminal(str, null)` and the static `WHITE_SPACE` singleton (an instance of
/// Java's private `WhiteSpace` nested class) -- `AssemblyStringTerminal` isn't ported yet, so a
/// concrete implementer must supply these the same way
/// [`AssemblyNumericTerminal::make_token`](
/// crate::app::plugin::assembler::sleigh::symbol::AssemblyNumericTerminal::make_token) stands in
/// for a construction this trait cannot perform itself. [`AssemblySymbol`] is the crate's existing
/// placeholder trait in [`crate::app::seam_stubs`]; its `terminal_tag()` (documented there as
/// standing in for `AssemblySymbol`'s LAZY `equals`/`hashCode`, both defined in terms of
/// `toString()`) is used here in place of Java's `instanceof WhiteSpace` check in the private
/// `lastWhiteSpace()` helper, since a trait object has no way to test for a specific concrete
/// implementer.
///
/// Java's `hashCode()` is not mapped: the class overrides `hashCode()` but *not* `equals()`, so it
/// inherits `Object`'s identity-based `equals()` -- pairing it with a value-based hash would be
/// unsound and reproducing it would be meaningless without also reproducing reference equality
/// (which `Arc::ptr_eq` already gives callers directly). `compareTo` and `toString`, by contrast,
/// are genuinely value-based and are ported as [`compare_to`](Self::compare_to) and
/// [`display_string`](Self::display_string) (named per the `display_string`/`fixed_display_string`
/// convention used elsewhere in this crate for ported `toString()` overrides, e.g.
/// [`AssemblyParseToken::display_string`](
/// crate::app::plugin::assembler::sleigh::tree::AssemblyParseToken::display_string)).
///
/// The private `WhiteSpace` terminal's `match`/`getSuggestions` implementation, and the public
/// nested `WhiteSpaceParseToken`/`TruncatedWhiteSpaceParseToken` classes it and
/// `AssemblyParseMachine` use, belong to the terminal-matching concern (`AssemblyTerminal::match`)
/// rather than to the sentential-building API this trait models -- nothing in this crate
/// references them yet, so they're left for `AssemblyStringTerminal`'s own future port.
pub trait AssemblySentential {
    /// Add a symbol to the right of this sentential.
    ///
    /// Mirrors `AssemblySentential.addSymbol(AssemblySymbol)`, which always returns `true`
    /// (`List.add`'s contract). Implementations that freeze their state in [`finish`](Self::finish)
    /// should make this a no-op (returning `false`) afterward, mirroring the
    /// `UnsupportedOperationException` Java's unmodifiable list throws once frozen.
    fn add_symbol(&mut self, symbol: Arc<dyn AssemblySymbol>) -> bool;

    /// Get the symbols in this sentential.
    ///
    /// Mirrors `AssemblySentential.getSymbols()`, returning cloned handles rather than Java's
    /// unmodifiable list view.
    fn get_symbols(&self) -> Vec<Arc<dyn AssemblySymbol>>;

    /// Trim leading and trailing whitespace, and make the sentential immutable.
    ///
    /// Mirrors `AssemblySentential.finish()`. Left as a required hook since freezing is a
    /// storage-level concern this trait has no state of its own to perform.
    fn finish(&mut self);

    /// Extract the sub-sentential spanning `[from_index, to_index)`.
    ///
    /// Mirrors `AssemblySentential.sub(int, int)`. A required hook (rather than a default method)
    /// since constructing a new `Self` generically isn't possible through a trait object; a
    /// concrete implementer knows how to build one of itself.
    fn sub(&self, from_index: usize, to_index: usize) -> Box<dyn AssemblySentential>;

    /// The "optional whitespace" terminal, standing in for the static `AssemblySentential.WHITE_SPACE`
    /// singleton (an instance of the private `WhiteSpace` class extending the unported
    /// `AssemblyStringTerminal`).
    ///
    /// A construction hook: this trait cannot conjure an `AssemblyStringTerminal` itself.
    fn white_space_symbol(&self) -> Arc<dyn AssemblySymbol>;

    /// Construct a terminal that accepts only the given literal string.
    ///
    /// Mirrors `new AssemblyStringTerminal(str, null)`, as called from `addCommaWS` and
    /// `addSeparatorPart`. A construction hook for the same reason as
    /// [`white_space_symbol`](Self::white_space_symbol).
    fn make_string_terminal(&self, str: &str) -> Arc<dyn AssemblySymbol>;

    /// Get the symbol at the given position.
    ///
    /// Mirrors `AssemblySentential.getSymbol(int)`. Panics if `pos` is out of bounds, matching
    /// Java's `List.get` throwing `IndexOutOfBoundsException`.
    fn get_symbol(&self, pos: usize) -> Arc<dyn AssemblySymbol> {
        self.get_symbols()[pos].clone()
    }

    /// Get the number of symbols, including whitespace, in this sentential.
    ///
    /// Mirrors `AssemblySentential.size()`.
    fn size(&self) -> usize {
        self.get_symbols().len()
    }

    /// If the right-most symbol is whitespace, return it.
    ///
    /// Mirrors the private `AssemblySentential.lastWhiteSpace()`, which tests `instanceof
    /// WhiteSpace`; this compares [`AssemblySymbol::terminal_tag`] against
    /// [`white_space_symbol`](Self::white_space_symbol)'s tag instead, since a trait object has no
    /// `instanceof`.
    fn last_white_space(&self) -> Option<Arc<dyn AssemblySymbol>> {
        let symbols = self.get_symbols();
        let last = symbols.last()?;
        if last.terminal_tag() == self.white_space_symbol().terminal_tag() {
            Some(last.clone())
        }
        else {
            None
        }
    }

    /// Add optional whitespace, if not already preceded by whitespace.
    ///
    /// Mirrors `AssemblySentential.addWS()`.
    fn add_ws(&mut self) -> bool {
        if self.last_white_space().is_some() {
            return false;
        }
        let ws = self.white_space_symbol();
        self.add_symbol(ws)
    }

    /// Add a comma followed by optional whitespace.
    ///
    /// Mirrors `AssemblySentential.addCommaWS()`.
    fn add_comma_ws(&mut self) {
        let comma = self.make_string_terminal(",");
        self.add_symbol(comma);
        self.add_ws();
    }

    /// Add a syntactic terminal element, but with consideration for optional whitespace
    /// surrounding special characters.
    ///
    /// Mirrors `AssemblySentential.addSeparatorPart(String)`.
    fn add_separator_part(&mut self, str: &str) {
        let tstr = str.trim();
        if tstr.is_empty() {
            self.add_ws();
            return;
        }
        let first = tstr.chars().next().unwrap();
        if !str.starts_with(tstr) {
            self.add_ws();
        }
        if !first.is_alphanumeric() {
            self.add_ws();
        }
        let term = self.make_string_terminal(tstr);
        self.add_symbol(term);
        let last = tstr.chars().next_back().unwrap();
        if !str.ends_with(tstr) {
            self.add_ws();
        }
        if !last.is_alphanumeric() {
            self.add_ws();
        }
    }

    /// Add a syntactic terminal element, but considering that commas contained within may be
    /// followed by optional whitespace.
    ///
    /// Mirrors `AssemblySentential.addSeparators(String)`, inlining the private static
    /// `forMatchUnmatch` helper (which Java uses only here).
    fn add_separators(&mut self, str: &str) {
        static PAT_COMMA_WS: once_cell::sync::Lazy<regex::Regex> =
            once_cell::sync::Lazy::new(|| regex::Regex::new(r",\s+").unwrap());
        let mut start_u = 0;
        for mat in PAT_COMMA_WS.find_iter(str) {
            if start_u < mat.start() {
                self.add_separator_part(&str[start_u..mat.start()]);
            }
            self.add_comma_ws();
            start_u = mat.end();
        }
        if start_u < str.len() {
            self.add_separator_part(&str[start_u..]);
        }
    }

    /// Iterate over the symbols in this sentential.
    ///
    /// Mirrors `AssemblySentential.iterator()` (`Iterable<AssemblySymbol>`).
    fn iter(&self) -> Box<dyn Iterator<Item = Arc<dyn AssemblySymbol>> + '_> {
        Box::new(self.get_symbols().into_iter())
    }

    /// Compare this sentential to another, symbol-by-symbol, then by length.
    ///
    /// Mirrors `AssemblySentential.compareTo(AssemblySentential<NT>)`, which itself calls the
    /// LAZY `AssemblySymbol.compareTo` (`toString().compareTo(that.toString())`) -- reproduced
    /// here via [`AssemblySymbol`]'s `Display` bound.
    fn compare_to(&self, that: &dyn AssemblySentential) -> std::cmp::Ordering {
        let a = self.get_symbols();
        let b = that.get_symbols();
        let min = a.len().min(b.len());
        for i in 0..min {
            let ord = a[i].to_string().cmp(&b[i].to_string());
            if ord != std::cmp::Ordering::Equal {
                return ord;
            }
        }
        a.len().cmp(&b.len())
    }

    /// Render this sentential as a space-separated string of its symbols, or `"e"` (epsilon) if
    /// empty.
    ///
    /// Mirrors `AssemblySentential.toString()`.
    fn display_string(&self) -> String {
        let symbols = self.get_symbols();
        if symbols.is_empty() {
            return "e".to_string();
        }
        symbols
            .iter()
            .map(|sym| sym.to_string())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct TestSymbol(String);

    impl std::fmt::Display for TestSymbol {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl AssemblySymbol for TestSymbol {
        fn terminal_tag(&self) -> &str {
            &self.0
        }
    }

    /// A minimal implementer backed by a plain `Vec`, proving object-safety and exercising the
    /// default methods' real (non-trivial) behavior rather than trivially-true assertions.
    #[derive(Default, Clone)]
    struct TestSentential {
        symbols: Vec<Arc<dyn AssemblySymbol>>,
        finished: bool,
    }

    impl AssemblySentential for TestSentential {
        fn add_symbol(&mut self, symbol: Arc<dyn AssemblySymbol>) -> bool {
            if self.finished {
                return false;
            }
            self.symbols.push(symbol);
            true
        }

        fn get_symbols(&self) -> Vec<Arc<dyn AssemblySymbol>> {
            self.symbols.clone()
        }

        fn finish(&mut self) {
            self.finished = true;
        }

        fn sub(&self, from_index: usize, to_index: usize) -> Box<dyn AssemblySentential> {
            Box::new(TestSentential {
                symbols: self.symbols[from_index..to_index].to_vec(),
                finished: false,
            })
        }

        fn white_space_symbol(&self) -> Arc<dyn AssemblySymbol> {
            Arc::new(TestSymbol("_".to_string()))
        }

        fn make_string_terminal(&self, str: &str) -> Arc<dyn AssemblySymbol> {
            Arc::new(TestSymbol(format!("\"{}\"", str)))
        }
    }

    #[test]
    fn empty_sentential_displays_as_epsilon() {
        let s = TestSentential::default();
        assert_eq!(s.display_string(), "e");
        assert_eq!(s.size(), 0);
    }

    #[test]
    fn add_ws_is_idempotent() {
        let mut s = TestSentential::default();
        assert!(s.add_ws());
        assert!(!s.add_ws());
        assert_eq!(s.size(), 1);
    }

    #[test]
    fn add_comma_ws_appends_comma_then_whitespace() {
        let mut s = TestSentential::default();
        s.add_comma_ws();
        assert_eq!(s.size(), 2);
        assert_eq!(s.display_string(), "\",\" _");
    }

    #[test]
    fn add_separator_part_wraps_non_alnum_with_whitespace() {
        let mut s = TestSentential::default();
        s.add_separator_part("+");
        assert_eq!(s.display_string(), "_ \"+\" _");
    }

    #[test]
    fn add_separator_part_leaves_alnum_bare() {
        let mut s = TestSentential::default();
        s.add_separator_part("foo");
        assert_eq!(s.display_string(), "\"foo\"");
    }

    #[test]
    fn add_separators_splits_on_commas_with_whitespace() {
        let mut s = TestSentential::default();
        s.add_separators("foo, bar");
        assert_eq!(s.size(), 4);
        assert_eq!(s.display_string(), "\"foo\" \",\" _ \"bar\"");
    }

    #[test]
    fn sub_extracts_a_sub_range() {
        let mut s = TestSentential::default();
        s.add_symbol(Arc::new(TestSymbol("a".to_string())));
        s.add_symbol(Arc::new(TestSymbol("b".to_string())));
        s.add_symbol(Arc::new(TestSymbol("c".to_string())));
        let sub = s.sub(1, 3);
        assert_eq!(sub.size(), 2);
        assert_eq!(sub.display_string(), "b c");
    }

    #[test]
    fn finish_prevents_further_mutation() {
        let mut s = TestSentential::default();
        s.add_symbol(Arc::new(TestSymbol("a".to_string())));
        s.finish();
        assert!(!s.add_symbol(Arc::new(TestSymbol("b".to_string()))));
        assert_eq!(s.size(), 1);
    }

    #[test]
    fn compare_to_orders_by_symbol_then_length() {
        let mut a = TestSentential::default();
        a.add_symbol(Arc::new(TestSymbol("a".to_string())));

        let mut b = TestSentential::default();
        b.add_symbol(Arc::new(TestSymbol("a".to_string())));
        b.add_symbol(Arc::new(TestSymbol("b".to_string())));

        assert_eq!(a.compare_to(&b), std::cmp::Ordering::Less);
        assert_eq!(b.compare_to(&a), std::cmp::Ordering::Greater);
        assert_eq!(a.compare_to(&a.clone()), std::cmp::Ordering::Equal);
    }

    #[test]
    fn iter_yields_symbols_in_order() {
        let mut s = TestSentential::default();
        s.add_symbol(Arc::new(TestSymbol("x".to_string())));
        s.add_symbol(Arc::new(TestSymbol("y".to_string())));
        let tags: Vec<String> = s.iter().map(|sym| sym.terminal_tag().to_string()).collect();
        assert_eq!(tags, vec!["x".to_string(), "y".to_string()]);
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let s = TestSentential::default();
        let as_dyn: &dyn AssemblySentential = &s;
        assert_eq!(as_dyn.size(), 0);
        assert_eq!(as_dyn.display_string(), "e");
    }
}
