//! Mirrors `ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNumericTerminal`.

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::app::plugin::assembler::sleigh::grammars::AssemblyGrammar;
use crate::app::plugin::assembler::sleigh::symbol::AssemblyTerminal;
use crate::app::plugin::assembler::sleigh::tree::AssemblyParseNumericToken;
use crate::app::seam_stubs::AssemblyNumericSymbols;
use crate::program::model::address::AddressSpace;

/// Prefix marking a hexadecimal literal.
///
/// Mirrors `AssemblyNumericTerminal.PREFIX_HEX`.
pub const PREFIX_HEX: &str = "0x";

/// Prefix marking an octal literal.
///
/// Mirrors `AssemblyNumericTerminal.PREFIX_OCT`.
pub const PREFIX_OCT: &str = "0";

/// Some suggestions, other than labels, to provide.
///
/// Mirrors `AssemblyNumericTerminal.SUGGESTIONS`.
const SUGGESTIONS: &[&str] = &["0", "1", "0x0", "+0x0", "-0x0", "01"];

/// The maximum number of labels to suggest.
///
/// Mirrors `AssemblyNumericTerminal.MAX_LABEL_SUGGESTIONS`.
const MAX_LABEL_SUGGESTIONS: usize = 10;

/// A terminal that accepts any numeric value or program symbol (label, equate).
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNumericTerminal`, a concrete class
/// extending [`AssemblyTerminal`] that adds a `bitsize`/`space` pair on top of the inherited
/// `name`. This type was chosen as a cut-point for a dependency cycle running through the
/// grammar, terminal, and parse-tree types (the same cycle [`AssemblyTerminal`] and
/// [`AssemblyParseNumericToken`] were themselves cut for).
///
/// The literal may take any form accepted by UNIX `strtol()` with base 0: decimal by default, hex
/// with a `0x` prefix, octal with a `0` prefix. It may also be a label, in which case
/// [`AssemblyNumericSymbols`] resolves it to a set of candidate values.
///
/// Java's `match(String, int, AssemblyGrammar, AssemblyNumericSymbols)` overrides
/// `AssemblyTerminal.match(...)` with a covariant return type (`Collection<AssemblyParseNumericToken>`
/// instead of `Collection<AssemblyParseToken>`), which Rust traits cannot express as a literal
/// override. Following the same shadowing convention used by
/// [`AssemblyExtendedNonTerminal::get_name`](
/// crate::app::plugin::assembler::sleigh::symbol::AssemblyExtendedNonTerminal::get_name) and
/// [`AssemblyParseNumericToken::display_string`], this and the other overridden/protected methods
/// (`matchLiteral`, `makeToken`, `matchHex`, `matchDec`, `matchOct`, `getSuggestions`) are ported
/// as distinctly-named default methods (`match_numeric`, `match_literal`, `make_numeric_token`,
/// `match_hex`, `match_dec`, `match_oct`, `get_numeric_suggestions`) built on the required
/// [`bitsize`](Self::bitsize)/[`space`](Self::space) accessors. A concrete implementer (a future
/// port of a subclass such as `AssemblyFixedNumericTerminal`) is expected to wire
/// `AssemblyTerminal::match`/`get_suggestions` to these using its own concrete
/// `AssemblyParseNumericToken` type, exactly as `AssemblyExtendedNonTerminal`'s implementers wire
/// `AssemblyNonTerminal::get_name`.
///
/// Since [`AssemblyParseNumericToken`] is itself a trait rather than a concrete struct (having
/// been cut from the same cycle), constructing one requires knowing a concrete type that
/// implements it -- something this trait cannot know. [`make_token`](Self::make_token) is
/// therefore a required hook standing in for `new AssemblyParseNumericToken(grammar, this, str,
/// val)`; the default methods that need to build a token call it rather than constructing one
/// directly. Java's public `match(String)` convenience (documented as "only a convenience for
/// testing", superseded by the four-argument overload) is dropped for the same reason
/// [`AssemblyParseNumericToken`] dropped its constructor's `AssemblyGrammar` parameter: it exists
/// only to plug in `AssemblyNumericSymbols.EMPTY`, a concrete singleton this trait has no way to
/// conjure.
///
/// [`AssemblyGrammar`] is an already-ported trait, referenced here via `&dyn`/`Option<&dyn>`
/// (mirroring Java's nullable `AssemblyGrammar` parameter, passed as `null` from the testing
/// convenience). [`AssemblyNumericSymbols`] isn't ported yet; this port extends its existing
/// empty placeholder in [`crate::app::seam_stubs`] with the `choose`/`getSuggestions` surface this
/// type actually calls on it. [`AddressSpace`] is already a real ported type (a concrete,
/// cloneable struct), so [`space`](Self::space) uses it directly rather than through a
/// placeholder.
pub trait AssemblyNumericTerminal: AssemblyTerminal {
    /// The maximum size of the value in bits, or `0` if unbounded.
    ///
    /// Mirrors `AssemblyNumericTerminal.getBitSize()` (and the `bitsize` field it returns).
    fn bitsize(&self) -> i32;

    /// The address space this terminal represents, if it is an address operand.
    ///
    /// Mirrors `AssemblyNumericTerminal.getSpace()` (and the `space` field it returns). `None`
    /// mirrors Java's nullable field: this terminal isn't restricted to a particular address
    /// space.
    fn space(&self) -> Option<Arc<AddressSpace>>;

    /// Construct a numeric parse token for this terminal.
    ///
    /// Mirrors `new AssemblyParseNumericToken(grammar, this, str, val)`, as called from
    /// `makeToken` and from the label-resolution branch of `match(int, ...)`.
    fn make_token(
        &self,
        grammar: Option<&dyn AssemblyGrammar>,
        str_val: &str,
        num_val: i64,
    ) -> Arc<dyn AssemblyParseNumericToken>;

    /// Try to match a numeric literal or program label at the given position.
    ///
    /// Mirrors `AssemblyNumericTerminal.match(String, int, AssemblyGrammar,
    /// AssemblyNumericSymbols)`.
    fn match_numeric(
        &self,
        buffer: &str,
        pos: usize,
        grammar: Option<&dyn AssemblyGrammar>,
        symbols: &dyn AssemblyNumericSymbols,
    ) -> Vec<Arc<dyn AssemblyParseNumericToken>> {
        if pos >= buffer.len() {
            return Vec::new();
        }
        match buffer[pos..].chars().next() {
            Some('+') => self.match_literal(buffer, pos + '+'.len_utf8(), pos, false, grammar),
            Some('-') => self.match_literal(buffer, pos + '-'.len_utf8(), pos, true, grammar),
            _ => self.match_label_or_literal(buffer, pos, grammar, symbols),
        }
    }

    /// Try to match a sign-less numeric literal, or a program label.
    ///
    /// Mirrors the protected `AssemblyNumericTerminal.match(int, String, AssemblyGrammar,
    /// AssemblyNumericSymbols)`.
    fn match_label_or_literal(
        &self,
        buffer: &str,
        s: usize,
        grammar: Option<&dyn AssemblyGrammar>,
        symbols: &dyn AssemblyNumericSymbols,
    ) -> Vec<Arc<dyn AssemblyParseNumericToken>> {
        if s >= buffer.len() {
            return Vec::new();
        }
        if buffer[s..].starts_with(|c: char| c.is_ascii_digit()) {
            return self.match_literal(buffer, s, s, false, grammar);
        }
        let mut b = s;
        for c in buffer[s..].chars() {
            if c.is_alphanumeric() || c == '_' || c == '$' {
                b += c.len_utf8();
                continue;
            }
            break;
        }
        let lab = &buffer[s..b];
        let space = self.space();
        symbols
            .choose(lab, space.as_deref())
            .into_iter()
            .map(|val| self.make_token(grammar, lab, val))
            .collect()
    }

    /// Try to match a numeric literal, after the optional sign, encoded in hex, decimal, or
    /// octal.
    ///
    /// Mirrors the protected `AssemblyNumericTerminal.matchLiteral(int, String, int, boolean,
    /// AssemblyGrammar)`.
    fn match_literal(
        &self,
        buffer: &str,
        s: usize,
        pos: usize,
        neg: bool,
        grammar: Option<&dyn AssemblyGrammar>,
    ) -> Vec<Arc<dyn AssemblyParseNumericToken>> {
        if buffer[s..].starts_with(PREFIX_HEX) {
            self.match_hex(buffer, s + PREFIX_HEX.len(), pos, neg, grammar)
        }
        else if buffer[s..].starts_with(PREFIX_OCT) {
            self.match_oct(buffer, s + PREFIX_OCT.len(), pos, neg, grammar)
        }
        else {
            self.match_dec(buffer, s, pos, neg, grammar)
        }
    }

    /// Construct a numeric token from a parsed digit run, if it is in range for this terminal's
    /// bit size.
    ///
    /// Mirrors the protected `AssemblyNumericTerminal.makeToken(String, String, int, boolean,
    /// AssemblyGrammar)`.
    fn make_numeric_token(
        &self,
        str_val: &str,
        num: &str,
        radix: u32,
        neg: bool,
        grammar: Option<&dyn AssemblyGrammar>,
    ) -> Vec<Arc<dyn AssemblyParseNumericToken>> {
        if num.is_empty() {
            return Vec::new();
        }
        let Ok(unsigned) = u64::from_str_radix(num, radix) else {
            return Vec::new();
        };
        let mut val = unsigned as i64;
        if neg {
            val = -val;
        }
        let bitsize = self.bitsize();
        if bitsize != 0 && bitsize != 64 {
            if val < (-1i64) << (bitsize - 1) {
                return Vec::new();
            }
            if val >= 1i64 << bitsize {
                return Vec::new();
            }
        }
        vec![self.make_token(grammar, str_val, val)]
    }

    /// Try to match a hexadecimal literal, following the optional sign and prefix.
    ///
    /// Mirrors the protected `AssemblyNumericTerminal.matchHex(int, String, int, boolean,
    /// AssemblyGrammar)`.
    fn match_hex(
        &self,
        buffer: &str,
        s: usize,
        pos: usize,
        neg: bool,
        grammar: Option<&dyn AssemblyGrammar>,
    ) -> Vec<Arc<dyn AssemblyParseNumericToken>> {
        let mut b = s;
        for c in buffer[s..].chars() {
            if c.is_ascii_hexdigit() {
                b += c.len_utf8();
                continue;
            }
            break;
        }
        self.make_numeric_token(&buffer[pos..b], &buffer[s..b], 16, neg, grammar)
    }

    /// Try to match a decimal literal, following the optional sign and optional prefix.
    ///
    /// Mirrors the protected `AssemblyNumericTerminal.matchDec(int, String, int, boolean,
    /// AssemblyGrammar)`.
    fn match_dec(
        &self,
        buffer: &str,
        s: usize,
        pos: usize,
        neg: bool,
        grammar: Option<&dyn AssemblyGrammar>,
    ) -> Vec<Arc<dyn AssemblyParseNumericToken>> {
        let mut b = s;
        for c in buffer[s..].chars() {
            if c.is_ascii_digit() {
                b += c.len_utf8();
                continue;
            }
            break;
        }
        self.make_numeric_token(&buffer[pos..b], &buffer[s..b], 10, neg, grammar)
    }

    /// Try to match an octal literal, following the optional sign and prefix.
    ///
    /// Mirrors the protected `AssemblyNumericTerminal.matchOct(int, String, int, boolean,
    /// AssemblyGrammar)`.
    fn match_oct(
        &self,
        buffer: &str,
        s: usize,
        pos: usize,
        neg: bool,
        grammar: Option<&dyn AssemblyGrammar>,
    ) -> Vec<Arc<dyn AssemblyParseNumericToken>> {
        let mut b = s;
        for c in buffer[s..].chars() {
            if ('0'..='7').contains(&c) {
                b += c.len_utf8();
                continue;
            }
            break;
        }
        if b == s {
            // Then the entire token is just 0.
            self.make_numeric_token(&buffer[pos..b], "0", 8, neg, grammar)
        }
        else {
            self.make_numeric_token(&buffer[pos..b], &buffer[s..b], 8, neg, grammar)
        }
    }

    /// Provide a collection of strings that this terminal would have accepted.
    ///
    /// Mirrors `AssemblyNumericTerminal.getSuggestions(String, AssemblyNumericSymbols)`.
    fn get_numeric_suggestions(&self, got: &str, symbols: &dyn AssemblyNumericSymbols) -> Vec<String> {
        let mut s: BTreeSet<String> = SUGGESTIONS.iter().map(|lit| lit.to_string()).collect();
        let space = self.space();
        s.extend(symbols.get_suggestions(got, space.as_deref(), MAX_LABEL_SUGGESTIONS));
        s.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::assembler::sleigh::tree::AssemblyParseToken;
    use crate::app::seam_stubs::AssemblySymbol;
    use crate::program::model::address::AddressSpaceType;

    struct MockSymbols {
        labels: std::collections::BTreeMap<&'static str, i64>,
    }

    impl AssemblyNumericSymbols for MockSymbols {
        fn choose(&self, name: &str, _space: Option<&AddressSpace>) -> BTreeSet<i64> {
            self.labels.get(name).copied().into_iter().collect()
        }

        fn get_suggestions(
            &self,
            got: &str,
            _space: Option<&AddressSpace>,
            _max: usize,
        ) -> Vec<String> {
            self.labels
                .keys()
                .filter(|k| k.starts_with(got))
                .map(|k| k.to_string())
                .collect()
        }
    }

    #[derive(Clone)]
    struct NumericToken {
        term_tag: String,
        str_val: String,
        val: i64,
    }

    impl std::fmt::Display for ImmTerminal {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "[num{}:{}]", self.bitsize, self.name)
        }
    }

    impl AssemblySymbol for ImmTerminal {
        fn terminal_tag(&self) -> &str {
            &self.name
        }
    }

    impl AssemblyParseToken for NumericToken {
        fn get_string(&self) -> &str {
            &self.str_val
        }

        fn get_sym(&self) -> Arc<dyn AssemblyTerminal> {
            Arc::new(ImmTerminal {
                name: self.term_tag.clone(),
                bitsize: 0,
                space: None,
            })
        }
    }

    impl AssemblyParseNumericToken for NumericToken {
        fn get_numeric_value(&self) -> i64 {
            self.val
        }
    }

    struct ImmTerminal {
        name: String,
        bitsize: i32,
        space: Option<Arc<AddressSpace>>,
    }

    impl AssemblyTerminal for ImmTerminal {
        fn r#match(
            &self,
            buffer: &str,
            pos: usize,
            grammar: &dyn AssemblyGrammar,
            symbols: &dyn AssemblyNumericSymbols,
        ) -> Vec<Arc<dyn AssemblyParseToken>> {
            self.match_numeric(buffer, pos, Some(grammar), symbols)
                .into_iter()
                .map(|tok| -> Arc<dyn AssemblyParseToken> {
                    Arc::new(NumericToken {
                        term_tag: self.name.clone(),
                        str_val: tok.get_string().to_string(),
                        val: tok.get_numeric_value(),
                    })
                })
                .collect()
        }

        fn get_suggestions(&self, got: &str, symbols: &dyn AssemblyNumericSymbols) -> Vec<String> {
            self.get_numeric_suggestions(got, symbols)
        }
    }

    impl AssemblyNumericTerminal for ImmTerminal {
        fn bitsize(&self) -> i32 {
            self.bitsize
        }

        fn space(&self) -> Option<Arc<AddressSpace>> {
            self.space.clone()
        }

        fn make_token(
            &self,
            _grammar: Option<&dyn AssemblyGrammar>,
            str_val: &str,
            num_val: i64,
        ) -> Arc<dyn AssemblyParseNumericToken> {
            Arc::new(NumericToken {
                term_tag: self.name.clone(),
                str_val: str_val.to_string(),
                val: num_val,
            })
        }
    }

    struct NoopGrammar;
    impl AssemblyGrammar for NoopGrammar {
        fn add_production(&mut self, _prod: Arc<dyn crate::app::seam_stubs::AssemblyProduction>) {}
        fn add_constructor_production(
            &mut self,
            _lhs: Arc<dyn crate::app::seam_stubs::AssemblyNonTerminal>,
            _rhs: Arc<dyn crate::app::seam_stubs::AssemblySentential>,
            _pattern: crate::program::model::lang::sleigh::pattern::DisjointPattern,
            _cons: Arc<dyn crate::app::seam_stubs::Constructor>,
            _indices: Vec<usize>,
        ) {
        }
        fn get_semantics(
            &self,
            _prod: &dyn crate::app::seam_stubs::AssemblyProduction,
        ) -> Vec<Arc<dyn crate::app::seam_stubs::AssemblyConstructorSemantic>> {
            Vec::new()
        }
        fn get_semantic(
            &self,
            _cons: &dyn crate::app::seam_stubs::Constructor,
        ) -> Option<Arc<dyn crate::app::seam_stubs::AssemblyConstructorSemantic>> {
            None
        }
        fn combine(&mut self, _that: &dyn AssemblyGrammar) {}
        fn get_pure_recursive(&self) -> Vec<Arc<dyn crate::app::seam_stubs::AssemblyProduction>> {
            Vec::new()
        }
        fn get_pure_recursion(
            &self,
            _lhs: &dyn crate::app::seam_stubs::AssemblyNonTerminal,
        ) -> Option<Arc<dyn crate::app::seam_stubs::AssemblyProduction>> {
            None
        }
    }

    fn imm8() -> ImmTerminal {
        ImmTerminal {
            name: "imm8".to_string(),
            bitsize: 8,
            space: None,
        }
    }

    fn no_symbols() -> MockSymbols {
        MockSymbols {
            labels: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn matches_decimal_literal() {
        let term = imm8();
        let toks = term.match_numeric("100", 0, None, &no_symbols());
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].get_numeric_value(), 100);
        assert_eq!(toks[0].get_string(), "100");
    }

    #[test]
    fn matches_hex_literal() {
        let term = imm8();
        let toks = term.match_numeric("0x2a", 0, None, &no_symbols());
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].get_numeric_value(), 42);
        assert_eq!(toks[0].get_string(), "0x2a");
    }

    #[test]
    fn matches_octal_literal() {
        let term = imm8();
        let toks = term.match_numeric("017", 0, None, &no_symbols());
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].get_numeric_value(), 15);
    }

    #[test]
    fn bare_zero_is_octal_zero() {
        let term = imm8();
        let toks = term.match_numeric("0", 0, None, &no_symbols());
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].get_numeric_value(), 0);
    }

    #[test]
    fn matches_negative_literal() {
        let term = imm8();
        let toks = term.match_numeric("-5", 0, None, &no_symbols());
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].get_numeric_value(), -5);
        assert_eq!(toks[0].get_string(), "-5");
    }

    #[test]
    fn rejects_value_out_of_bitsize_range() {
        let term = imm8();
        // An 8-bit value's range is [-128, 255]; 256 overflows it.
        let toks = term.match_numeric("256", 0, None, &no_symbols());
        assert!(toks.is_empty());
    }

    #[test]
    fn accepts_min_signed_bitsize_value() {
        let term = imm8();
        let toks = term.match_numeric("-128", 0, None, &no_symbols());
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].get_numeric_value(), -128);
    }

    #[test]
    fn resolves_label_via_symbols() {
        let term = imm8();
        let mut labels = std::collections::BTreeMap::new();
        labels.insert("foo", 7i64);
        let symbols = MockSymbols { labels };
        let toks = term.match_numeric("foo", 0, None, &symbols);
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].get_numeric_value(), 7);
        assert_eq!(toks[0].get_string(), "foo");
    }

    #[test]
    fn unresolved_label_yields_no_tokens() {
        let term = imm8();
        let toks = term.match_numeric("bar", 0, None, &no_symbols());
        assert!(toks.is_empty());
    }

    #[test]
    fn get_numeric_suggestions_includes_defaults_and_labels() {
        let term = imm8();
        let mut labels = std::collections::BTreeMap::new();
        labels.insert("label1", 1i64);
        let symbols = MockSymbols { labels };
        let suggestions = term.get_numeric_suggestions("", &symbols);
        assert!(suggestions.contains(&"0".to_string()));
        assert!(suggestions.contains(&"label1".to_string()));
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let term = imm8();
        let as_dyn: &dyn AssemblyNumericTerminal = &term;
        assert_eq!(as_dyn.bitsize(), 8);
        let toks = as_dyn.match_numeric("42", 0, None, &no_symbols());
        assert_eq!(toks.len(), 1);
    }

    #[test]
    fn wired_through_assembly_terminal_match() {
        let term = imm8();
        let grammar = NoopGrammar;
        let symbols = no_symbols();
        let toks = AssemblyTerminal::r#match(&term, "42", 0, &grammar, &symbols);
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].get_string(), "42");
    }

    #[test]
    fn respects_address_space_hint() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let term = ImmTerminal {
            name: "addr".to_string(),
            bitsize: 32,
            space: Some(space),
        };
        assert!(term.space().is_some());
        assert_eq!(term.space().unwrap().name(), "ram");
    }
}
