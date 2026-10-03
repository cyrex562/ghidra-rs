//! Models `ghidra.pcodeCPort.slghsymbol.TokenSymbol`.

use super::sleigh_symbol::SleighSymbol;
use super::symbol_type::SymbolType;
use crate::decompiler::context::token::Token;
use crate::sleigh::grammar::location::Location;

/// A symbol naming a SLEIGH token definition.
///
/// Models `ghidra.pcodeCPort.slghsymbol.TokenSymbol`, which extends `SleighSymbol` and adds
/// only the [`Token`] it names.
pub struct TokenSymbol {
    symbol: SleighSymbol,
    tok: Token,
}

impl TokenSymbol {
    /// Creates a new token symbol at the given location, named after `tok`.
    ///
    /// Mirrors the Java `TokenSymbol(Location, Token)` constructor.
    pub fn new(location: Location, tok: Token) -> Self {
        Self {
            symbol: SleighSymbol::with_name(location, tok.name().to_string()),
            tok,
        }
    }

    /// Gets the token this symbol names.
    pub fn token(&self) -> &Token {
        &self.tok
    }

    /// Returns the symbol type for a token symbol.
    pub fn symbol_type(&self) -> SymbolType {
        SymbolType::TokenSymbol
    }

    /// Gets a reference to the base SleighSymbol.
    pub fn symbol(&self) -> &SleighSymbol {
        &self.symbol
    }

    /// Gets a mutable reference to the base SleighSymbol.
    pub fn symbol_mut(&mut self) -> &mut SleighSymbol {
        &mut self.symbol
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc() -> Location {
        Location::new("test.sla", 1)
    }

    #[test]
    fn new_creates_symbol_with_token_name() {
        let tok = Token::new("imm8", 8, true, 0);
        let sym = TokenSymbol::new(loc(), tok);
        assert_eq!(sym.symbol().name(), "imm8");
        assert_eq!(sym.symbol_type(), SymbolType::TokenSymbol);
    }

    #[test]
    fn token_getter_returns_reference() {
        let tok = Token::new("op1", 16, false, 1);
        let sym = TokenSymbol::new(loc(), tok);
        assert_eq!(sym.token().name(), "op1");
        assert_eq!(sym.token().size(), 16);
        assert!(!sym.token().is_big_endian());
    }

    #[test]
    fn can_access_base_symbol() {
        let tok = Token::new("op2", 8, true, 2);
        let sym = TokenSymbol::new(loc(), tok);
        let base = sym.symbol();
        assert_eq!(base.name(), "op2");
    }

    #[test]
    fn can_mutate_via_symbol_mut() {
        let tok = Token::new("op3", 8, true, 3);
        let mut sym = TokenSymbol::new(loc(), tok);
        sym.symbol_mut().set_was_sought(true);
        assert!(sym.symbol().was_sought());
    }
}
