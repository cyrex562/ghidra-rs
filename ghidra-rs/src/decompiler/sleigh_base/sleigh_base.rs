use super::named_symbol_provider::NamedSymbolProvider;
use crate::decompiler::context::SleighError;
use crate::decompiler::seam_stubs::Translate;
use crate::decompiler::slghsymbol::SleighSymbol;
use crate::decompiler::space::AddrSpace;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::VarnodeData;
use crate::sleigh::grammar::{Location, RadixBigInteger, RadixBigIntegerError};
use std::io;

/// Maximum size, in bytes, of a varnode in the unique space.
///
/// Mirrors `SleighBase.MAX_UNIQUE_SIZE`. Must match the corresponding value defined by
/// `sleighbase.cc`. Kept as a module-level constant rather than an associated trait const, since
/// associated consts would make this trait dyn-incompatible (it must support `&dyn SleighBase`).
pub const MAX_UNIQUE_SIZE: u64 = 256;

/// The shared base behavior of a compiled or loaded SLEIGH language definition.
///
/// Mirrors the abstract class `ghidra.pcodeCPort.sleighbase.SleighBase`, which extends
/// `Translate` and implements `NamedSymbolProvider`. Java's private/protected fields (`symtab`,
/// `varnode_xref`, `userop`, `root`, `indexer`, ...) back several methods with nontrivial,
/// data-structure-specific logic (a symbol table lookup, an address-sorted cross-reference of
/// registers, source-file-indexed encoding); those data structures (`SymbolTable`, `address_set`,
/// `SourceFileIndexer`) are not yet ported, so the methods that depend on them are left as
/// required methods here rather than guessed-at default implementations. Methods whose Java body
/// is self-contained (no dependency on those unported types) keep their default implementation.
pub trait SleighBase: NamedSymbolProvider + Translate {
    /// Looks up a symbol by its unique id (the Java package-private `findSymbol(int id)`, backed
    /// by `symtab.findSymbol(id)`).
    fn find_symbol_by_id(&self, id: i32) -> Option<&SleighSymbol>;

    /// Whether this base has been fully initialized, i.e. its root constructor/table has been set
    /// (mirrors `isInitialized`, which checks `root != null`).
    fn is_initialized(&self) -> bool;

    /// Looks up a fixed register varnode by name.
    ///
    /// Mirrors `getRegister`, which throws `SleighError` when `nm` is not a known symbol or names
    /// a symbol that isn't a register (varnode symbol).
    fn get_register(&self, nm: &str) -> Result<VarnodeData, SleighError>;

    /// Finds the name of the (innermost) register overlapping `[off, off + size)` in `base`, or
    /// an empty string if none is registered there.
    ///
    /// Mirrors `getRegisterName`, which walks the address-sorted `varnode_xref` cross-reference.
    fn get_register_name(&self, base: &dyn AddrSpace, off: i64, size: i32) -> String;

    /// The language-defined user ops, indexed by their assigned index (the Java `userop` field).
    fn user_ops(&self) -> &[String];

    /// Returns the list of all language-defined user ops, in index order.
    ///
    /// Mirrors `getUserOpNames(VectorSTL<String> res)`, restated to return an owned `Vec` rather
    /// than filling an out-parameter.
    fn get_user_op_names(&self) -> Vec<String> {
        self.user_ops().to_vec()
    }

    /// Parses `text` as a base-10 integer literal at `loc`.
    ///
    /// Mirrors `parseIntegerLiteral`, which constructs `new RadixBigInteger(loc, text, 10)`; the
    /// Rust `RadixBigInteger` constructor reports invalid input as a `Result` rather than an
    /// unchecked exception.
    fn parse_integer_literal(
        &self,
        loc: Location,
        text: &str,
    ) -> Result<RadixBigInteger, RadixBigIntegerError> {
        RadixBigInteger::from_decimal_str(loc, text)
    }

    /// Encodes this SLEIGH base (spaces, symbol table, and header attributes) to `encoder`.
    ///
    /// Mirrors `encode(Encoder)`. Left as a required method: the real body depends on the
    /// not-yet-ported `SourceFileIndexer` and `SymbolTable` encoders plus several `Translate`
    /// accessors (`alignment`, `getUniqueBase`, `getDefaultSpace`, `numSpaces`/`getSpace`) beyond
    /// the minimal placeholder currently in [`crate::decompiler::seam_stubs`].
    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    struct MockSleighBase {
        symbols: Vec<SleighSymbol>,
        initialized: bool,
        user_ops: Vec<String>,
    }

    impl NamedSymbolProvider for MockSleighBase {
        fn find_symbol(&self, nm: &str) -> Option<&SleighSymbol> {
            self.symbols.iter().find(|s| s.name() == nm)
        }
    }

    impl Translate for MockSleighBase {
        fn get_default_size(&self) -> i32 {
            4
        }
    }

    impl SleighBase for MockSleighBase {
        fn find_symbol_by_id(&self, id: i32) -> Option<&SleighSymbol> {
            self.symbols.iter().find(|s| s.id == id)
        }

        fn is_initialized(&self) -> bool {
            self.initialized
        }

        fn get_register(&self, nm: &str) -> Result<VarnodeData, SleighError> {
            let space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0);
            self.find_symbol(nm)
                .map(|_| VarnodeData {
                    space,
                    offset: 0,
                    size: 4,
                })
                .ok_or_else(|| {
                    SleighError::new(
                        format!("Unknown register name '{}'", nm),
                        Location::new("test.sla", 1),
                    )
                })
        }

        fn get_register_name(&self, _base: &dyn AddrSpace, _off: i64, _size: i32) -> String {
            String::new()
        }

        fn user_ops(&self) -> &[String] {
            &self.user_ops
        }

        fn encode(&self, _encoder: &mut dyn Encoder) -> io::Result<()> {
            Ok(())
        }
    }

    fn mock() -> MockSleighBase {
        MockSleighBase {
            symbols: vec![SleighSymbol::with_name(Location::new("test.sla", 1), "r0")],
            initialized: true,
            user_ops: vec!["callother0".to_string()],
        }
    }

    #[test]
    fn trait_is_object_safe_and_usable_via_dyn() {
        let base = mock();
        let dyn_base: &dyn SleighBase = &base;
        assert!(dyn_base.is_initialized());
        assert!(dyn_base.find_symbol("r0").is_some());
        assert!(dyn_base.find_symbol_by_id(0).is_none());
    }

    #[test]
    fn get_user_op_names_returns_owned_copy_in_order() {
        let base = mock();
        assert_eq!(base.get_user_op_names(), vec!["callother0".to_string()]);
    }

    #[test]
    fn get_register_errors_for_unknown_name() {
        let base = mock();
        let err = base.get_register("nope").unwrap_err();
        assert!(err.message().contains("nope"));
    }

    #[test]
    fn get_register_succeeds_for_known_name() {
        let base = mock();
        let data = base.get_register("r0").unwrap();
        assert_eq!(data.offset, 0);
    }

    #[test]
    fn parse_integer_literal_parses_base_10() {
        let base = mock();
        let value = base
            .parse_integer_literal(Location::new("test.sla", 1), "42")
            .unwrap();
        assert_eq!(value.to_string(), "42");
    }
}
