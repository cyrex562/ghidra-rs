//! Port of `ghidra.program.model.pcode.HighSymbol`.
//!
//! A symbol within the decompiler's model of a particular function. The symbol has a name and a
//! data-type along with other properties. The symbol is mapped to one or more storage locations
//! by attaching a `SymbolEntry` for each mapping.
//!
//! This was selected as a dependency-cycle cut-point (multiple other pcode types, e.g.
//! [`HighCodeSymbol`](crate::program::model::pcode::high_code_symbol::HighCodeSymbol) and
//! [`HighConstant`](crate::program::model::pcode::high_constant::HighConstant), reference
//! `HighSymbol` long before `HighFunction`/`Program`/`SymbolEntry` are fully ported), so it is
//! modeled as a trait rather than a concrete struct. This promotes the minimal placeholder that
//! used to live in `seam_stubs.rs` (see `STUBS.tsv`); every existing importer keeps compiling
//! against the methods that placeholder already exposed, with additional public API filled in
//! below.
//!
//! The three Java constructors (which wire up `function`/`dtmanage` and the initial
//! name/data-type/lock state) are construction-time plumbing rather than public API, and have no
//! Rust trait equivalent; implementors are expected to perform that setup themselves via their own
//! fields. Likewise the protected `addMapEntry` mutator (building `entryList` from a `SymbolEntry`)
//! is not public API and is not modeled here.
//!
//! [`get_first_whole_map`](HighSymbol::get_first_whole_map), [`get_size`](HighSymbol::get_size),
//! [`get_pc_address`](HighSymbol::get_pc_address), [`get_storage`](HighSymbol::get_storage), and
//! [`get_mutability`](HighSymbol::get_mutability) all delegate, in Java, to the private
//! `entryList[0]` (a `SymbolEntry`). Rather than requiring every implementor to also expose that
//! raw entry (`SymbolEntry`/`MappedEntry`/`MappedDataEntry`/`DynamicEntry` are not modeled as a
//! trait hierarchy anywhere else in this crate either), each of these is kept as an independent
//! trait method defaulting to the value a `HighSymbol` with no attached mapping would produce;
//! `get_first_whole_map` itself is kept for API completeness but defaults to `None` since nothing
//! yet needs the raw entry handle (see the new [`SymbolEntry`
//! placeholder](crate::program::seam_stubs::SymbolEntry) in `seam_stubs.rs`).
//!
//! [`get_program`](HighSymbol::get_program) is required with no default (mirroring
//! `CodeSymbol::get_program`): the real method reads `dtmanage.getProgram()`, and `dtmanage`
//! (`PcodeDataTypeManager`) is private, not part of `HighSymbol`'s public surface, so there is no
//! sensible placeholder `Program` to hand back generically. Because [`get_symbol`] needs mutable
//! access to `Program::get_symbol_table` that a `&self` method can't reach through
//! `Arc<dyn Program>`, it defaults to `None` (a `HighSymbol` whose id doesn't resolve to a live
//! database symbol); [`get_namespace`] mirrors the real `getSymbol().getParentNamespace()` chain on
//! top of that default.
//!
//! [`encode`](HighSymbol::encode) is required with no default, following the precedent of
//! [`FunctionPrototype::encode_prototype`](crate::program::model::pcode::function_prototype::FunctionPrototype::encode_prototype):
//! the real `encodeHeader` writes the private `category` field verbatim as `ATTRIB_CAT` (not just
//! its `isParameter()`/`getCategoryIndex()` projections), so a generic body can't be reconstructed
//! purely from this trait's public accessors. `decode` is kept as the placeholder's no-op default
//! (`HighCodeSymbol::decode`'s default body already builds on it), documented the same way:
//! `decodeHeader` resets private fields and `entryList` construction needs `DynamicEntry`/
//! `MappedEntry`/`MappedDataEntry`, none of which are modeled as a shared `SymbolEntry` hierarchy
//! here.
//!
//! The static factory `decodeMapSym`/`encodeMapSym` utilities (which instantiate
//! `EquateSymbol`/`HighCodeSymbol`/`MappedEntry`/`DynamicEntry` based on what's next in the stream)
//! are not modeled as trait members -- they are `HighSymbol`-producing factories, not instance
//! methods, and depend on several sibling classes that are not yet ported.

use std::io;
use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::mutability_settings_definition::NORMAL;
use crate::program::model::listing::Program;
use crate::program::model::pcode::decoder::Decoder;
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::high_variable::HighVariable;
use crate::program::model::symbol::{Namespace, Symbol};
use crate::program::seam_stubs::{HighFunction, PlaceholderDataType, PlaceholderVariableStorage, SymbolEntry, VariableStorage};

/// Put keys in the dynamic symbol portion of the key space. Port of `HighSymbol.ID_BASE`.
pub const ID_BASE: i64 = 0x4000_0000_0000_0000;

/// A symbol within the decompiler's model of a particular function. Port of
/// `ghidra.program.model.pcode.HighSymbol`.
pub trait HighSymbol: Send + Sync {
    /// Get id associated with this symbol. Port of `HighSymbol.getId()`.
    fn get_id(&self) -> i64;

    /// Get the function model of which this symbol is a part. Port of
    /// `HighSymbol.getHighFunction()`.
    fn get_high_function(&self) -> Arc<dyn HighFunction>;

    /// Get the Program object containing the function being modeled. Port of
    /// `HighSymbol.getProgram()`.
    fn get_program(&self) -> Arc<dyn Program>;

    /// Get the base name of this symbol. Port of `HighSymbol.getName()`.
    fn get_name(&self) -> String {
        String::new()
    }

    /// The data-type associated with this symbol. Port of `HighSymbol.getDataType()`.
    fn get_data_type(&self) -> Box<dyn DataType> {
        Box::new(PlaceholderDataType)
    }

    /// Get the `HighVariable` associated with this symbol if any. Port of
    /// `HighSymbol.getHighVariable()`.
    fn get_high_variable(&self) -> Option<Box<dyn HighVariable>> {
        None
    }

    /// Fetch the corresponding database `Symbol` if it exists. Port of `HighSymbol.getSymbol()`.
    fn get_symbol(&self) -> Option<Arc<dyn Symbol>> {
        None
    }

    /// Fetch the namespace owning this symbol, if it exists. Port of
    /// `HighSymbol.getNamespace()`.
    fn get_namespace(&self) -> Option<Arc<dyn Namespace>> {
        self.get_symbol().and_then(|sym| sym.get_parent_namespace())
    }

    /// The first mapping object attached to this symbol. Port of `HighSymbol.getFirstWholeMap()`.
    fn get_first_whole_map(&self) -> Option<Arc<dyn SymbolEntry>> {
        None
    }

    /// The number of bytes consumed by the storage for this symbol. Port of
    /// `HighSymbol.getSize()`.
    fn get_size(&self) -> i32 {
        0
    }

    /// Get the first code `Address`, within the function, where this symbol's storage actually
    /// holds the value of the symbol. Port of `HighSymbol.getPCAddress()`.
    fn get_pc_address(&self) -> Option<Address> {
        None
    }

    /// The storage associated with this symbol (associated with the first mapping). Port of
    /// `HighSymbol.getStorage()`.
    fn get_storage(&self) -> Box<dyn VariableStorage> {
        Box::new(PlaceholderVariableStorage)
    }

    /// One of `MutabilitySettingsDefinition::NORMAL`/`VOLATILE`/`CONSTANT`. Port of
    /// `HighSymbol.getMutability()`.
    fn get_mutability(&self) -> i32 {
        NORMAL
    }

    /// Set whether this symbol's data-type is considered "locked". Port of
    /// `HighSymbol.setTypeLock(boolean)`.
    fn set_type_lock(&mut self, typelock: bool) {
        let _ = typelock;
    }

    /// Set whether this symbol's name is considered "locked". Port of
    /// `HighSymbol.setNameLock(boolean)`.
    fn set_name_lock(&mut self, namelock: bool) {
        let _ = namelock;
    }

    /// If this returns true, this symbol's data-type is "locked". Port of
    /// `HighSymbol.isTypeLocked()`.
    fn is_type_locked(&self) -> bool {
        false
    }

    /// If this returns true, this symbol's name is "locked". Port of
    /// `HighSymbol.isNameLocked()`.
    fn is_name_locked(&self) -> bool {
        false
    }

    /// If this returns true, the decompiler will not speculatively merge this with other
    /// variables. Currently, being isolated is equivalent to being typelocked. Port of
    /// `HighSymbol.isIsolated()`.
    fn is_isolated(&self) -> bool {
        self.is_type_locked()
    }

    /// Is this symbol a parameter for a function. Port of `HighSymbol.isParameter()`.
    fn is_parameter(&self) -> bool {
        false
    }

    /// For parameters (category=0), the position of the parameter within the function prototype.
    /// Port of `HighSymbol.getCategoryIndex()`.
    fn get_category_index(&self) -> i32 {
        -1
    }

    /// Is this symbol in the global scope or some other global namespace. Port of
    /// `HighSymbol.isGlobal()`.
    fn is_global(&self) -> bool {
        false
    }

    /// True if symbol is a "this" pointer for a class method. Port of
    /// `HighSymbol.isThisPointer()`.
    fn is_this_pointer(&self) -> bool {
        false
    }

    /// True if symbol holds a pointer to where a function's return value should be stored. Port
    /// of `HighSymbol.isHiddenReturn()`.
    fn is_hidden_return(&self) -> bool {
        false
    }

    /// Simplified stand-in for `symbol.getFirstWholeMap() instanceof DynamicEntry ?
    /// ((DynamicEntry) symbol.getFirstWholeMap()).getHash() : null`, used by
    /// [`HighFunctionDBUtil`](crate::program::model::pcode::high_function_db_util::HighFunctionDBUtil)'s
    /// private `isValidUniqueVariable` helper. Not a distinct Java method; grown onto the
    /// placeholder before this promotion since the real `SymbolEntry`/`DynamicEntry` class
    /// hierarchy is not modeled separately here. Implementors backed by a dynamic (hash-addressed)
    /// entry are expected to override this to return that entry's hash.
    fn get_dynamic_hash(&self) -> Option<i64> {
        None
    }

    /// Encode the symbol description as an element to the stream. This does NOT save the
    /// mappings. Port of `HighSymbol.encode(Encoder)`.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()>;

    /// Decode this symbol object and its associated mappings from the stream. Port of
    /// `HighSymbol.decode(Decoder)`.
    ///
    /// The real method decodes header attributes, resolves the datatype, and builds the mapping
    /// entry list from the stream; that logic needs the private `dtmanage`/`entryList` state and
    /// the unported `SymbolEntry` hierarchy, so this defaults to a no-op that consumes nothing
    /// from the stream. [`HighCodeSymbol::decode`](crate::program::model::pcode::high_code_symbol::HighCodeSymbol::decode)'s
    /// default body builds on this.
    ///
    /// # Errors
    /// Returns an error for invalid encodings.
    fn decode(&mut self, decoder: &dyn Decoder) -> Result<(), DecoderException> {
        let _ = decoder;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    struct MockHighSymbol {
        id: i64,
        name: String,
        typelock: bool,
        namelock: bool,
        category: i32,
        category_index: i32,
    }

    impl HighSymbol for MockHighSymbol {
        fn get_id(&self) -> i64 {
            self.id
        }

        fn get_high_function(&self) -> Arc<dyn HighFunction> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn set_type_lock(&mut self, typelock: bool) {
            self.typelock = typelock;
        }

        fn set_name_lock(&mut self, namelock: bool) {
            self.namelock = namelock;
        }

        fn is_type_locked(&self) -> bool {
            self.typelock
        }

        fn is_name_locked(&self) -> bool {
            self.namelock
        }

        fn is_parameter(&self) -> bool {
            self.category == 0
        }

        fn get_category_index(&self) -> i32 {
            self.category_index
        }

        fn encode(&self, _encoder: &mut dyn Encoder) -> io::Result<()> {
            Ok(())
        }
    }

    fn plain_symbol() -> MockHighSymbol {
        MockHighSymbol {
            id: 7,
            name: "local_1".to_string(),
            typelock: false,
            namelock: false,
            category: -1,
            category_index: -1,
        }
    }

    #[test]
    fn fresh_symbol_defaults_match_java_uninitialized_state() {
        let sym = plain_symbol();
        // Mirrors the state right after the `HighSymbol(long, String, DataType, HighFunction)`
        // constructor: unlocked, uncategorized, not a parameter/global/this/hidden-return.
        assert!(!sym.is_type_locked());
        assert!(!sym.is_name_locked());
        assert!(!sym.is_isolated());
        assert!(!sym.is_parameter());
        assert!(!sym.is_global());
        assert!(!sym.is_this_pointer());
        assert!(!sym.is_hidden_return());
        assert_eq!(sym.get_category_index(), -1);
        assert_eq!(sym.get_size(), 0);
        assert_eq!(sym.get_mutability(), NORMAL);
        assert!(sym.get_pc_address().is_none());
        assert!(sym.get_first_whole_map().is_none());
    }

    #[test]
    fn set_type_lock_makes_symbol_isolated() {
        let mut sym = plain_symbol();
        assert!(!sym.is_isolated());

        sym.set_type_lock(true);

        // `isIsolated()` is defined as `return typelock;`, so locking the type must flip both.
        assert!(sym.is_type_locked());
        assert!(sym.is_isolated());
    }

    #[test]
    fn category_zero_marks_symbol_as_parameter() {
        let mut sym = plain_symbol();
        sym.category = 0;
        sym.category_index = 2;

        assert!(sym.is_parameter());
        assert_eq!(sym.get_category_index(), 2);
    }

    #[test]
    fn get_namespace_chains_through_get_symbol_default() {
        let sym = plain_symbol();
        // The placeholder `get_symbol` default is `None` (no database access modeled), so
        // `get_namespace`'s default chain through it must also report `None`.
        assert!(sym.get_symbol().is_none());
        assert!(sym.get_namespace().is_none());
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let mut boxed: Box<dyn HighSymbol> = Box::new(plain_symbol());
        assert_eq!(boxed.get_id(), 7);
        assert_eq!(boxed.get_name(), "local_1");

        boxed.set_name_lock(true);
        assert!(boxed.is_name_locked());

        use crate::program::model::pcode::ids::{AttributeId, ElementId};

        struct NoopEncoder;
        impl Encoder for NoopEncoder {
            fn open_element(&mut self, _elem_id: ElementId) -> io::Result<()> {
                Ok(())
            }
            fn close_element(&mut self, _elem_id: ElementId) -> io::Result<()> {
                Ok(())
            }
            fn write_bool(&mut self, _attrib_id: AttributeId, _val: bool) -> io::Result<()> {
                Ok(())
            }
            fn write_signed_integer(&mut self, _attrib_id: AttributeId, _val: i64) -> io::Result<()> {
                Ok(())
            }
            fn write_unsigned_integer(&mut self, _attrib_id: AttributeId, _val: u64) -> io::Result<()> {
                Ok(())
            }
            fn write_string(&mut self, _attrib_id: AttributeId, _val: &str) -> io::Result<()> {
                Ok(())
            }
            fn write_string_indexed(&mut self, _attrib_id: AttributeId, _index: i32, _val: &str) -> io::Result<()> {
                Ok(())
            }
            fn write_space(&mut self, _attrib_id: AttributeId, _spc: &AddressSpace) -> io::Result<()> {
                Ok(())
            }
            fn write_space_indexed(&mut self, _attrib_id: AttributeId, _index: i32, _name: &str) -> io::Result<()> {
                Ok(())
            }
            fn write_opcode(&mut self, _attrib_id: AttributeId, _opcode: crate::decompiler::opcodes::op_code::OpCode) -> io::Result<()> {
                Ok(())
            }
            fn write_opcode_ordinal(&mut self, _attrib_id: AttributeId, _opcode: i32) -> io::Result<()> {
                Ok(())
            }
        }
        let mut encoder = NoopEncoder;
        boxed.encode(&mut encoder).expect("encode should succeed");
    }
}
