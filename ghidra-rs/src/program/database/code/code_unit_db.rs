//! Port of `ghidra.program.database.code.CodeUnitDB` as a trait (cycle cut-point).
//!
//! The Java class is a package-private `abstract class CodeUnitDB extends DbObject implements
//! CodeUnit, ProcessorContext`. `DataDB` and `InstructionDB` both extend it, and `CodeUnitDB`
//! itself is constructed from (and calls back into) `CodeManager`/`ProgramDB`/`ReferenceDBManager`
//! -- the not-yet-ported `CodeManager` in particular sits at the center of that dependency web, so
//! porting `CodeUnitDB` as a concrete struct would pull in the whole `code` package at once. That
//! is the cycle this port cuts.
//!
//! Nearly all of `CodeUnitDB`'s `@Override` methods simply implement the already-ported
//! [`CodeUnit`] and [`ProcessorContext`] interfaces (see
//! [`DataDb`](crate::program::database::code::data_db::DataDb) for the same observation about
//! `DataDB`), so they are not repeated here. What `CodeUnitDb` adds on top of those two supertraits
//! (plus [`DbObject`], for the `key`/`cache`/`refresh` bookkeeping) is the class's own novel
//! contract -- the methods `DataDB`/`InstructionDB`/`DataComponent` each override with independent
//! logic:
//!
//! - `hasBeenDeleted(DBRecord)`: `protected abstract`, so every concrete subclass must supply its
//!   own "is this code unit still present" check.
//! - `getPreferredCacheLength()`: `protected`, overridden by `InstructionDB` (and `DataComponent`)
//!   to account for instruction length overrides / component sizing; `CodeUnitDB`'s own body is
//!   just `getLength()`, kept here as the default.
//! - `toString()`: `public abstract`, overridden by each subclass to render its own mnemonic and
//!   operands.
//!
//! Left out as implementation detail of a concrete DB-backed type (mirroring how
//! [`ReferenceDbManager`](crate::program::database::references::ReferenceDbManager) left out its
//! constructor): the constructor's `CodeManager`/`Address`/cache-key wiring, `DbObject.refresh`'s
//! address-map-decode-and-reset-caches body (needs `CodeManager.getAddressMap()`), and the private
//! comment/byte-cache helpers (`getCommentRecord`, `populateByteArray`, `readComments`,
//! `updateCommentRecord`) -- none of which are referenced outside this file in the original source.

use crate::framework::db::DBRecord;
use crate::program::database::db_object::DbObject;
use crate::program::model::lang::processor_context::ProcessorContext;
use crate::program::model::listing::code_unit::CodeUnit;

/// Database implementation of [`CodeUnit`] (and [`ProcessorContext`]).
///
/// Port of `ghidra.program.database.code.CodeUnitDB`. See the module docs for what was
/// intentionally left out.
pub trait CodeUnitDb: CodeUnit + ProcessorContext + DbObject {
    /// Determines whether this code unit has been deleted. If a record has been provided, it may
    /// be used to facilitate a refresh without performing a record query from the database.
    /// `record` mirrors the Java method's `DBRecord` parameter, which may be absent when the
    /// caller expects the implementor to look its own record up as needed.
    ///
    /// Stands in for the abstract `CodeUnitDB.hasBeenDeleted(DBRecord)`.
    fn has_been_deleted(&self, record: Option<&DBRecord>) -> bool;

    /// The number of bytes that should be cached for fast [`CodeUnit::get_byte`]/`get_bytes`
    /// access. Stands in for `CodeUnitDB.getPreferredCacheLength()`, whose default body is just
    /// `getLength()`; `InstructionDB` overrides this to account for an instruction length
    /// override.
    fn get_preferred_cache_length(&self) -> i32 {
        self.get_length()
    }

    /// Returns a string that represents this code unit with default markup. Only the mnemonic
    /// and operands are included. Stands in for the abstract `CodeUnitDB.toString()`.
    fn code_unit_string(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::db_object::DbObjectState;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::processor_context_view::ProcessorContextView;
    use crate::program::model::lang::register::{Register, RegisterRef};
    use crate::program::model::listing::context_change_exception::ContextChangeException;
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        ExternalReference, RefType as SymRefType, Reference as SymReference, ReferenceIterator,
        SourceType, Symbol,
    };
    use crate::program::model::util::PropertySet;
    use crate::program::seam_stubs::{CommentType, MemBuffer, RegisterValue};
    use std::sync::Arc;

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    fn mock_register() -> RegisterRef {
        let space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 1);
        Register::new(
            "context",
            "Processor context register",
            Address::new(space, 0),
            4,
            false,
            0,
        )
    }

    /// A minimal object-safe `CodeUnitDb`: a fixed-length, unnamed code unit with a length-based
    /// preferred cache length override and a record-presence-based deletion check, mirroring (in
    /// miniature) how `InstructionDB` overrides `getPreferredCacheLength` and how any `CodeUnitDB`
    /// subclass implements `hasBeenDeleted`.
    struct MockCodeUnitDb {
        state: DbObjectState,
        min_address: Address,
        length: i32,
        cache_length_override: Option<i32>,
        present: bool,
    }

    impl MemBuffer for MockCodeUnitDb {
        fn get_address(&self) -> Address {
            self.min_address.clone()
        }
    }
    impl PropertySet for MockCodeUnitDb {}

    impl DbObject for MockCodeUnitDb {
        fn state(&self) -> &DbObjectState {
            &self.state
        }

        fn refresh(&self, _record: Option<&DBRecord>) -> bool {
            self.present
        }
    }

    impl CodeUnit for MockCodeUnitDb {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            format!("{:08x}", self.min_address.offset())
        }
        fn get_label(&self) -> Option<String> {
            None
        }
        fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
            Vec::new()
        }
        fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn get_min_address(&self) -> Address {
            self.min_address.clone()
        }
        fn get_max_address(&self) -> Address {
            self.min_address.clone()
        }
        fn get_mnemonic_string(&self) -> String {
            "??".to_string()
        }
        fn get_comment(&self, _comment_type: CommentType) -> Option<String> {
            None
        }
        fn get_comment_as_array(&self, _comment_type: CommentType) -> Vec<String> {
            Vec::new()
        }
        fn set_comment(&mut self, _comment_type: CommentType, _comment: Option<String>) {}
        fn set_comment_as_array(&mut self, _comment_type: CommentType, _comment: &[String]) {}
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(vec![0; self.length as usize])
        }
        fn get_bytes_in_code_unit(
            &self,
            _buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), MemoryAccessException> {
            Ok(())
        }
        fn contains(&self, test_addr: &Address) -> bool {
            test_addr.offset() >= self.min_address.offset()
                && test_addr.offset() < self.min_address.offset() + self.length as i64
        }
        fn compare_to(&self, addr: &Address) -> i32 {
            self.min_address.offset().cmp(&addr.offset()) as i32
        }
        fn add_mnemonic_reference(
            &mut self,
            _ref_addr: Address,
            _ref_type: SymRefType,
            _source_type: SourceType,
        ) {
        }
        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}
        fn get_mnemonic_references(&self) -> Vec<Arc<dyn SymReference>> {
            Vec::new()
        }
        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn SymReference>> {
            Vec::new()
        }
        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn SymReference>> {
            None
        }
        fn add_operand_reference(
            &mut self,
            _index: i32,
            _ref_addr: Address,
            _ref_type: SymRefType,
            _source_type: SourceType,
        ) {
        }
        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}
        fn get_references_from(&self) -> Vec<Arc<dyn SymReference>> {
            Vec::new()
        }
        fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
            Box::new(crate::program::model::symbol::EmptyReferenceIterator)
        }
        fn get_program(&self) -> Arc<dyn crate::program::model::listing::Program> {
            struct MockProgram;
            impl crate::framework::model::DomainObject for MockProgram {}
            impl crate::program::model::listing::Program for MockProgram {
                fn get_name(&self) -> String {
                    "mock.bin".to_string()
                }
                fn get_language_id(&self) -> String {
                    "test:LE:32:default".to_string()
                }
            }
            Arc::new(MockProgram)
        }
        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> {
            None
        }
        fn remove_external_reference(&mut self, _op_index: i32) {}
        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn SymReference>) {}
        fn set_stack_reference(
            &mut self,
            _op_index: i32,
            _offset: i32,
            _source_type: SourceType,
            _ref_type: SymRefType,
        ) {
        }
        fn set_register_reference(
            &mut self,
            _op_index: i32,
            _reg: &Register,
            _source_type: SourceType,
            _ref_type: SymRefType,
        ) {
        }
        fn get_num_operands(&self) -> i32 {
            1
        }
        fn get_address(&self, _op_index: i32) -> Option<Address> {
            None
        }
        fn get_scalar(&self, _op_index: i32) -> Option<Scalar> {
            None
        }
    }

    impl ProcessorContextView for MockCodeUnitDb {
        fn get_base_context_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register(&self, _name: &str) -> Option<RegisterRef> {
            None
        }
        fn get_value(&self, _register: &Register, _signed: bool) -> Option<i128> {
            None
        }
        fn get_register_value(&self, _register: &Register) -> Option<Box<dyn RegisterValue>> {
            None
        }
        fn has_value(&self, _register: &Register) -> bool {
            false
        }
    }

    impl ProcessorContext for MockCodeUnitDb {
        fn set_value(
            &mut self,
            _register: &Register,
            _value: i128,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn set_register_value(
            &mut self,
            _value: Box<dyn RegisterValue>,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn clear_register(&mut self, _register: &Register) -> Result<(), ContextChangeException> {
            Ok(())
        }
    }

    impl CodeUnitDb for MockCodeUnitDb {
        fn has_been_deleted(&self, record: Option<&DBRecord>) -> bool {
            record.is_none() && !self.present
        }

        fn get_preferred_cache_length(&self) -> i32 {
            self.cache_length_override.unwrap_or_else(|| self.get_length())
        }

        fn code_unit_string(&self) -> String {
            self.get_mnemonic_string()
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let plain = MockCodeUnitDb {
            state: DbObjectState::new(1),
            min_address: mock_address(0x100),
            length: 4,
            cache_length_override: None,
            present: true,
        };
        let dyn_plain: &dyn CodeUnitDb = &plain;
        assert_eq!(dyn_plain.get_preferred_cache_length(), 4);
        assert!(!dyn_plain.has_been_deleted(None));
        assert_eq!(dyn_plain.code_unit_string(), "??");

        // Mirrors InstructionDB overriding getPreferredCacheLength() to diverge from getLength().
        let overridden = MockCodeUnitDb {
            state: DbObjectState::new(2),
            min_address: mock_address(0x200),
            length: 4,
            cache_length_override: Some(1),
            present: false,
        };
        let dyn_overridden: &dyn CodeUnitDb = &overridden;
        assert_eq!(dyn_overridden.get_preferred_cache_length(), 1);
        assert_ne!(dyn_overridden.get_preferred_cache_length(), dyn_overridden.get_length());
        assert!(dyn_overridden.has_been_deleted(None));
        assert!(dyn_overridden.refresh(None) == false);

        assert!(mock_register().borrow().name() == "context");
    }
}
