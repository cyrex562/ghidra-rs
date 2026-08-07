//! Port of `ghidra.program.database.code.DataDB`.
//!
//! The Java class is package-private and implements `Data` (already ported as
//! [`Data`](crate::program::model::listing::data::Data)) while extending the not-yet-ported
//! abstract `CodeUnitDB` (itself extending the already-ported
//! [`DbObject`](crate::program::database::db_object::DbObject)). Every method the Java class
//! overrides is either part of the already-ported `Data`/`Settings`/`CodeUnit` contract (so it is
//! not repeated here) or an internal implementation detail (private helpers like
//! `computeLength`/`ComponentFactory`, which depend on the not-yet-ported `CodeManager`/
//! `DataComponent` and are out of scope for a public-API port).
//!
//! The one piece of DataDB's own contract that matters for the dependency cycle is
//! `hasBeenDeleted(DBRecord)`: `CodeUnitDB` declares it abstract, `DataDB` supplies the "is this
//! address still data" implementation, and `DataComponent` (which `extends DataDB`, and which
//! `DataDB.ComponentFactory` constructs) overrides it again with component-specific logic. That
//! two-level override is exactly the DataDB <-> DataComponent inheritance cycle this port cuts:
//! by exposing `has_been_deleted` as a required trait method here, both a future `DataDB` port and
//! a future `DataComponent` port can each provide their own implementation and be referenced
//! polymorphically as `dyn DataDb`, without either one needing to name the other's concrete type.
//!
//! `getBaseDataType(DataType)` is also ported, as the free function [`base_data_type`]: it is a
//! `protected static` helper (real, self-contained logic), not an instance method, so it does not
//! belong on the trait itself.

use crate::framework::db::DBRecord;
use crate::program::database::db_object::DbObject;
use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::data::Data;

/// If `data_type` is a typedef, returns its base data type; otherwise returns `data_type`
/// unchanged. Stands in for the protected static `DataDB.getBaseDataType(DataType)`.
pub fn base_data_type(data_type: Box<dyn DataType>) -> Box<dyn DataType> {
    if data_type.is_typedef() {
        if let Some(base) = data_type.typedef_base_data_type() {
            return base;
        }
    }
    data_type
}

/// Database implementation of the [`Data`] interface.
///
/// Port of `ghidra.program.database.code.DataDB`.
pub trait DataDb: Data + DbObject {
    /// Determines whether this data code unit has been deleted (or, following a refresh, updates
    /// this object's cached data type to match the current database state and returns `false`).
    /// `record` mirrors the Java method's `DBRecord` parameter, which may be absent when the
    /// caller expects the implementor to look its own record up as needed.
    ///
    /// Stands in for the protected `DataDB.hasBeenDeleted(DBRecord)`. Declared here as a required
    /// method (rather than given a shared default) because `DataComponent` overrides it again
    /// with independent logic -- see the module docs.
    fn has_been_deleted(&self, record: Option<&DBRecord>) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::database::db_object::DbObjectState;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        ExternalReference, RefType as SymRefType, Reference as SymReference, ReferenceIterator,
        SourceType, Symbol,
    };
    use crate::program::model::util::PropertySet;
    use crate::program::seam_stubs::{RefType, Reference};
use crate::program::model::mem::MemBuffer;
use crate::program::model::listing::CommentType;
    use std::any::{Any, TypeId};
    use std::sync::Arc;

    struct MockDataType {
        typedef: bool,
    }

    impl DataType for MockDataType {
        fn is_typedef(&self) -> bool {
            self.typedef
        }

        fn typedef_base_data_type(&self) -> Option<Box<dyn DataType>> {
            if self.typedef {
                Some(Box::new(MockDataType { typedef: false }))
            } else {
                None
            }
        }
    }

    #[test]
    fn base_data_type_unwraps_typedef() {
        let typedef: Box<dyn DataType> = Box::new(MockDataType { typedef: true });
        let base = base_data_type(typedef);
        assert!(!base.is_typedef());
    }

    #[test]
    fn base_data_type_passes_through_non_typedef() {
        let plain: Box<dyn DataType> = Box::new(MockDataType { typedef: false });
        let base = base_data_type(plain);
        assert!(!base.is_typedef());
    }

    struct MockRefType;
    impl RefType for MockRefType {}

    struct MockReference;
    impl Reference for MockReference {}

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    /// A minimal object-safe `DataDb`: reports deleted once its backing record is gone, mirroring
    /// (in miniature) `DataDB.hasBeenDeleted`'s "record disappeared" branch.
    struct MockDataDb {
        state: DbObjectState,
        present: bool,
    }

    impl MemBuffer for MockDataDb {
        fn get_byte(&self, _offset: i32) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> Address {
            mock_address(0)
        }
    }
    impl PropertySet for MockDataDb {}
    impl Settings for MockDataDb {}

    impl DbObject for MockDataDb {
        fn state(&self) -> &DbObjectState {
            &self.state
        }

        fn refresh(&self, _record: Option<&DBRecord>) -> bool {
            self.present
        }
    }

    impl CodeUnit for MockDataDb {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            "00000000".to_string()
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
            mock_address(0)
        }
        fn get_max_address(&self) -> Address {
            mock_address(0)
        }
        fn get_mnemonic_string(&self) -> String {
            String::new()
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
            1
        }
        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(Vec::new())
        }
        fn get_bytes_in_code_unit(
            &self,
            _buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), MemoryAccessException> {
            Ok(())
        }
        fn contains(&self, _test_addr: &Address) -> bool {
            false
        }
        fn compare_to(&self, _addr: &Address) -> i32 {
            0
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
            _reg: &crate::program::model::lang::register::Register,
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

    impl Data for MockDataDb {
        fn get_value(&self) -> Option<Box<dyn Any>> {
            None
        }

        fn get_value_class(&self) -> Option<TypeId> {
            None
        }

        fn has_string_value(&self) -> bool {
            false
        }

        fn is_constant(&self) -> bool {
            false
        }

        fn is_writable(&self) -> bool {
            true
        }

        fn is_volatile(&self) -> bool {
            false
        }

        fn is_defined(&self) -> bool {
            self.present
        }

        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType { typedef: false })
        }

        fn get_base_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType { typedef: false })
        }

        fn get_value_references(&self) -> Vec<Box<dyn Reference>> {
            vec![Box::new(MockReference)]
        }

        fn add_value_reference(&mut self, _ref_addr: Address, _ref_type: Box<dyn RefType>) {}

        fn remove_value_reference(&mut self, _ref_addr: Address) {}

        fn get_field_name(&self) -> Option<String> {
            None
        }

        fn get_path_name(&self) -> String {
            "mock".to_string()
        }

        fn get_component_path_name(&self) -> String {
            String::new()
        }

        fn is_pointer(&self) -> bool {
            false
        }

        fn is_union(&self) -> bool {
            false
        }

        fn is_structure(&self) -> bool {
            false
        }

        fn is_array(&self) -> bool {
            false
        }

        fn is_dynamic(&self) -> bool {
            false
        }

        fn get_parent(&self) -> Option<Box<dyn Data>> {
            None
        }

        fn get_root(&self) -> Box<dyn Data> {
            Box::new(MockDataDb {
                state: DbObjectState::new(self.state.get_key()),
                present: self.present,
            })
        }

        fn get_root_offset(&self) -> i32 {
            0
        }

        fn get_parent_offset(&self) -> i32 {
            0
        }

        fn get_component(&self, _index: i32) -> Option<Box<dyn Data>> {
            None
        }

        fn get_component_by_path(&self, _component_path: &[i32]) -> Option<Box<dyn Data>> {
            None
        }

        fn get_component_path(&self) -> Vec<i32> {
            Vec::new()
        }

        fn get_num_components(&self) -> i32 {
            0
        }

        #[allow(deprecated)]
        fn get_component_at(&self, _offset: i32) -> Option<Box<dyn Data>> {
            None
        }

        fn get_component_containing(&self, _offset: i32) -> Option<Box<dyn Data>> {
            None
        }

        fn get_components_containing(&self, _offset: i32) -> Option<Vec<Box<dyn Data>>> {
            None
        }

        fn get_primitive_at(&self, _offset: i32) -> Option<Box<dyn Data>> {
            None
        }

        fn get_component_index(&self) -> i32 {
            -1
        }

        fn get_component_level(&self) -> i32 {
            0
        }

        fn get_default_value_representation(&self) -> String {
            String::new()
        }

        fn get_default_label_prefix(&self, _options: &dyn DataTypeDisplayOptions) -> Option<String> {
            None
        }
    }

    impl DataDb for MockDataDb {
        fn has_been_deleted(&self, record: Option<&DBRecord>) -> bool {
            record.is_none() && !self.present
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let present = MockDataDb {
            state: DbObjectState::new(1),
            present: true,
        };
        let dyn_present: &dyn DataDb = &present;
        assert!(!dyn_present.has_been_deleted(None));
        assert!(Data::is_defined(dyn_present));

        let gone = MockDataDb {
            state: DbObjectState::new(2),
            present: false,
        };
        let dyn_gone: &dyn DataDb = &gone;
        assert!(dyn_gone.has_been_deleted(None));
        assert!(!Data::is_defined(dyn_gone));
        assert!(dyn_gone.refresh(None) == false);
    }
}
