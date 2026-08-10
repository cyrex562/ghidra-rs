use crate::program::model::listing::data::Data;
use crate::program::model::listing::code_unit::CodeUnit;
use crate::trace::model::listing::trace_code_unit::TraceCodeUnit;

/// A [`Data`] unit in a [`Trace`](crate::trace::model::trace::Trace).
///
/// Port of `ghidra.trace.model.listing.TraceData`.
///
/// The Java interface overrides several inherited `Data` members purely to narrow their return
/// types to trace-specific ones. Rust has no notion of covariantly re-overriding an inherited
/// trait method (the same issue documented on
/// [`TraceCodeUnit`](crate::trace::model::listing::trace_code_unit::TraceCodeUnit)), so those
/// overrides are not re-declared here; implementations of the inherited [`Data`] methods must
/// reproduce them directly:
/// - `get_component`, `get_component_at`, `get_component_containing`, and
///   `get_component_by_path` must each return a `TraceData` (boxed as `Box<dyn Data>`), not an
///   arbitrary `Data`.
/// - `get_primitive_at` must likewise return a `TraceData`.
/// - `get_value_references` must return
///   [`TraceReference`](crate::trace::model::symbol::trace_reference::TraceReference)s (as the
///   base `Reference` type).
pub trait TraceData: TraceCodeUnit + Data {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressRange, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
    use crate::program::model::lang::Language;
    use crate::program::model::listing::program::Program;
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
    use crate::docking::settings::settings::Settings;
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::trace::Trace;
    use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
    use crate::trace::seam_stubs::{TraceThread};
    use crate::trace::model::guest::trace_platform::TracePlatform;
    use std::any::{Any, TypeId};
    use std::sync::Arc;

    struct MockDataType;
    impl DataType for MockDataType {}

    struct MockRefType;
    impl RefType for MockRefType {}

    struct MockReference;
    impl Reference for MockReference {}

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock.bin".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
        }
    }

    struct MockReferenceIterator;
    impl Iterator for MockReferenceIterator {
        // The real trait, not the `seam_stubs::Reference` placeholder this module imports.
        type Item = Arc<dyn crate::program::model::symbol::Reference>;

        fn next(&mut self) -> Option<Self::Item> {
            None
        }
    }

    impl ReferenceIterator for MockReferenceIterator {}

    struct MockTraceData {
        min_address: Address,
        length: i32,
        start_snap: i64,
        end_snap: i64,
        value: i32,
        deleted: bool,
    }

    impl MemBuffer for MockTraceData {
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
            self.min_address.clone()
        }
    }
    impl PropertySet for MockTraceData {}
    impl Settings for MockTraceData {}

    impl CodeUnit for MockTraceData {
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
            "db".to_string()
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
            Ok(vec![0x00; self.length as usize])
        }

        fn get_bytes_in_code_unit(
            &self,
            buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), MemoryAccessException> {
            buffer.fill(0x00);
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
            Box::new(MockReferenceIterator)
        }

        fn get_program(&self) -> Arc<dyn Program> {
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

    impl Data for MockTraceData {
        fn get_value(&self) -> Option<Box<dyn Any>> {
            Some(Box::new(self.value))
        }

        fn get_value_class(&self) -> Option<TypeId> {
            Some(TypeId::of::<i32>())
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
            true
        }

        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType)
        }

        fn get_base_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType)
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
            Box::new(MockTraceData {
                min_address: self.min_address.clone(),
                length: self.length,
                start_snap: self.start_snap,
                end_snap: self.end_snap,
                value: self.value,
                deleted: self.deleted,
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
            self.value.to_string()
        }

        fn get_default_label_prefix(&self, _options: &dyn DataTypeDisplayOptions) -> Option<String> {
            None
        }
    }

    impl TraceCodeUnit for MockTraceData {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_platform(&self) -> Box<dyn TracePlatform> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_thread(&self) -> Box<dyn TraceThread> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_bounds(&self) -> Box<dyn TraceAddressSnapRange> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_range(&self) -> AddressRange {
            AddressRange::new(
                self.min_address.clone(),
                addr(self.min_address.offset() + self.length as i64 - 1),
            )
        }

        fn get_lifespan(&self) -> Lifespan {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_start_snap(&self) -> i64 {
            self.start_snap
        }

        fn set_end_snap(&mut self, end_snap: i64) {
            self.end_snap = end_snap;
        }

        fn get_end_snap(&self) -> i64 {
            self.end_snap
        }

        fn delete(&mut self) {
            self.deleted = true;
        }
    }

    impl TraceData for MockTraceData {}

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    fn make_data() -> MockTraceData {
        MockTraceData {
            min_address: addr(0x400),
            length: 4,
            start_snap: 0,
            end_snap: 10,
            value: 42,
            deleted: false,
        }
    }

    #[test]
    fn usable_as_trait_object_via_both_supertraits() {
        let mut data: Box<dyn TraceData> = Box::new(make_data());

        // TraceCodeUnit (supertrait) methods remain reachable through the trait object.
        assert_eq!(data.get_start_snap(), 0);
        assert_eq!(data.get_end_snap(), 10);
        assert_eq!(
            data.get_range(),
            AddressRange::new(addr(0x400), addr(0x403))
        );

        // Data (supertrait) methods remain reachable through the trait object.
        assert_eq!(
            Data::get_value(data.as_ref()).and_then(|v| v.downcast::<i32>().ok()),
            Some(Box::new(42))
        );
        assert!(data.is_defined());
        assert_eq!(data.get_value_references().len(), 1);

        data.set_end_snap(20);
        assert_eq!(data.get_end_snap(), 20);

        data.delete();
        assert_eq!(data.get_start_snap(), 0);
    }
}
