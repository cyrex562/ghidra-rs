//! Port of `ghidra.program.util.LinearDataAddressCorrelation`.

use crate::program::model::address::{Address, AddressRange};
use crate::program::model::listing::Data;
use crate::program::seam_stubs::AddressCorrelationRangeLike;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

use super::{AddressCorrelation, AddressCorrelationRange};

/// An [`AddressCorrelation`] that linearly maps addresses within one [`Data`] item to addresses
/// within another, using the byte offset of the source address relative to the source data's
/// start address as the displacement from the destination data's start address.
///
/// Port of `ghidra.program.util.LinearDataAddressCorrelation`.
///
/// # Why this stores `Address` fields rather than `Box<dyn Data>`
///
/// The Java class keeps the whole `Data sourceData`/`Data destinationData` fields and calls
/// `getAddress()` on each every time `getCorrelatedDestinationRange` runs. `AddressCorrelation`
/// (this trait) requires `Send + Sync`, but `Data` (via `CodeUnit`/`MemBuffer`) deliberately does
/// not -- see [`MemBuffer`](crate::program::model::mem::MemBuffer)'s own doc comment, since the
/// model layer is `Rc`-based and single-threaded. A `Box<dyn Data>` field would therefore make
/// this struct `!Send`/`!Sync` and it could never implement `AddressCorrelation` at all. Since
/// the only thing ever read from either `Data` is its (fixed, immutable-for-the-object's-life)
/// start address, this port captures that address once at construction instead of holding the
/// `Data` itself -- behaviorally identical to Java (a `Data` object's start address does not
/// change), while staying `Send + Sync`.
pub struct LinearDataAddressCorrelation {
    source_address: Address,
    destination_address: Address,
}

impl LinearDataAddressCorrelation {
    /// Port of `LinearDataAddressCorrelation(Data, Data)`.
    ///
    /// See the struct docs for why this captures each `Data`'s start address up front rather
    /// than storing the `Data` trait objects themselves.
    pub fn new(source_data: &dyn Data, destination_data: &dyn Data) -> Self {
        use crate::program::model::mem::MemBuffer;
        Self {
            source_address: MemBuffer::get_address(source_data),
            destination_address: MemBuffer::get_address(destination_data),
        }
    }
}

impl AddressCorrelation for LinearDataAddressCorrelation {
    /// Port of `LinearDataAddressCorrelation.getCorrelatedDestinationRange`.
    ///
    /// Java computes `destinationData.getAddress().add(delta)`, where `Address.add(long)` throws
    /// the unchecked `AddressOutOfBoundsException` on overflow (it is not declared in this
    /// method's `throws` clause and is left to propagate). Per this crate's convention for
    /// unchecked exceptions (see e.g. `program::util::program_merge`'s module docs), that becomes
    /// an `.expect()` panic here rather than a new `Result` variant.
    fn get_correlated_destination_range(
        &self,
        source_address: &Address,
        _monitor: &dyn TaskMonitor,
    ) -> Result<Option<Box<dyn AddressCorrelationRangeLike>>, CancelledException> {
        let offset = source_address.offset();
        let base = self.source_address.offset();
        let delta = offset - base;
        let address = self
            .destination_address
            .add(delta)
            .expect("Address overflow in LinearDataAddressCorrelation");
        let range = AddressRange::new(address.clone(), address);
        Ok(Some(Box::new(AddressCorrelationRange::new(range, self.get_name()))))
    }

    fn get_name(&self) -> String
    where
        Self: Sized,
    {
        "LinearDataAddressCorrelation".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
    use crate::program::model::lang::register::Register;
    use crate::program::model::listing::program::Program;
    use crate::program::model::listing::{CodeUnit, CommentType};
    use crate::program::model::mem::{MemBuffer, MemoryAccessException};
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        ExternalReference, RefType as SymRefType, Reference as SymReference, ReferenceIterator,
        SourceType, Symbol,
    };
    use crate::program::model::util::PropertySet;
    use crate::program::seam_stubs::{RefType, Reference};
    use std::any::{Any, TypeId};
    use std::sync::Arc;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        Address::new(space.clone(), offset)
    }

    /// A minimal `Data` test double whose only role is to report a fixed start address, since
    /// that is all `LinearDataAddressCorrelation` reads from its two `Data` fields.
    struct MockData {
        address: Address,
    }

    impl MemBuffer for MockData {
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_byte(&self, _offset: i32) -> Result<u8, MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
    }
    impl PropertySet for MockData {}

    impl CodeUnit for MockData {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            String::new()
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
            self.address.clone()
        }
        fn get_max_address(&self) -> Address {
            self.address.clone()
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
        fn get_program(&self) -> Arc<dyn Program> {
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
    impl crate::docking::settings::settings::Settings for MockData {}

    struct MockDataType;
    impl DataType for MockDataType {}

    impl Data for MockData {
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
            true
        }
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType)
        }
        fn get_base_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType)
        }
        fn get_value_references(&self) -> Vec<Box<dyn Reference>> {
            Vec::new()
        }
        fn add_value_reference(&mut self, _ref_addr: Address, _ref_type: Box<dyn RefType>) {}
        fn remove_value_reference(&mut self, _ref_addr: Address) {}
        fn get_field_name(&self) -> Option<String> {
            None
        }
        fn get_path_name(&self) -> String {
            String::new()
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
            unimplemented!("not exercised by these tests")
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

    #[test]
    fn maps_source_address_by_offset_delta() {
        let sp = space();
        let source = MockData { address: addr(&sp, 0x1000) };
        let dest = MockData { address: addr(&sp, 0x2000) };
        let corr = LinearDataAddressCorrelation::new(&source, &dest);
        let monitor = crate::util::task::DummyMonitor;

        // source offset 0x1008 is delta 8 past the source data's start (0x1000), so the
        // correlated destination address is 8 past the destination data's start (0x2008).
        let result = corr
            .get_correlated_destination_range(&addr(&sp, 0x1008), &monitor)
            .expect("not cancelled")
            .expect("range present");
        assert_eq!(result.min_address(), addr(&sp, 0x2008));
        assert_eq!(result.range().min_address(), &addr(&sp, 0x2008));
        assert_eq!(result.range().max_address(), &addr(&sp, 0x2008));
    }

    #[test]
    fn zero_delta_maps_directly_to_destination_start() {
        let sp = space();
        let source = MockData { address: addr(&sp, 0x400) };
        let dest = MockData { address: addr(&sp, 0x800) };
        let corr = LinearDataAddressCorrelation::new(&source, &dest);
        let monitor = crate::util::task::DummyMonitor;

        let result = corr
            .get_correlated_destination_range(&addr(&sp, 0x400), &monitor)
            .expect("not cancelled")
            .expect("range present");
        assert_eq!(result.min_address(), addr(&sp, 0x800));
    }

    #[test]
    fn negative_delta_maps_before_destination_start() {
        let sp = space();
        let source = MockData { address: addr(&sp, 0x1000) };
        let dest = MockData { address: addr(&sp, 0x2000) };
        let corr = LinearDataAddressCorrelation::new(&source, &dest);
        let monitor = crate::util::task::DummyMonitor;

        // Source address before the source data's own start yields a negative delta.
        let result = corr
            .get_correlated_destination_range(&addr(&sp, 0x0FF0), &monitor)
            .expect("not cancelled")
            .expect("range present");
        assert_eq!(result.min_address(), addr(&sp, 0x1FF0));
    }

    #[test]
    fn get_name_matches_java() {
        let sp = space();
        let source = MockData { address: addr(&sp, 0) };
        let dest = MockData { address: addr(&sp, 0) };
        let corr = LinearDataAddressCorrelation::new(&source, &dest);
        assert_eq!(corr.get_name(), "LinearDataAddressCorrelation");
    }

    #[test]
    fn result_name_reflects_get_name() {
        let sp = space();
        let source = MockData { address: addr(&sp, 0x10) };
        let dest = MockData { address: addr(&sp, 0x20) };
        let corr = LinearDataAddressCorrelation::new(&source, &dest);
        let monitor = crate::util::task::DummyMonitor;

        let result = corr
            .get_correlated_destination_range(&addr(&sp, 0x10), &monitor)
            .expect("not cancelled")
            .expect("range present");
        assert_eq!(result.correlator_name(), "LinearDataAddressCorrelation");
    }

    #[test]
    fn trait_object_creation() {
        let sp = space();
        let source = MockData { address: addr(&sp, 0) };
        let dest = MockData { address: addr(&sp, 0) };
        let corr = LinearDataAddressCorrelation::new(&source, &dest);
        let _: Box<dyn AddressCorrelation> = Box::new(corr);
    }
}
