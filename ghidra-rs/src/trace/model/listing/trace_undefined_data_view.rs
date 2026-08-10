use crate::trace::model::listing::trace_base_code_units_view::TraceBaseCodeUnitsView;

/// A view of default / undefined data units.
///
/// Port of `ghidra.trace.model.listing.TraceUndefinedDataView`.
///
/// This excludes all instructions and defined data. Typically, it is used to find ranges of
/// undefined addresses.
///
/// The Java interface is `TraceBaseCodeUnitsView<TraceData>`; it declares no members of its own,
/// existing only to narrow the view's element type. Rust's [`TraceBaseCodeUnitsView`] already
/// represents its element type as `Box<dyn TraceCodeUnit>` (see that trait's docs), so there is
/// no type parameter left to narrow here — this trait is likewise a pure marker, extending
/// [`TraceBaseCodeUnitsView`] without adding methods. Implementations should document that the
/// units they hand back are, in fact,
/// [`TraceData`](crate::trace::model::listing::trace_data::TraceData).
pub trait TraceUndefinedDataView: TraceBaseCodeUnitsView {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{
        Address, AddressRange, AddressSet, AddressSetView, AddressSpace, AddressSpaceType,
    };
    use crate::program::model::lang::Language;
    use crate::program::model::lang::Register;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        ExternalReference, RefType, Reference, ReferenceIterator, SourceType, Symbol,
    };
    use crate::program::model::util::PropertySet;
    use crate::program::model::mem::MemBuffer;
use crate::program::model::listing::CommentType;
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::listing::trace_code_unit::TraceCodeUnit;
    use crate::trace::model::trace::Trace;
    use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
    use crate::trace::model::thread::TraceThread;
    use crate::trace::model::guest::trace_platform::TracePlatform;
    use std::sync::Arc;

    #[derive(Clone)]
    struct MockUndefinedUnit {
        address: Address,
        length: i32,
    }

    impl MemBuffer for MockUndefinedUnit {
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
            self.address.clone()
        }
    }
    impl PropertySet for MockUndefinedUnit {}

    impl CodeUnit for MockUndefinedUnit {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            format!("{:08x}", self.address.offset())
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
            self.address.add_wrap(self.length as i64 - 1)
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
            Ok(vec![0u8; self.length as usize])
        }

        fn get_bytes_in_code_unit(
            &self,
            buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), MemoryAccessException> {
            buffer.fill(0);
            Ok(())
        }

        fn contains(&self, test_addr: &Address) -> bool {
            test_addr.offset() >= self.address.offset()
                && test_addr.offset() < self.address.offset() + self.length as i64
        }

        fn compare_to(&self, addr: &Address) -> i32 {
            self.address.offset().cmp(&addr.offset()) as i32
        }

        fn add_mnemonic_reference(
            &mut self,
            _ref_addr: Address,
            _ref_type: RefType,
            _source_type: SourceType,
        ) {
        }

        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}

        fn get_mnemonic_references(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }

        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }

        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn Reference>> {
            None
        }

        fn add_operand_reference(
            &mut self,
            _index: i32,
            _ref_addr: Address,
            _ref_type: RefType,
            _source_type: SourceType,
        ) {
        }

        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}

        fn get_references_from(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }

        fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_program(&self) -> Arc<dyn crate::program::model::listing::program::Program> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> {
            None
        }

        fn remove_external_reference(&mut self, _op_index: i32) {}

        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn Reference>) {}

        fn set_stack_reference(
            &mut self,
            _op_index: i32,
            _offset: i32,
            _source_type: SourceType,
            _ref_type: RefType,
        ) {
        }

        fn set_register_reference(
            &mut self,
            _op_index: i32,
            _reg: &Register,
            _source_type: SourceType,
            _ref_type: RefType,
        ) {
        }

        fn get_num_operands(&self) -> i32 {
            0
        }

        fn get_address(&self, _op_index: i32) -> Option<Address> {
            None
        }

        fn get_scalar(&self, _op_index: i32) -> Option<Scalar> {
            None
        }
    }

    impl TraceCodeUnit for MockUndefinedUnit {
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
            AddressRange::new(self.address.clone(), self.address.add_wrap(self.length as i64 - 1))
        }

        fn get_lifespan(&self) -> Lifespan {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_start_snap(&self) -> i64 {
            0
        }

        fn set_end_snap(&mut self, _end_snap: i64) {}

        fn get_end_snap(&self) -> i64 {
            i64::MAX
        }

        fn delete(&mut self) {}
    }

    /// A minimal in-memory view: undefined data fills every address not covered by the two
    /// fixed "defined" units, proving the marker trait carries the base view's real filtering
    /// behavior through a trait object.
    struct MockUndefinedView {
        defined: Vec<Address>,
        unit_length: i32,
    }

    impl MockUndefinedView {
        fn is_defined(&self, address: &Address) -> bool {
            self.defined.iter().any(|d| d.offset() == address.offset())
        }
    }

    impl TraceBaseCodeUnitsView for MockUndefinedView {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn size(&self) -> i32 {
            i32::MAX
        }

        fn get_before(&self, _snap: i64, _address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_floor(&self, _snap: i64, _address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_containing(&self, _snap: i64, address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            if self.is_defined(address) {
                return None;
            }
            Some(Box::new(MockUndefinedUnit { address: address.clone(), length: self.unit_length }))
        }

        fn get_at(&self, snap: i64, address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            self.get_containing(snap, address)
        }

        fn get_ceiling(&self, _snap: i64, _address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_after(&self, _snap: i64, _address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_between(
            &self,
            _snap: i64,
            _min: &Address,
            _max: &Address,
            _forward: bool,
        ) -> Vec<Box<dyn TraceCodeUnit>> {
            Vec::new()
        }

        fn get_in_set(
            &self,
            _snap: i64,
            _set: &dyn AddressSetView,
            _forward: bool,
        ) -> Vec<Box<dyn TraceCodeUnit>> {
            Vec::new()
        }

        fn get_in_range(
            &self,
            _snap: i64,
            _range: &AddressRange,
            _forward: bool,
        ) -> Vec<Box<dyn TraceCodeUnit>> {
            Vec::new()
        }

        fn get_from(&self, _snap: i64, _start: &Address, _forward: bool) -> Vec<Box<dyn TraceCodeUnit>> {
            Vec::new()
        }

        fn get_all(&self, _snap: i64, _forward: bool) -> Vec<Box<dyn TraceCodeUnit>> {
            Vec::new()
        }

        fn get_intersecting(&self, _tasr: &dyn TraceAddressSnapRange) -> Vec<Box<dyn TraceCodeUnit>> {
            Vec::new()
        }

        fn get_address_set_view(&self, _snap: i64) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }

        fn get_address_set_view_within(
            &self,
            _snap: i64,
            _within: &AddressRange,
        ) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }

        fn contains_address(&self, _snap: i64, address: &Address) -> bool {
            !self.is_defined(address)
        }

        fn covers_range(&self, _span: Lifespan, _range: &AddressRange) -> bool {
            false
        }

        fn covers_snap_range(&self, _range: &dyn TraceAddressSnapRange) -> bool {
            false
        }

        fn intersects_range(&self, _span: Lifespan, _range: &AddressRange) -> bool {
            false
        }

        fn intersects_snap_range(&self, _range: &dyn TraceAddressSnapRange) -> bool {
            false
        }

        fn get_for_register_on_platform(
            &self,
            _platform: &dyn TracePlatform,
            _snap: i64,
            _register: &Register,
        ) -> Option<Box<dyn TraceCodeUnit>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_containing_register_on_platform(
            &self,
            _platform: &dyn TracePlatform,
            _snap: i64,
            _register: &Register,
        ) -> Option<Box<dyn TraceCodeUnit>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_by_platform_register(
            &self,
            _platform: &dyn TracePlatform,
            _snap: i64,
            _register: &Register,
            _forward: bool,
        ) -> Vec<Box<dyn TraceCodeUnit>> {
            Vec::new()
        }
    }

    impl TraceUndefinedDataView for MockUndefinedView {}

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    fn usable_as_trait_object_and_excludes_defined_addresses() {
        let view: Box<dyn TraceUndefinedDataView> =
            Box::new(MockUndefinedView { defined: vec![addr(0x400)], unit_length: 1 });

        // Undefined addresses are reported as present, backed by a synthesized unit.
        assert!(view.contains_address(0, &addr(0x401)));
        let unit = view.get_at(0, &addr(0x401)).expect("undefined unit at 0x401");
        assert_eq!(unit.get_min_address(), addr(0x401));

        // Defined addresses are excluded from this view.
        assert!(!view.contains_address(0, &addr(0x400)));
        assert!(view.get_containing(0, &addr(0x400)).is_none());
    }
}
