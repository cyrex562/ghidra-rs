use crate::trace::model::listing::trace_base_code_units_view::TraceBaseCodeUnitsView;

/// A view of all data units.
///
/// Port of `ghidra.trace.model.listing.TraceDataView`.
///
/// This only excludes instructions. In particular, it includes default / undefined data units.
///
/// The Java interface merely finalizes the type parameter of
/// [`TraceBaseCodeUnitsView`]`<TraceData>`, adding no members of its own. Since
/// [`TraceBaseCodeUnitsView`] is already expressed in terms of `Box<dyn TraceCodeUnit>` rather
/// than a type parameter, this trait is likewise just a marker supertrait bound.
pub trait TraceDataView: TraceBaseCodeUnitsView {}

impl<T: TraceBaseCodeUnitsView + ?Sized> TraceDataView for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{
        Address, AddressRange, AddressSet, AddressSetView, AddressSpace, AddressSpaceType,
    };
    use crate::program::model::lang::Register;
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::listing::trace_code_unit::TraceCodeUnit;
    use crate::trace::model::trace::Trace;
    use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
    use crate::trace::model::guest::trace_platform::TracePlatform;

    /// A view backed by a single fixed data unit, only realistic enough to prove that a
    /// `TraceBaseCodeUnitsView` impl is automatically usable as a `TraceDataView` trait object
    /// (the blanket impl above), not merely as its narrower supertrait.
    struct SingleUnitView {
        address: Address,
    }

    impl TraceBaseCodeUnitsView for SingleUnitView {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn size(&self) -> i32 {
            1
        }

        fn get_before(&self, _snap: i64, _address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            None
        }

        fn get_floor(&self, _snap: i64, _address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            None
        }

        fn get_containing(&self, _snap: i64, _address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            None
        }

        fn get_at(&self, snap: i64, address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            if snap >= 0 && address.offset() == self.address.offset() {
                Some(Box::new(MockData { address: self.address.clone() }))
            } else {
                None
            }
        }

        fn get_ceiling(&self, _snap: i64, _address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            None
        }

        fn get_after(&self, _snap: i64, _address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            None
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

        fn get_all(&self, snap: i64, _forward: bool) -> Vec<Box<dyn TraceCodeUnit>> {
            if snap >= 0 {
                vec![Box::new(MockData { address: self.address.clone() })]
            } else {
                Vec::new()
            }
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

        fn contains_address(&self, snap: i64, address: &Address) -> bool {
            snap >= 0 && address.offset() == self.address.offset()
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
            None
        }

        fn get_containing_register_on_platform(
            &self,
            _platform: &dyn TracePlatform,
            _snap: i64,
            _register: &Register,
        ) -> Option<Box<dyn TraceCodeUnit>> {
            None
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

    /// A minimal `TraceCodeUnit` stand-in for a data unit, only realistic enough to be returned
    /// from [`SingleUnitView`] lookups.
    struct MockData {
        address: Address,
    }

    impl crate::program::model::mem::MemBuffer for MockData {
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
    impl crate::program::model::util::PropertySet for MockData {}

    impl crate::program::model::listing::code_unit::CodeUnit for MockData {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            format!("{:08x}", self.address.offset())
        }

        fn get_label(&self) -> Option<String> {
            None
        }

        fn get_symbols(&self) -> Vec<std::sync::Arc<dyn crate::program::model::symbol::Symbol>> {
            Vec::new()
        }

        fn get_primary_symbol(
            &self,
        ) -> Option<std::sync::Arc<dyn crate::program::model::symbol::Symbol>> {
            None
        }

        fn get_min_address(&self) -> Address {
            self.address.clone()
        }

        fn get_max_address(&self) -> Address {
            self.address.clone()
        }

        fn get_mnemonic_string(&self) -> String {
            "db".to_string()
        }

        fn get_comment(
            &self,
            _comment_type: crate::program::model::listing::CommentType,
        ) -> Option<String> {
            None
        }

        fn get_comment_as_array(
            &self,
            _comment_type: crate::program::model::listing::CommentType,
        ) -> Vec<String> {
            Vec::new()
        }

        fn set_comment(
            &mut self,
            _comment_type: crate::program::model::listing::CommentType,
            _comment: Option<String>,
        ) {
        }

        fn set_comment_as_array(
            &mut self,
            _comment_type: crate::program::model::listing::CommentType,
            _comment: &[String],
        ) {
        }

        fn get_length(&self) -> i32 {
            1
        }

        fn get_bytes(&self) -> Result<Vec<u8>, crate::program::model::mem::MemoryAccessException> {
            Ok(vec![0x00])
        }

        fn get_bytes_in_code_unit(
            &self,
            buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), crate::program::model::mem::MemoryAccessException> {
            buffer.fill(0x00);
            Ok(())
        }

        fn contains(&self, test_addr: &Address) -> bool {
            test_addr.offset() == self.address.offset()
        }

        fn compare_to(&self, addr: &Address) -> i32 {
            self.address.offset().cmp(&addr.offset()) as i32
        }

        fn add_mnemonic_reference(
            &mut self,
            _ref_addr: Address,
            _ref_type: crate::program::model::symbol::RefType,
            _source_type: crate::program::model::symbol::SourceType,
        ) {
        }

        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}

        fn get_mnemonic_references(
            &self,
        ) -> Vec<std::sync::Arc<dyn crate::program::model::symbol::Reference>> {
            Vec::new()
        }

        fn get_operand_references(
            &self,
            _index: i32,
        ) -> Vec<std::sync::Arc<dyn crate::program::model::symbol::Reference>> {
            Vec::new()
        }

        fn get_primary_reference(
            &self,
            _index: i32,
        ) -> Option<std::sync::Arc<dyn crate::program::model::symbol::Reference>> {
            None
        }

        fn add_operand_reference(
            &mut self,
            _index: i32,
            _ref_addr: Address,
            _ref_type: crate::program::model::symbol::RefType,
            _source_type: crate::program::model::symbol::SourceType,
        ) {
        }

        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}

        fn get_references_from(
            &self,
        ) -> Vec<std::sync::Arc<dyn crate::program::model::symbol::Reference>> {
            Vec::new()
        }

        fn get_reference_iterator_to(
            &self,
        ) -> Box<dyn crate::program::model::symbol::ReferenceIterator> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_program(&self) -> std::sync::Arc<dyn crate::program::model::listing::program::Program> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_external_reference(
            &self,
            _op_index: i32,
        ) -> Option<std::sync::Arc<dyn crate::program::model::symbol::ExternalReference>> {
            None
        }

        fn remove_external_reference(&mut self, _op_index: i32) {}

        fn set_primary_memory_reference(
            &mut self,
            _reference: std::sync::Arc<dyn crate::program::model::symbol::Reference>,
        ) {
        }

        fn set_stack_reference(
            &mut self,
            _op_index: i32,
            _offset: i32,
            _source_type: crate::program::model::symbol::SourceType,
            _ref_type: crate::program::model::symbol::RefType,
        ) {
        }

        fn set_register_reference(
            &mut self,
            _op_index: i32,
            _reg: &crate::program::model::lang::register::Register,
            _source_type: crate::program::model::symbol::SourceType,
            _ref_type: crate::program::model::symbol::RefType,
        ) {
        }

        fn get_num_operands(&self) -> i32 {
            0
        }

        fn get_address(&self, _op_index: i32) -> Option<Address> {
            None
        }

        fn get_scalar(&self, _op_index: i32) -> Option<crate::program::model::scalar::Scalar> {
            None
        }
    }

    impl TraceCodeUnit for MockData {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_platform(&self) -> Box<dyn TracePlatform> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_thread(&self) -> Box<dyn crate::trace::seam_stubs::TraceThread> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_language(&self) -> Box<dyn crate::program::model::lang::Language> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_bounds(&self) -> Box<dyn TraceAddressSnapRange> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_range(&self) -> AddressRange {
            AddressRange::new(self.address.clone(), self.address.clone())
        }

        fn get_lifespan(&self) -> Lifespan {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_start_snap(&self) -> i64 {
            0
        }

        fn set_end_snap(&mut self, _end_snap: i64) {}

        fn get_end_snap(&self) -> i64 {
            10
        }

        fn delete(&mut self) {}
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    fn usable_as_trace_data_view_trait_object() {
        let view: Box<dyn TraceDataView> = Box::new(SingleUnitView { address: addr(0x400) });

        assert_eq!(view.size(), 1);
        assert!(view.get_at(0, &addr(0x400)).is_some());
        assert!(view.get_at(0, &addr(0x404)).is_none());
        assert!(view.contains_address(0, &addr(0x400)));
        assert_eq!(view.get_all(0, true).len(), 1);
    }
}
