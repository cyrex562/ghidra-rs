//! Port of `ghidra.trace.database.listing.DBTraceDataCompositeFieldComponent`.
//!
//! The implementation of a field data component in a `DBTrace`. This is the concrete leaf that
//! fills in [`AbstractDBTraceDataComponent`]'s one abstract member (`getFieldSyntax()`) for the
//! struct/union-field case: a field's syntax is `.fieldName`, and its field name falls back to
//! the [`DataTypeComponent`]'s default field name when no explicit name is set.
//!
//! `getRange()`/`getBounds()` mirror the Java overrides literally, and follow the same pattern as
//! the sibling [`DBTraceDataArrayElementComponent`](super::db_trace_data_array_element_component::DBTraceDataArrayElementComponent):
//! `AddressRangeImpl` has no dedicated Rust port (it is just [`AddressRange::new`]), and
//! [`ImmutableTraceAddressSnapRange`](crate::trace::model::immutable_trace_address_snap_range::ImmutableTraceAddressSnapRange)
//! was ported as a trait rather than a concrete type, so [`ComponentBounds`] is the minimal
//! concrete [`TraceAddressSnapRange`] this leaf needs to stand in for `new
//! ImmutableTraceAddressSnapRange(min, max, lifespan)`.

use std::sync::Arc;

use crate::program::model::address::range::AddressRange;
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::trace::database::listing::abstract_db_trace_data_component::{
    AbstractDBTraceDataComponent, AbstractDBTraceDataComponentBase,
};
use crate::trace::database::listing::db_trace_data::DBTraceData;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
use crate::trace::seam_stubs::DBTraceDefinedDataAdapter;

/// A minimal, standalone [`TraceAddressSnapRange`] over a fixed `(min, max, lifespan)` triple.
///
/// Stands in for `new ImmutableTraceAddressSnapRange(min, max, lifespan)`; see the module
/// documentation for why no shared concrete implementor exists to reuse instead.
struct ComponentBounds {
    min: Address,
    max: Address,
    lifespan: Lifespan,
}

impl TraceAddressSnapRange for ComponentBounds {
    fn get_lifespan(&self) -> Lifespan {
        self.lifespan
    }

    fn get_range(&self) -> AddressRange {
        AddressRange::new(self.min.clone(), self.max.clone())
    }

    fn get_bounds(&self) -> Box<dyn TraceAddressSnapRange> {
        Box::new(ComponentBounds {
            min: self.min.clone(),
            max: self.max.clone(),
            lifespan: self.lifespan,
        })
    }

    fn immutable(
        &self,
        x1: Address,
        x2: Address,
        y1: i64,
        y2: i64,
    ) -> Box<dyn TraceAddressSnapRange> {
        Box::new(ComponentBounds {
            min: x1,
            max: x2,
            lifespan: Lifespan::span(y1, y2),
        })
    }
}

/// The implementation of a field data component in a `DBTrace`.
///
/// Port of `ghidra.trace.database.listing.DBTraceDataCompositeFieldComponent`.
pub struct DBTraceDataCompositeFieldComponent {
    base: AbstractDBTraceDataComponentBase,
    /// The data type component giving this field's index, data type, and length. Mirrors the
    /// constructor-injected `dtc` field.
    dtc: Box<dyn DataTypeComponent>,
}

impl DBTraceDataCompositeFieldComponent {
    /// Create a field.
    ///
    /// Mirrors the constructor `DBTraceDataCompositeFieldComponent(DBTraceData,
    /// DBTraceDefinedDataAdapter, Address, DataTypeComponent)`, which forwards the component's
    /// ordinal, data type, and length to the `AbstractDBTraceDataComponent` superclass
    /// constructor.
    pub fn new(
        root: Arc<dyn DBTraceData>,
        parent: Arc<dyn DBTraceDefinedDataAdapter>,
        address: Address,
        dtc: Box<dyn DataTypeComponent>,
    ) -> Self {
        let index = dtc.get_ordinal();
        let data_type: Arc<dyn DataType> = Arc::from(dtc.get_data_type());
        let length = dtc.get_length();
        DBTraceDataCompositeFieldComponent {
            base: AbstractDBTraceDataComponentBase::new(root, parent, index, address, data_type, length),
            dtc,
        }
    }

    /// Mirrors `DBTraceDataCompositeFieldComponent.getFieldName()`: the component's own field
    /// name, or its default field name when none is set (or it is empty).
    pub fn get_field_name(&self) -> Option<String> {
        match self.dtc.get_field_name() {
            Some(field_name) if !field_name.is_empty() => Some(field_name),
            _ => self.dtc.get_default_field_name(),
        }
    }

    /// Mirrors `DBTraceDataCompositeFieldComponent.getRange()`.
    pub fn get_range(&self) -> AddressRange {
        AddressRange::new(self.base.get_address(), self.base.get_max_address())
    }

    /// Mirrors `DBTraceDataCompositeFieldComponent.getBounds()`.
    pub fn get_bounds(&self) -> Box<dyn TraceAddressSnapRange> {
        Box::new(ComponentBounds {
            min: self.base.get_address(),
            max: self.base.get_max_address(),
            lifespan: self.base.get_lifespan(),
        })
    }

    /// Access to the embedded base's fields and methods (root, parent, index, address, data type,
    /// length, and the rest of `AbstractDBTraceDataComponent`'s concrete surface).
    pub fn base(&self) -> &AbstractDBTraceDataComponentBase {
        &self.base
    }
}

impl AbstractDBTraceDataComponent for DBTraceDataCompositeFieldComponent {
    /// Mirrors `DBTraceDataCompositeFieldComponent.getFieldSyntax()`: `"." + getFieldName()`.
    fn get_field_syntax(&self) -> String {
        format!(".{}", self.get_field_name().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::mem::{MemBuffer, MemoryAccessException};

    struct ByteDataType;

    impl DataType for ByteDataType {
        fn get_mnemonic(&self, _settings: &dyn Settings) -> String {
            "byte".to_string()
        }
        fn get_representation(&self, buf: &dyn MemBuffer, _settings: &dyn Settings, _length: i32) -> String {
            format!("{:#04x}", buf.get_byte(0).unwrap())
        }
        fn get_length(&self) -> i32 {
            1
        }
    }

    struct MockDataTypeComponent {
        ordinal: i32,
        length: i32,
        field_name: Option<String>,
        default_field_name: Option<String>,
    }

    impl DataTypeComponent for MockDataTypeComponent {
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(ByteDataType)
        }
        fn get_ordinal(&self) -> i32 {
            self.ordinal
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_field_name(&self) -> Option<String> {
            self.field_name.clone()
        }
        fn get_default_field_name(&self) -> Option<String> {
            self.default_field_name.clone()
        }
    }

    struct MockRootUnit {
        address: Address,
        bytes: Vec<u8>,
        start_snap: i64,
        end_snap: i64,
    }

    impl MemBuffer for MockRootUnit {
        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            self.bytes
                .get(offset as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of range"))
        }
        fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
            let start = offset as usize;
            let n = buf.len().min(self.bytes.len().saturating_sub(start));
            buf[..n].copy_from_slice(&self.bytes[start..start + n]);
            n
        }
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
    }

    impl crate::program::model::util::PropertySet for MockRootUnit {}

    impl Settings for MockRootUnit {
        fn get_default_settings(&self) -> Option<Box<dyn Settings>> {
            None
        }
    }

    impl crate::program::model::listing::code_unit::CodeUnit for MockRootUnit {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            format!("{:08x}", self.address.offset())
        }
        fn get_label(&self) -> Option<String> {
            None
        }
        fn get_symbols(&self) -> Vec<Arc<dyn crate::program::model::symbol::Symbol>> {
            Vec::new()
        }
        fn get_primary_symbol(&self) -> Option<Arc<dyn crate::program::model::symbol::Symbol>> {
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
        fn get_comment(&self, _comment_type: crate::program::model::listing::CommentType) -> Option<String> {
            None
        }
        fn get_comment_as_array(&self, _comment_type: crate::program::model::listing::CommentType) -> Vec<String> {
            Vec::new()
        }
        fn set_comment(&mut self, _comment_type: crate::program::model::listing::CommentType, _comment: Option<String>) {}
        fn set_comment_as_array(&mut self, _comment_type: crate::program::model::listing::CommentType, _comment: &[String]) {}
        fn get_length(&self) -> i32 {
            self.bytes.len() as i32
        }
        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(self.bytes.clone())
        }
        fn get_bytes_in_code_unit(&self, buffer: &mut [u8], _buffer_offset: i32) -> Result<(), MemoryAccessException> {
            buffer.fill(0x00);
            Ok(())
        }
        fn contains(&self, test_addr: &Address) -> bool {
            test_addr.offset() >= self.address.offset()
                && test_addr.offset() < self.address.offset() + self.bytes.len() as i64
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
        fn get_mnemonic_references(&self) -> Vec<Arc<dyn crate::program::model::symbol::Reference>> {
            Vec::new()
        }
        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn crate::program::model::symbol::Reference>> {
            Vec::new()
        }
        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn crate::program::model::symbol::Reference>> {
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
        fn get_references_from(&self) -> Vec<Arc<dyn crate::program::model::symbol::Reference>> {
            Vec::new()
        }
        fn get_reference_iterator_to(&self) -> Box<dyn crate::program::model::symbol::ReferenceIterator> {
            struct EmptyIter;
            impl Iterator for EmptyIter {
                type Item = Arc<dyn crate::program::model::symbol::Reference>;
                fn next(&mut self) -> Option<Self::Item> {
                    None
                }
            }
            impl crate::program::model::symbol::ReferenceIterator for EmptyIter {}
            Box::new(EmptyIter)
        }
        fn get_program(&self) -> Arc<dyn crate::program::model::listing::program::Program> {
            struct MockProgram;
            impl crate::framework::model::DomainObject for MockProgram {}
            impl crate::program::model::listing::program::Program for MockProgram {
                fn get_name(&self) -> String {
                    "mock.bin".to_string()
                }
                fn get_language_id(&self) -> String {
                    "test:LE:32:default".to_string()
                }
            }
            Arc::new(MockProgram)
        }
        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn crate::program::model::symbol::ExternalReference>> {
            None
        }
        fn remove_external_reference(&mut self, _op_index: i32) {}
        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn crate::program::model::symbol::Reference>) {}
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
            1
        }
        fn get_address(&self, _op_index: i32) -> Option<Address> {
            None
        }
        fn get_scalar(&self, _op_index: i32) -> Option<crate::program::model::scalar::Scalar> {
            None
        }
    }

    impl crate::program::model::listing::data::Data for MockRootUnit {
        fn get_value(&self) -> Option<Box<dyn std::any::Any>> {
            None
        }
        fn get_value_class(&self) -> Option<std::any::TypeId> {
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
            Box::new(ByteDataType)
        }
        fn get_base_data_type(&self) -> Box<dyn DataType> {
            Box::new(ByteDataType)
        }
        fn get_value_references(&self) -> Vec<Box<dyn crate::program::seam_stubs::Reference>> {
            Vec::new()
        }
        fn add_value_reference(&mut self, _ref_addr: Address, _ref_type: Box<dyn crate::program::seam_stubs::RefType>) {}
        fn remove_value_reference(&mut self, _ref_addr: Address) {}
        fn get_field_name(&self) -> Option<String> {
            None
        }
        fn get_path_name(&self) -> String {
            "ROOT".to_string()
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
        fn get_parent(&self) -> Option<Box<dyn crate::program::model::listing::data::Data>> {
            None
        }
        fn get_root(&self) -> Box<dyn crate::program::model::listing::data::Data> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_root_offset(&self) -> i32 {
            0
        }
        fn get_parent_offset(&self) -> i32 {
            0
        }
        fn get_component(&self, _index: i32) -> Option<Box<dyn crate::program::model::listing::data::Data>> {
            None
        }
        fn get_component_by_path(&self, _component_path: &[i32]) -> Option<Box<dyn crate::program::model::listing::data::Data>> {
            None
        }
        fn get_component_path(&self) -> Vec<i32> {
            Vec::new()
        }
        fn get_num_components(&self) -> i32 {
            0
        }
        fn get_component_at(&self, _offset: i32) -> Option<Box<dyn crate::program::model::listing::data::Data>> {
            None
        }
        fn get_component_containing(&self, _offset: i32) -> Option<Box<dyn crate::program::model::listing::data::Data>> {
            None
        }
        fn get_components_containing(&self, _offset: i32) -> Option<Vec<Box<dyn crate::program::model::listing::data::Data>>> {
            None
        }
        fn get_primitive_at(&self, _offset: i32) -> Option<Box<dyn crate::program::model::listing::data::Data>> {
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
        fn get_default_label_prefix(
            &self,
            _options: &dyn crate::program::model::data::data_type_display_options::DataTypeDisplayOptions,
        ) -> Option<String> {
            None
        }
    }

    impl crate::trace::model::listing::trace_code_unit::TraceCodeUnit for MockRootUnit {
        fn get_trace(&self) -> Box<dyn crate::trace::model::trace::Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_platform(&self) -> Box<dyn crate::trace::model::guest::trace_platform::TracePlatform> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_thread(&self) -> Box<dyn crate::trace::model::thread::TraceThread> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_language(&self) -> Box<dyn crate::program::model::lang::Language> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_bounds(&self) -> Box<dyn TraceAddressSnapRange> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_range(&self) -> AddressRange {
            AddressRange::new(self.address.clone(), addr(self.address.offset() + self.bytes.len() as i64 - 1))
        }
        fn get_lifespan(&self) -> Lifespan {
            Lifespan::span(self.start_snap, self.end_snap)
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
        fn delete(&mut self) {}
    }

    impl crate::trace::model::listing::trace_data::TraceData for MockRootUnit {}
    impl crate::trace::util::data_adapter_minimal::DataAdapterMinimal for MockRootUnit {}
    impl crate::trace::seam_stubs::DataAdapterFromDataType for MockRootUnit {}

    impl crate::trace::seam_stubs::DBTraceCodeUnitAdapter for MockRootUnit {
        fn trace_change_manager(&mut self) -> &mut dyn crate::trace::util::trace_change_manager::TraceChangeManager {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl crate::trace::database::listing::db_trace_data_adapter::DBTraceDataAdapter for MockRootUnit {
        fn get_settings_space(
            &self,
            _create_if_absent: bool,
        ) -> Option<Box<dyn crate::trace::database::data::db_trace_data_settings_operations::DBTraceDataSettingsOperations>> {
            None
        }
    }

    impl DBTraceDefinedDataAdapter for MockRootUnit {
        fn do_get_component_cache(&self) -> Vec<Box<dyn AbstractDBTraceDataComponent>> {
            Vec::new()
        }
        fn append_path_name(&self, builder: &mut String, include_root_symbol: bool) {
            if include_root_symbol {
                builder.push_str("ROOT");
            }
        }
    }

    impl DBTraceData for MockRootUnit {
        fn to_string(&self) -> String {
            crate::program::model::listing::data::Data::get_path_name(self)
        }
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    fn make_root() -> Arc<MockRootUnit> {
        Arc::new(MockRootUnit {
            address: addr(0x400),
            bytes: (0u8..8).collect(),
            start_snap: 0,
            end_snap: 10,
        })
    }

    fn make_field(dtc: MockDataTypeComponent) -> DBTraceDataCompositeFieldComponent {
        let root = make_root();
        DBTraceDataCompositeFieldComponent::new(root.clone(), root, addr(0x404), Box::new(dtc))
    }

    #[test]
    fn field_name_uses_explicit_name_when_set() {
        let field = make_field(MockDataTypeComponent {
            ordinal: 1,
            length: 1,
            field_name: Some("count".to_string()),
            default_field_name: Some("field1".to_string()),
        });
        assert_eq!(field.get_field_name(), Some("count".to_string()));
        assert_eq!(field.get_field_syntax(), ".count");
    }

    #[test]
    fn field_name_falls_back_to_default_when_unset() {
        let field = make_field(MockDataTypeComponent {
            ordinal: 2,
            length: 1,
            field_name: None,
            default_field_name: Some("field2".to_string()),
        });
        assert_eq!(field.get_field_name(), Some("field2".to_string()));
        assert_eq!(field.get_field_syntax(), ".field2");
    }

    #[test]
    fn field_name_falls_back_to_default_when_empty() {
        let field = make_field(MockDataTypeComponent {
            ordinal: 3,
            length: 1,
            field_name: Some(String::new()),
            default_field_name: Some("field3".to_string()),
        });
        assert_eq!(field.get_field_name(), Some("field3".to_string()));
    }

    #[test]
    fn range_spans_min_to_max_address() {
        let field = make_field(MockDataTypeComponent {
            ordinal: 0,
            length: 1,
            field_name: None,
            default_field_name: None,
        });
        let range = field.get_range();
        assert_eq!(range.min_address(), &addr(0x404));
        assert_eq!(range.max_address(), &addr(0x404));
    }

    #[test]
    fn bounds_combine_range_and_lifespan() {
        let field = make_field(MockDataTypeComponent {
            ordinal: 0,
            length: 1,
            field_name: None,
            default_field_name: None,
        });
        let bounds = field.get_bounds();
        assert_eq!(bounds.get_x1(), addr(0x404));
        assert_eq!(bounds.get_x2(), addr(0x404));
        assert_eq!(bounds.get_lifespan(), Lifespan::span(0, 10));
    }

    #[test]
    fn base_exposes_embedded_fields_derived_from_dtc() {
        let field = make_field(MockDataTypeComponent {
            ordinal: 7,
            length: 4,
            field_name: None,
            default_field_name: None,
        });
        assert_eq!(field.base().index, 7);
        assert_eq!(field.base().get_length(), 4);
        assert_eq!(field.base().get_address(), addr(0x404));
    }
}
