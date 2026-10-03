use std::any::{Any, TypeId};

use crate::program::model::address::Address;
use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
use crate::program::model::listing::Data;
use crate::program::model::scalar::Scalar;

/// Mixin supplying `Data`/`CodeUnit` method bodies derived purely from a data unit's
/// [`DataType`](crate::program::model::data::data_type::DataType), independent of how the unit
/// itself is stored.
///
/// Port of `ghidra.trace.util.DataAdapterFromDataType`.
///
/// The Java interface `extends Data` and supplies `default` overrides of several `Data`/
/// `CodeUnit` abstract members, every one of them computed from `getDataType()`/
/// `getBaseDataType()`/`getValue()`/`getLength()` alone. Rust has no trait-method
/// re-overriding -- the same issue documented on
/// [`DataAdapterMinimal`](super::data_adapter_minimal::DataAdapterMinimal) and
/// [`DBTraceDataAdapter`](crate::trace::database::listing::db_trace_data_adapter::DBTraceDataAdapter) --
/// so each method below is a *new*, separately dispatched method of the same name, not an
/// override of the inherited `Data`/`CodeUnit` abstract method it mirrors. A type implementing
/// both `Data` (directly, or transitively through `CodeUnit`) and this trait must disambiguate a
/// call with UFCS (e.g. `DataAdapterFromDataType::get_mnemonic_string(&x)`); a `Data`/`CodeUnit`
/// impl that wants this behavior should delegate its body to the `DataAdapterFromDataType`
/// version. The default bodies below call each other the same way, for the same reason.
///
/// `isDynamic()` mirrors `getBaseDataType() instanceof DynamicDataType`; the closest available
/// stand-in in this crate is [`DataType::is_dynamic_type`], which stands in for the broader
/// `instanceof Dynamic` check (see that method's docs) -- there is no narrower
/// `DynamicDataType`-specific marker yet, so this reuses it rather than inventing one.
///
/// [`DataType::is_dynamic_type`]: crate::program::model::data::data_type::DataType::is_dynamic_type
pub trait DataAdapterFromDataType: Data {
    /// Mirrors `doToString()`: the mnemonic, then (if non-empty) a space and the default value
    /// representation.
    fn do_to_string(&self) -> String
    where
        Self: Sized,
    {
        let mut result = DataAdapterFromDataType::get_mnemonic_string(self);
        let representation = DataAdapterFromDataType::get_default_value_representation(self);
        if !representation.is_empty() {
            result.push(' ');
            result.push_str(&representation);
        }
        result
    }

    /// Mirrors the `CodeUnit.getMnemonicString()` override: the data type's mnemonic under this
    /// data's own settings.
    fn get_mnemonic_string(&self) -> String
    where
        Self: Sized,
    {
        self.get_data_type().get_mnemonic(self)
    }

    /// Mirrors the `CodeUnit.getAddress(int)` override: operand 0's value, if it is an `Address`.
    fn get_address(&self, op_index: i32) -> Option<Address>
    where
        Self: Sized,
    {
        if op_index != 0 {
            return None;
        }
        let obj = DataAdapterFromDataType::get_value(self)?;
        obj.downcast::<Address>().ok().map(|b| *b)
    }

    /// Mirrors the `CodeUnit.getScalar(int)` override: operand 0's value as a `Scalar`, or an
    /// `Address` widened to an unsigned, pointer-sized `Scalar`.
    fn get_scalar(&self, op_index: i32) -> Option<Scalar>
    where
        Self: Sized,
    {
        if op_index != 0 {
            return None;
        }
        let obj = DataAdapterFromDataType::get_value(self)?;
        match obj.downcast::<Scalar>() {
            Ok(scalar) => Some(*scalar),
            Err(obj) => {
                let addr = obj.downcast::<Address>().ok()?;
                let offset = addr.addressable_word_offset();
                let bit_length = (addr.space().pointer_size() * 8) as u8;
                Some(Scalar::new_with_signedness(bit_length, offset, false))
            }
        }
    }

    /// Mirrors the `Data.getValue()` override: the base data type's interpretation of this
    /// data's own bytes/settings/length.
    fn get_value(&self) -> Option<Box<dyn Any>>
    where
        Self: Sized,
    {
        self.get_base_data_type()
            .get_value(self, self, self.get_length())
    }

    /// Mirrors the `Data.getValueClass()` override.
    fn get_value_class(&self) -> Option<TypeId>
    where
        Self: Sized,
    {
        self.get_base_data_type().get_value_class(self)
    }

    /// Mirrors the `Data.hasStringValue()` override: whether the value class is (assignable to)
    /// `String`.
    fn has_string_value(&self) -> bool
    where
        Self: Sized,
    {
        matches!(
            DataAdapterFromDataType::get_value_class(self),
            Some(class) if class == TypeId::of::<String>()
        )
    }

    /// Mirrors the `Data.isPointer()` override.
    fn is_pointer(&self) -> bool {
        self.get_base_data_type().is_pointer()
    }

    /// Mirrors the `Data.isUnion()` override.
    fn is_union(&self) -> bool {
        self.get_base_data_type().is_union()
    }

    /// Mirrors the `Data.isStructure()` override.
    fn is_structure(&self) -> bool {
        self.get_base_data_type().is_structure()
    }

    /// Mirrors the `Data.isArray()` override.
    fn is_array(&self) -> bool {
        self.get_base_data_type().is_array()
    }

    /// Mirrors the `Data.isDynamic()` override. See the trait's own docs for the
    /// `is_dynamic_type` substitution.
    fn is_dynamic(&self) -> bool {
        self.get_base_data_type().is_dynamic_type()
    }

    /// Mirrors the `Data.getDefaultValueRepresentation()` override.
    fn get_default_value_representation(&self) -> String
    where
        Self: Sized,
    {
        self.get_data_type()
            .get_representation(self, self, self.get_length())
    }

    /// Mirrors the `Data.getDefaultLabelPrefix(DataTypeDisplayOptions)` override.
    fn get_default_label_prefix(&self, options: &dyn DataTypeDisplayOptions) -> Option<String>
    where
        Self: Sized,
    {
        self.get_data_type().get_default_label_prefix_for_data(
            self,
            self,
            self.get_length(),
            options,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::docking::settings::settings::Settings;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::lang::register::Register;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::CommentType;
    use crate::program::model::listing::program::Program;
    use crate::program::model::mem::{MemBuffer, MemoryAccessException};
    use crate::program::model::symbol::{
        ExternalReference, RefType as SymRefType, Reference as SymReference, ReferenceIterator,
        SourceType, Symbol,
    };
    use crate::program::model::util::PropertySet;
    use crate::program::seam_stubs::{RefType as StubRefType, Reference as StubReference};

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    /// A minimal `DataType` whose value is either a fixed `Address`, or a plain `i64` (neither
    /// a `Scalar` nor an `Address`) when `as_address` is `None` -- enough to exercise every
    /// branch of `DataAdapterFromDataType::get_address`/`get_scalar` without a full `DataType`
    /// port. Every other member uses `DataType`'s own defaults (it has no required methods).
    #[derive(Clone)]
    struct FakeDataType {
        mnemonic: String,
        as_address: Option<Address>,
    }

    impl DataType for FakeDataType {
        fn get_mnemonic(&self, _settings: &dyn Settings) -> String {
            self.mnemonic.clone()
        }
        fn get_value(
            &self,
            _buf: &dyn MemBuffer,
            _settings: &dyn Settings,
            _length: i32,
        ) -> Option<Box<dyn Any>> {
            match &self.as_address {
                Some(a) => Some(Box::new(a.clone())),
                None => Some(Box::new(7i64)),
            }
        }
        fn get_representation(
            &self,
            _buf: &dyn MemBuffer,
            _settings: &dyn Settings,
            _length: i32,
        ) -> String {
            match &self.as_address {
                Some(a) => format!("addr:{}", a.offset()),
                None => "7".to_string(),
            }
        }
    }

    /// A minimal `Data` implementation. Only [`get_data_type`](Data::get_data_type),
    /// [`get_base_data_type`](Data::get_base_data_type), and
    /// [`CodeUnit::get_length`](crate::program::model::listing::code_unit::CodeUnit::get_length)
    /// are exercised by [`DataAdapterFromDataType`]'s default methods; every other required
    /// member of `Data`/`CodeUnit`/`MemBuffer`/`Settings` is unreachable from these tests.
    struct MockData {
        data_type: FakeDataType,
        length: i32,
    }

    impl MemBuffer for MockData {
        fn get_address(&self) -> Address {
            addr(0x1000)
        }
        fn get_byte(&self, _offset: i32) -> Result<u8, MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            true
        }
    }

    impl PropertySet for MockData {}

    impl Settings for MockData {}

    impl CodeUnit for MockData {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            unimplemented!("not exercised by these tests")
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
            addr(0x1000)
        }
        fn get_max_address(&self) -> Address {
            addr(0x1000)
        }
        fn get_mnemonic_string(&self) -> String {
            self.data_type.mnemonic.clone()
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
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes_in_code_unit(
            &self,
            _buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), MemoryAccessException> {
            unimplemented!("not exercised by these tests")
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
            unimplemented!("not exercised by these tests")
        }
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not exercised by these tests")
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
            Box::new(self.data_type.clone())
        }
        fn get_base_data_type(&self) -> Box<dyn DataType> {
            Box::new(self.data_type.clone())
        }
        fn get_value_references(&self) -> Vec<Box<dyn StubReference>> {
            Vec::new()
        }
        fn add_value_reference(&mut self, _ref_addr: Address, _ref_type: Box<dyn StubRefType>) {}
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
        fn get_default_label_prefix(
            &self,
            _options: &dyn DataTypeDisplayOptions,
        ) -> Option<String> {
            None
        }
    }

    impl DataAdapterFromDataType for MockData {}

    #[test]
    fn get_scalar_widens_address_to_pointer_sized_unsigned_scalar() {
        let data = MockData {
            data_type: FakeDataType {
                mnemonic: "ptr".to_string(),
                as_address: Some(addr(0x2000)),
            },
            length: 4,
        };
        let scalar = DataAdapterFromDataType::get_scalar(&data, 0).unwrap();
        assert_eq!(scalar.get_unsigned_value(), 0x2000);
        assert!(!scalar.is_signed());
    }

    #[test]
    fn get_scalar_returns_none_for_non_scalar_non_address_value() {
        let data = MockData {
            data_type: FakeDataType {
                mnemonic: "int".to_string(),
                as_address: None,
            },
            length: 4,
        };
        assert!(DataAdapterFromDataType::get_scalar(&data, 0).is_none());
    }

    #[test]
    fn get_scalar_returns_none_for_nonzero_op_index() {
        let data = MockData {
            data_type: FakeDataType {
                mnemonic: "ptr".to_string(),
                as_address: Some(addr(0x2000)),
            },
            length: 4,
        };
        assert!(DataAdapterFromDataType::get_scalar(&data, 1).is_none());
    }

    #[test]
    fn get_address_extracts_address_valued_data() {
        let data = MockData {
            data_type: FakeDataType {
                mnemonic: "ptr".to_string(),
                as_address: Some(addr(0x3000)),
            },
            length: 4,
        };
        let a = DataAdapterFromDataType::get_address(&data, 0).unwrap();
        assert_eq!(a.offset(), 0x3000);
    }

    #[test]
    fn do_to_string_joins_mnemonic_and_representation() {
        let data = MockData {
            data_type: FakeDataType {
                mnemonic: "int".to_string(),
                as_address: None,
            },
            length: 4,
        };
        assert_eq!(DataAdapterFromDataType::do_to_string(&data), "int 7");
    }

    #[test]
    fn has_string_value_is_false_for_non_string_class() {
        let data = MockData {
            data_type: FakeDataType {
                mnemonic: "int".to_string(),
                as_address: None,
            },
            length: 4,
        };
        assert!(!DataAdapterFromDataType::has_string_value(&data));
    }
}
