//! Port of `ghidra.program.model.pcode.MappedDataEntry`.
//!
//! A normal address-based `HighSymbol` mapping with an associated `Data` object.
//!
//! The Java class `extends MappedEntry`. Since Rust has no implementation inheritance, this
//! struct composes a [`MappedEntry`](crate::program::model::pcode::mapped_entry::MappedEntry) by
//! value (a "has-a" in place of Java's "is-a") and delegates every
//! [`SymbolEntry`](crate::program::model::pcode::symbol_entry::SymbolEntry) member Java inherits
//! unchanged (`get_high_symbol`/`get_pc_address`/`set_pc_address`/`encode`/`get_storage`/
//! `get_size`) straight through to it, mirroring `super.foo()` for the members
//! `MappedDataEntry` does not itself override. Only [`decode`](SymbolEntry::decode) (which Java
//! extends with `super.decode(decoder)` plus a Data lookup) and
//! [`get_mutability`](SymbolEntry::get_mutability) (which Java fully overrides, falling back to
//! `super.getMutability()`) have real bodies here.
//!
//! [`decode`](SymbolEntry::decode)'s Data lookup (`symbol.getProgram().getListing().getDataAt(...)`)
//! goes through the program's listing handle. This port's tests do not exercise the
//! "listing found" happy path with a dedicated mock: `Listing` is an exceptionally large trait
//! (~70 required methods covering every code-unit/instruction/data query), so building a
//! from-scratch mock implementor purely to return one `Data` value from `get_data_at` was judged
//! not worth the boilerplate here. The "no listing available" default-degrade branch (`data`
//! stays `None`, matching what a real `getDataAt` returning `null` would also produce) *is*
//! tested below, and the full "data was found" mutability decision tree is tested directly via
//! [`MappedDataEntry::with_data`], which does not depend on `decode`/`Listing` at all.
//!
//! [`get_mutability`](SymbolEntry::get_mutability) dereferences the `data` field
//! (`data.isVolatile()`/`isConstant()`/`isWritable()`) exactly as Java does, and so panics
//! (mirroring Java's `NullPointerException`) if called while `data` is unset -- which can happen
//! either because `decode` was never called, or because `decode` ran but found no `Data` at the
//! storage address (a real, reachable null, not just a construction-order quirk); both are tested
//! below via [`MappedEntry`]'s established convention for this same kind of panic.

use std::io;
use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::data::mutability_settings_definition::{CONSTANT, NORMAL, VOLATILE};
use crate::program::model::listing::variable_storage::VariableStorage;
use crate::program::model::listing::Data;
use crate::program::model::pcode::decoder::Decoder;
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::high_symbol::HighSymbol;
use crate::program::model::pcode::mapped_entry::MappedEntry;
use crate::program::model::pcode::pcode_factory::PcodeFactory;
use crate::program::model::pcode::symbol_entry::SymbolEntry;

/// A normal address-based `HighSymbol` mapping with an associated `Data` object. Port of
/// `ghidra.program.model.pcode.MappedDataEntry`.
pub struct MappedDataEntry {
    mapped: MappedEntry,
    data: Option<Arc<dyn Data>>,
}

impl MappedDataEntry {
    /// For use with [`SymbolEntry::decode`]. Port of the `MappedDataEntry(HighSymbol sym)`
    /// constructor.
    pub fn new(symbol: Arc<dyn HighSymbol>) -> Self {
        MappedDataEntry { mapped: MappedEntry::new(symbol), data: None }
    }

    /// Construct given a symbol, storage, and a backing `Data` object. Port of
    /// `MappedDataEntry(HighSymbol sym, VariableStorage store, Data d)` (which passes `null` for
    /// the base `MappedEntry`'s first-use address).
    pub fn with_data(symbol: Arc<dyn HighSymbol>, storage: Arc<dyn VariableStorage>, data: Arc<dyn Data>) -> Self {
        MappedDataEntry { mapped: MappedEntry::with_storage(symbol, storage, None), data: Some(data) }
    }

    /// The backing `Data` object, if any. Port of `MappedDataEntry.getData()`.
    pub fn get_data(&self) -> Option<Arc<dyn Data>> {
        self.data.clone()
    }
}

impl SymbolEntry for MappedDataEntry {
    fn get_high_symbol(&self) -> Arc<dyn HighSymbol> {
        self.mapped.get_high_symbol()
    }

    fn get_pc_address(&self) -> Option<Address> {
        self.mapped.get_pc_address()
    }

    fn set_pc_address(&mut self, addr: Option<Address>) {
        self.mapped.set_pc_address(addr);
    }

    fn decode(
        &mut self,
        decoder: &dyn Decoder,
        pcode_factory: &dyn PcodeFactory,
    ) -> Result<(), DecoderException> {
        self.mapped.decode(decoder, pcode_factory)?;
        let min_addr = self.mapped.get_storage().and_then(|s| s.get_min_address());
        self.data = min_addr.and_then(|addr| {
            let program = self.mapped.get_high_symbol().get_program();
            let data = program.get_listing().and_then(|l| l.get_data_at(&addr));
            data
        });
        Ok(())
    }

    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        self.mapped.encode(encoder)
    }

    fn get_storage(&self) -> Option<Box<dyn VariableStorage>> {
        self.mapped.get_storage()
    }

    fn get_size(&self) -> i32 {
        self.mapped.get_size()
    }

    fn get_mutability(&self) -> i32 {
        let data = self.data.as_ref().expect(
            "MappedDataEntry: `data` was dereferenced before it was set (mirrors Java's \
             NullPointerException on the null `data` field -- either decode() was never called, \
             or it ran but found no Data at the storage address)",
        );
        if data.is_volatile() {
            return VOLATILE;
        }
        if data.is_constant() {
            return CONSTANT;
        }
        if data.is_writable() {
            return NORMAL;
        }
        self.mapped.get_mutability()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
    use crate::program::model::lang::register::Register;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::CommentType;
    use crate::program::model::listing::Program;
    use crate::program::model::mem::{MemBuffer, MemoryAccessException};
    use crate::program::model::pcode::decoder::DecoderError;
    use crate::program::model::pcode::ids::{AttributeId, ElementId};
    use crate::program::model::pcode::Varnode;
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        EmptyReferenceIterator, ExternalReference, RefType, Reference, ReferenceIterator, SourceType,
        Symbol,
    };
    use crate::program::model::util::PropertySet;
    use crate::program::seam_stubs::VarnodeListStorage;
    use std::any::{Any, TypeId};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 5)
    }

    struct MockDataType;
    impl DataType for MockDataType {}

    /// `DataType` with a non-zero length, used as the `HighSymbol`'s data type so
    /// `MappedEntry::decode`'s `sz == 0` guard doesn't reject it (the plain [`MockDataType`]
    /// above, with the trait's default zero length, is only used where the data type's length is
    /// irrelevant).
    struct MockSizedDataType(i32);
    impl DataType for MockSizedDataType {
        fn get_length(&self) -> i32 {
            self.0
        }
    }

    struct MockHighSymbol {
        program: Arc<dyn Program>,
    }
    impl HighSymbol for MockHighSymbol {
        fn get_id(&self) -> i64 {
            1
        }
        fn get_high_function(&self) -> Arc<dyn crate::program::model::pcode::high_function::HighFunction> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_program(&self) -> Arc<dyn Program> {
            self.program.clone()
        }
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockSizedDataType(4))
        }
        fn encode(&self, _encoder: &mut dyn Encoder) -> io::Result<()> {
            unimplemented!("not needed for this smoke test")
        }
    }

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
        // `get_listing` is left at the trait default (`None`), exercising the documented
        // "no listing available" degrade path.
    }

    fn mock_symbol() -> Arc<dyn HighSymbol> {
        Arc::new(MockHighSymbol { program: Arc::new(MockProgram) })
    }

    fn mock_storage(addr_offset: i64) -> Arc<dyn VariableStorage> {
        Arc::new(VarnodeListStorage(vec![Varnode::new(ram_space().address(addr_offset), 4)]))
    }

    /// Full `Data` mock, adapted from the reference implementation in
    /// `program::model::listing::data`'s own tests, extended with independently controllable
    /// volatile/constant/writable flags to exercise
    /// [`MappedDataEntry::get_mutability`]'s full decision tree.
    struct MockData {
        volatile: bool,
        constant: bool,
        writable: bool,
    }

    impl MemBuffer for MockData {
        fn get_byte(&self, _offset: i32) -> Result<u8, MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> Address {
            ram_space().address(0)
        }
    }
    impl PropertySet for MockData {}

    impl CodeUnit for MockData {
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
            ram_space().address(0)
        }
        fn get_max_address(&self) -> Address {
            ram_space().address(0)
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
        fn add_mnemonic_reference(&mut self, _ref_addr: Address, _ref_type: RefType, _source_type: SourceType) {}
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
            Box::new(EmptyReferenceIterator)
        }
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
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
            self.constant
        }
        fn is_writable(&self) -> bool {
            self.writable
        }
        fn is_volatile(&self) -> bool {
            self.volatile
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
        fn get_value_references(&self) -> Vec<Box<dyn crate::program::seam_stubs::Reference>> {
            Vec::new()
        }
        fn add_value_reference(
            &mut self,
            _ref_addr: Address,
            _ref_type: Box<dyn crate::program::seam_stubs::RefType>,
        ) {
        }
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
            Box::new(MockData { volatile: self.volatile, constant: self.constant, writable: self.writable })
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

    // --- constructors / accessors ---

    #[test]
    fn with_data_round_trips_get_data() {
        let data: Arc<dyn Data> = Arc::new(MockData { volatile: false, constant: false, writable: true });
        let entry = MappedDataEntry::with_data(mock_symbol(), mock_storage(0x10), data.clone());
        let got = entry.get_data().expect("data should be set");
        assert!(std::ptr::eq(Arc::as_ptr(&got) as *const (), Arc::as_ptr(&data) as *const ()));
    }

    #[test]
    fn new_has_no_data_until_decode() {
        let entry = MappedDataEntry::new(mock_symbol());
        assert!(entry.get_data().is_none());
    }

    // --- get_mutability decision tree (via with_data, independent of decode/Listing) ---

    #[test]
    fn mutability_is_volatile_when_data_says_so() {
        let data: Arc<dyn Data> = Arc::new(MockData { volatile: true, constant: false, writable: false });
        let entry = MappedDataEntry::with_data(mock_symbol(), mock_storage(0x10), data);
        assert_eq!(entry.get_mutability(), VOLATILE);
    }

    #[test]
    fn mutability_is_constant_when_data_says_so() {
        let data: Arc<dyn Data> = Arc::new(MockData { volatile: false, constant: true, writable: false });
        let entry = MappedDataEntry::with_data(mock_symbol(), mock_storage(0x10), data);
        assert_eq!(entry.get_mutability(), CONSTANT);
    }

    #[test]
    fn mutability_is_normal_when_data_says_writable() {
        let data: Arc<dyn Data> = Arc::new(MockData { volatile: false, constant: false, writable: true });
        let entry = MappedDataEntry::with_data(mock_symbol(), mock_storage(0x10), data);
        assert_eq!(entry.get_mutability(), NORMAL);
    }

    #[test]
    fn mutability_falls_back_to_mapped_entry_when_data_flags_are_all_false() {
        // Java: `data.isVolatile()`/`isConstant()`/`isWritable()` all false falls through to
        // `super.getMutability()` (`MappedEntry.getMutability()`), which here resolves to NORMAL
        // since the mock `Program` has no memory/language configured.
        let data: Arc<dyn Data> = Arc::new(MockData { volatile: false, constant: false, writable: false });
        let entry = MappedDataEntry::with_data(mock_symbol(), mock_storage(0x10), data);
        assert_eq!(entry.get_mutability(), NORMAL);
    }

    #[test]
    #[should_panic(expected = "data")]
    fn mutability_before_data_is_set_panics() {
        // Faithful to Java: `MappedDataEntry.getMutability()` dereferences the null `data` field.
        let entry = MappedDataEntry::new(mock_symbol());
        entry.get_mutability();
    }

    // --- delegation to the composed MappedEntry ---

    #[test]
    fn get_storage_and_size_delegate_to_mapped_entry() {
        let data: Arc<dyn Data> = Arc::new(MockData { volatile: false, constant: false, writable: true });
        let entry = MappedDataEntry::with_data(mock_symbol(), mock_storage(0x10), data);
        assert_eq!(entry.get_size(), 4);
        assert!(entry.get_storage().is_some());
    }

    // --- decode() degrade path (no Listing available on the mock Program) ---

    struct MockPcodeFactory;
    impl PcodeFactory for MockPcodeFactory {
        fn get_address_factory(&self) -> Arc<dyn crate::program::model::address::AddressFactory> {
            unimplemented!("not exercised by this test")
        }
        fn get_data_type_manager(
            &self,
        ) -> Arc<dyn crate::program::model::pcode::pcode_data_type_manager::PcodeDataTypeManager> {
            unimplemented!("not exercised by this test")
        }
        fn new_varnode_with_ref(&self, _sz: i32, _addr: Address, _ref_id: i32) -> Varnode {
            unimplemented!("not exercised by this test")
        }
        fn get_join_address(&self, _storage: &dyn VariableStorage) -> Option<Address> {
            unimplemented!("not exercised by this test")
        }
        fn build_storage(
            &self,
            _vn: &Varnode,
        ) -> Result<Box<dyn VariableStorage>, crate::util::exception::InvalidInputException> {
            unimplemented!("not exercised by this test")
        }
        fn get_ref(&self, _refid: i32) -> Option<Varnode> {
            unimplemented!("not exercised by this test")
        }
        fn get_op_ref(&self, _refid: i32) -> Option<crate::program::model::pcode::PcodeOp> {
            unimplemented!("not exercised by this test")
        }
        fn get_symbol(&self, _symbol_id: i64) -> Option<Arc<dyn crate::program::seam_stubs::HighSymbol>> {
            unimplemented!("not exercised by this test")
        }
        fn new_op(
            &self,
            _sq: crate::program::model::pcode::SequenceNumber,
            _opc: crate::program::model::pcode::OpCode,
            _inputs: Vec<Varnode>,
            _output: Option<Varnode>,
        ) -> crate::program::model::pcode::PcodeOp {
            unimplemented!("not exercised by this test")
        }
    }

    struct MockDecoder {
        space: Arc<AddressSpace>,
        offset: u64,
        attr_pos: AtomicUsize,
    }
    impl Decoder for MockDecoder {
        fn get_address_factory(&self) -> Arc<dyn crate::program::model::address::AddressFactory> {
            unimplemented!()
        }
        fn set_address_factory(&self, _factory: Arc<dyn crate::program::model::address::AddressFactory>) {}
        fn peek_element(&self) -> Result<i32, DecoderError> {
            Ok(0)
        }
        fn open_element(&self) -> Result<i32, DecoderError> {
            Ok(1)
        }
        fn open_element_with_id(&self, _elem_id: ElementId) -> Result<i32, DecoderError> {
            self.open_element()
        }
        fn close_element(&self, _id: i32) -> Result<(), DecoderError> {
            Ok(())
        }
        fn close_element_skipping(&self, _id: i32) -> Result<(), DecoderError> {
            Ok(())
        }
        fn get_next_attribute_id(&self) -> Result<i32, DecoderError> {
            use crate::program::model::pcode::ids::{ATTRIB_OFFSET, ATTRIB_SPACE};
            let idx = self.attr_pos.fetch_add(1, Ordering::SeqCst);
            Ok(match idx {
                0 => ATTRIB_SPACE.id,
                1 => ATTRIB_OFFSET.id,
                _ => 0,
            })
        }
        fn rewind_attributes(&self) {
            self.attr_pos.store(0, Ordering::SeqCst);
        }
        fn read_bool(&self) -> Result<bool, DecoderError> {
            unimplemented!()
        }
        fn read_bool_with_id(&self, _attrib_id: AttributeId) -> Result<bool, DecoderError> {
            unimplemented!()
        }
        fn read_signed_integer(&self) -> Result<i64, DecoderError> {
            unimplemented!()
        }
        fn read_signed_integer_with_id(&self, _attrib_id: AttributeId) -> Result<i64, DecoderError> {
            unimplemented!()
        }
        fn read_unsigned_integer(&self) -> Result<u64, DecoderError> {
            Ok(self.offset)
        }
        fn read_unsigned_integer_with_id(&self, _attrib_id: AttributeId) -> Result<u64, DecoderError> {
            unimplemented!()
        }
        fn read_string(&self) -> Result<String, DecoderError> {
            unimplemented!()
        }
        fn read_string_with_id(&self, _attrib_id: AttributeId) -> Result<String, DecoderError> {
            unimplemented!()
        }
        fn read_space(&self) -> Result<Arc<AddressSpace>, DecoderError> {
            Ok(self.space.clone())
        }
        fn read_space_with_id(&self, _attrib_id: AttributeId) -> Result<Arc<AddressSpace>, DecoderError> {
            Ok(self.space.clone())
        }
    }

    #[test]
    fn decode_leaves_data_none_when_program_has_no_listing() {
        let space = ram_space();
        let mut entry = MappedDataEntry::new(mock_symbol());
        let decoder =
            MockDecoder { space: space.clone(), offset: 0x30, attr_pos: AtomicUsize::new(0) };

        entry.decode(&decoder, &MockPcodeFactory).expect("decode should succeed");

        // The mock Program's `get_listing()` uses the trait default (`None`), the same outcome a
        // real `getDataAt` call returning `null` would produce.
        assert!(entry.get_data().is_none());
        // But storage/pc-address decoding (delegated to the composed MappedEntry) still worked.
        assert_eq!(entry.get_size(), 4);
    }
}
