use std::sync::Arc;

use crate::framework::cmd::Command;
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_utilities::{ClearDataMode, DataUtilities};
use crate::program::model::listing::Program;
use crate::program::seam_stubs::share_data_type;

/// Bare, state-free implementor used to reach [`DataUtilities`]'s default-implemented methods,
/// mirroring the "a bare `impl DataUtilities for Foo {}` is enough" convention documented on that
/// trait (see also
/// [`DyldChainedFixupsCommand`](crate::format::macho::commands::chained::dyld_chained_fixups_command::DyldChainedFixupsCommand)'s
/// identical `Du` helper).
struct Du;
impl DataUtilities for Du {}

/// This command will create a data of type `dataType` at the given address. This command will
/// only work for fixed length dataTypes. If there are any existing instructions in the area to
/// be made into data, the command will fail. Existing data in the area may be replaced with the
/// new dataType (with optional pointer conversion). If the existing dataType is a pointer, then
/// the existing data will be changed into a pointer to the given dataType. If the given dataType
/// is a default-pointer, it will become a pointer to the existing type.
///
/// Port of `ghidra.app.cmd.data.CreateDataCmd`.
///
/// Java stores `newDataType` as a plain `DataType` field re-passed to
/// `DataUtilities.createData` on every `applyTo` call; since that Rust `create_data*` API
/// consumes an owned `Box<dyn DataType>`, this port holds the type as an `Arc<dyn DataType>` and
/// hands out an aliasing `Box` via [`share_data_type`] each time `apply_to` runs, mirroring the
/// established convention documented on
/// [`DataUtilities::create_data_with_stack_pointers`](crate::program::model::data::data_utilities::DataUtilities::create_data_with_stack_pointers).
pub struct CreateDataCmd {
    addr: Address,
    new_data_type: Arc<dyn DataType>,
    cmd_name: String,
    msg: Option<String>,
    clear_mode: ClearDataMode,
    stack_pointers: bool,
}

impl CreateDataCmd {
    /// This constructor provides the most flexibility when creating data, allowing optional
    /// pointer conversion and various clearing options for conflicting data.
    ///
    /// Port of `CreateDataCmd(Address, DataType, boolean, ClearDataMode)`.
    pub fn new(
        addr: Address,
        data_type: Box<dyn DataType>,
        stack_pointers: bool,
        clear_mode: ClearDataMode,
    ) -> Self {
        let cmd_name = format!("Create {}", data_type.get_display_name());
        CreateDataCmd {
            addr,
            new_data_type: Arc::from(data_type),
            cmd_name,
            msg: None,
            clear_mode,
            stack_pointers,
        }
    }

    /// Constructs a command for creating data at an address. Simple pointer conversion will NOT
    /// be performed and existing defined data will not be cleared, however existing Undefined
    /// data will be cleared.
    ///
    /// Port of `CreateDataCmd(Address, DataType, boolean, boolean)`.
    pub fn new_cycle(
        addr: Address,
        data_type: Box<dyn DataType>,
        is_cycle: bool,
        stack_pointers: bool,
    ) -> Self {
        let clear_mode = if is_cycle {
            ClearDataMode::ClearSingleData
        } else {
            ClearDataMode::ClearAllUndefinedConflictData
        };
        Self::new(addr, data_type, stack_pointers, clear_mode)
    }

    /// Constructs a command for creating data at an address. Simple pointer conversion will NOT
    /// be performed and existing defined data will not be cleared, however existing Undefined
    /// data will be cleared.
    ///
    /// Port of `CreateDataCmd(Address, DataType)`.
    pub fn new_default(addr: Address, data_type: Box<dyn DataType>) -> Self {
        Self::new_cycle(addr, data_type, false, false)
    }

    /// Constructs a command for creating data at an address. Simple pointer conversion will NOT
    /// be performed. Existing Undefined data will always be cleared even when `force` is
    /// `false`.
    ///
    /// `force`: if true any existing conflicting data will be cleared.
    ///
    /// Port of `CreateDataCmd(Address, boolean, DataType)`.
    pub fn new_simple(addr: Address, force: bool, data_type: Box<dyn DataType>) -> Self {
        let clear_mode = if force {
            ClearDataMode::ClearAllConflictData
        } else {
            ClearDataMode::ClearAllUndefinedConflictData
        };
        Self::new(addr, data_type, false, clear_mode)
    }

    /// This is the same as [`CreateDataCmd::new_simple`] except that it allows the caller to
    /// control whether or not pointer conversion should be handled.
    ///
    /// Port of `CreateDataCmd(Address, boolean, boolean, DataType)`.
    pub fn new_with_stack_pointers(
        addr: Address,
        force: bool,
        stack_pointers: bool,
        data_type: Box<dyn DataType>,
    ) -> Self {
        let clear_mode = if force {
            ClearDataMode::ClearAllConflictData
        } else {
            ClearDataMode::ClearAllUndefinedConflictData
        };
        Self::new(addr, data_type, stack_pointers, clear_mode)
    }
}

impl Command<dyn Program + 'static> for CreateDataCmd {
    fn apply_to(&mut self, program: &mut (dyn Program + 'static)) -> bool {
        let du = Du;
        match du.create_data_with_stack_pointers(
            program,
            &self.addr,
            share_data_type(&self.new_data_type),
            -1,
            self.stack_pointers,
            self.clear_mode,
        ) {
            Ok(_) => true,
            Err(e) => {
                self.msg = Some(e.message().to_string());
                false
            }
        }
    }

    fn status_msg(&self) -> Option<String> {
        self.msg.clone()
    }

    fn name(&self) -> String {
        self.cmd_name.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::data::Data;
    use crate::program::model::listing::{CommentType, Listing};
    use crate::program::model::mem::{MemBuffer, MemoryAccessException};
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        EmptyReferenceIterator, ExternalReference, RefType as SymRefType, Reference as SymReference,
        ReferenceIterator, SourceType, Symbol,
    };
    use crate::program::model::util::PropertySet;
    use crate::program::util::CodeUnitInsertionException;
    use crate::docking::settings::settings::Settings;

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    struct MockDataType {
        name: &'static str,
    }
    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            self.name.to_string()
        }
    }

    // --- constructor delegation tests ---------------------------------------------------------

    #[test]
    fn new_sets_name_from_display_name_and_stores_fields() {
        let cmd = CreateDataCmd::new(
            test_address(0x1000),
            Box::new(MockDataType { name: "byte" }),
            true,
            ClearDataMode::ClearSingleData,
        );
        assert_eq!(cmd.name(), "Create byte");
        assert_eq!(cmd.status_msg(), None);
    }

    #[test]
    fn new_simple_not_forced_clears_only_undefined_conflicts() {
        let cmd = CreateDataCmd::new_simple(
            test_address(0x1000),
            false,
            Box::new(MockDataType { name: "dword" }),
        );
        assert_eq!(cmd.clear_mode, ClearDataMode::ClearAllUndefinedConflictData);
        assert!(!cmd.stack_pointers);
    }

    #[test]
    fn new_simple_forced_clears_all_conflicts() {
        let cmd = CreateDataCmd::new_simple(
            test_address(0x1000),
            true,
            Box::new(MockDataType { name: "dword" }),
        );
        assert_eq!(cmd.clear_mode, ClearDataMode::ClearAllConflictData);
        assert!(!cmd.stack_pointers);
    }

    #[test]
    fn new_with_stack_pointers_propagates_stack_pointers_flag() {
        let cmd = CreateDataCmd::new_with_stack_pointers(
            test_address(0x1000),
            true,
            true,
            Box::new(MockDataType { name: "ptr" }),
        );
        assert_eq!(cmd.clear_mode, ClearDataMode::ClearAllConflictData);
        assert!(cmd.stack_pointers);
    }

    #[test]
    fn new_default_matches_new_cycle_with_no_cycle_and_no_stack_pointers() {
        let cmd = CreateDataCmd::new_default(test_address(0x1000), Box::new(MockDataType { name: "word" }));
        assert_eq!(cmd.clear_mode, ClearDataMode::ClearAllUndefinedConflictData);
        assert!(!cmd.stack_pointers);
    }

    #[test]
    fn new_cycle_true_uses_clear_single_data() {
        let cmd = CreateDataCmd::new_cycle(
            test_address(0x1000),
            Box::new(MockDataType { name: "word" }),
            true,
            true,
        );
        assert_eq!(cmd.clear_mode, ClearDataMode::ClearSingleData);
        assert!(cmd.stack_pointers);
    }

    #[test]
    fn new_cycle_false_uses_clear_all_undefined_conflict_data() {
        let cmd = CreateDataCmd::new_cycle(
            test_address(0x1000),
            Box::new(MockDataType { name: "word" }),
            false,
            false,
        );
        assert_eq!(cmd.clear_mode, ClearDataMode::ClearAllUndefinedConflictData);
        assert!(!cmd.stack_pointers);
    }

    // --- apply_to behavior ---------------------------------------------------------------------

    struct NoListingProgram;
    impl DomainObject for NoListingProgram {}
    impl Program for NoListingProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    #[test]
    fn apply_to_fails_when_program_has_no_listing() {
        let mut cmd = CreateDataCmd::new_simple(
            test_address(0x1000),
            true,
            Box::new(MockDataType { name: "byte" }),
        );
        let mut program = NoListingProgram;
        assert!(!cmd.apply_to(&mut program));
        assert_eq!(
            cmd.status_msg(),
            Some(format!("Could not create Data at address {}", test_address(0x1000)))
        );
    }

    /// Minimal [`Data`] mock. Only the handful of methods actually reached along the two
    /// `apply_to` code paths exercised below (`is_parent_data`/`getData`/`is_defined`/existing
    /// `DataType`/length) are given real bodies; everything else panics if reached, matching the
    /// established `unimplemented!("not exercised...")` convention used elsewhere in this crate
    /// for the same kind of narrowly-scoped mock (see e.g.
    /// `program::model::data::structure_factory`'s and `program::model::listing::data`'s own test
    /// mocks).
    struct MockData {
        address: Address,
        data_type_name: &'static str,
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
            self.address.clone()
        }
    }
    impl PropertySet for MockData {}
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
            4
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
            Box::new(EmptyReferenceIterator)
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
    impl Settings for MockData {}
    impl Data for MockData {
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
            Box::new(MockDataType { name: self.data_type_name })
        }
        fn get_base_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType { name: self.data_type_name })
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
            _options: &dyn crate::program::model::data::data_type_display_options::DataTypeDisplayOptions,
        ) -> Option<String> {
            None
        }
    }

    struct MockListing {
        existing: Address,
        existing_type_name: &'static str,
        create_data_sized_calls: std::sync::atomic::AtomicI32,
    }
    impl crate::program::model::listing::stub_listing::StubListing for MockListing {
        fn get_data_at(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            Some(Arc::new(MockData {
                address: self.existing.clone(),
                data_type_name: self.existing_type_name,
            }))
        }
        fn create_data_sized(
            &mut self,
            addr: Address,
            _data_type: Box<dyn DataType>,
            _length: i32,
        ) -> Result<Arc<dyn Data>, CodeUnitInsertionException> {
            self.create_data_sized_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Arc::new(MockData {
                address: addr,
                data_type_name: "new_type",
            }))
        }
    }

    struct MockProgram {
        listing: crate::program::model::listing::ManagerCell<MockListing>,
    }
    impl DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
        fn get_listing(&self) -> Option<crate::program::model::listing::ManagerGuard<'_, dyn Listing>> {
        Some(crate::program::model::listing::ManagerGuard::lock(&self.listing))
    }
    }

    fn mock_program(addr: Address) -> MockProgram {
        MockProgram {
            listing: crate::program::model::listing::ManagerCell::new(MockListing {
                existing: addr,
                existing_type_name: "existing_type",
                create_data_sized_calls: std::sync::atomic::AtomicI32::new(0),
            }),
        }
    }

    /// Java quirk being reproduced here: when `force` is `false`, `CreateDataCmd` uses
    /// `ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA`, which denies clearing any *defined*
    /// conflicting data -- see `DataUtilities.isDataClearingDenied` (ported at
    /// `crate::program::model::data::data_utilities::is_data_clearing_denied`, which returns
    /// `true`, i.e. "denied", whenever the mode is `ClearAllUndefinedConflictData` and the
    /// existing type is not itself undefined). So applying a `CreateDataCmd` built with
    /// `force == false` on top of already-defined (non-Undefined) data always fails, exactly
    /// like the doc comment on `CreateDataCmd`'s Address+boolean+DataType constructor promises
    /// ("If there are any existing instructions... the command will fail" generalizes to any
    /// non-undefined conflict when not forced).
    #[test]
    fn apply_to_fails_on_defined_conflict_when_not_forced() {
        let addr = test_address(0x2000);
        let mut cmd = CreateDataCmd::new_simple(addr.clone(), false, Box::new(MockDataType { name: "new_type" }));
        let mut program = mock_program(addr.clone());

        assert!(!cmd.apply_to(&mut program));
        assert_eq!(
            cmd.status_msg(),
            Some(format!("Could not create Data at address {addr}"))
        );
        assert_eq!(program.listing.lock().create_data_sized_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn apply_to_succeeds_on_defined_conflict_when_forced() {
        let addr = test_address(0x2000);
        let mut cmd = CreateDataCmd::new_simple(addr.clone(), true, Box::new(MockDataType { name: "new_type" }));
        let mut program = mock_program(addr.clone());

        assert!(cmd.apply_to(&mut program));
        assert_eq!(cmd.status_msg(), None);
        assert_eq!(program.listing.lock().create_data_sized_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
