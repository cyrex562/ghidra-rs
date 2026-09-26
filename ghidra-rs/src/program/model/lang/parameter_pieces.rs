//! Port of `ghidra.program.model.lang.ParameterPieces`.
//!
//! Basic elements of a parameter: address, data-type, properties.
//!
//! This was originally a placeholder concrete struct living in `seam_stubs.rs` (only
//! `type`/`isIndirect`/`hiddenReturnPtr`/`address`/`joinPieces` were modeled, since those were
//! the only members its early consumers -- [`ParamList`](super::param_list::ParamList),
//! [`ParamListStandardOut`](super::param_list_standard_out::ParamListStandardOut),
//! [`ParamListStandard`](super::param_list_standard::ParamListStandard), and
//! [`ParamEntry`](super::param_entry::ParamEntry) -- read or wrote). It has since grown into the
//! direct dependency of the entire `protorules` `AssignAction` cluster
//! ([`AssignAction::assign_address`](super::protorules::assign_action::AssignAction::assign_address)
//! takes `res: &mut ParameterPieces` as its output parameter). This file graduates it to a real,
//! faithful port, adding the previously-omitted `isThisPointer` field and the real
//! `swapMarkup`/`getVariableStorage` methods (`mergeSequence`/`assignAddressFromPieces` were
//! already faithfully ported in the seam-stub version and are carried over unchanged).
//! `seam_stubs.rs` re-exports [`ParameterPieces`] under its old path so none of those existing
//! call sites need to change, following this crate's established precedent for graduating a
//! seam-stub type in place (e.g. `DataTypePath`, `Mask`, `StackFrame`, `VariableFilter`).
//!
//! `Debug` is intentionally not derived since `DataType` has no `Debug` supertrait yet.

use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::lang::language::Language;
use crate::program::model::listing::program::Program;
use crate::program::model::listing::variable_storage::{UnassignedStorage, VariableStorage, VoidStorage};
use crate::program::model::pcode::Varnode;
use crate::program::seam_stubs::{is_void_data_type, VarnodeListStorage};

/// Stands in for `DataType.DEFAULT`, assigned by [`ParameterPieces::get_variable_storage`] when
/// [`ParameterPieces::data_type`] is `None`, mirroring the identical `DefaultDataTypeStandIn`
/// stand-ins used elsewhere in this crate (e.g.
/// `program::database::data::parameter_definition_db`) in place of a global `DataType.DEFAULT`
/// singleton, which this crate does not model.
#[derive(Debug, Clone, Copy)]
struct DefaultDataTypeStandIn;

impl DataType for DefaultDataTypeStandIn {
    fn get_name(&self) -> String {
        "undefined".to_string()
    }

    fn get_length(&self) -> i32 {
        1
    }

    fn is_default_data_type(&self) -> bool {
        true
    }
}

/// Basic elements of a parameter: address, data-type, properties.
///
/// Port of `ghidra.program.model.lang.ParameterPieces`.
#[derive(Default, Clone)]
pub struct ParameterPieces {
    /// The data-type of the parameter (`ParameterPieces.type`; renamed since `type` is a Rust
    /// keyword).
    pub data_type: Option<Arc<dyn DataType>>,
    /// True if parameter is an indirect pointer to the actual parameter
    /// (`ParameterPieces.isIndirect`).
    pub is_indirect: bool,
    /// True if this is an input pointer to return storage (`ParameterPieces.hiddenReturnPtr`).
    pub hidden_return_ptr: bool,
    /// True if this is the "this" pointer (`ParameterPieces.isThisPointer`).
    pub is_this_pointer: bool,
    /// The starting address of the parameter's storage, or `None` if not yet assigned
    /// (`ParameterPieces.address`).
    pub address: Option<Address>,
    /// If non-`None`, multiple pieces stitched together for a single logical value
    /// (`ParameterPieces.joinPieces`).
    pub join_pieces: Option<Vec<Varnode>>,
}

impl ParameterPieces {
    /// Swap data-type markup between this and another parameter.
    ///
    /// Swaps the data-type and flags (`hiddenReturnPtr`/`isIndirect`/`isThisPointer`/
    /// `joinPieces`), but leaves the storage address intact. This assumes the two parameters are
    /// the same size.
    ///
    /// Port of `ParameterPieces.swapMarkup(ParameterPieces)`.
    pub fn swap_markup(&mut self, other: &mut ParameterPieces) {
        std::mem::swap(&mut self.hidden_return_ptr, &mut other.hidden_return_ptr);
        std::mem::swap(&mut self.is_indirect, &mut other.is_indirect);
        std::mem::swap(&mut self.is_this_pointer, &mut other.is_this_pointer);
        std::mem::swap(&mut self.data_type, &mut other.data_type);
        std::mem::swap(&mut self.join_pieces, &mut other.join_pieces);
    }

    /// Compute variable storage describing this parameter.
    ///
    /// Port of `ParameterPieces.getVariableStorage(Program)`.
    ///
    /// # Known gap
    /// Java constructs a `new DynamicVariableStorage(program, ...)` for every non-trivial case
    /// (the "this" pointer, join-pieces, hidden-return-ptr, and the general assigned-address
    /// case). This crate's
    /// [`DynamicVariableStorage`](crate::program::model::lang::dynamic_variable_storage::DynamicVariableStorage)
    /// is a trait only (no concrete, `ProgramArchitecture`-validated backing exists yet). The
    /// cases whose storage carries no dynamic flag -- plain assigned storage that is not forced
    /// indirect, and join pieces -- return a [`VarnodeListStorage`] of the assigned varnodes (the
    /// crate's in-memory storage for a bare varnode list). The auto-parameter ("this", hidden
    /// return pointer) and forced-indirect cases, whose flags a plain varnode list cannot carry,
    /// still fall back to [`UnassignedStorage`], as does Java's own `catch
    /// (InvalidInputException)` path.
    pub fn get_variable_storage(&mut self, _program: &dyn Program) -> Box<dyn VariableStorage> {
        if self.data_type.is_none() {
            self.data_type = Some(Arc::new(DefaultDataTypeStandIn));
        }
        let data_type = self.data_type.as_ref().expect("just set above if it was None");
        if is_void_data_type(Some(data_type.as_ref())) {
            // Java: `isIndirect` selects `DynamicVariableStorage.INDIRECT_VOID_STORAGE` instead
            // of `VariableStorage.VOID_STORAGE`. See the "Known gap" section above: this crate
            // has no concrete `DynamicVariableStorage`, so both branches return `VoidStorage`
            // here.
            return Box::new(VoidStorage);
        }
        let sz = data_type.get_length();
        if sz == 0 {
            return Box::new(UnassignedStorage);
        }
        // See the "Known gap" doc above for which Java `DynamicVariableStorage` branches are
        // represented.
        if self.is_this_pointer {
            return Box::new(UnassignedStorage);
        }
        if let Some(join_pieces) = &self.join_pieces {
            return Box::new(VarnodeListStorage(join_pieces.clone()));
        }
        if self.hidden_return_ptr || self.is_indirect {
            return Box::new(UnassignedStorage);
        }
        match &self.address {
            Some(address) => Box::new(VarnodeListStorage(vec![Varnode::new(address.clone(), sz)])),
            None => Box::new(UnassignedStorage),
        }
    }

    /// Assuming the given list of Varnodes go from most significant to least significant, merge
    /// any contiguous elements in the list. Merges in a register space are only allowed if the
    /// bigger Varnode exists as a formal register.
    ///
    /// Port of the static `ghidra.program.model.lang.ParameterPieces.mergeSequence`. Needed by
    /// [`assign_address_from_pieces`](Self::assign_address_from_pieces), which
    /// [`MultiMemberAssign`](crate::program::model::lang::protorules::MultiMemberAssign) calls to
    /// stitch together the per-primitive-member pieces it collects into one storage location.
    pub fn merge_sequence(seq: Vec<Varnode>, language: &dyn Language) -> Vec<Varnode> {
        let big_endian = language.is_big_endian();
        let mut i = 1usize;
        while i < seq.len() {
            if seq[i - 1].is_contiguous(&seq[i], big_endian) {
                break;
            }
            i += 1;
        }
        if i >= seq.len() {
            return seq;
        }
        let mut buffer: Vec<Varnode> = vec![seq[0].clone()];
        let mut last_is_informal = false;
        let mut i = 1usize;
        while i < seq.len() {
            let hi = buffer.last().expect("buffer seeded with seq[0]").clone();
            let lo = &seq[i];
            if hi.is_contiguous(lo, big_endian) {
                let off = if big_endian { hi.get_offset() } else { lo.get_offset() };
                let sz = hi.get_size() + lo.get_size();
                let new_vn = Varnode::new(Address::new(hi.get_address().space().clone(), off), sz);
                buffer.pop();
                // Test if the new Varnode is a formal register
                if !new_vn.get_address().is_stack_address() {
                    last_is_informal = language
                        .get_register_at(new_vn.get_address(), new_vn.get_size())
                        .is_none();
                }
                buffer.push(new_vn);
            } else {
                if last_is_informal {
                    break;
                }
                buffer.push(lo.clone());
            }
            i += 1;
        }
        if last_is_informal {
            // If the merge contains an informal register, throw it out and keep the original
            // sequence
            return seq;
        }
        buffer
    }

    /// Generate a parameter address given the list of Varnodes making up the parameter.
    ///
    /// `pieces` is the given list of Varnodes; `most_to_least` is true if the list is ordered
    /// most significant to least; `one_piece_join` is true if the address should be considered a
    /// join of one piece; `language` is the Language associated with the calling convention.
    ///
    /// Port of `ghidra.program.model.lang.ParameterPieces.assignAddressFromPieces`.
    pub fn assign_address_from_pieces(
        &mut self,
        mut pieces: Vec<Varnode>,
        most_to_least: bool,
        one_piece_join: bool,
        language: &dyn Language,
    ) {
        if !most_to_least && pieces.len() > 1 {
            pieces.reverse();
        }
        let pieces = Self::merge_sequence(pieces, language);
        if pieces.len() == 1 && !one_piece_join {
            self.address = Some(pieces[0].get_address().clone());
            return;
        }
        self.join_pieces = Some(pieces);
        // Java sets `address = Address.NO_ADDRESS` here ("Placeholder for join space address");
        // this port's `address` is already `Option<Address>` with `None` meaning "not yet
        // assigned" (see the field doc above), so `None` is the direct equivalent.
        self.address = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::register::RegisterRef;

    #[derive(Debug, Clone, Copy)]
    struct MockDataType {
        length: i32,
        void: bool,
    }

    impl DataType for MockDataType {
        fn get_length(&self) -> i32 {
            self.length
        }

        fn is_void_type(&self) -> bool {
            self.void
        }
    }

    /// Minimal `Language` mock, reporting little-endian and no formal registers anywhere
    /// (so [`ParameterPieces::merge_sequence`] never treats a merged Varnode as a formal
    /// register). Mirrors the `TwoRegLanguage` mock in
    /// `protorules::multi_member_assign::tests`.
    struct MockLanguage;

    impl Language for MockLanguage {
        fn get_language_id(&self) -> crate::program::model::lang::language_id::LanguageID {
            unimplemented!()
        }
        fn get_language_description(&self) -> Box<dyn crate::program::model::lang::language_description::LanguageDescription> {
            unimplemented!()
        }
        fn get_parallel_instruction_helper(&self) -> Option<Box<dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper>> {
            None
        }
        fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
            unimplemented!()
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!()
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            ram_space()
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            ram_space()
        }
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_instruction_alignment(&self) -> i32 {
            1
        }
        fn supports_pcode(&self) -> bool {
            true
        }
        fn is_volatile(&self, _addr: &Address) -> bool {
            false
        }
        fn parse(
            &self,
            _buf: &dyn crate::program::model::mem::MemBuffer,
            _context: &mut dyn crate::program::model::lang::processor_context::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<
            Box<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>,
            crate::program::model::lang::language::ParseError,
        > {
            unimplemented!()
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }
        fn get_registers_at(&self, _address: &Address) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_in_space(&self, _addrspc: &Arc<AddressSpace>, _offset: i64, _size: i32) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_register_by_name(&self, _name: &str) -> Option<RegisterRef> {
            None
        }
        fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<RegisterRef> {
            // No formal register recognized at any address -- forces merge_sequence to treat
            // every merge as "informal" unless the test overrides this behavior.
            None
        }
        fn get_program_counter(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_base_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_default_memory_blocks(&self) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
            Vec::new()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
            Vec::new()
        }
        fn get_segmented_space(&self) -> String {
            String::new()
        }
        fn get_volatile_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!()
        }
        fn apply_context_settings(
            &self,
            _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext,
        ) {
        }
        fn reload_language(&self, _task_monitor: &dyn crate::util::task::TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>> {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
        ) -> Result<Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec>, crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException>
        {
            unimplemented!()
        }
        fn get_default_compiler_spec(&self) -> Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec> {
            unimplemented!()
        }
        fn has_property(&self, _key: &str) -> bool {
            false
        }
        fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
            default_int
        }
        fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
            default_boolean
        }
        fn get_property_or(&self, _key: &str, default_string: &str) -> String {
            default_string.to_string()
        }
        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }
        fn get_property_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }
        fn has_manual(&self) -> bool {
            false
        }
        fn get_manual_entry(&self, _instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }
        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!()
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn ram_varnode(offset: i64, size: i32) -> Varnode {
        Varnode::new(Address::new(ram_space(), offset), size)
    }

    /// A stack address space, used for merge tests: `merge_sequence` skips the "is this a
    /// formal register" check entirely for stack addresses (`Address::is_stack_address`), so
    /// these merges succeed under [`MockLanguage`] without needing a register-aware mock.
    fn stack_space() -> Arc<AddressSpace> {
        AddressSpace::new("stack", 32, 1, AddressSpaceType::Stack, 0)
    }

    fn stack_varnode(offset: i64, size: i32) -> Varnode {
        Varnode::new(Address::new(stack_space(), offset), size)
    }

    #[test]
    fn default_has_no_address_and_no_flags() {
        let pieces = ParameterPieces::default();
        assert!(pieces.data_type.is_none());
        assert!(!pieces.is_indirect);
        assert!(!pieces.hidden_return_ptr);
        assert!(!pieces.is_this_pointer);
        assert!(pieces.address.is_none());
        assert!(pieces.join_pieces.is_none());
    }

    #[test]
    fn swap_markup_swaps_flags_and_type_but_not_address() {
        let addr_a = Address::new(ram_space(), 0x1000);
        let addr_b = Address::new(ram_space(), 0x2000);
        let mut a = ParameterPieces {
            data_type: Some(Arc::new(MockDataType { length: 4, void: false })),
            is_indirect: true,
            hidden_return_ptr: false,
            is_this_pointer: true,
            address: Some(addr_a.clone()),
            join_pieces: None,
        };
        let mut b = ParameterPieces {
            data_type: Some(Arc::new(MockDataType { length: 8, void: false })),
            is_indirect: false,
            hidden_return_ptr: true,
            is_this_pointer: false,
            address: Some(addr_b.clone()),
            join_pieces: Some(vec![ram_varnode(0x10, 2)]),
        };

        a.swap_markup(&mut b);

        // Addresses are untouched.
        assert_eq!(a.address, Some(addr_a));
        assert_eq!(b.address, Some(addr_b));
        // Flags/type/joinPieces are swapped.
        assert_eq!(a.data_type.unwrap().get_length(), 8);
        assert!(!a.is_indirect);
        assert!(a.hidden_return_ptr);
        assert!(!a.is_this_pointer);
        assert_eq!(a.join_pieces.unwrap().len(), 1);

        assert_eq!(b.data_type.unwrap().get_length(), 4);
        assert!(b.is_indirect);
        assert!(!b.hidden_return_ptr);
        assert!(b.is_this_pointer);
        assert!(b.join_pieces.is_none());
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
    }

    #[test]
    fn get_variable_storage_void_type_returns_void_storage() {
        let mut pieces = ParameterPieces {
            data_type: Some(Arc::new(MockDataType { length: 0, void: true })),
            ..Default::default()
        };
        let storage = pieces.get_variable_storage(&MockProgram);
        assert!(storage.is_void_storage());
    }

    #[test]
    fn get_variable_storage_assigned_address_and_join_pieces_report_their_varnodes() {
        let addr = Address::new(ram_space(), 0x1000);
        let mut pieces = ParameterPieces {
            data_type: Some(Arc::new(MockDataType { length: 4, void: false })),
            address: Some(addr.clone()),
            ..Default::default()
        };
        let storage = pieces.get_variable_storage(&MockProgram);
        assert_eq!(storage.get_varnodes(), vec![Varnode::new(addr.clone(), 4)]);

        let join = vec![Varnode::new(Address::new(ram_space(), 0x2000), 4), Varnode::new(addr.clone(), 4)];
        let mut pieces = ParameterPieces {
            data_type: Some(Arc::new(MockDataType { length: 8, void: false })),
            address: Some(addr.clone()),
            join_pieces: Some(join.clone()),
            ..Default::default()
        };
        assert_eq!(pieces.get_variable_storage(&MockProgram).get_varnodes(), join);

        // Auto-parameter and forced-indirect storage need DynamicVariableStorage's flags.
        let mut this_ptr = ParameterPieces {
            data_type: Some(Arc::new(MockDataType { length: 4, void: false })),
            address: Some(addr.clone()),
            is_this_pointer: true,
            ..Default::default()
        };
        assert!(this_ptr.get_variable_storage(&MockProgram).is_unassigned_storage());
        let mut indirect = ParameterPieces {
            data_type: Some(Arc::new(MockDataType { length: 4, void: false })),
            address: Some(addr),
            is_indirect: true,
            ..Default::default()
        };
        assert!(indirect.get_variable_storage(&MockProgram).is_unassigned_storage());
    }

    #[test]
    fn get_variable_storage_zero_length_returns_unassigned_storage() {
        let mut pieces = ParameterPieces {
            data_type: Some(Arc::new(MockDataType { length: 0, void: false })),
            ..Default::default()
        };
        let storage = pieces.get_variable_storage(&MockProgram);
        assert!(storage.is_unassigned_storage());
    }

    #[test]
    fn get_variable_storage_none_type_defaults_to_undefined_and_is_unassigned() {
        let mut pieces = ParameterPieces::default();
        assert!(pieces.data_type.is_none());
        let storage = pieces.get_variable_storage(&MockProgram);
        // DataType.DEFAULT (undefined1, length 1) is non-void with sz != 0, so the general
        // fallback (currently UnassignedStorage -- see the "Known gap" doc) applies, and the
        // `data_type` field itself gets populated from `None`, mirroring Java's `type =
        // DataType.DEFAULT` assignment.
        assert!(pieces.data_type.is_some());
        assert_eq!(pieces.data_type.unwrap().get_length(), 1);
        assert!(storage.is_unassigned_storage());
    }

    #[test]
    fn merge_sequence_merges_contiguous_little_endian_pieces_on_the_stack() {
        // Uses stack-space varnodes: `merge_sequence` only consults `get_register_at` (which
        // `MockLanguage` always answers `None` for) when the merged Varnode is NOT a stack
        // address, so a stack merge exercises the "always merge" path without needing a
        // register-aware mock.
        let lang = MockLanguage;
        let hi = stack_varnode(0x1004, 4);
        let lo = stack_varnode(0x1000, 4);
        let merged = ParameterPieces::merge_sequence(vec![hi, lo], &lang);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].get_offset(), 0x1000);
        assert_eq!(merged[0].get_size(), 8);
    }

    #[test]
    fn merge_sequence_leaves_non_contiguous_pieces_alone() {
        let lang = MockLanguage;
        let a = ram_varnode(0x1000, 4);
        let b = ram_varnode(0x2000, 4);
        let merged = ParameterPieces::merge_sequence(vec![a.clone(), b.clone()], &lang);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].get_offset(), a.get_offset());
        assert_eq!(merged[1].get_offset(), b.get_offset());
    }

    /// A `Language` whose `get_register_at` recognizes a formal register at any address in
    /// `register_space` (mirroring the pattern in
    /// `program::model::listing::variable_storage::tests::MockLanguage`), letting a test prove
    /// out the "merges in a register space are only allowed if the bigger Varnode exists as a
    /// formal register" rule (`ParameterPieces.mergeSequence`'s doc comment) both ways.
    struct RegisterAwareLanguage {
        register_space: Arc<AddressSpace>,
    }

    impl Language for RegisterAwareLanguage {
        fn get_language_id(&self) -> crate::program::model::lang::language_id::LanguageID {
            unimplemented!()
        }
        fn get_language_description(&self) -> Box<dyn crate::program::model::lang::language_description::LanguageDescription> {
            unimplemented!()
        }
        fn get_parallel_instruction_helper(&self) -> Option<Box<dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper>> {
            None
        }
        fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
            unimplemented!()
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!()
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            ram_space()
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            ram_space()
        }
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_instruction_alignment(&self) -> i32 {
            1
        }
        fn supports_pcode(&self) -> bool {
            true
        }
        fn is_volatile(&self, _addr: &Address) -> bool {
            false
        }
        fn parse(
            &self,
            _buf: &dyn crate::program::model::mem::MemBuffer,
            _context: &mut dyn crate::program::model::lang::processor_context::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<
            Box<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>,
            crate::program::model::lang::language::ParseError,
        > {
            unimplemented!()
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }
        fn get_registers_at(&self, _address: &Address) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_in_space(&self, _addrspc: &Arc<AddressSpace>, _offset: i64, _size: i32) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_register_by_name(&self, _name: &str) -> Option<RegisterRef> {
            None
        }
        fn get_register_at(&self, addr: &Address, size: i32) -> Option<RegisterRef> {
            if addr.space().as_ref() != self.register_space.as_ref() {
                return None;
            }
            Some(crate::program::model::lang::register::Register::new(
                "r0",
                "mock register",
                addr.clone(),
                size,
                false,
                0,
            ))
        }
        fn get_program_counter(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_base_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_default_memory_blocks(&self) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
            Vec::new()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
            Vec::new()
        }
        fn get_segmented_space(&self) -> String {
            String::new()
        }
        fn get_volatile_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!()
        }
        fn apply_context_settings(
            &self,
            _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext,
        ) {
        }
        fn reload_language(&self, _task_monitor: &dyn crate::util::task::TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>> {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
        ) -> Result<Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec>, crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException>
        {
            unimplemented!()
        }
        fn get_default_compiler_spec(&self) -> Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec> {
            unimplemented!()
        }
        fn has_property(&self, _key: &str) -> bool {
            false
        }
        fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
            default_int
        }
        fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
            default_boolean
        }
        fn get_property_or(&self, _key: &str, default_string: &str) -> String {
            default_string.to_string()
        }
        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }
        fn get_property_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }
        fn has_manual(&self) -> bool {
            false
        }
        fn get_manual_entry(&self, _instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }
        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!()
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    fn register_space() -> Arc<AddressSpace> {
        AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0)
    }

    fn register_varnode(offset: i64, size: i32) -> Varnode {
        Varnode::new(Address::new(register_space(), offset), size)
    }

    #[test]
    fn merge_sequence_merges_contiguous_pieces_that_form_a_formal_register() {
        let lang = RegisterAwareLanguage { register_space: register_space() };
        let hi = register_varnode(0x4, 4);
        let lo = register_varnode(0x0, 4);
        let merged = ParameterPieces::merge_sequence(vec![hi, lo], &lang);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].get_offset(), 0x0);
        assert_eq!(merged[0].get_size(), 8);
    }

    #[test]
    fn merge_sequence_discards_merge_of_pieces_that_do_not_form_a_formal_register() {
        // MockLanguage's `get_register_at` always answers `None`, so a merged register-space
        // Varnode is never recognized as formal -- the whole merge is thrown out and the
        // original (unmerged) sequence is returned, per the doc comment on
        // `ParameterPieces.mergeSequence`.
        let lang = MockLanguage;
        let hi = register_varnode(0x4, 4);
        let lo = register_varnode(0x0, 4);
        let original_len = 2;
        let merged = ParameterPieces::merge_sequence(vec![hi, lo], &lang);
        assert_eq!(merged.len(), original_len);
    }

    #[test]
    fn assign_address_from_pieces_single_piece_sets_address() {
        let lang = MockLanguage;
        let mut pieces = ParameterPieces::default();
        pieces.assign_address_from_pieces(vec![ram_varnode(0x3000, 4)], true, false, &lang);
        assert_eq!(pieces.address, Some(Address::new(ram_space(), 0x3000)));
        assert!(pieces.join_pieces.is_none());
    }

    #[test]
    fn assign_address_from_pieces_multiple_non_contiguous_pieces_sets_join_pieces() {
        let lang = MockLanguage;
        let mut pieces = ParameterPieces::default();
        pieces.assign_address_from_pieces(
            vec![ram_varnode(0x1000, 4), ram_varnode(0x2000, 4)],
            true,
            false,
            &lang,
        );
        assert!(pieces.address.is_none());
        assert_eq!(pieces.join_pieces.unwrap().len(), 2);
    }

    #[test]
    fn assign_address_from_pieces_reverses_when_least_to_most() {
        let lang = MockLanguage;
        // Contiguous when read most-significant-first: [0x1004 (hi), 0x1000 (lo)]. Passed in
        // least-to-most order: [0x1000, 0x1004]. Uses stack-space varnodes so the merge succeeds
        // under `MockLanguage` without a register-aware mock (see
        // `merge_sequence_merges_contiguous_little_endian_pieces_on_the_stack`).
        let mut pieces = ParameterPieces::default();
        pieces.assign_address_from_pieces(
            vec![stack_varnode(0x1000, 4), stack_varnode(0x1004, 4)],
            false,
            false,
            &lang,
        );
        assert_eq!(pieces.address, Some(Address::new(stack_space(), 0x1000)));
        assert!(pieces.join_pieces.is_none());
    }

    #[test]
    fn assign_address_from_pieces_one_piece_join_forces_join_pieces() {
        let lang = MockLanguage;
        let mut pieces = ParameterPieces::default();
        pieces.assign_address_from_pieces(vec![ram_varnode(0x3000, 4)], true, true, &lang);
        assert!(pieces.address.is_none());
        assert_eq!(pieces.join_pieces.unwrap().len(), 1);
    }
}
