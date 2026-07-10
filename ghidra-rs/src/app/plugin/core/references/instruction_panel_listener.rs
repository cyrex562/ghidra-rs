use crate::program::model::address::AddressSetView;
use crate::program::model::listing::CodeUnit;

/// Listener for instruction panel events.
///
/// Receives notifications about operand selection and drag-drop interactions
/// on the instruction panel. Maps to `ghidra.app.plugin.core.references.InstructionPanelListener`.
pub trait InstructionPanelListener {
    /// Called when an operand is selected.
    ///
    /// # Arguments
    /// * `op_index` - index of the operand (mnemonic is typically -1)
    /// * `sub_index` - sub-index within the operand
    fn operand_selected(&mut self, op_index: i32, sub_index: i32);

    /// Called when a selection is dropped on an instruction.
    ///
    /// # Arguments
    /// * `set` - the address set being dropped
    /// * `cu` - the code unit (instruction or data) under the drop point
    /// * `op_index` - index of the operand at the drop location
    fn selection_dropped(&mut self, set: &dyn AddressSetView, cu: &dyn CodeUnit, op_index: i32);

    /// Returns whether drag-drop is supported by this listener.
    fn drop_supported(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use crate::program::model::address::{Address, AddressSet, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::register::Register;
    use crate::program::model::listing::program::Program;
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        ExternalReference, RefType, Reference, ReferenceIterator, SourceType, Symbol,
    };
    use crate::program::model::util::PropertySet;
    use crate::program::seam_stubs::{CommentType, MemBuffer};

    fn fake_address() -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, 0)
    }

    struct FakeCodeUnit;

    impl MemBuffer for FakeCodeUnit {
        fn get_address(&self) -> Address {
            fake_address()
        }
    }

    impl PropertySet for FakeCodeUnit {}

    impl CodeUnit for FakeCodeUnit {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            "0x0".to_string()
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
            fake_address()
        }
        fn get_max_address(&self) -> Address {
            fake_address()
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
            Box::new(crate::program::model::symbol::EmptyReferenceIterator)
        }
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not needed for this smoke test")
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

    struct RecordingListener {
        operand_selections: Vec<(i32, i32)>,
        drops: Vec<i32>,
        drop_support: bool,
    }

    impl RecordingListener {
        fn new(drop_support: bool) -> Self {
            Self {
                operand_selections: vec![],
                drops: vec![],
                drop_support,
            }
        }
    }

    impl InstructionPanelListener for RecordingListener {
        fn operand_selected(&mut self, op_index: i32, sub_index: i32) {
            self.operand_selections.push((op_index, sub_index));
        }

        fn selection_dropped(&mut self, _set: &dyn AddressSetView, _cu: &dyn CodeUnit, op_index: i32) {
            self.drops.push(op_index);
        }

        fn drop_supported(&self) -> bool {
            self.drop_support
        }
    }

    #[test]
    fn operand_selected_records_indices() {
        let mut listener = RecordingListener::new(false);
        listener.operand_selected(1, 0);
        assert_eq!(listener.operand_selections, vec![(1, 0)]);
    }

    #[test]
    fn operand_selected_records_multiple() {
        let mut listener = RecordingListener::new(false);
        listener.operand_selected(0, 0);
        listener.operand_selected(1, 1);
        listener.operand_selected(2, 0);
        assert_eq!(
            listener.operand_selections,
            vec![(0, 0), (1, 1), (2, 0)]
        );
    }

    #[test]
    fn operand_selected_with_negative_index() {
        let mut listener = RecordingListener::new(false);
        listener.operand_selected(-1, 0);
        assert_eq!(listener.operand_selections, vec![(-1, 0)]);
    }

    #[test]
    fn selection_dropped_records_op_index() {
        let mut listener = RecordingListener::new(true);
        let addr_set = AddressSet::new();
        let code_unit = FakeCodeUnit;
        listener.selection_dropped(&addr_set, &code_unit, 3);
        assert_eq!(listener.drops, vec![3]);
    }

    #[test]
    fn selection_dropped_records_multiple() {
        let mut listener = RecordingListener::new(true);
        let addr_set = AddressSet::new();
        let code_unit = FakeCodeUnit;
        listener.selection_dropped(&addr_set, &code_unit, 0);
        listener.selection_dropped(&addr_set, &code_unit, 1);
        assert_eq!(listener.drops, vec![0, 1]);
    }

    #[test]
    fn drop_supported_returns_configured_value() {
        let listener_yes = RecordingListener::new(true);
        let listener_no = RecordingListener::new(false);
        assert_eq!(listener_yes.drop_supported(), true);
        assert_eq!(listener_no.drop_supported(), false);
    }
}
