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

    struct FakeAddressSet;
    impl AddressSetView for FakeAddressSet {
        fn min(&self) -> Option<crate::program::model::address::Address> {
            None
        }
        fn max(&self) -> Option<crate::program::model::address::Address> {
            None
        }
        fn is_empty(&self) -> bool {
            true
        }
        fn contains(&self, _addr: crate::program::model::address::Address) -> bool {
            false
        }
        fn get_ranges(&self) -> Vec<crate::program::model::address::AddressRange> {
            vec![]
        }
        fn get_num_address_ranges(&self) -> usize {
            0
        }
        fn intersects(&self, _other: &dyn AddressSetView) -> bool {
            false
        }
        fn intersect(&self, _other: &dyn AddressSetView) -> Box<dyn AddressSetView> {
            Box::new(FakeAddressSet)
        }
        fn union(&self, _other: &dyn AddressSetView) -> Box<dyn AddressSetView> {
            Box::new(FakeAddressSet)
        }
        fn subtract(&self, _other: &dyn AddressSetView) -> Box<dyn AddressSetView> {
            Box::new(FakeAddressSet)
        }
        fn xor(&self, _other: &dyn AddressSetView) -> Box<dyn AddressSetView> {
            Box::new(FakeAddressSet)
        }
        fn contains_range(&self, _start: crate::program::model::address::Address, _end: crate::program::model::address::Address) -> bool {
            false
        }
        fn has_gap_between(&self, _start: crate::program::model::address::Address, _end: crate::program::model::address::Address) -> bool {
            false
        }
        fn clone_box(&self) -> Box<dyn AddressSetView> {
            Box::new(FakeAddressSet)
        }
        fn size(&self) -> i64 {
            0
        }
    }

    struct FakeCodeUnit;
    impl crate::program::model::mem::MemBuffer for FakeCodeUnit {
        fn get_byte(&self, _offset: i32) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            Ok(0)
        }
        fn get_bytes(&self, _offset: i32, _buf: &mut [u8]) -> Result<i32, crate::program::model::mem::MemoryAccessException> {
            Ok(0)
        }
        fn length(&self) -> usize {
            0
        }
    }
    impl crate::program::seam_stubs::PropertySet for FakeCodeUnit {}
    impl CodeUnit for FakeCodeUnit {
        fn get_address_string(
            &self,
            _show_block_name: bool,
            _pad: bool,
        ) -> String {
            "0x0".to_string()
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
        let addr_set = FakeAddressSet;
        let code_unit = FakeCodeUnit;
        listener.selection_dropped(&addr_set, &code_unit, 3);
        assert_eq!(listener.drops, vec![3]);
    }

    #[test]
    fn selection_dropped_records_multiple() {
        let mut listener = RecordingListener::new(true);
        let addr_set = FakeAddressSet;
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
