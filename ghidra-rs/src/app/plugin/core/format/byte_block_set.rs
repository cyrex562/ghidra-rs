use std::sync::Arc;

use super::{ByteBlock, ByteBlockSelection};
use crate::app::seam_stubs::{ProgramLocationPluginEvent, ProgramSelectionPluginEvent};
use crate::program::model::address::AddressSet;

/// Defines methods for getting byte blocks and translating events.
///
/// Port of `ghidra.app.plugin.core.format.ByteBlockSet`.
pub trait ByteBlockSet {
    /// Returns `true` if this instance represents a valid source of data, `false` if this
    /// instance does not represent a valid source of data.
    fn is_valid(&self) -> bool {
        true
    }

    /// Get the blocks in this set.
    fn get_blocks(&self) -> Vec<Arc<dyn ByteBlock>>;

    /// Get a plugin event for the given block and offset.
    ///
    /// # Arguments
    /// * `source` - source to use in the event
    /// * `block` - block to use to generate the event
    /// * `offset` - offset into the block
    /// * `column` - the column within the UI byte field
    fn get_plugin_event_for_location(
        &self,
        source: &str,
        block: &Arc<dyn ByteBlock>,
        offset: i128,
        column: i32,
    ) -> ProgramLocationPluginEvent;

    /// Get the appropriate plugin event for the given block selection.
    ///
    /// # Arguments
    /// * `source` - source to use in the event
    /// * `selection` - selection to use to generate the event
    fn get_plugin_event_for_selection(
        &self,
        source: &str,
        selection: &ByteBlockSelection,
    ) -> ProgramSelectionPluginEvent;

    /// Return true if the block has been changed at the given index.
    ///
    /// # Arguments
    /// * `block` - byte block
    /// * `index` - offset into the block
    /// * `length` - number of bytes in question
    fn is_changed(&self, block: &Arc<dyn ByteBlock>, index: i128, length: i32) -> bool;

    /// Send a notification that a byte block edit occurred.
    ///
    /// # Arguments
    /// * `block` - block being edited
    /// * `index` - offset into the block
    /// * `old_value` - old byte values
    /// * `new_value` - new byte values
    fn notify_byte_editing(
        &mut self,
        block: &Arc<dyn ByteBlock>,
        index: i128,
        old_value: &[u8],
        new_value: &[u8],
    );

    /// Release resources that this object may be using.
    fn dispose(&mut self);

    /// Convert the byte block selection to the address set it covers.
    ///
    /// # Arguments
    /// * `selection` - the selection from the byte block perspective
    fn get_address_set(&self, selection: &ByteBlockSelection) -> AddressSet;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::core::format::{ByteBlockAccessException, ByteBlockRange};
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::Program;
    use crate::program::util::program_location::ProgramLocation;
    use crate::app::seam_stubs::ProgramSelection;

    struct MockProgram;

    impl crate::framework::model::DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "MockProgram".to_string()
        }

        fn get_language_id(&self) -> String {
            "x86".to_string()
        }
    }

    struct MockProgramLocation {
        program: Arc<dyn Program>,
        address: Address,
    }

    impl ProgramLocation for MockProgramLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            self.program.clone()
        }

        fn get_address(&self) -> Address {
            self.address.clone()
        }

        fn get_byte_address(&self) -> Address {
            self.address.clone()
        }
    }

    struct MockProgramSelection;

    impl ProgramSelection for MockProgramSelection {}

    struct MockByteBlock {
        len: i128,
    }

    impl ByteBlock for MockByteBlock {
        fn get_location_representation(
            &self,
            index: i128,
        ) -> Result<String, ByteBlockAccessException> {
            Ok(format!("0x{:x}", index))
        }

        fn get_max_location_representation_size(&self) -> i32 {
            16
        }

        fn get_index_name(&self) -> String {
            "Byte Offset".to_string()
        }

        fn get_length(&self) -> i128 {
            self.len
        }

        fn get_byte(&self, _index: i128) -> Result<u8, ByteBlockAccessException> {
            Ok(0)
        }

        fn get_bytes(
            &self,
            _bytes: &mut [u8],
            _index: i128,
            _count: usize,
        ) -> Result<usize, ByteBlockAccessException> {
            Ok(0)
        }

        fn get_short(&self, _index: i128) -> Result<i16, ByteBlockAccessException> {
            Ok(0)
        }

        fn get_int(&self, _index: i128) -> Result<i32, ByteBlockAccessException> {
            Ok(0)
        }

        fn get_long(&self, _index: i128) -> Result<i64, ByteBlockAccessException> {
            Ok(0)
        }

        fn set_byte(&mut self, _index: i128, _value: u8) -> Result<(), ByteBlockAccessException> {
            Ok(())
        }

        fn set_short(
            &mut self,
            _index: i128,
            _value: i16,
        ) -> Result<(), ByteBlockAccessException> {
            Ok(())
        }

        fn set_int(&mut self, _index: i128, _value: i32) -> Result<(), ByteBlockAccessException> {
            Ok(())
        }

        fn set_long(&mut self, _index: i128, _value: i64) -> Result<(), ByteBlockAccessException> {
            Ok(())
        }

        fn is_editable(&self) -> bool {
            true
        }

        fn set_big_endian(&mut self, _big_endian: bool) {}

        fn is_big_endian(&self) -> bool {
            true
        }

        fn get_alignment(&self, _radix: i32) -> i32 {
            0
        }
    }

    /// Mirrors `ghidra.app.plugin.core.byteviewer.ProgramByteBlockSet`: blocks are addressable
    /// memory, so `getAddressSet` maps each range's block-relative index onto the block's base
    /// address, and edits are recorded so `isChanged`/`notifyByteEditing` can be exercised.
    struct MemoryByteBlockSet {
        program: Arc<dyn Program>,
        base: Address,
        blocks: Vec<Arc<dyn ByteBlock>>,
        edits: Vec<(i128, Vec<u8>, Vec<u8>)>,
        disposed: bool,
    }

    impl ByteBlockSet for MemoryByteBlockSet {
        fn get_blocks(&self) -> Vec<Arc<dyn ByteBlock>> {
            self.blocks.clone()
        }

        fn get_plugin_event_for_location(
            &self,
            source: &str,
            _block: &Arc<dyn ByteBlock>,
            offset: i128,
            _column: i32,
        ) -> ProgramLocationPluginEvent {
            let location = Arc::new(MockProgramLocation {
                program: self.program.clone(),
                address: self.base.add(offset as i64).unwrap(),
            });
            ProgramLocationPluginEvent::new(source, location, self.program.clone())
        }

        fn get_plugin_event_for_selection(
            &self,
            source: &str,
            _selection: &ByteBlockSelection,
        ) -> ProgramSelectionPluginEvent {
            let selection = Arc::new(MockProgramSelection);
            ProgramSelectionPluginEvent::new(source, selection, self.program.clone())
        }

        fn is_changed(&self, _block: &Arc<dyn ByteBlock>, index: i128, length: i32) -> bool {
            self.edits
                .iter()
                .any(|(edit_index, _, new_value)| {
                    *edit_index == index && new_value.len() as i32 == length
                })
        }

        fn notify_byte_editing(
            &mut self,
            _block: &Arc<dyn ByteBlock>,
            index: i128,
            old_value: &[u8],
            new_value: &[u8],
        ) {
            self.edits.push((index, old_value.to_vec(), new_value.to_vec()));
        }

        fn dispose(&mut self) {
            self.disposed = true;
        }

        fn get_address_set(&self, selection: &ByteBlockSelection) -> AddressSet {
            let mut addr_set = AddressSet::new();
            for i in 0..selection.number_of_ranges() {
                let range = selection.range(i);
                let start = self.base.add(range.start_index() as i64).unwrap();
                let end = self.base.add(range.end_index() as i64).unwrap();
                addr_set.add_range(&start, &end);
            }
            addr_set
        }
    }

    fn make_set() -> MemoryByteBlockSet {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let base = space.address(0x1000);
        let block: Arc<dyn ByteBlock> = Arc::new(MockByteBlock { len: 16 });
        MemoryByteBlockSet {
            program: Arc::new(MockProgram),
            base,
            blocks: vec![block],
            edits: Vec::new(),
            disposed: false,
        }
    }

    #[test]
    fn is_valid_defaults_to_true() {
        let set = make_set();
        assert!(set.is_valid());
    }

    #[test]
    fn get_blocks_returns_the_configured_blocks() {
        let set = make_set();
        assert_eq!(set.get_blocks().len(), 1);
    }

    #[test]
    fn get_plugin_event_for_location_carries_source_and_program() {
        let set = make_set();
        let block = set.get_blocks()[0].clone();
        let event = set.get_plugin_event_for_location("TestPlugin", &block, 4, 0);

        assert_eq!(event.event().source_name(), "TestPlugin");
        assert!(event.get_program().is_some());
        assert_eq!(event.get_location().get_address(), set.base.add(4).unwrap());
    }



    #[test]
    fn get_plugin_event_for_selection_carries_source() {
        let set = make_set();
        let selection = ByteBlockSelection::new(vec![]);
        let event = set.get_plugin_event_for_selection("TestPlugin", &selection);

        assert_eq!(event.event().source_name(), "TestPlugin");
        assert!(event.get_program().is_some());
    }

    #[test]
    fn notify_byte_editing_then_is_changed_reports_true() {
        let mut set = make_set();
        let block = set.get_blocks()[0].clone();

        assert!(!set.is_changed(&block, 4, 2));
        set.notify_byte_editing(&block, 4, &[0x00, 0x00], &[0xAA, 0xBB]);
        assert!(set.is_changed(&block, 4, 2));
    }

    #[test]
    fn dispose_marks_the_set_disposed() {
        let mut set = make_set();
        assert!(!set.disposed);
        set.dispose();
        assert!(set.disposed);
    }

    #[test]
    fn get_address_set_covers_the_selection_ranges() {
        let set = make_set();
        let block = set.get_blocks()[0].clone();
        let range = ByteBlockRange::new(block, 0, 3);
        let selection = ByteBlockSelection::new(vec![range]);

        let addr_set = set.get_address_set(&selection);
        let ranges = addr_set.to_list();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].min_address(), &set.base);
        assert_eq!(ranges[0].max_address(), &set.base.add(3).unwrap());
    }
}
