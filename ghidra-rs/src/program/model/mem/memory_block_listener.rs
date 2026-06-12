use crate::program::model::address::Address;
use crate::program::model::mem::MemoryBlock;

/// Listener notified when a memory block changes.
///
/// This mirrors Ghidra's `MemoryBlockListener` interface.
pub trait MemoryBlockListener {
    /// Notification that a block name changed.
    fn name_changed(&mut self, block: &dyn MemoryBlock, old_name: &str, new_name: &str);

    /// Notification that a block comment changed.
    fn comment_changed(
        &mut self,
        block: &dyn MemoryBlock,
        old_comment: Option<&str>,
        new_comment: Option<&str>,
    );

    /// Notification that a block read attribute changed.
    fn read_status_changed(&mut self, block: &dyn MemoryBlock, is_read: bool);

    /// Notification that a block write attribute changed.
    fn write_status_changed(&mut self, block: &dyn MemoryBlock, is_write: bool);

    /// Notification that a block execute attribute changed.
    fn execute_status_changed(&mut self, block: &dyn MemoryBlock, is_execute: bool);

    /// Notification that a block source changed.
    fn source_changed(&mut self, block: &dyn MemoryBlock, old_source: &str, new_source: &str);

    /// Notification that a block source offset changed.
    fn source_offset_changed(&mut self, block: &dyn MemoryBlock, old_offset: i64, new_offset: i64);

    /// Notification that block bytes changed.
    fn data_changed(
        &mut self,
        block: &dyn MemoryBlock,
        addr: &Address,
        old_data: &[u8],
        new_data: &[u8],
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::mem::MemoryBlockImpl;

    #[derive(Default)]
    struct RecordingListener {
        events: Vec<String>,
    }

    impl MemoryBlockListener for RecordingListener {
        fn name_changed(&mut self, block: &dyn MemoryBlock, old_name: &str, new_name: &str) {
            self.events.push(format!(
                "name:{}:{}:{}",
                block.get_name(),
                old_name,
                new_name
            ));
        }

        fn comment_changed(
            &mut self,
            block: &dyn MemoryBlock,
            old_comment: Option<&str>,
            new_comment: Option<&str>,
        ) {
            self.events.push(format!(
                "comment:{}:{}:{}",
                block.get_name(),
                old_comment.unwrap_or(""),
                new_comment.unwrap_or("")
            ));
        }

        fn read_status_changed(&mut self, block: &dyn MemoryBlock, is_read: bool) {
            self.events
                .push(format!("read:{}:{}", block.get_name(), is_read));
        }

        fn write_status_changed(&mut self, block: &dyn MemoryBlock, is_write: bool) {
            self.events
                .push(format!("write:{}:{}", block.get_name(), is_write));
        }

        fn execute_status_changed(&mut self, block: &dyn MemoryBlock, is_execute: bool) {
            self.events
                .push(format!("execute:{}:{}", block.get_name(), is_execute));
        }

        fn source_changed(&mut self, block: &dyn MemoryBlock, old_source: &str, new_source: &str) {
            self.events.push(format!(
                "source:{}:{}:{}",
                block.get_name(),
                old_source,
                new_source
            ));
        }

        fn source_offset_changed(
            &mut self,
            block: &dyn MemoryBlock,
            old_offset: i64,
            new_offset: i64,
        ) {
            self.events.push(format!(
                "source_offset:{}:{}:{}",
                block.get_name(),
                old_offset,
                new_offset
            ));
        }

        fn data_changed(
            &mut self,
            block: &dyn MemoryBlock,
            addr: &Address,
            old_data: &[u8],
            new_data: &[u8],
        ) {
            self.events.push(format!(
                "data:{}:{}:{}:{}",
                block.get_name(),
                addr,
                old_data.len(),
                new_data.len()
            ));
        }
    }

    #[test]
    fn listener_receives_memory_block_change_values() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let addr = Address::new(space, 0x1000);
        let block = MemoryBlockImpl::new("block".to_string(), addr.clone(), 16, true);
        let mut listener = RecordingListener::default();

        listener.name_changed(&block, "old", "new");
        listener.comment_changed(&block, None, Some("comment"));
        listener.read_status_changed(&block, true);
        listener.write_status_changed(&block, false);
        listener.execute_status_changed(&block, true);
        listener.source_changed(&block, "old.bin", "new.bin");
        listener.source_offset_changed(&block, 4, 8);
        listener.data_changed(&block, &addr, &[1, 2], &[3, 4, 5]);

        assert_eq!(
            listener.events,
            vec![
                "name:block:old:new",
                "comment:block::comment",
                "read:block:true",
                "write:block:false",
                "execute:block:true",
                "source:block:old.bin:new.bin",
                "source_offset:block:4:8",
                "data:block:ram:0x1000:2:3",
            ]
        );
    }
}
