use std::sync::Arc;

use crate::app::plugin::core::byteviewer::ByteBlockChangePluginEvent;
use crate::app::plugin::core::format::{
    ByteBlock, ByteBlockInfo, ByteBlockRange, ByteBlockSelection, ByteBlockSet, ByteEditInfo,
};
use crate::app::seam_stubs::{
    AddressSetProgramSelection, ByteBlockChangeManager, MemoryByteBlock,
    ProgramByteViewerComponentProvider, ProgramLocationPluginEvent, ProgramSelectionPluginEvent,
};
use crate::framework::seam_stubs::SaveState;
use crate::program::model::address::{Address, AddressRange, AddressSet, AddressSetView};
use crate::program::model::listing::Program;

/// `ByteBlockSet` implementation for a `Program` object.
///
/// Port of `ghidra.app.plugin.core.byteviewer.ProgramByteBlockSet`.
pub struct ProgramByteBlockSet {
    program: Arc<dyn Program>,
    bbcm: ByteBlockChangeManager,
    blocks: Vec<Arc<MemoryByteBlock>>,
    provider: Arc<dyn ProgramByteViewerComponentProvider>,
}

impl ProgramByteBlockSet {
    /// Description used for the transaction opened around a memory edit.
    pub const MEMORY_EDIT: &'static str = "Memory Edit";

    const NUMBER_OF_CHANGES: &'static str = "NumberOfByteBlockChanges";
    const BLOCK_NUMBER: &'static str = "BlockNumber";
    const BLOCK_OFFSET: &'static str = "BlockOffset";
    const OLD_VALUE: &'static str = "OldValue";
    const NEW_VALUE: &'static str = "NewValue";

    /// Constructs a set covering the given program's memory blocks.
    ///
    /// Corresponds to
    /// `ProgramByteBlockSet(ProgramByteViewerComponentProvider, Program, ByteBlockChangeManager)`.
    /// Java hands `this` to `provider.newByteBlockChangeManager(this, bbcm)`; that back-reference
    /// is the provider/block-set cycle, so the manager is built directly from the previous one
    /// here (which is all the default factory method does).
    pub fn new(
        provider: Arc<dyn ProgramByteViewerComponentProvider>,
        program: Arc<dyn Program>,
        bbcm: Option<&ByteBlockChangeManager>,
    ) -> Self {
        let mut set = Self {
            program,
            bbcm: ByteBlockChangeManager::new(bbcm),
            blocks: Vec::new(),
            provider,
        };
        set.new_memory_blocks();
        set
    }

    /// The program whose memory this set covers.
    pub fn program(&self) -> &Arc<dyn Program> {
        &self.program
    }

    /// Convert a byte block selection into a program selection.
    ///
    /// Corresponds to `convertSelection(ByteBlockSelection)`.
    pub fn convert_selection(&self, selection: &ByteBlockSelection) -> AddressSetProgramSelection {
        AddressSetProgramSelection::new(self.get_address_set(selection))
    }

    /// Records the edit carried by the event, when it belongs to this set's program.
    ///
    /// Corresponds to the package-private `processByteBlockChangeEvent(ByteBlockChangePluginEvent)`.
    pub fn process_byte_block_change_event(&mut self, event: &ByteBlockChangePluginEvent) {
        let is_our_program = event
            .get_program()
            .is_some_and(|program| Arc::ptr_eq(&program, &self.program));
        if is_our_program {
            self.bbcm.add(event.get_byte_edit_info());
        }
    }

    /// Appends a block range for each of this set's blocks that the address range covers.
    ///
    /// Corresponds to `collectBlockSelection(AddressRange, List<ByteBlockRange>)`.
    pub fn collect_block_selection(&self, range: &AddressRange, result: &mut Vec<ByteBlockRange>) {
        for block in &self.blocks {
            let block_range = AddressRange::new(block.get_start().clone(), block.get_end());
            let Some(intersection) = range.intersect(&block_range)
            else {
                continue;
            };
            let (Some(start_info), Some(end_info)) = (
                self.get_byte_block_info(intersection.min_address()),
                self.get_byte_block_info(intersection.max_address()),
            )
            else {
                continue;
            };
            result.push(ByteBlockRange::new(
                start_info.block().clone(),
                start_info.offset(),
                end_info.offset(),
            ));
        }
    }

    /// The block selection covering a single address range.
    ///
    /// Corresponds to `getBlockSelection(AddressRange)`.
    pub fn get_block_selection_for_range(&self, range: &AddressRange) -> ByteBlockSelection {
        let mut list = Vec::new();
        self.collect_block_selection(range, &mut list);
        ByteBlockSelection::new(list)
    }

    /// The block selection covering every range the iterator yields.
    ///
    /// Corresponds to `getBlockSelection(AddressRangeIterator)`.
    pub fn get_block_selection_for_ranges(
        &self,
        ranges: impl Iterator<Item = AddressRange>,
    ) -> ByteBlockSelection {
        let mut list = Vec::new();
        for range in ranges {
            self.collect_block_selection(&range, &mut list);
        }
        ByteBlockSelection::new(list)
    }

    /// The block selection covering an address set.
    ///
    /// Corresponds to `getBlockSelection(AddressSetView)`.
    pub fn get_block_selection(&self, addresses: &dyn AddressSetView) -> ByteBlockSelection {
        self.get_block_selection_for_ranges(addresses.address_ranges())
    }

    /// The block selection covering a program selection.
    ///
    /// Corresponds to `getBlockSelection(ProgramSelection)`.
    pub fn get_block_selection_for_selection(
        &self,
        selection: &AddressSetProgramSelection,
    ) -> ByteBlockSelection {
        self.get_block_selection(selection.addresses())
    }

    /// Replaces the change manager.
    ///
    /// Corresponds to the package-private `setByteBlockChangeManager(ByteBlockChangeManager)`.
    pub fn set_byte_block_change_manager(
        &mut self,
        byte_block_change_manager: ByteBlockChangeManager,
    ) {
        self.bbcm = byte_block_change_manager;
    }

    /// Get the byte block change manager.
    ///
    /// Corresponds to `getByteBlockChangeManager()`.
    pub fn get_byte_block_change_manager(&self) -> &ByteBlockChangeManager {
        &self.bbcm
    }

    /// Write the state of the change list.
    ///
    /// Corresponds to the package-private `getUndoRedoState()`, which returns a new `SaveState`;
    /// this crate has no constructible `SaveState` yet, so the caller supplies one. The
    /// block-number mapping this needs is why the serialization lives here rather than on
    /// [`ByteBlockChangeManager`] as it does in Java.
    ///
    /// Java seeds its entry counter with the change-list size and then increments it once per
    /// entry written, so it records about twice as many entries as it wrote; the surplus indices
    /// restore as no-ops because their byte arrays are missing. This port writes the true count.
    pub fn get_undo_redo_state(&self, save_state: &mut dyn SaveState) {
        let mut change_count = 0;
        for (i, edit) in self.bbcm.changes().iter().enumerate() {
            let block_number = self.get_byte_block_number(edit.block_address());
            if block_number < 0 {
                continue;
            }
            change_count += 1;
            save_state.put_int(&format!("{}{i}", Self::BLOCK_NUMBER), block_number);
            save_state.put_string(
                &format!("{}{i}", Self::BLOCK_OFFSET),
                Some(&edit.offset().to_string()),
            );
            save_state.put_bytes(&format!("{}{i}", Self::OLD_VALUE), Some(edit.old_value()));
            save_state.put_bytes(&format!("{}{i}", Self::NEW_VALUE), Some(edit.new_value()));
        }
        save_state.put_int(Self::NUMBER_OF_CHANGES, change_count);
    }

    /// Read the state of the change list.
    ///
    /// Corresponds to the package-private `restoreUndoRedoState(SaveState)`.
    pub fn restore_undo_redo_state(&mut self, save_state: &dyn SaveState) {
        let number_of_changes = save_state.get_int(Self::NUMBER_OF_CHANGES, 0);
        let mut changes = Vec::new();
        for i in 0..number_of_changes.max(0) {
            let block_number = save_state.get_int(&format!("{}{i}", Self::BLOCK_NUMBER), 0);
            let block_offset = save_state
                .get_string(&format!("{}{i}", Self::BLOCK_OFFSET), Some("0"))
                .and_then(|offset| offset.parse::<i128>().ok())
                .unwrap_or(0);
            let old_value = save_state.get_bytes(&format!("{}{i}", Self::OLD_VALUE), None);
            let new_value = save_state.get_bytes(&format!("{}{i}", Self::NEW_VALUE), None);

            if let (Some(old_value), Some(new_value), Some(block_start)) = (
                old_value,
                new_value,
                self.get_block_start_at(block_number as usize),
            ) {
                changes.push(ByteEditInfo::new(
                    block_start,
                    block_offset,
                    old_value,
                    new_value,
                ));
            }
        }
        self.bbcm.set_changes(changes);
    }

    /// Get the address for the given block and offset, or `None` when the block does not belong
    /// to this set.
    ///
    /// Corresponds to `getAddress(ByteBlock, BigInteger)`, which throws
    /// `IndexOutOfBoundsException` when the offset runs past the block's address space; this port
    /// answers `None` there too.
    pub fn get_address(&self, block: &Arc<dyn ByteBlock>, offset: i128) -> Option<Address> {
        self.index_of(block)
            .and_then(|i| self.blocks[i].get_address(offset))
    }

    /// Given an address, get the byte block info.
    ///
    /// Corresponds to `getByteBlockInfo(Address)`.
    pub fn get_byte_block_info(&self, address: &Address) -> Option<ByteBlockInfo> {
        let memory = self.program.get_memory()?;
        if !memory.contains(address) {
            // this block set is out of date...eventually a new ProgramByteBlockSet will be created
            return None;
        }

        self.blocks
            .iter()
            .find(|block| block.contains(address))
            .map(|block| {
                let offset = address.subtract(block.get_start()) as u64 as i128;
                ByteBlockInfo::new(block.clone(), offset)
            })
    }

    /// The starting address of the given block.
    ///
    /// Corresponds to `getBlockStart(ByteBlock)`.
    pub fn get_block_start(&self, block: &Arc<dyn ByteBlock>) -> Option<Address> {
        self.get_address(block, 0)
    }

    /// The starting address of the block with the given index.
    ///
    /// Corresponds to `getBlockStart(int)`, which throws when the index is out of range.
    pub fn get_block_start_at(&self, block_number: usize) -> Option<Address> {
        self.blocks
            .get(block_number)
            .map(|block| block.get_start().clone())
    }

    /// The index of the block starting at the given address, or `-1` when there is none.
    ///
    /// Corresponds to `getByteBlockNumber(Address)`.
    pub fn get_byte_block_number(&self, block_start_addr: &Address) -> i32 {
        self.blocks
            .iter()
            .position(|block| block.get_start() == block_start_addr)
            .map_or(-1, |i| i as i32)
    }

    /// Rebuild the byte blocks from the program's current memory blocks.
    ///
    /// Corresponds to `newMemoryBlocks()`.
    pub fn new_memory_blocks(&mut self) {
        let Some(memory) = self.program.get_memory()
        else {
            self.blocks.clear();
            return;
        };
        self.blocks = memory
            .get_blocks()
            .into_iter()
            .map(|mem_block| Arc::new(self.new_memory_byte_block(&memory, mem_block)))
            .collect();
    }

    /// Factory hook for the byte block wrapping a single memory block.
    ///
    /// Corresponds to `newMemoryByteBlock(MemoryBlock)`; the memory is passed alongside the block
    /// because this crate's `MemoryByteBlock` cannot re-derive it from an `Arc<dyn Program>`.
    pub fn new_memory_byte_block(
        &self,
        memory: &Arc<dyn crate::program::model::mem::Memory>,
        mem_block: Arc<dyn crate::program::model::mem::MemoryBlock>,
    ) -> MemoryByteBlock {
        MemoryByteBlock::new(self.program.clone(), memory.clone(), mem_block)
    }

    /// Open a transaction for a memory edit.
    ///
    /// Corresponds to `startTransaction()`. Java calls through to the `program` field; this
    /// crate's transactions need `&mut` access to the program, which this set's shared
    /// `Arc<dyn Program>` cannot give, so the caller passes its own mutable handle.
    pub fn start_transaction(&self, program: &mut dyn Program) -> i32 {
        program.start_transaction(Self::MEMORY_EDIT)
    }

    /// Close a transaction opened by [`start_transaction`](Self::start_transaction).
    ///
    /// Corresponds to `endTransaction(int, boolean)`.
    pub fn end_transaction(
        &self,
        program: &mut dyn Program,
        transaction_id: i32,
        commit: bool,
    ) -> bool {
        program.end_transaction(transaction_id, commit)
    }

    /// The position of the given block within this set, matched by identity as Java's `!=` does.
    fn index_of(&self, block: &Arc<dyn ByteBlock>) -> Option<usize> {
        let needle = Arc::as_ptr(block) as *const u8;
        self.blocks
            .iter()
            .position(|candidate| Arc::as_ptr(candidate) as *const u8 == needle)
    }
}

impl ByteBlockSet for ProgramByteBlockSet {
    fn get_blocks(&self) -> Vec<Arc<dyn ByteBlock>> {
        self.blocks
            .iter()
            .map(|block| block.clone() as Arc<dyn ByteBlock>)
            .collect()
    }

    fn get_plugin_event_for_location(
        &self,
        source: &str,
        block: &Arc<dyn ByteBlock>,
        offset: i128,
        column: i32,
    ) -> ProgramLocationPluginEvent {
        let location = self.provider.get_location(block, offset, column);
        ProgramLocationPluginEvent::new(source, location, self.program.clone())
    }

    fn get_plugin_event_for_selection(
        &self,
        source: &str,
        selection: &ByteBlockSelection,
    ) -> ProgramSelectionPluginEvent {
        let selection = self.convert_selection(selection);
        ProgramSelectionPluginEvent::new(source, Arc::new(selection), self.program.clone())
    }

    fn is_changed(&self, block: &Arc<dyn ByteBlock>, index: i128, length: i32) -> bool {
        self.get_block_start(block)
            .is_some_and(|block_addr| self.bbcm.is_changed(&block_addr, index, length))
    }

    fn notify_byte_editing(
        &mut self,
        block: &Arc<dyn ByteBlock>,
        index: i128,
        old_value: &[u8],
        new_value: &[u8],
    ) {
        let Some(block_addr) = self.get_address(block, 0)
        else {
            return;
        };
        let edit = ByteEditInfo::new(
            block_addr,
            index,
            old_value.to_vec(),
            new_value.to_vec(),
        );

        self.bbcm.add(&edit);
        self.provider.notify_edit(&edit);
    }

    fn dispose(&mut self) {
        // nothing to do?!?!?
    }

    fn get_address_set(&self, selection: &ByteBlockSelection) -> AddressSet {
        let mut addr_set = AddressSet::new();

        for i in 0..selection.number_of_ranges() {
            let br = selection.range(i);
            let block = br.byte_block();
            let (Some(start), Some(end)) = (
                self.get_address(block, br.start_index()),
                self.get_address(block, br.end_index()),
            )
            else {
                continue;
            };
            addr_set.add_range(&start, &end);
        }
        addr_set
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::mem::{Memory, MemoryAccessException, MemoryBlock};
    use crate::program::util::program_location::ProgramLocation;

    struct MockMemoryBlock {
        name: String,
        start: Address,
        bytes: Vec<u8>,
    }

    impl MemoryBlock for MockMemoryBlock {
        fn get_name(&self) -> &str {
            &self.name
        }

        fn get_start(&self) -> Address {
            self.start.clone()
        }

        fn get_end(&self) -> Address {
            self.start.add(self.bytes.len() as i64 - 1).unwrap()
        }

        fn get_size(&self) -> u64 {
            self.bytes.len() as u64
        }

        fn is_initialized(&self) -> bool {
            true
        }

        fn contains(&self, addr: &Address) -> bool {
            addr.space() == self.start.space()
                && addr.offset() >= self.start.offset()
                && addr.offset() <= self.start.offset() + self.bytes.len() as i64 - 1
        }

        fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
            if !self.contains(addr) {
                return Err(MemoryAccessException::new("out of block"));
            }
            Ok(self.bytes[addr.subtract(&self.start) as usize])
        }

        fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
            if !self.contains(addr) {
                return 0;
            }
            let offset = addr.subtract(&self.start) as usize;
            let count = dest.len().min(self.bytes.len() - offset);
            dest[..count].copy_from_slice(&self.bytes[offset..offset + count]);
            count
        }

        fn set_bytes(
            &mut self,
            _addr: &Address,
            _source: &[u8],
        ) -> Result<(), MemoryAccessException> {
            Ok(())
        }
    }

    struct MockMemory {
        blocks: Vec<Arc<dyn MemoryBlock>>,
    }

    impl Memory for MockMemory {
        fn is_big_endian(&self) -> bool {
            true
        }

        fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
            self.get_block(addr)
                .ok_or_else(|| MemoryAccessException::new("not in memory"))
                .and_then(|block| block.get_byte(addr))
        }

        fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
            self.get_block(addr)
                .map_or(0, |block| block.get_bytes(addr, dest))
        }

        fn set_bytes(
            &mut self,
            _addr: &Address,
            _source: &[u8],
        ) -> Result<(), MemoryAccessException> {
            Ok(())
        }

        fn get_block(&self, addr: &Address) -> Option<Arc<dyn MemoryBlock>> {
            self.blocks
                .iter()
                .find(|block| block.contains(addr))
                .cloned()
        }

        fn get_blocks(&self) -> Vec<Arc<dyn MemoryBlock>> {
            self.blocks.clone()
        }
    }

    struct MockProgram {
        memory: Arc<dyn Memory>,
    }

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "MockProgram".to_string()
        }

        fn get_language_id(&self) -> String {
            "x86".to_string()
        }

        fn get_memory(&self) -> Option<Arc<dyn Memory>> {
            Some(self.memory.clone())
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

    struct MockProvider {
        program: Arc<dyn Program>,
        base: Address,
        edits: Mutex<Vec<ByteEditInfo>>,
    }

    impl ProgramByteViewerComponentProvider for MockProvider {
        fn get_location(
            &self,
            _block: &Arc<dyn ByteBlock>,
            offset: i128,
            _column: i32,
        ) -> Arc<dyn ProgramLocation + Send + Sync> {
            Arc::new(MockProgramLocation {
                program: self.program.clone(),
                address: self.base.add(offset as i64).unwrap(),
            })
        }

        fn notify_edit(&self, edit: &ByteEditInfo) {
            self.edits.lock().unwrap().push(edit.clone());
        }
    }

    /// Two 16-byte memory blocks, at ram:0x1000 and ram:0x2000.
    fn make_set() -> (ProgramByteBlockSet, Arc<MockProvider>, Arc<AddressSpace>) {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let blocks: Vec<Arc<dyn MemoryBlock>> = vec![
            Arc::new(MockMemoryBlock {
                name: "first".to_string(),
                start: space.address(0x1000),
                bytes: (0..16u8).collect(),
            }),
            Arc::new(MockMemoryBlock {
                name: "second".to_string(),
                start: space.address(0x2000),
                bytes: vec![0xFF; 16],
            }),
        ];
        let memory: Arc<dyn Memory> = Arc::new(MockMemory { blocks });
        let program: Arc<dyn Program> = Arc::new(MockProgram { memory });
        let provider = Arc::new(MockProvider {
            program: program.clone(),
            base: space.address(0x1000),
            edits: Mutex::new(Vec::new()),
        });

        let set = ProgramByteBlockSet::new(provider.clone(), program, None);
        (set, provider, space)
    }

    #[test]
    fn one_byte_block_is_created_per_memory_block() {
        let (set, _provider, space) = make_set();
        let blocks = set.get_blocks();

        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].get_length(), 16);
        assert_eq!(blocks[0].get_index_name(), "Addresses");
        assert_eq!(set.get_block_start(&blocks[0]), Some(space.address(0x1000)));
        assert_eq!(set.get_block_start(&blocks[1]), Some(space.address(0x2000)));
    }

    #[test]
    fn get_address_offsets_from_the_owning_block_start() {
        let (set, _provider, space) = make_set();
        let blocks = set.get_blocks();

        assert_eq!(set.get_address(&blocks[1], 4), Some(space.address(0x2004)));

        // A block this set does not own has no address, as Java's null return says.
        let foreign: Arc<dyn ByteBlock> = blocks[0].clone();
        assert!(set.get_address(&foreign, 0).is_some());
        let other = ProgramByteBlockSet::new(
            Arc::new(MockProvider {
                program: set.program().clone(),
                base: space.address(0x1000),
                edits: Mutex::new(Vec::new()),
            }),
            set.program().clone(),
            None,
        );
        assert_eq!(other.get_address(&foreign, 0), None);
    }

    #[test]
    fn get_byte_block_info_maps_an_address_back_to_block_and_offset() {
        let (set, _provider, space) = make_set();

        let info = set.get_byte_block_info(&space.address(0x2003)).unwrap();
        assert_eq!(info.offset(), 3);
        assert_eq!(info.block().get_length(), 16);
        assert_eq!(set.get_block_start(info.block()), Some(space.address(0x2000)));

        // Addresses outside memory belong to no block.
        assert!(set.get_byte_block_info(&space.address(0x5000)).is_none());
    }

    #[test]
    fn get_byte_block_number_finds_blocks_by_start_address() {
        let (set, _provider, space) = make_set();

        assert_eq!(set.get_byte_block_number(&space.address(0x1000)), 0);
        assert_eq!(set.get_byte_block_number(&space.address(0x2000)), 1);
        assert_eq!(set.get_byte_block_number(&space.address(0x2001)), -1);
    }

    #[test]
    fn block_selection_clips_a_range_to_each_block_it_crosses() {
        let (set, _provider, space) = make_set();

        // 0x1008..0x2007 spans the tail of the first block and the head of the second.
        let range = AddressRange::new(space.address(0x1008), space.address(0x2007));
        let selection = set.get_block_selection_for_range(&range);

        assert_eq!(selection.number_of_ranges(), 2);
        assert_eq!(selection.range(0).start_index(), 8);
        assert_eq!(selection.range(0).end_index(), 15);
        assert_eq!(selection.range(1).start_index(), 0);
        assert_eq!(selection.range(1).end_index(), 7);

        // ...and mapping it back yields the covered addresses.
        let addr_set = set.get_address_set(&selection);
        let ranges = addr_set.to_list();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].min_address(), &space.address(0x1008));
        assert_eq!(ranges[0].max_address(), &space.address(0x100F));
        assert_eq!(ranges[1].min_address(), &space.address(0x2000));
        assert_eq!(ranges[1].max_address(), &space.address(0x2007));
    }

    #[test]
    fn block_selection_from_an_address_set_covers_every_range() {
        let (set, _provider, space) = make_set();

        let mut addresses = AddressSet::new();
        addresses.add_range(&space.address(0x1000), &space.address(0x1003));
        addresses.add_range(&space.address(0x2008), &space.address(0x200F));

        let selection = set.get_block_selection(&addresses);
        assert_eq!(selection.number_of_ranges(), 2);
        assert_eq!(selection.range(0).end_index(), 3);
        assert_eq!(selection.range(1).start_index(), 8);
    }

    #[test]
    fn convert_selection_carries_the_selected_addresses() {
        let (set, _provider, space) = make_set();
        let range = AddressRange::new(space.address(0x1004), space.address(0x1007));

        let selection = set.convert_selection(&set.get_block_selection_for_range(&range));
        let ranges = selection.addresses().to_list();

        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].min_address(), &space.address(0x1004));
        assert_eq!(ranges[0].max_address(), &space.address(0x1007));
    }

    #[test]
    fn notify_byte_editing_records_the_edit_and_tells_the_provider() {
        let (mut set, provider, _space) = make_set();
        let block = set.get_blocks()[0].clone();

        assert!(!set.is_changed(&block, 4, 2));
        set.notify_byte_editing(&block, 4, &[0x00, 0x01], &[0xAA, 0x01]);

        // Only the byte that actually changed is marked changed.
        assert!(set.is_changed(&block, 4, 1));
        assert!(!set.is_changed(&block, 5, 1));

        let edits = provider.edits.lock().unwrap();
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].offset(), 4);
        assert_eq!(edits[0].new_value(), &[0xAA, 0x01]);
    }

    #[test]
    fn a_new_set_inherits_the_previous_change_list() {
        let (mut set, provider, _space) = make_set();
        let block = set.get_blocks()[0].clone();
        set.notify_byte_editing(&block, 4, &[0x00], &[0xAA]);

        let successor = ProgramByteBlockSet::new(
            provider,
            set.program().clone(),
            Some(set.get_byte_block_change_manager()),
        );
        let successor_block = successor.get_blocks()[0].clone();

        assert!(successor.is_changed(&successor_block, 4, 1));
    }

    #[test]
    fn plugin_events_carry_the_source_program_and_payload() {
        let (set, _provider, space) = make_set();
        let block = set.get_blocks()[0].clone();

        let location_event = set.get_plugin_event_for_location("TestPlugin", &block, 4, 0);
        assert_eq!(location_event.event().source_name(), "TestPlugin");
        assert!(location_event.get_program().is_some());
        assert_eq!(
            location_event.get_location().get_address(),
            space.address(0x1004)
        );

        let range = AddressRange::new(space.address(0x1000), space.address(0x1003));
        let selection = set.get_block_selection_for_range(&range);
        let selection_event = set.get_plugin_event_for_selection("TestPlugin", &selection);
        assert_eq!(selection_event.event().source_name(), "TestPlugin");
        assert!(!selection_event.get_selection().is_empty());
    }
}
