use std::cell::RefCell;
use std::hash::Hash;
use std::rc::Rc;
use std::sync::Arc;

use crate::feature::base::memsearch::bytesource::AddressableByteSource;
use crate::program::model::address::{
    Address, AddressRange, AddressRangeSplitter, AddressSet, AddressSetView,
};
use crate::program::model::listing::Program;
use crate::program::model::mem::MemoryBlock;
use crate::util::bytesearch::{
    AddressMatch, BulkPatternSearcher, ByteSequence, BytePattern, ExtendedByteSequence, Match,
};
use crate::util::exception::CancelledException;
use crate::util::seam_stubs::{AddressableByteSequence, ProgramByteSource};
use crate::util::task::TaskMonitor;

const BUF_SIZE: usize = 4096;

/// Port of `ghidra.util.bytesearch.ProgramMemorySearcher`.
///
/// Efficiently searches for one or more patterns in memory. Patterns used by this type can be
/// any type that implements [`BytePattern`], so clients are free to define their own custom
/// pattern types.
///
/// Note: this searcher searches each memory block individually. It intentionally does not find
/// patterns that span memory blocks (even if the memory blocks are adjacent). If patterns need
/// to span memory blocks, a non-block-oriented searcher should be used instead.
pub struct ProgramMemorySearcher<T: BytePattern> {
    name: String,
    program: Arc<dyn Program>,
    pattern_searcher: BulkPatternSearcher<T>,
    max_pattern_length: usize,
    pre: Rc<RefCell<AddressableByteSequence>>,
    main: Rc<RefCell<AddressableByteSequence>>,
    post: Rc<RefCell<AddressableByteSequence>>,
    intermediate_results: Vec<Match<T>>,
}

impl<T: BytePattern + Clone + Eq + Hash> ProgramMemorySearcher<T> {
    /// Constructs a searcher for `patterns` over `program`'s memory. `name` is used by task
    /// monitor messages.
    pub fn new(name: impl Into<String>, program: Arc<dyn Program>, patterns: Vec<T>) -> Self {
        Self::with_pattern_searcher(name, program, BulkPatternSearcher::new(patterns))
    }

    /// Constructs a searcher from a pre-built, state-less [`BulkPatternSearcher`], saving the
    /// time of rebuilding the state machine for the patterns.
    pub fn with_pattern_searcher(
        name: impl Into<String>,
        program: Arc<dyn Program>,
        pattern_searcher: BulkPatternSearcher<T>,
    ) -> Self {
        let max_pattern_length = pattern_searcher.get_max_pattern_length();
        let byte_source: Arc<dyn AddressableByteSource> =
            Arc::new(ProgramByteSource::new(program.clone()));
        Self {
            name: name.into(),
            program,
            pattern_searcher,
            max_pattern_length,
            pre: Rc::new(RefCell::new(AddressableByteSequence::new(byte_source.clone(), BUF_SIZE))),
            main: Rc::new(RefCell::new(AddressableByteSequence::new(byte_source.clone(), BUF_SIZE))),
            post: Rc::new(RefCell::new(AddressableByteSequence::new(byte_source, BUF_SIZE))),
            intermediate_results: Vec::new(),
        }
    }

    /// Searches all loaded, initialized memory in the program for the patterns given to this
    /// searcher, invoking `consumer` for each match found.
    pub fn search_all(
        &mut self,
        consumer: &mut dyn FnMut(AddressMatch<T>),
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        let memory = self
            .program
            .get_memory()
            .expect("ProgramMemorySearcher requires a program with memory");
        let addresses = memory.get_loaded_and_initialized_address_set();
        self.search(addresses.as_ref(), consumer, monitor)
    }

    /// Searches `addresses` (further restricted to initialized program memory) for the patterns
    /// given to this searcher, invoking `consumer` for each match found.
    pub fn search(
        &mut self,
        addresses: &dyn AddressSetView,
        consumer: &mut dyn FnMut(AddressMatch<T>),
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        let memory = self
            .program
            .get_memory()
            .expect("ProgramMemorySearcher requires a program with memory");

        // we can't search in uninitialized memory, so exclude those addresses
        let initialized_addresses = addresses.intersect(memory.get_all_initialized_address_set().as_ref());
        monitor.set_message(&self.name);
        monitor.initialize(initialized_addresses.num_addresses() as i64);

        for block in memory.get_blocks() {
            monitor.check_cancelled()?;
            self.search_block(block.as_ref(), &initialized_addresses, consumer, monitor)?;
        }
        Ok(())
    }

    fn search_block(
        &mut self,
        block: &dyn MemoryBlock,
        addresses: &AddressSet,
        consumer: &mut dyn FnMut(AddressMatch<T>),
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        let block_set = addresses.intersect_range(&block.get_start(), &block.get_end());
        for range in block_set.to_list() {
            self.search_range(block, &range, consumer, monitor)?;
        }
        Ok(())
    }

    fn search_range(
        &mut self,
        block: &dyn MemoryBlock,
        range: &AddressRange,
        consumer: &mut dyn FnMut(AddressMatch<T>),
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        self.pre.borrow_mut().clear();
        self.main.borrow_mut().clear();
        self.post.borrow_mut().clear();

        // load data before range to allow for pre sequence patterns to match
        self.populate_pre_sequence_for_look_behind_patterns(block, range);

        let mut splitter = AddressRangeSplitter::new(range.clone(), BUF_SIZE as u64, true).peekable();
        self.main.borrow_mut().set_range(&splitter.next().expect("range is non-empty"));
        while splitter.peek().is_some() {
            monitor.check_cancelled()?;
            let next_range = splitter.next().expect("peeked Some");
            self.post.borrow_mut().set_range(&next_range);
            self.perform_search(consumer);
            monitor.increment_progress(range.length() as i64);
            self.rotate_buffers();
        }
        // load data some past end of range to allow pattern to complete
        self.populate_post_sequence_for_pattern_completion(block, range);
        self.perform_search(consumer);
        Ok(())
    }

    fn perform_search(&mut self, consumer: &mut dyn FnMut(AddressMatch<T>)) {
        self.intermediate_results.clear();
        let overlap_size = self.max_pattern_length; // number of bytes in pre/post that need to be used
        let sequence = ExtendedByteSequence::new(
            Box::new(AddressableByteSequenceView(Rc::clone(&self.main))),
            Some(Box::new(AddressableByteSequenceView(Rc::clone(&self.pre)))),
            Some(Box::new(AddressableByteSequenceView(Rc::clone(&self.post)))),
            overlap_size,
        );
        self.pattern_searcher.search_extended(&sequence, &mut self.intermediate_results);
        for m in &self.intermediate_results {
            let start = m.get_start() + m.get_pattern().pre_sequence_length() as u64;
            let address = self.main.borrow().get_address(start as usize);
            let length = m.get_length();
            let pattern = m.get_pattern().clone();
            let address_match = AddressMatch::new(pattern, start, length, address);
            consumer(address_match);
        }
    }

    fn rotate_buffers(&mut self) {
        std::mem::swap(&mut self.pre, &mut self.main);
        std::mem::swap(&mut self.main, &mut self.post);
    }

    fn populate_pre_sequence_for_look_behind_patterns(&mut self, block: &dyn MemoryBlock, range: &AddressRange) {
        let block_start = block.get_start();
        let range_start = range.min_address().clone();
        if range_start == block_start {
            return;
        }
        // We don't go back beyond block start for pre bytes
        let available_pre_bytes = range_start.subtract(&block_start) as usize;
        let pre_size = available_pre_bytes.min(self.max_pattern_length);
        let pre_start_address = range_start.add(-(pre_size as i64)).expect("pre-sequence start within block");
        self.pre.borrow_mut().set_range_at(pre_start_address, pre_size);
    }

    fn populate_post_sequence_for_pattern_completion(&mut self, block: &dyn MemoryBlock, range: &AddressRange) {
        let block_end = block.get_end();
        let range_end = range.max_address().clone();
        if range_end == block_end {
            return;
        }
        let available_post_bytes = block_end.subtract(&range_end) as usize;
        let post_size = available_post_bytes.min(self.max_pattern_length);
        let post_start = range_end.next().expect("range end has a successor within block");
        self.post.borrow_mut().set_range_at(post_start, post_size);
    }
}

/// Shares an [`AddressableByteSequence`] between the owning [`ProgramMemorySearcher`] (which
/// mutates it via `set_range`/`clear`) and any number of [`ByteSequence`] views handed to an
/// [`ExtendedByteSequence`] (which only reads from it), mirroring the `StreamBufferView` pattern
/// used by [`BulkPatternSearcher::search_stream_max`](crate::util::bytesearch::BulkPatternSearcher).
/// `ExtendedByteSequence`'s fields are owned, non-lifetime-parameterized `Box<dyn ByteSequence>`,
/// so a borrowed view cannot be used here; sharing via `Rc<RefCell<_>>` lets `pre`/`main`/`post`
/// keep being reused (and cheaply rotated) across search chunks instead of being consumed.
struct AddressableByteSequenceView(Rc<RefCell<AddressableByteSequence>>);

impl ByteSequence for AddressableByteSequenceView {
    fn len(&self) -> usize {
        self.0.borrow().len()
    }

    fn get_byte(&self, index: usize) -> u8 {
        self.0.borrow().get_byte(index)
    }

    fn get_bytes(&self, start: usize, length: usize) -> Vec<u8> {
        self.0.borrow().get_bytes(start, length)
    }

    fn has_available_bytes(&self, index: usize, length: usize) -> bool {
        self.0.borrow().has_available_bytes(index, length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::listing::Program;
    use crate::program::model::mem::{Memory, MemoryAccessException, MemoryBlockImpl};
    use crate::util::bytesearch::DittedBitSequence;
    use crate::util::task::DummyMonitor;

    // Port of the Java test's private `TestPattern`, a `DittedBitSequence` matching a literal
    // ASCII string, with an optional pre-sequence length (`ghidra.util.bytesearch
    // .ProgramMemorySearcherTest.TestPattern`).
    #[derive(Debug, Clone)]
    struct TestPattern {
        sequence: DittedBitSequence,
        pre_sequence_length: usize,
    }

    impl TestPattern {
        fn new(input: &str) -> Self {
            Self::with_pre_sequence_length(input, 0)
        }

        fn with_pre_sequence_length(input: &str, pre_sequence_length: usize) -> Self {
            let bytes = input.as_bytes().to_vec();
            let mask = vec![0xffu8; input.len()];
            Self {
                sequence: DittedBitSequence::from_bytes_and_mask(bytes, mask),
                pre_sequence_length,
            }
        }
    }

    impl BytePattern for TestPattern {
        fn size(&self) -> usize {
            self.sequence.size()
        }

        fn is_match(&self, pattern_offset: usize, byte_value: u8) -> bool {
            self.sequence.is_match(pattern_offset, byte_value)
        }

        fn pre_sequence_length(&self) -> usize {
            self.pre_sequence_length
        }
    }

    impl PartialEq for TestPattern {
        fn eq(&self, other: &Self) -> bool {
            self.sequence == other.sequence && self.pre_sequence_length == other.pre_sequence_length
        }
    }

    impl Eq for TestPattern {}

    impl Hash for TestPattern {
        fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
            self.sequence.hash(state);
            self.pre_sequence_length.hash(state);
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        Address::new(space.clone(), offset)
    }

    /// Writes `data` starting at `start_offset`, splitting the write across whichever of
    /// `blocks` actually own each byte (mirrors `ProgramBuilder.setString`, which can write
    /// across adjacent memory blocks).
    fn write_string(blocks: &mut [MemoryBlockImpl], space: &Arc<AddressSpace>, start_offset: i64, data: &[u8]) {
        for (i, &byte) in data.iter().enumerate() {
            let address = addr(space, start_offset + i as i64);
            for block in blocks.iter_mut() {
                if block.contains(&address) {
                    block.set_bytes(&address, &[byte]).unwrap();
                    break;
                }
            }
        }
    }

    struct TestMemory {
        blocks: Vec<Arc<dyn MemoryBlock>>,
    }

    impl Memory for TestMemory {
        fn is_big_endian(&self) -> bool {
            false
        }

        fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
            self.get_block(addr)
                .ok_or_else(|| MemoryAccessException::new("no block at address"))?
                .get_byte(addr)
        }

        fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
            match self.get_block(addr) {
                Some(block) => block.get_bytes(addr, dest),
                None => 0,
            }
        }

        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            Err(MemoryAccessException::new("TestMemory is read-only"))
        }

        fn get_block(&self, addr: &Address) -> Option<Arc<dyn MemoryBlock>> {
            self.blocks.iter().find(|b| b.contains(addr)).cloned()
        }

        fn get_blocks(&self) -> Vec<Arc<dyn MemoryBlock>> {
            self.blocks.clone()
        }

        fn get_all_initialized_address_set(&self) -> Box<dyn AddressSetView> {
            let mut set = AddressSet::new();
            for block in &self.blocks {
                set.add_range(&block.get_start(), &block.get_end());
            }
            Box::new(set)
        }

        fn get_loaded_and_initialized_address_set(&self) -> Box<dyn AddressSetView> {
            self.get_all_initialized_address_set()
        }
    }

    struct TestProgram {
        memory: Arc<TestMemory>,
    }

    impl DomainObject for TestProgram {}

    impl Program for TestProgram {
        fn get_name(&self) -> String {
            "Test".to_string()
        }

        fn get_language_id(&self) -> String {
            "test".to_string()
        }

        fn get_memory(&self) -> Option<Arc<dyn Memory>> {
            Some(self.memory.clone() as Arc<dyn Memory>)
        }
    }

    /// Port of `ProgramMemorySearcherTest.testMatchesDontSpanBlocks`: three memory blocks
    /// (`b1`=0x1001000..0x10010ff, `b2`=0x1001100..0x10011ff, `b3`=0x1001500..0x10015ff), with
    /// "Hello" written fully inside `b1`, "Hello" written straddling the `b1`/`b2` boundary (so
    /// neither block sees the full pattern), and "There" written fully inside `b3`. Only the two
    /// non-straddling matches should be found -- the block-oriented searcher must not find
    /// patterns spanning block boundaries.
    #[test]
    fn matches_dont_span_blocks() {
        let space = ram_space();
        let mut blocks = vec![
            MemoryBlockImpl::new("b1".into(), addr(&space, 0x1001000), 0x100, true),
            MemoryBlockImpl::new("b2".into(), addr(&space, 0x1001100), 0x100, true),
            MemoryBlockImpl::new("b3".into(), addr(&space, 0x1001500), 0x100, true),
        ];
        write_string(&mut blocks, &space, 0x1001010, b"Hello");
        write_string(&mut blocks, &space, 0x10010ff, b"Hello"); // crosses block boundary
        write_string(&mut blocks, &space, 0x1001520, b"There");

        let memory = Arc::new(TestMemory {
            blocks: blocks.into_iter().map(|b| Arc::new(b) as Arc<dyn MemoryBlock>).collect(),
        });
        let program: Arc<dyn Program> = Arc::new(TestProgram { memory });

        let p1 = TestPattern::new("Hello");
        let p2 = TestPattern::new("There");
        let mut searcher = ProgramMemorySearcher::new("Test", program, vec![p1, p2]);

        let mut results: Vec<AddressMatch<TestPattern>> = Vec::new();
        let monitor = DummyMonitor;
        searcher.search_all(&mut |m| results.push(m), &monitor).unwrap();

        assert_eq!(results.len(), 2);
        assert_eq!(*results[0].get_address(), addr(&space, 0x1001010));
        assert_eq!(*results[1].get_address(), addr(&space, 0x1001520));
    }

    /// Port of `ProgramMemorySearcherTest.testMatchInAddressSet`: restricting the search to an
    /// explicit address set (rather than `searchAll`) still finds a match fully contained within
    /// it.
    #[test]
    fn match_in_address_set() {
        let space = ram_space();
        let mut blocks = vec![MemoryBlockImpl::new("b1".into(), addr(&space, 0x1001000), 0x100, true)];
        write_string(&mut blocks, &space, 0x1001010, b"Hello");

        let memory = Arc::new(TestMemory {
            blocks: blocks.into_iter().map(|b| Arc::new(b) as Arc<dyn MemoryBlock>).collect(),
        });
        let program: Arc<dyn Program> = Arc::new(TestProgram { memory });

        let p1 = TestPattern::new("Hello");
        let mut searcher = ProgramMemorySearcher::new("Test", program, vec![p1]);

        let search_set = AddressSet::from_start_end(addr(&space, 0x1001005), addr(&space, 0x1001030));
        let mut results: Vec<AddressMatch<TestPattern>> = Vec::new();
        let monitor = DummyMonitor;
        searcher.search(&search_set, &mut |m| results.push(m), &monitor).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(*results[0].get_address(), addr(&space, 0x1001010));
    }

    /// Port of `ProgramMemorySearcherTest.testMatchStartsOutsideRange`: a match whose start
    /// falls outside the searched address set must not be reported, even though the pattern
    /// exists in memory.
    #[test]
    fn match_starting_outside_range_is_not_found() {
        let space = ram_space();
        let mut blocks = vec![MemoryBlockImpl::new("b1".into(), addr(&space, 0x1001000), 0x100, true)];
        write_string(&mut blocks, &space, 0x1001010, b"Hello");

        let memory = Arc::new(TestMemory {
            blocks: blocks.into_iter().map(|b| Arc::new(b) as Arc<dyn MemoryBlock>).collect(),
        });
        let program: Arc<dyn Program> = Arc::new(TestProgram { memory });

        let p1 = TestPattern::new("Hello");
        let mut searcher = ProgramMemorySearcher::new("Test", program, vec![p1]);

        let search_set = AddressSet::from_start_end(addr(&space, 0x1001011), addr(&space, 0x1001030));
        let mut results: Vec<AddressMatch<TestPattern>> = Vec::new();
        let monitor = DummyMonitor;
        searcher.search(&search_set, &mut |m| results.push(m), &monitor).unwrap();

        assert!(results.is_empty());
    }
}
