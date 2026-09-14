//! Port of `ghidra.app.emulator.FilteredMemoryState`.

use std::sync::Arc;

use crate::app::emulator::memory_access_filter::{
    MemoryAccessFilterCallbacks, MemoryAccessFilterChain, MemoryAccessFilterId,
};
use crate::pcode::error::lowlevel_error::LowlevelError;
use crate::pcode::memstate::abstract_memory_state::AbstractMemoryState;
use crate::pcode::memstate::default_memory_state::DefaultMemoryState;
use crate::pcode::memstate::memory_bank::MemoryBankImpl;
use crate::pcode::memstate::memory_state::MemoryState;
use crate::program::model::address::AddressSpace;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::pcode::Varnode;

/// A [`DefaultMemoryState`] whose reads and writes are additionally routed through a chain of
/// [`MemoryAccessFilterCallbacks`].
///
/// Port of the package-private `ghidra.app.emulator.FilteredMemoryState`, a concrete class
/// `extends DefaultMemoryState`. Per this crate's composition-over-inheritance convention, this
/// becomes a struct holding a `base: DefaultMemoryState` field.
///
/// # Shape: one filter field becomes a filter chain
///
/// Java's `filter: MemoryAccessFilter` is a single reference, but that referenced object is
/// itself the *head* of an intrusive `prevFilter`/`nextFilter` linked list that
/// `MemoryAccessFilter.addFilter(Emulator)` builds up (see
/// [`MemoryAccessFilterChain`]'s own module docs, which already anticipated this exact situation:
/// "a `FilteredMemoryState` implementation that embeds a `MemoryAccessFilterChain` supplies that
/// bit itself when calling in"). [`add_filter`](Self::add_filter) here plays the combined role of
/// Java's `addFilter(Emulator)` (linking the new filter in as the chain's head) *and*
/// `FilteredMemoryState.setFilter` (recording that new head) in one step, exactly matching what
/// [`MemoryAccessFilterChain::add_filter`] already does.
///
/// # Divergence: `is_executing` is a stored flag, not a live `Emulator` query
///
/// Java's `filter.filterRead`/`filterWrite` (the package-private final methods on
/// `MemoryAccessFilter` itself, ported here as [`MemoryAccessFilterChain::filter_read`]/
/// [`filter_write`](MemoryAccessFilterChain::filter_write)) internally call `emu.isExecuting()`
/// through the `emu` field each filter captured when it was added via `addFilter(Emulator)`.
/// Since this crate's [`MemoryAccessFilterChain`] does not hold an `Emulator` reference at all
/// (see that type's own docs), this state instead caches the executing flag directly via
/// [`set_is_executing`](Self::set_is_executing); an owning `Emulator` implementation is expected
/// to keep it in sync (e.g. before/after `execute_instruction`), the same way it would otherwise
/// have to make itself observable to every registered filter object.
#[deprecated(since = "12.1", note = "scheduled for removal in a future release")]
pub struct FilteredMemoryState {
    base: DefaultMemoryState,
    chain: MemoryAccessFilterChain,
    /// Guards against re-entrant filtering when a filter's own callback would otherwise trigger
    /// another `get_chunk`/`set_chunk` on this same state. Mirrors the private `filterEnabled`
    /// field (`used to prevent filtering filter queries`).
    filter_enabled: bool,
    is_executing: bool,
}

#[allow(deprecated)]
impl FilteredMemoryState {
    /// Construct a filtered memory state for the given language.
    ///
    /// Port of `FilteredMemoryState(Language lang)`, which is just `super(lang)` (`filter` starts
    /// `null` and `filterEnabled` starts `true`).
    pub fn new(lang: Box<dyn Language>) -> Self {
        FilteredMemoryState {
            base: DefaultMemoryState::new(lang),
            chain: MemoryAccessFilterChain::new(),
            filter_enabled: true,
            is_executing: false,
        }
    }

    /// Report whether the owning emulator is currently executing. See the struct's own docs for
    /// why this is a cached flag rather than a live query.
    pub fn set_is_executing(&mut self, is_executing: bool) {
        self.is_executing = is_executing;
    }

    /// Register a new filter, making it the new head of the filter chain (invoked first, ahead of
    /// every filter already registered).
    ///
    /// Stands in for the combined effect of `MemoryAccessFilter.addFilter(Emulator)` and
    /// `FilteredMemoryState.setFilter(MemoryAccessFilter)`; see the struct's own docs.
    pub fn add_filter(&mut self, callbacks: Box<dyn MemoryAccessFilterCallbacks>) -> MemoryAccessFilterId {
        self.chain.add_filter(callbacks)
    }

    /// Unregister a previously-added filter.
    ///
    /// Stands in for `MemoryAccessFilter.dispose()`.
    pub fn dispose_filter(&mut self, id: MemoryAccessFilterId) {
        self.chain.dispose(id);
    }
}

#[allow(deprecated)]
impl AbstractMemoryState for FilteredMemoryState {
    fn is_big_endian(&self) -> bool {
        self.base.is_big_endian()
    }

    fn get_register_by_name(&self, name: &str) -> Option<RegisterRef> {
        self.base.get_register_by_name(name)
    }

    /// Port of the overridden `getChunk(byte[], AddressSpace, long, int, boolean)`.
    ///
    /// Reads through to the base [`DefaultMemoryState`], then (unless already inside a filter
    /// callback) passes the read bytes through [`MemoryAccessFilterChain::filter_read`], which may
    /// mutate them in place.
    fn get_chunk(
        &mut self,
        res: &mut [u8],
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
        stop_on_uninitialized: bool,
    ) -> Result<i32, LowlevelError> {
        let read_len =
            AbstractMemoryState::get_chunk(&mut self.base, res, spc, off, size, stop_on_uninitialized)?;
        if self.filter_enabled {
            self.filter_enabled = false;
            self.chain.filter_read(self.is_executing, spc, off, read_len, res);
            self.filter_enabled = true;
        }
        Ok(read_len)
    }

    /// Port of the overridden `setChunk(byte[], AddressSpace, long, int)`.
    ///
    /// Writes through to the base [`DefaultMemoryState`] first, then (unless already inside a
    /// filter callback) notifies [`MemoryAccessFilterChain::filter_write`] with the written bytes.
    ///
    /// A mutable copy of `val` is passed to the filter chain rather than `val` itself, since
    /// [`AbstractMemoryState::set_chunk`]'s signature takes an immutable `&[u8]` while
    /// [`MemoryAccessFilterChain::filter_write`] takes `&mut [u8]` (mirroring
    /// `MemoryAccessFilter.processWrite`'s Java signature). This is behaviorally identical to
    /// Java: the write to memory has already completed by the time the filter runs, so any
    /// mutation a filter makes to the byte buffer it's handed is purely observational either way.
    fn set_chunk(
        &mut self,
        val: &[u8],
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
    ) -> Result<(), LowlevelError> {
        AbstractMemoryState::set_chunk(&mut self.base, val, spc, off, size)?;
        if self.filter_enabled {
            self.filter_enabled = false;
            let mut buf = val.to_vec();
            self.chain.filter_write(self.is_executing, spc, off, size, &mut buf);
            self.filter_enabled = true;
        }
        Ok(())
    }
}

#[allow(deprecated)]
impl MemoryState for FilteredMemoryState {
    fn set_memory_bank(&mut self, bank: Box<dyn MemoryBankImpl>) {
        MemoryState::set_memory_bank(&mut self.base, bank);
    }

    fn get_memory_bank(&self, spc: &Arc<AddressSpace>) -> Option<&dyn MemoryBankImpl> {
        MemoryState::get_memory_bank(&self.base, spc)
    }

    fn set_value_varnode(&mut self, vn: &Varnode, cval: i64) -> Result<(), LowlevelError> {
        AbstractMemoryState::set_value_varnode(self, vn, cval)
    }

    fn set_value_register(&mut self, reg: &Register, cval: i64) -> Result<(), LowlevelError> {
        AbstractMemoryState::set_value_register(self, reg, cval)
    }

    fn set_value_by_name(&mut self, nm: &str, cval: i64) -> Result<(), LowlevelError> {
        AbstractMemoryState::set_value_by_name(self, nm, cval)
    }

    fn set_value(
        &mut self,
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
        cval: i64,
    ) -> Result<(), LowlevelError> {
        AbstractMemoryState::set_value(self, spc, off, size, cval)
    }

    fn get_value_varnode(&mut self, vn: &Varnode) -> Result<i64, LowlevelError> {
        AbstractMemoryState::get_value_varnode(self, vn)
    }

    fn get_value_register(&mut self, reg: &Register) -> Result<i64, LowlevelError> {
        AbstractMemoryState::get_value_register(self, reg)
    }

    fn get_value_by_name(&mut self, nm: &str) -> Result<i64, LowlevelError> {
        AbstractMemoryState::get_value_by_name(self, nm)
    }

    fn get_value(&mut self, spc: &Arc<AddressSpace>, off: i64, size: i32) -> Result<i64, LowlevelError> {
        AbstractMemoryState::get_value(self, spc, off, size)
    }

    fn set_big_value_varnode(&mut self, vn: &Varnode, cval: i128) -> Result<(), LowlevelError> {
        AbstractMemoryState::set_big_value_varnode(self, vn, cval)
    }

    fn set_big_value_register(&mut self, reg: &Register, cval: i128) -> Result<(), LowlevelError> {
        AbstractMemoryState::set_big_value_register(self, reg, cval)
    }

    fn set_big_value_by_name(&mut self, nm: &str, cval: i128) -> Result<(), LowlevelError> {
        AbstractMemoryState::set_big_value_by_name(self, nm, cval)
    }

    fn set_big_value(
        &mut self,
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
        cval: i128,
    ) -> Result<(), LowlevelError> {
        AbstractMemoryState::set_big_value(self, spc, off, size, cval)
    }

    fn get_big_integer_varnode(&mut self, vn: &Varnode, signed: bool) -> Result<i128, LowlevelError> {
        AbstractMemoryState::get_big_integer_varnode(self, vn, signed)
    }

    fn get_big_integer_register(&mut self, reg: &Register) -> Result<i128, LowlevelError> {
        AbstractMemoryState::get_big_integer_register(self, reg)
    }

    fn get_big_integer_by_name(&mut self, nm: &str) -> Result<i128, LowlevelError> {
        AbstractMemoryState::get_big_integer_by_name(self, nm)
    }

    fn get_big_integer(
        &mut self,
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
        signed: bool,
    ) -> Result<i128, LowlevelError> {
        AbstractMemoryState::get_big_integer(self, spc, off, size, signed)
    }

    fn get_chunk(
        &mut self,
        res: &mut [u8],
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
        stop_on_uninitialized: bool,
    ) -> Result<i32, LowlevelError> {
        AbstractMemoryState::get_chunk(self, res, spc, off, size, stop_on_uninitialized)
    }

    fn set_chunk(
        &mut self,
        val: &[u8],
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
    ) -> Result<(), LowlevelError> {
        AbstractMemoryState::set_chunk(self, val, spc, off, size)
    }

    /// Not overridden by `FilteredMemoryState.java`; inherited from `DefaultMemoryState`
    /// unchanged, so filtering does not apply to it.
    fn set_initialized(
        &mut self,
        initialized: bool,
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
    ) -> Result<(), LowlevelError> {
        MemoryState::set_initialized(&mut self.base, initialized, spc, off, size)
    }
}


#[cfg(test)]
#[allow(deprecated)]
mod tests {
    // Deliberately *not* `use super::*` -- `FilteredMemoryState` implements both
    // `AbstractMemoryState` and `MemoryState` (identically-named convenience methods), so plain
    // dot-call syntax would become ambiguous. Only what's actually needed is imported.
    use super::{FilteredMemoryState, Language};
    use crate::app::emulator::memory_access_filter::MemoryAccessFilterCallbacks;
    use crate::pcode::error::lowlevel_error::LowlevelError;
    use crate::pcode::memstate::abstract_memory_state::AbstractMemoryState;
    use crate::pcode::memstate::memory_bank::{MemoryBankImpl, MemoryBankState};
    use crate::pcode::memstate::memory_page::MemoryPage;
    use crate::pcode::memstate::memory_state::MemoryState;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::compiler_spec::CompilerSpec;
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::lang::language::ParseError;
    use crate::program::model::lang::language_description::LanguageDescription;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper;
    use crate::program::model::lang::register::RegisterRef;
    use crate::program::model::lang::unknown_instruction_exception::UnknownInstructionException;
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::app::plugin::processors::generic::MemoryBlockDefinition;
    use crate::program::seam_stubs::{AddressLabelInfo, Processor};
    use crate::program::model::address::{AddressFactory, AddressSet, AddressSetView};
    use crate::program::model::mem::mem_buffer::MemBuffer;
    use crate::util::task::TaskMonitor;
    use std::collections::HashMap;
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    /// Mirrors the identical `TestLanguage` double already used by `DefaultMemoryState`'s and
    /// `AdaptedMemoryState`'s own tests: only `is_big_endian`/`get_register_by_name` are
    /// exercised.
    struct TestLanguage {
        is_big_endian: bool,
        registers: HashMap<String, RegisterRef>,
    }

    impl Language for TestLanguage {
        fn get_language_id(&self) -> LanguageID {
            unimplemented!("not exercised by these tests")
        }
        fn get_language_description(&self) -> Box<dyn LanguageDescription> {
            unimplemented!("not exercised by these tests")
        }
        fn get_parallel_instruction_helper(&self) -> Option<Box<dyn ParallelInstructionLanguageHelper>> {
            None
        }
        fn get_processor(&self) -> Box<dyn Processor> {
            unimplemented!("not exercised by these tests")
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            unimplemented!("not exercised by these tests")
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by these tests")
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            self.is_big_endian
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
            _buf: &dyn MemBuffer,
            _context: &mut dyn crate::program::model::lang::processor_context::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<Box<dyn InstructionPrototype>, ParseError> {
            Err(ParseError::UnknownInstruction(UnknownInstructionException::new()))
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
        fn get_register_in_space(
            &self,
            _addrspc: &Arc<AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            self.registers.values().cloned().collect()
        }
        fn get_register_names(&self) -> Vec<String> {
            self.registers.keys().cloned().collect()
        }
        fn get_register_by_name(&self, name: &str) -> Option<RegisterRef> {
            self.registers.get(name).cloned()
        }
        fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<RegisterRef> {
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
        fn get_default_memory_blocks(&self) -> Vec<Box<dyn MemoryBlockDefinition>> {
            Vec::new()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn AddressLabelInfo>> {
            Vec::new()
        }
        fn get_segmented_space(&self) -> String {
            String::new()
        }
        fn get_volatile_addresses(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {}
        fn reload_language(&self, _task_monitor: &dyn TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpec>, CompilerSpecNotFoundException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by these tests")
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
        fn get_property_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn has_manual(&self) -> bool {
            false
        }
        fn get_manual_entry(&self, _instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }
        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_addresses(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    fn language(is_big_endian: bool) -> Box<dyn Language> {
        Box::new(TestLanguage { is_big_endian, registers: HashMap::new() })
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0)
    }

    struct SinglePageBank {
        state: MemoryBankState,
        page: MemoryPage,
    }

    impl SinglePageBank {
        fn new(space: Arc<AddressSpace>, is_big_endian: bool, pagesize: i32) -> Self {
            Self {
                state: MemoryBankState::new(space, is_big_endian, pagesize, None),
                page: MemoryPage::new(pagesize as usize),
            }
        }
    }

    impl MemoryBankImpl for SinglePageBank {
        fn state(&self) -> &MemoryBankState {
            &self.state
        }
        fn get_page(&mut self, _addr: i64) -> &mut MemoryPage {
            &mut self.page
        }
        fn set_page(&mut self, _addr: i64, val: &[u8], skip: i32, size: i32, buf_offset: i32) {
            let skip = skip as usize;
            let size = size as usize;
            let buf_offset = buf_offset as usize;
            self.page.data[skip..skip + size].copy_from_slice(&val[buf_offset..buf_offset + size]);
        }
        fn set_page_initialized(
            &mut self,
            _addr: i64,
            initialized: bool,
            skip: i32,
            size: i32,
            _buf_offset: i32,
        ) {
            if initialized {
                self.page.mark_initialized(skip as usize, size as usize);
            } else {
                self.page.mark_uninitialized(skip as usize, size as usize);
            }
        }
    }

    fn state_with_ram(is_big_endian: bool) -> (FilteredMemoryState, Arc<AddressSpace>) {
        let space = ram_space();
        let mut state = FilteredMemoryState::new(language(is_big_endian));
        MemoryState::set_memory_bank(
            &mut state,
            Box::new(SinglePageBank::new(space.clone(), is_big_endian, 64)),
        );
        (state, space)
    }

    /// Records every read/write it observes.
    struct RecordingFilter {
        log: Arc<Mutex<Vec<(&'static str, Vec<u8>)>>>,
    }

    impl MemoryAccessFilterCallbacks for RecordingFilter {
        fn process_read(&mut self, _spc: &Arc<AddressSpace>, _off: i64, _size: i32, values: &mut [u8]) {
            self.log.lock().unwrap().push(("read", values.to_vec()));
        }
        fn process_write(&mut self, _spc: &Arc<AddressSpace>, _off: i64, _size: i32, values: &mut [u8]) {
            self.log.lock().unwrap().push(("write", values.to_vec()));
        }
    }

    #[test]
    fn set_chunk_then_get_chunk_round_trips_through_the_base_state() {
        let (mut state, space) = state_with_ram(false);
        MemoryState::set_chunk(&mut state, &[1, 2, 3, 4], &space, 0, 4).unwrap();
        let mut res = [0u8; 4];
        let read = MemoryState::get_chunk(&mut state, &mut res, &space, 0, 4, false).unwrap();
        assert_eq!(read, 4);
        assert_eq!(res, [1, 2, 3, 4]);
    }

    #[test]
    fn without_a_filter_reads_and_writes_are_unfiltered() {
        let (mut state, space) = state_with_ram(false);
        MemoryState::set_chunk(&mut state, &[9, 9], &space, 0, 2).unwrap();
        let mut res = [0u8; 2];
        MemoryState::get_chunk(&mut state, &mut res, &space, 0, 2, false).unwrap();
        assert_eq!(res, [9, 9]);
    }

    #[test]
    fn a_registered_filter_observes_reads_and_writes() {
        let (mut state, space) = state_with_ram(false);
        let log = Arc::new(Mutex::new(Vec::new()));
        state.add_filter(Box::new(RecordingFilter { log: log.clone() }));
        state.set_is_executing(true);

        MemoryState::set_chunk(&mut state, &[5, 6], &space, 0, 2).unwrap();
        let mut res = [0u8; 2];
        MemoryState::get_chunk(&mut state, &mut res, &space, 0, 2, false).unwrap();

        let events = log.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], ("write", vec![5, 6]));
        assert_eq!(events[1], ("read", vec![5, 6]));
    }

    /// A filter's default `filter_on_execution_only` means it should be skipped while the
    /// emulator is not (reported as) executing.
    #[test]
    fn filter_is_skipped_while_not_executing() {
        let (mut state, space) = state_with_ram(false);
        let log = Arc::new(Mutex::new(Vec::new()));
        state.add_filter(Box::new(RecordingFilter { log: log.clone() }));
        // is_executing left false (the default).

        MemoryState::set_chunk(&mut state, &[1], &space, 0, 1).unwrap();
        assert!(log.lock().unwrap().is_empty());
    }

    #[test]
    fn disposed_filter_is_no_longer_invoked() {
        let (mut state, space) = state_with_ram(false);
        let log = Arc::new(Mutex::new(Vec::new()));
        let id = state.add_filter(Box::new(RecordingFilter { log: log.clone() }));
        state.set_is_executing(true);
        state.dispose_filter(id);

        MemoryState::set_chunk(&mut state, &[7], &space, 0, 1).unwrap();
        assert!(log.lock().unwrap().is_empty());
    }

    #[test]
    fn is_big_endian_and_register_lookup_delegate_to_base() {
        let state = FilteredMemoryState::new(language(true));
        assert!(AbstractMemoryState::is_big_endian(&state));
        assert!(state.get_register_by_name("nope").is_none());
    }

    #[test]
    fn set_initialized_delegates_to_base_unfiltered() {
        // FilteredMemoryState.java has no setInitialized override, so it's inherited straight
        // from DefaultMemoryState/AbstractMemoryState -- it neither invokes filters nor routes
        // through process_read/process_write. Verified by confirming no filter callback fires,
        // the same way disposed_filter_is_no_longer_invoked checks non-invocation. (SinglePageBank
        // here always reports fully initialized -- see MemoryPage::new's own established
        // "no mask == fully initialized" convention -- so this can't be verified by an
        // initialized-vs-uninitialized read-length difference.)
        let (mut state, space) = state_with_ram(false);
        let log = Arc::new(Mutex::new(Vec::new()));
        state.add_filter(Box::new(RecordingFilter { log: log.clone() }));

        MemoryState::set_initialized(&mut state, true, &space, 0, 2).unwrap();
        assert!(log.lock().unwrap().is_empty());

        let mut res = [0xAAu8; 2];
        let read = MemoryState::get_chunk(&mut state, &mut res, &space, 0, 2, true).unwrap();
        assert_eq!(read, 2);
    }
}
