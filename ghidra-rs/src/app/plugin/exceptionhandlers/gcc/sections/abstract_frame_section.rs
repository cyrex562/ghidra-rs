//! Ported from `ghidra.app.plugin.exceptionhandlers.gcc.sections.AbstractFrameSection`.
//!
//! Extend this class to parse the call frame information exception handling structures within a
//! particular frame memory section.
//!
//! # Shape
//!
//! The Java class carries both state (`monitor`, `program`, a `cieMap` cache) and behavior, and
//! is `implements CieSource` without providing `getCie` -- that single abstract method is left
//! for concrete subclasses. This is split accordingly: [`AbstractFrameSectionBase`] holds the
//! fields and every concrete method, and [`AbstractFrameSection`] is a supertrait bound of
//! [`CieSource`] with nothing of its own, since there is no other abstract method to declare.
//!
//! # Divergences from the Java
//!
//! * **Cie construction is caller-supplied.** `createCie`/`getCieOrCreateIfMissing` call `new
//!   Cie(monitor, program, isInDebugFrame)`. The `Cie` Java class is not ported yet -- only a
//!   [`seam_stubs::Cie`] trait exists, referenced by [`CieSource`] -- so there is no concrete
//!   type to instantiate here. Both methods instead take a `new_cie` factory closure, which real
//!   callers (a ported `Cie::new` once it lands) or tests (a stub `Cie`) supply.
//! * **`Address.NO_ADDRESS`.** `createAugmentationData` compares
//!   `frame.getAugmentationExDataAddress()` against `Address.NO_ADDRESS`; the ported [`Address`]
//!   has no such sentinel, so [`seam_stubs::FrameDescriptionEntry::get_augmentation_ex_data_address`]
//!   reports it as `None`.
//! * **`Symbol.setName` on a shared handle.** `createCieLabel`'s rename branch calls
//!   `cieSym.setName(...)` on the `Symbol` the symbol table just handed back. The ported
//!   [`SymbolTable::get_primary_symbol`] hands out `Arc<dyn Symbol>`, which may be aliased (e.g.
//!   held by the table's own cache), so the rename is only attempted when `Arc::get_mut` proves
//!   this call holds the only handle; otherwise it is silently skipped, same as if renaming were
//!   unsupported.
//! * **Command results ignored, same as the Java.** `CreateArrayCmd`/`SetCommentCmd` are not
//!   ported (see [`seam_stubs::CreateArrayCmd`]/[`seam_stubs::SetCommentCmd`]); their `apply_to`
//!   stubs are no-ops that report success, matching the Java, which also discards `applyTo`'s
//!   return value.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::app::plugin::exceptionhandlers::gcc::sections::cie_source::{CieSource, CieSourceError};
use crate::app::plugin::exceptionhandlers::gcc::ExceptionHandlerFrameException;
use crate::app::seam_stubs::{self, CreateArrayCmd, RegionDescriptor, SetCommentCmd};
use crate::program::model::address::Address;
use crate::program::model::listing::{CommentType, Program};
use crate::program::model::symbol::SourceType;
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

/// Marker trait for concrete frame-section types built on [`AbstractFrameSectionBase`].
///
/// Port of `abstract class AbstractFrameSection implements CieSource`. The Java class declares
/// no abstract methods of its own -- `CieSource.getCie` (inherited, unimplemented) is the only
/// method left for subclasses to provide -- so this side of the split is a supertrait bound with
/// nothing extra: state and every concrete method live on [`AbstractFrameSectionBase`].
pub trait AbstractFrameSection: CieSource {}

/// Shared state and concrete behavior for GCC exception-handling frame sections.
///
/// Port of `abstract class AbstractFrameSection`'s fields and non-abstract methods. See the
/// module docs for how `Cie` construction and a couple of other forward references are handled.
pub struct AbstractFrameSectionBase {
    /// A status monitor for indicating progress or allowing a task to be cancelled.
    pub monitor: Arc<dyn TaskMonitor>,
    /// The program containing this particular frame section.
    pub program: Arc<Mutex<dyn Program>>,
    cie_map: HashMap<Address, Arc<dyn seam_stubs::Cie>>,
}

impl AbstractFrameSectionBase {
    /// Constructor for an individual frame section.
    pub fn new(monitor: Arc<dyn TaskMonitor>, program: Arc<Mutex<dyn Program>>) -> Self {
        Self {
            monitor,
            program,
            cie_map: HashMap::new(),
        }
    }

    /// Creates data structures for the specified Common Information Entry (CIE) and its Frame
    /// Description Entries (FDEs) as indicated by the regions.
    ///
    /// # Arguments
    /// * `regions` - the region descriptors for the FDEs.
    /// * `cie` - the CIE for the FDEs.
    pub fn create_augmentation_data(&mut self, regions: &[Arc<dyn RegionDescriptor>], cie: &dyn seam_stubs::Cie) {
        for region in regions {
            let frame = region.get_frame_descriptor_entry();
            let Some(aug_data_ex_addr) = frame.get_augmentation_ex_data_address() else {
                continue;
            };

            let block = {
                let program = self.program.lock().expect("program lock poisoned");
                program.get_memory().and_then(|memory| memory.get_block(&aug_data_ex_addr))
            };
            let Some(block) = block else {
                continue;
            };

            let alignment = cie.get_code_alignment() as i64;
            let mut addr = aug_data_ex_addr.clone();
            let mut len: i64 = 0;
            loop {
                len += alignment;
                addr = addr.add_wrap(alignment);

                let has_primary_symbol = {
                    let mut program = self.program.lock().expect("program lock poisoned");
                    program
                        .get_symbol_table()
                        .and_then(|table| table.get_primary_symbol(&addr).ok().flatten())
                        .is_some()
                };
                if has_primary_symbol || !block.contains(&addr) {
                    break;
                }
            }

            if len > 0 {
                let array_cmd = CreateArrayCmd::new(aug_data_ex_addr, len as i32, 1, 1);
                let mut program = self.program.lock().expect("program lock poisoned");
                array_cmd.apply_to(&mut *program);
            }
        }
    }

    /// Creates the data for a common information entry (CIE) at the address and puts a label and
    /// comment on it.
    ///
    /// # Arguments
    /// * `cur_address` - the address with the CIE
    /// * `is_in_debug_frame` - true indicates the frame containing this CIE is a debug frame.
    /// * `new_cie` - constructs the `Cie` for `cur_address`; stands in for `new Cie(monitor,
    ///   program, isInDebugFrame)`, see the module docs.
    ///
    /// # Errors
    /// Returns `Err` if memory for the CIE couldn't be read, or another problem was encountered
    /// while creating it.
    pub fn create_cie(
        &mut self,
        cur_address: &Address,
        is_in_debug_frame: bool,
        new_cie: impl FnOnce(&Arc<dyn TaskMonitor>, &Arc<Mutex<dyn Program>>, bool) -> Arc<dyn seam_stubs::Cie>,
    ) -> Result<Arc<dyn seam_stubs::Cie>, CieSourceError> {
        let cie = new_cie(&self.monitor, &self.program, is_in_debug_frame);
        cie.create(cur_address).map_err(|e| {
            CieSourceError::ExceptionHandlerFrame(ExceptionHandlerFrameException::with_message_and_source(
                e.to_string(),
                Box::new(e),
            ))
        })?;
        if cie.is_end_of_frame() {
            return Ok(cie);
        }
        self.create_cie_label(cur_address);
        self.create_cie_comment(cur_address);
        Ok(cie)
    }

    /// This maintains a lookup of common information entry (CIE) objects; this retrieves an
    /// existing object (by address), and creates a new CIE if not found.
    ///
    /// # Arguments
    /// * `cur_address` - the address with the CIE
    /// * `is_in_debug_frame` - true indicates the frame containing this CIE is a debug frame.
    /// * `new_cie` - constructs the `Cie` for `cur_address` if it isn't already cached; see
    ///   [`Self::create_cie`].
    ///
    /// # Errors
    /// Returns `Err` if memory for the CIE couldn't be read, or another problem was encountered
    /// while creating it.
    pub fn get_cie_or_create_if_missing(
        &mut self,
        cur_address: &Address,
        is_in_debug_frame: bool,
        new_cie: impl FnOnce(&Arc<dyn TaskMonitor>, &Arc<Mutex<dyn Program>>, bool) -> Arc<dyn seam_stubs::Cie>,
    ) -> Result<Arc<dyn seam_stubs::Cie>, CieSourceError> {
        if let Some(cie) = self.cie_map.get(cur_address) {
            return Ok(Arc::clone(cie));
        }
        let cie = self.create_cie(cur_address, is_in_debug_frame, new_cie)?;
        self.cie_map.insert(cur_address.clone(), Arc::clone(&cie));
        Ok(cie)
    }

    /// Creates a label indicating there is an CIE at the address.
    pub fn create_cie_label(&mut self, cur_address: &Address) {
        let cie_label = format!("cie_{}", cur_address);
        let mut program = self.program.lock().expect("program lock poisoned");
        let Some(table) = program.get_symbol_table() else {
            return;
        };

        let existing = table.get_primary_symbol(cur_address).ok().flatten();
        let result: Result<(), Box<dyn std::error::Error>> = match existing {
            None => table
                .create_label(cur_address, &cie_label, SourceType::Analysis)
                .map(|_| ())
                .map_err(Into::into),
            Some(mut sym) => match Arc::get_mut(&mut sym) {
                Some(sym) => sym.set_name(&cie_label, SourceType::Analysis).map_err(Into::into),
                // Aliased elsewhere (e.g. the symbol table's own cache); nothing we can rename
                // through, so leave it as-is rather than erroring.
                None => Ok(()),
            },
        };

        if let Err(e) = result {
            Msg::info("AbstractFrameSection", &format!("Unable to label CIE -- {}", e));
        }
    }

    /// Creates a comment indicating there is an CIE at the address.
    pub fn create_cie_comment(&mut self, cur_address: &Address) {
        self.create_plate_comment(cur_address, "Common Information Entry");
    }

    /// Creates a comment indicating there is an FDE at the address.
    pub fn create_fde_comment(&mut self, cur_address: &Address) {
        self.create_plate_comment(cur_address, "Frame Descriptor Entry");
    }

    fn create_plate_comment(&mut self, cur_address: &Address, comment: &str) {
        let comment_cmd = SetCommentCmd::new(cur_address.clone(), CommentType::Plate, comment);
        let mut program = self.program.lock().expect("program lock poisoned");
        comment_cmd.apply_to(&mut *program);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::exceptionhandlers::gcc::DwarfEHDecoder;
    use crate::app::seam_stubs::FrameDescriptionEntry;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::mem::memory_block_stub::MemoryBlockStub;
    use crate::program::model::mem::{Memory, MemoryAccessException, MemoryBlock};
    use crate::program::model::symbol::{Symbol, SymbolTable, SymbolType};
    use crate::util::task::CancelledListener;
    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn ram_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    struct NoOpMonitor;
    impl TaskMonitor for NoOpMonitor {
        fn is_cancelled(&self) -> bool {
            false
        }
        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, _message: &str) {}
        fn get_message(&self) -> String {
            String::new()
        }
        fn set_progress(&self, _value: i64) {}
        fn initialize(&self, _max: i64) {}
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 {
            0
        }
        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }
        fn check_cancelled(&self) -> Result<(), crate::util::exception::CancelledException> {
            Ok(())
        }
        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 {
            0
        }
        fn cancel(&self) {}
        fn add_cancelled_listener(&self, _listener: Box<dyn CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {}
    }

    struct MockSymbolTable {
        create_label_calls: Arc<Mutex<Vec<(Address, String)>>>,
        existing_primary: Option<Arc<dyn Symbol>>,
    }

    impl SymbolTable for MockSymbolTable {
        fn create_label(&mut self, addr: &Address, name: &str, _source: SourceType) -> io::Result<Arc<dyn Symbol>> {
            self.create_label_calls.lock().unwrap().push((addr.clone(), name.to_string()));
            Ok(Arc::new(StubSymbol { address: addr.clone(), name: name.to_string() }))
        }
        fn get_symbol(&self, _id: i64) -> io::Result<Option<Arc<dyn Symbol>>> {
            Ok(None)
        }
        fn get_symbols(&self, _addr: &Address) -> io::Result<Vec<Arc<dyn Symbol>>> {
            Ok(Vec::new())
        }
        fn get_primary_symbol(&self, _addr: &Address) -> io::Result<Option<Arc<dyn Symbol>>> {
            Ok(self.existing_primary.clone())
        }
    }

    struct StubSymbol {
        address: Address,
        name: String,
    }
    impl Symbol for StubSymbol {
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Label
        }
        fn get_source(&self) -> SourceType {
            SourceType::Analysis
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            1
        }
        fn get_parent_id(&self) -> i64 {
            0
        }
    }

    struct MockMemory {
        block: Option<Arc<dyn MemoryBlock>>,
        get_block_calls: Arc<AtomicUsize>,
    }
    impl Memory for MockMemory {
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_byte(&self, _addr: &Address) -> Result<u8, MemoryAccessException> {
            Ok(0)
        }
        fn get_bytes(&self, _addr: &Address, _dest: &mut [u8]) -> usize {
            0
        }
        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            Ok(())
        }
        fn get_block(&self, _addr: &Address) -> Option<Arc<dyn MemoryBlock>> {
            self.get_block_calls.fetch_add(1, Ordering::SeqCst);
            self.block.clone()
        }
    }

    struct MockProgram {
        memory: Option<Arc<dyn Memory>>,
        symbol_table: Option<MockSymbolTable>,
    }
    impl DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
        }
        fn get_memory(&self) -> Option<Arc<dyn Memory>> {
            self.memory.clone()
        }
        fn get_symbol_table(&mut self) -> Option<&mut dyn SymbolTable> {
            self.symbol_table.as_mut().map(|t| t as &mut dyn SymbolTable)
        }
    }

    fn section_with(program: MockProgram) -> AbstractFrameSectionBase {
        AbstractFrameSectionBase::new(Arc::new(NoOpMonitor), Arc::new(Mutex::new(program)))
    }

    fn empty_program() -> MockProgram {
        MockProgram { memory: None, symbol_table: None }
    }

    struct StubCie {
        address: Address,
        code_alignment: i32,
        end_of_frame: bool,
        create_calls: Arc<AtomicUsize>,
    }
    impl seam_stubs::Cie for StubCie {
        fn is_in_debug_frame(&self) -> bool {
            false
        }
        fn create(&self, _cie_address: &Address) -> io::Result<()> {
            self.create_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn get_next_address(&self) -> Address {
            self.address.clone()
        }
        fn get_augmentation_string(&self) -> String {
            String::new()
        }
        fn get_fde_encoding(&self) -> i32 {
            0
        }
        fn get_fde_decoder(&self) -> Box<dyn DwarfEHDecoder> {
            unimplemented!()
        }
        fn get_lsda_encoding(&self) -> i32 {
            0
        }
        fn get_lsda_decoder(&self) -> Box<dyn DwarfEHDecoder> {
            unimplemented!()
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_data_alignment(&self) -> i32 {
            1
        }
        fn get_code_alignment(&self) -> i32 {
            self.code_alignment
        }
        fn is_end_of_frame(&self) -> bool {
            self.end_of_frame
        }
        fn get_segment_size(&self) -> i32 {
            0
        }
        fn get_return_address_register_column(&self) -> i32 {
            0
        }
        fn get_cie_id(&self) -> i32 {
            0
        }
    }

    struct StubFrameDescriptionEntry {
        aug_address: Option<Address>,
    }
    impl FrameDescriptionEntry for StubFrameDescriptionEntry {
        fn get_augmentation_ex_data_address(&self) -> Option<Address> {
            self.aug_address.clone()
        }
    }

    struct StubRegion {
        frame: Arc<dyn FrameDescriptionEntry>,
    }
    impl RegionDescriptor for StubRegion {
        fn get_frame_descriptor_entry(&self) -> Arc<dyn FrameDescriptionEntry> {
            Arc::clone(&self.frame)
        }
    }

    #[test]
    fn get_cie_or_create_if_missing_caches_by_address() {
        let mut section = section_with(empty_program());
        let addr = ram_address(0x1000);
        let create_calls = Arc::new(AtomicUsize::new(0));

        let first = section
            .get_cie_or_create_if_missing(&addr, false, {
                let create_calls = Arc::clone(&create_calls);
                let addr = addr.clone();
                move |_monitor, _program, _debug| -> Arc<dyn seam_stubs::Cie> {
                    Arc::new(StubCie {
                        address: addr.clone(),
                        code_alignment: 4,
                        end_of_frame: false,
                        create_calls: Arc::clone(&create_calls),
                    })
                }
            })
            .unwrap();

        assert_eq!(create_calls.load(Ordering::SeqCst), 1);
        assert_eq!(first.get_code_alignment(), 4);

        // A second lookup at the same address must hit the cache: this factory panics if it
        // actually runs.
        let second = section
            .get_cie_or_create_if_missing(&addr, false, |_m, _p, _d| -> Arc<dyn seam_stubs::Cie> {
                panic!("factory should not run for a cached address");
            })
            .unwrap();

        assert_eq!(create_calls.load(Ordering::SeqCst), 1);
        assert_eq!(second.get_code_alignment(), 4);
    }

    #[test]
    fn create_cie_skips_label_when_end_of_frame() {
        let create_label_calls = Arc::new(Mutex::new(Vec::new()));
        let symbol_table = MockSymbolTable {
            create_label_calls: Arc::clone(&create_label_calls),
            existing_primary: None,
        };
        let mut section = section_with(MockProgram { memory: None, symbol_table: Some(symbol_table) });
        let addr = ram_address(0x2000);
        let create_calls = Arc::new(AtomicUsize::new(0));

        let cie = section
            .create_cie(&addr, false, {
                let addr = addr.clone();
                let create_calls = Arc::clone(&create_calls);
                move |_m, _p, _d| -> Arc<dyn seam_stubs::Cie> {
                    Arc::new(StubCie {
                        address: addr.clone(),
                        code_alignment: 1,
                        end_of_frame: true,
                        create_calls,
                    })
                }
            })
            .unwrap();

        assert!(cie.is_end_of_frame());
        assert_eq!(create_calls.load(Ordering::SeqCst), 1);
        assert!(create_label_calls.lock().unwrap().is_empty());
    }

    #[test]
    fn create_cie_labels_address_when_not_end_of_frame() {
        let create_label_calls = Arc::new(Mutex::new(Vec::new()));
        let symbol_table = MockSymbolTable {
            create_label_calls: Arc::clone(&create_label_calls),
            existing_primary: None,
        };
        let mut section = section_with(MockProgram { memory: None, symbol_table: Some(symbol_table) });
        let addr = ram_address(0x3000);
        let create_calls = Arc::new(AtomicUsize::new(0));

        section
            .create_cie(&addr, false, {
                let addr = addr.clone();
                move |_m, _p, _d| -> Arc<dyn seam_stubs::Cie> {
                    Arc::new(StubCie {
                        address: addr.clone(),
                        code_alignment: 1,
                        end_of_frame: false,
                        create_calls,
                    })
                }
            })
            .unwrap();

        let calls = create_label_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], (addr.clone(), format!("cie_{}", addr)));
    }

    #[test]
    fn create_cie_label_skips_create_when_primary_symbol_already_exists() {
        let create_label_calls = Arc::new(Mutex::new(Vec::new()));
        let existing: Arc<dyn Symbol> = Arc::new(StubSymbol { address: ram_address(0x4000), name: "existing".into() });
        let symbol_table = MockSymbolTable {
            create_label_calls: Arc::clone(&create_label_calls),
            existing_primary: Some(existing),
        };
        let mut section = section_with(MockProgram { memory: None, symbol_table: Some(symbol_table) });

        section.create_cie_label(&ram_address(0x4000));

        assert!(create_label_calls.lock().unwrap().is_empty());
    }

    #[test]
    fn create_augmentation_data_skips_region_without_augmentation_address() {
        let get_block_calls = Arc::new(AtomicUsize::new(0));
        let memory = MockMemory { block: None, get_block_calls: Arc::clone(&get_block_calls) };
        let mut section = section_with(MockProgram { memory: Some(Arc::new(memory)), symbol_table: None });

        let region: Arc<dyn RegionDescriptor> =
            Arc::new(StubRegion { frame: Arc::new(StubFrameDescriptionEntry { aug_address: None }) });
        let cie = StubCie {
            address: ram_address(0x5000),
            code_alignment: 4,
            end_of_frame: false,
            create_calls: Arc::new(AtomicUsize::new(0)),
        };

        section.create_augmentation_data(&[region], &cie);

        assert_eq!(get_block_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn create_augmentation_data_consults_memory_when_augmentation_address_present() {
        let get_block_calls = Arc::new(AtomicUsize::new(0));
        let block: Arc<dyn MemoryBlock> = Arc::new(MemoryBlockStub::new(ram_address(0x6000), ram_address(0x600f)));
        let memory = MockMemory { block: Some(block), get_block_calls: Arc::clone(&get_block_calls) };
        let mut section = section_with(MockProgram { memory: Some(Arc::new(memory)), symbol_table: None });

        let region: Arc<dyn RegionDescriptor> = Arc::new(StubRegion {
            frame: Arc::new(StubFrameDescriptionEntry { aug_address: Some(ram_address(0x6000)) }),
        });
        let cie = StubCie {
            address: ram_address(0x6000),
            code_alignment: 4,
            end_of_frame: false,
            create_calls: Arc::new(AtomicUsize::new(0)),
        };

        section.create_augmentation_data(&[region], &cie);

        assert_eq!(get_block_calls.load(Ordering::SeqCst), 1);
    }
}
