//! Ported from
//! `ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDAActionRecord`.
//!
//! A record that associates the type info with a catch action.
//!
//! # Divergences from the Java
//!
//! * **`GccAnalysisClass` base fields are inlined.** The Java class extends the abstract
//!   `GccAnalysisClass` purely for its `monitor`/`program` fields and a couple of protected
//!   static helpers; there's no interface to implement, so those fields live directly on
//!   [`LSDAActionRecord`] instead of introducing a trait for a base class with nothing
//!   polymorphic about it.
//! * **The unused `region` constructor parameter is dropped.** The Java constructor accepts a
//!   `RegionDescriptor region` parameter that it never stores or otherwise uses (not even in the
//!   `super(...)` call) -- so there is nothing for a Rust equivalent to carry.
//! * **`Address.NO_ADDRESS` sentinel.** `nextActionAddress` is either a real address or the
//!   `Address.NO_ADDRESS` sentinel (when `displacementToNext == 0`); the ported [`Address`] has
//!   no such sentinel (same divergence documented on
//!   [`AbstractFrameSectionBase`](crate::app::plugin::exceptionhandlers::gcc::sections::abstract_frame_section::AbstractFrameSectionBase)),
//!   so `next_action_address` uses `None` for both "not yet created" and "no next action",
//!   matching the Java's own null-before-`create()` contract on the getters.
//! * **`SignedLeb128DataType` is not applied.** `createTypeFilter`/`createNextActionRef` call
//!   `createAndCommentData(..., SignedLeb128DataType.dataType, ...)`, which both creates a typed
//!   `Data` unit and a comment. There is no ported `DataType` for `SignedLeb128DataType` yet, so
//!   -- like [`CreateArrayCmd`](crate::app::seam_stubs::CreateArrayCmd)'s dropped `ByteDataType`
//!   argument -- only the comment half of that call is performed here.
//! * **Command results ignored, same as the Java.** [`SetCommentCmd`](crate::app::seam_stubs::SetCommentCmd)
//!   isn't ported; its `apply_to` stub no-ops and reports success, matching the Java, which also
//!   discards `applyTo`'s return value.

use std::sync::{Arc, Mutex};

use crate::app::seam_stubs::{self, GccAnalysisUtils, SetCommentCmd};
use crate::program::model::address::Address;
use crate::program::model::listing::{CommentType, Program};
use crate::program::model::mem::MemoryAccessException;
use crate::util::task::TaskMonitor;

/// A record that associates the type info with a catch action.
///
/// Port of `class LSDAActionRecord extends GccAnalysisClass`.
#[derive(Clone)]
pub struct LSDAActionRecord {
    monitor: Arc<dyn TaskMonitor>,
    program: Arc<Mutex<dyn Program>>,
    lsda_action_table: Arc<seam_stubs::LSDAActionTable>,

    record_address: Option<Address>,
    next_address: Option<Address>,

    type_filter: i32,
    displacement_to_next: i32,
    next_action_address: Option<Address>,
    size: i32,
}

impl LSDAActionRecord {
    /// Port of `LSDAActionRecord.NO_ACTION`.
    pub const NO_ACTION: i64 = 0;

    /// Constructor for an action record.
    ///
    /// Note: [`create`](Self::create) must be called after constructing an `LSDAActionRecord` to
    /// associate it with an address before any of its `get_...` methods are called.
    ///
    /// # Arguments
    /// * `monitor` - task monitor to see if the user has cancelled analysis.
    /// * `program` - the program containing the action record.
    /// * `lsda_action_table` - the action table containing the action record.
    pub fn new(
        monitor: Arc<dyn TaskMonitor>,
        program: Arc<Mutex<dyn Program>>,
        lsda_action_table: Arc<seam_stubs::LSDAActionTable>,
    ) -> Self {
        Self {
            monitor,
            program,
            lsda_action_table,
            record_address: None,
            next_address: None,
            type_filter: 0,
            displacement_to_next: 0,
            next_action_address: None,
            size: 0,
        }
    }

    /// Creates data for an action record at the indicated address and creates a comment to
    /// identify it as an action record.
    ///
    /// Note: this method must get called before any of the `get_...` methods.
    ///
    /// # Arguments
    /// * `address` - the start (minimum address) of this action record.
    pub fn create(&mut self, address: Address) -> Result<(), MemoryAccessException> {
        if self.monitor.is_cancelled() {
            return Ok(());
        }
        self.record_address = Some(address.clone());
        self.size = 0;

        let addr = self.create_type_filter(address.clone())?;
        let addr = self.create_next_action_ref(addr)?;

        {
            let mut program = self.program.lock().expect("program lock poisoned");
            let comment_cmd =
                SetCommentCmd::new(address, CommentType::Plate, "(LSDA) Action Record");
            comment_cmd.apply_to(&mut *program);
        }

        self.next_address = Some(addr);
        Ok(())
    }

    fn create_type_filter(&mut self, addr: Address) -> Result<Address, MemoryAccessException> {
        let comment = "(LSDA Action Table) Type Filter";

        let sleb128 = {
            let program = self.program.lock().expect("program lock poisoned");
            GccAnalysisUtils::read_sleb128_info(&*program, &addr)?
        };

        self.type_filter = sleb128.as_long() as i32;

        {
            let mut program = self.program.lock().expect("program lock poisoned");
            let comment_cmd = SetCommentCmd::new(addr.clone(), CommentType::Eol, comment);
            comment_cmd.apply_to(&mut *program);
        }

        self.size += sleb128.get_length();

        addr.add(sleb128.get_length() as i64)
            .map_err(|e| MemoryAccessException::new(e.to_string()))
    }

    fn create_next_action_ref(&mut self, addr: Address) -> Result<Address, MemoryAccessException> {
        let comment = "(LSDA Action Table) Next-Action Reference";

        let sleb128 = {
            let program = self.program.lock().expect("program lock poisoned");
            GccAnalysisUtils::read_sleb128_info(&*program, &addr)?
        };

        self.displacement_to_next = sleb128.as_long() as i32;

        self.next_action_address = if self.displacement_to_next == 0 {
            // Address.NO_ADDRESS sentinel; see the module docs.
            None
        } else {
            Some(
                addr.add(self.displacement_to_next as i64)
                    .map_err(|e| MemoryAccessException::new(e.to_string()))?,
            )
        };

        {
            let mut program = self.program.lock().expect("program lock poisoned");
            let comment_cmd = SetCommentCmd::new(addr.clone(), CommentType::Eol, comment);
            comment_cmd.apply_to(&mut *program);
        }

        self.size += sleb128.get_length();

        addr.add(sleb128.get_length() as i64)
            .map_err(|e| MemoryAccessException::new(e.to_string()))
    }

    /// Gets the filter value indicating which type is associated with this action record.
    pub fn get_action_type_filter(&self) -> i32 {
        self.type_filter
    }

    /// Gets the base address of the next action record to consider in the action table, or
    /// `None` if there isn't one.
    pub fn get_next_action_address(&self) -> Option<Address> {
        self.next_action_address.clone()
    }

    /// Gets the next address indicating the address after this action record, or `None` if this
    /// action record hasn't been created at any address yet.
    pub fn get_next_address(&self) -> Option<Address> {
        self.next_address.clone()
    }

    /// Gets the base address (minimum address) indicating the start of this action record, or
    /// `None` if this action record hasn't been created at any address yet.
    pub fn get_address(&self) -> Option<Address> {
        self.record_address.clone()
    }

    /// Gets the record for the next action that the catch should fall to if the type isn't the
    /// one for this action, or `None` if there isn't another specific type of exception for this
    /// try.
    ///
    /// # Panics
    /// Panics if `get_next_action_address()` names an address that isn't in the owning action
    /// table, mirroring the Java's `IllegalArgumentException("Invalid action table record
    /// address")`.
    pub fn get_next_action(&self) -> Option<LSDAActionRecord> {
        let rec_addr = self.get_next_action_address()?;
        if self.lsda_action_table.get_address() == Some(rec_addr.clone()) {
            return None;
        }

        self.lsda_action_table
            .get_action_records()
            .iter()
            .find(|rec| rec.get_address() == Some(rec_addr.clone()))
            .cloned()
            .or_else(|| panic!("Invalid action table record address"))
    }

    /// Gets the size of the action record, or 0 if this action record hasn't been created at any
    /// address yet.
    pub fn get_size(&self) -> i32 {
        self.size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::seam_stubs::LSDAActionTable;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::mem::Memory;
    use crate::util::task::{DummyMonitor, TaskMonitor as TaskMonitorTrait};

    /// A single fixed-size memory block backed by a byte vector, used to test LEB128 decoding
    /// through [`GccAnalysisUtils::read_sleb128_info`].
    struct FakeMemory {
        bytes: Vec<u8>,
    }

    impl Memory for FakeMemory {
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
            self.bytes
                .get(addr.offset() as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of range"))
        }
        fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
            let start = addr.offset() as usize;
            let mut n = 0;
            for (i, slot) in dest.iter_mut().enumerate() {
                match self.bytes.get(start + i) {
                    Some(b) => {
                        *slot = *b;
                        n += 1;
                    }
                    None => break,
                }
            }
            n
        }
        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            Err(MemoryAccessException::new("read-only"))
        }
    }

    struct MockProgram {
        memory: Arc<FakeMemory>,
    }

    impl DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:64:default".to_string()
        }
        fn get_memory(&self) -> Option<Arc<dyn Memory>> {
            Some(self.memory.clone())
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn ram_address(offset: i64) -> Address {
        Address::new(ram_space(), offset)
    }

    fn program_with_bytes(bytes: Vec<u8>) -> Arc<Mutex<dyn Program>> {
        Arc::new(Mutex::new(MockProgram {
            memory: Arc::new(FakeMemory { bytes }),
        }))
    }

    #[test]
    fn create_decodes_type_filter_and_zero_displacement_as_no_next_action() {
        // type filter SLEB128 = 5 (0x05), next-action displacement SLEB128 = 0 (0x00).
        let program = program_with_bytes(vec![0x05, 0x00]);
        let monitor: Arc<dyn TaskMonitorTrait> = Arc::new(DummyMonitor);
        let table = Arc::new(LSDAActionTable::new(None, Vec::new()));
        let mut record = LSDAActionRecord::new(monitor, program, table);

        record.create(ram_address(0)).expect("create should succeed");

        assert_eq!(record.get_action_type_filter(), 5);
        assert_eq!(record.get_next_action_address(), None);
        assert_eq!(record.get_address(), Some(ram_address(0)));
        assert_eq!(record.get_size(), 2);
        assert_eq!(record.get_next_address(), Some(ram_address(2)));
    }

    #[test]
    fn create_decodes_nonzero_displacement_into_next_action_address() {
        // type filter SLEB128 = 1 (0x01) at offset 0, next-action displacement SLEB128 = 3 (0x03) at
        // offset 1, so the next action address is offset 1 (start of displacement) + 3 = 4.
        let program = program_with_bytes(vec![0x01, 0x03]);
        let monitor: Arc<dyn TaskMonitorTrait> = Arc::new(DummyMonitor);
        let table = Arc::new(LSDAActionTable::new(None, Vec::new()));
        let mut record = LSDAActionRecord::new(monitor, program, table);

        record.create(ram_address(0)).expect("create should succeed");

        assert_eq!(record.get_next_action_address(), Some(ram_address(4)));
    }

    #[test]
    fn get_next_action_finds_matching_record_in_table() {
        let program = program_with_bytes(vec![0x01, 0x03]);
        let monitor: Arc<dyn TaskMonitorTrait> = Arc::new(DummyMonitor);

        // Build the "next" record directly at the address create() will compute (offset 4).
        let mut next_record =
            LSDAActionRecord::new(monitor.clone(), program.clone(), Arc::new(LSDAActionTable::new(None, Vec::new())));
        next_record.record_address = Some(ram_address(4));

        let table = Arc::new(LSDAActionTable::new(Some(ram_address(100)), vec![next_record.clone()]));
        let mut record = LSDAActionRecord::new(monitor, program, table);
        record.create(ram_address(0)).expect("create should succeed");

        let found = record.get_next_action().expect("should find the next action");
        assert_eq!(found.get_address(), Some(ram_address(4)));
    }

    #[test]
    fn get_next_action_returns_none_before_create() {
        let monitor: Arc<dyn TaskMonitorTrait> = Arc::new(DummyMonitor);
        let program = program_with_bytes(vec![]);
        let table = Arc::new(LSDAActionTable::new(None, Vec::new()));
        let record = LSDAActionRecord::new(monitor, program, table);

        assert!(record.get_next_action().is_none());
    }
}
