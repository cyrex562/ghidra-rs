use std::sync::Arc;

use crate::pcode::error::lowlevel_error::LowlevelError;
use crate::pcode::memstate::memory_bank::MemoryBankImpl;
use crate::program::model::address::AddressSpace;
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::pcode::Varnode;

/// Interface for reading and writing state during pcode emulation.
///
/// A `MemoryState` object presents a single view of registers and memory during emulation. It
/// acts as an even layer of abstraction on top of the address spaces associated with a processor.
/// Each address space that will be used during emulation must have a registered
/// [`MemoryBankImpl`] (via [`set_memory_bank`](Self::set_memory_bank)) before that space can be
/// read or written through this interface.
///
/// Corresponds to `ghidra.pcode.memstate.MemoryState`.
///
/// # Deprecation
///
/// Deprecated since Ghidra 12.1 and scheduled for removal.
#[deprecated(since = "12.1", note = "scheduled for removal in a future release")]
pub trait MemoryState {
    /// `MemoryBank`s associated with specific address spaces must be registered with this
    /// `MemoryState` via this method. Each address space that will be used during emulation must
    /// be registered separately. The `MemoryState` does not assume responsibility for freeing the
    /// `MemoryBank`.
    ///
    /// Corresponds to `MemoryState.setMemoryBank(MemoryBank)`.
    fn set_memory_bank(&mut self, bank: Box<dyn MemoryBankImpl>);

    /// Any `MemoryBank` that has been registered with this `MemoryState` can be retrieved via
    /// this method if the `MemoryBank`'s associated address space is known.
    ///
    /// Corresponds to `MemoryState.getMemoryBank(AddressSpace)`.
    ///
    /// Returns `None` if no bank is associated with `spc`.
    fn get_memory_bank(&self, spc: &Arc<AddressSpace>) -> Option<&dyn MemoryBankImpl>;

    /// A convenience method for setting a value directly on a varnode rather than breaking out
    /// the components.
    ///
    /// Corresponds to `MemoryState.setValue(Varnode, long)`.
    fn set_value_varnode(&mut self, vn: &Varnode, cval: i64) -> Result<(), LowlevelError>;

    /// A convenience method for setting a value directly on a register rather than breaking out
    /// the components.
    ///
    /// Corresponds to `MemoryState.setValue(Register, long)`.
    fn set_value_register(&mut self, reg: &Register, cval: i64) -> Result<(), LowlevelError>;

    /// A convenience method for setting registers by name. Any register name known to the
    /// language can be used as a write location. The associated address space, offset, and size
    /// is looked up and automatically passed to the main [`set_value`](Self::set_value) routine.
    ///
    /// Corresponds to `MemoryState.setValue(String, long)`.
    fn set_value_by_name(&mut self, nm: &str, cval: i64) -> Result<(), LowlevelError>;

    /// The main interface for writing values to the `MemoryState`. If there is no registered
    /// `MemoryBank` for the desired address space, or if there is some other error, an error is
    /// returned.
    ///
    /// Corresponds to `MemoryState.setValue(AddressSpace, long, int, long)`.
    fn set_value(
        &mut self,
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
        cval: i64,
    ) -> Result<(), LowlevelError>;

    /// A convenience method for reading a value directly from a varnode rather than querying for
    /// the offset and space.
    ///
    /// Corresponds to `MemoryState.getValue(Varnode)`.
    fn get_value_varnode(&mut self, vn: &Varnode) -> Result<i64, LowlevelError>;

    /// A convenience method for reading a value directly from a register rather than querying for
    /// the offset and space.
    ///
    /// Corresponds to `MemoryState.getValue(Register)`.
    fn get_value_register(&mut self, reg: &Register) -> Result<i64, LowlevelError>;

    /// A convenience method for reading registers by name. Any register name known to the
    /// language can be used as a read location. The associated address space, offset, and size is
    /// looked up and automatically passed to the main [`get_value`](Self::get_value) routine.
    ///
    /// Corresponds to `MemoryState.getValue(String)`.
    fn get_value_by_name(&mut self, nm: &str) -> Result<i64, LowlevelError>;

    /// The main interface for reading values from the `MemoryState`. If there is no registered
    /// `MemoryBank` for the desired address space, or if there is some other error, an error is
    /// returned.
    ///
    /// Corresponds to `MemoryState.getValue(AddressSpace, long, int)`.
    fn get_value(&mut self, spc: &Arc<AddressSpace>, off: i64, size: i32) -> Result<i64, LowlevelError>;

    /// A convenience method for setting a value directly on a varnode rather than breaking out
    /// the components.
    ///
    /// Corresponds to `MemoryState.setValue(Varnode, BigInteger)`.
    fn set_big_value_varnode(&mut self, vn: &Varnode, cval: i128) -> Result<(), LowlevelError>;

    /// A convenience method for setting a value directly on a register rather than breaking out
    /// the components.
    ///
    /// Corresponds to `MemoryState.setValue(Register, BigInteger)`.
    fn set_big_value_register(&mut self, reg: &Register, cval: i128) -> Result<(), LowlevelError>;

    /// A convenience method for setting registers by name. Any register name known to the
    /// language can be used as a write location. The associated address space, offset, and size
    /// is looked up and automatically passed to the main [`set_big_value`](Self::set_big_value)
    /// routine.
    ///
    /// Corresponds to `MemoryState.setValue(String, BigInteger)`.
    fn set_big_value_by_name(&mut self, nm: &str, cval: i128) -> Result<(), LowlevelError>;

    /// The main interface for writing values to the `MemoryState`. If there is no registered
    /// `MemoryBank` for the desired address space, or if there is some other error, an error is
    /// returned.
    ///
    /// Corresponds to `MemoryState.setValue(AddressSpace, long, int, BigInteger)`.
    fn set_big_value(
        &mut self,
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
        cval: i128,
    ) -> Result<(), LowlevelError>;

    /// A convenience method for reading a value directly from a varnode rather than querying for
    /// the offset and space.
    ///
    /// Corresponds to `MemoryState.getBigInteger(Varnode, boolean)`.
    fn get_big_integer_varnode(&mut self, vn: &Varnode, signed: bool) -> Result<i128, LowlevelError>;

    /// A convenience method for reading a value directly from a register rather than querying for
    /// the offset and space.
    ///
    /// Corresponds to `MemoryState.getBigInteger(Register)`.
    fn get_big_integer_register(&mut self, reg: &Register) -> Result<i128, LowlevelError>;

    /// A convenience method for reading registers by name. Any register name known to the
    /// language can be used as a read location. The associated address space, offset, and size is
    /// looked up and automatically passed to the main [`get_big_integer`](Self::get_big_integer)
    /// routine.
    ///
    /// Corresponds to `MemoryState.getBigInteger(String)`.
    fn get_big_integer_by_name(&mut self, nm: &str) -> Result<i128, LowlevelError>;

    /// The main interface for reading values from the `MemoryState`. If there is no registered
    /// `MemoryBank` for the desired address space, or if there is some other error, an error is
    /// returned.
    ///
    /// Corresponds to `MemoryState.getBigInteger(AddressSpace, long, int, boolean)`.
    fn get_big_integer(
        &mut self,
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
        signed: bool,
    ) -> Result<i128, LowlevelError>;

    /// The main interface for reading a range of bytes from the `MemoryState`. The `MemoryBank`
    /// associated with the address space of the query is looked up and the request is forwarded
    /// to the `get_chunk` method on the `MemoryBank`. If there is no registered `MemoryBank` or
    /// some other error, an error is returned.
    ///
    /// `stop_on_uninitialized`: if `true` a partial read is permitted and the returned size may
    /// be smaller than the size requested.
    ///
    /// Returns the number of bytes actually read.
    ///
    /// Corresponds to `MemoryState.getChunk(byte[], AddressSpace, long, int, boolean)`.
    fn get_chunk(
        &mut self,
        res: &mut [u8],
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
        stop_on_uninitialized: bool,
    ) -> Result<i32, LowlevelError>;

    /// The main interface for setting values for a range of bytes in the `MemoryState`. The
    /// `MemoryBank` associated with the desired address space is looked up and the write is
    /// forwarded to the `set_chunk` method on the `MemoryBank`. If there is no registered
    /// `MemoryBank` or some other error, an error is returned.
    ///
    /// Corresponds to `MemoryState.setChunk(byte[], AddressSpace, long, int)`.
    fn set_chunk(
        &mut self,
        val: &[u8],
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
    ) -> Result<(), LowlevelError>;

    /// The main interface for setting the initialization status for a range of bytes in the
    /// `MemoryState`. The `MemoryBank` associated with the desired address space is looked up and
    /// the write is forwarded to the `set_initialized` method on the `MemoryBank`. If there is no
    /// registered `MemoryBank` or some other error, an error is returned.
    ///
    /// Corresponds to `MemoryState.setInitialized(boolean, AddressSpace, long, int)`.
    fn set_initialized(
        &mut self,
        initialized: bool,
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
    ) -> Result<(), LowlevelError>;
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::pcode::memstate::memory_bank::{MemoryBankImpl, MemoryBankState};
    use crate::pcode::memstate::memory_page::MemoryPage;
    use crate::pcode::utils::{
        big_integer_to_bytes, bytes_to_big_integer, bytes_to_long, long_to_bytes,
    };
    use crate::program::model::address::{Address, AddressSpaceType};
    use std::collections::HashMap;

    /// A single-page `MemoryBankImpl` for tests, matching the pattern already used by
    /// `memory_bank::tests::TestBank`.
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
            self.page.data[skip..skip + size]
                .copy_from_slice(&val[buf_offset..buf_offset + size]);
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

    /// A minimal `MemoryState` backed by a `HashMap` of banks keyed by address space id, and a
    /// name-to-register table -- standing in for `AbstractMemoryState`'s `Language` lookup, which
    /// isn't part of this interface.
    struct TestMemoryState {
        is_big_endian: bool,
        banks: HashMap<i32, Box<dyn MemoryBankImpl>>,
        registers: HashMap<String, RegisterRef>,
    }

    impl TestMemoryState {
        fn new(is_big_endian: bool) -> Self {
            Self {
                is_big_endian,
                banks: HashMap::new(),
                registers: HashMap::new(),
            }
        }

        fn add_register(&mut self, reg: RegisterRef) {
            let name = reg.borrow().name().to_string();
            self.registers.insert(name, reg);
        }
    }

    impl MemoryState for TestMemoryState {
        fn set_memory_bank(&mut self, bank: Box<dyn MemoryBankImpl>) {
            let space_id = bank.state().space().space_id();
            self.banks.insert(space_id, bank);
        }

        fn get_memory_bank(&self, spc: &Arc<AddressSpace>) -> Option<&dyn MemoryBankImpl> {
            self.banks.get(&spc.space_id()).map(|b| b.as_ref())
        }

        fn set_value_varnode(&mut self, vn: &Varnode, cval: i64) -> Result<(), LowlevelError> {
            let addr = vn.get_address();
            self.set_value(addr.space(), addr.offset(), vn.get_size(), cval)
        }

        fn set_value_register(&mut self, reg: &Register, cval: i64) -> Result<(), LowlevelError> {
            let space = reg.address_space();
            self.set_value(&space, reg.address().offset(), reg.minimum_byte_size(), cval)
        }

        fn set_value_by_name(&mut self, nm: &str, cval: i64) -> Result<(), LowlevelError> {
            let reg = self
                .registers
                .get(nm)
                .cloned()
                .ok_or_else(|| LowlevelError::with_message(format!("unknown register: {nm}")))?;
            let reg = reg.borrow();
            self.set_value_register(&reg, cval)
        }

        fn set_value(
            &mut self,
            spc: &Arc<AddressSpace>,
            off: i64,
            size: i32,
            cval: i64,
        ) -> Result<(), LowlevelError> {
            let bytes = long_to_bytes(cval, size as usize, self.is_big_endian);
            self.set_chunk(&bytes, spc, off, size)
        }

        fn get_value_varnode(&mut self, vn: &Varnode) -> Result<i64, LowlevelError> {
            let addr = vn.get_address();
            self.get_value(addr.space(), addr.offset(), vn.get_size())
        }

        fn get_value_register(&mut self, reg: &Register) -> Result<i64, LowlevelError> {
            let space = reg.address_space();
            let offset = reg.address().offset();
            let size = reg.minimum_byte_size();
            self.get_value(&space, offset, size)
        }

        fn get_value_by_name(&mut self, nm: &str) -> Result<i64, LowlevelError> {
            let reg = self
                .registers
                .get(nm)
                .cloned()
                .ok_or_else(|| LowlevelError::with_message(format!("unknown register: {nm}")))?;
            let reg = reg.borrow();
            self.get_value_register(&reg)
        }

        fn get_value(
            &mut self,
            spc: &Arc<AddressSpace>,
            off: i64,
            size: i32,
        ) -> Result<i64, LowlevelError> {
            let mut bytes = vec![0u8; size as usize];
            self.get_chunk(&mut bytes, spc, off, size, false)?;
            Ok(bytes_to_long(&bytes, size as usize, self.is_big_endian))
        }

        fn set_big_value_varnode(&mut self, vn: &Varnode, cval: i128) -> Result<(), LowlevelError> {
            let addr = vn.get_address();
            self.set_big_value(addr.space(), addr.offset(), vn.get_size(), cval)
        }

        fn set_big_value_register(&mut self, reg: &Register, cval: i128) -> Result<(), LowlevelError> {
            let space = reg.address_space();
            self.set_big_value(&space, reg.address().offset(), reg.minimum_byte_size(), cval)
        }

        fn set_big_value_by_name(&mut self, nm: &str, cval: i128) -> Result<(), LowlevelError> {
            let reg = self
                .registers
                .get(nm)
                .cloned()
                .ok_or_else(|| LowlevelError::with_message(format!("unknown register: {nm}")))?;
            let reg = reg.borrow();
            self.set_big_value_register(&reg, cval)
        }

        fn set_big_value(
            &mut self,
            spc: &Arc<AddressSpace>,
            off: i64,
            size: i32,
            cval: i128,
        ) -> Result<(), LowlevelError> {
            let bytes = big_integer_to_bytes(cval, size as usize, self.is_big_endian);
            self.set_chunk(&bytes, spc, off, size)
        }

        fn get_big_integer_varnode(
            &mut self,
            vn: &Varnode,
            signed: bool,
        ) -> Result<i128, LowlevelError> {
            let addr = vn.get_address();
            self.get_big_integer(addr.space(), addr.offset(), vn.get_size(), signed)
        }

        fn get_big_integer_register(&mut self, reg: &Register) -> Result<i128, LowlevelError> {
            let space = reg.address_space();
            let offset = reg.address().offset();
            let size = reg.minimum_byte_size();
            self.get_big_integer(&space, offset, size, false)
        }

        fn get_big_integer_by_name(&mut self, nm: &str) -> Result<i128, LowlevelError> {
            let reg = self
                .registers
                .get(nm)
                .cloned()
                .ok_or_else(|| LowlevelError::with_message(format!("unknown register: {nm}")))?;
            let reg = reg.borrow();
            self.get_big_integer_register(&reg)
        }

        fn get_big_integer(
            &mut self,
            spc: &Arc<AddressSpace>,
            off: i64,
            size: i32,
            signed: bool,
        ) -> Result<i128, LowlevelError> {
            let mut bytes = vec![0u8; size as usize];
            self.get_chunk(&mut bytes, spc, off, size, false)?;
            Ok(bytes_to_big_integer(&bytes, size as usize, self.is_big_endian, signed))
        }

        fn get_chunk(
            &mut self,
            res: &mut [u8],
            spc: &Arc<AddressSpace>,
            off: i64,
            size: i32,
            stop_on_uninitialized: bool,
        ) -> Result<i32, LowlevelError> {
            let bank = self.banks.get_mut(&spc.space_id()).ok_or_else(|| {
                LowlevelError::with_message(format!("no memory bank for space {}", spc.name()))
            })?;
            Ok(bank.get_chunk(off, size, res, stop_on_uninitialized))
        }

        fn set_chunk(
            &mut self,
            val: &[u8],
            spc: &Arc<AddressSpace>,
            off: i64,
            size: i32,
        ) -> Result<(), LowlevelError> {
            let bank = self.banks.get_mut(&spc.space_id()).ok_or_else(|| {
                LowlevelError::with_message(format!("no memory bank for space {}", spc.name()))
            })?;
            bank.set_chunk(off, size, val);
            Ok(())
        }

        fn set_initialized(
            &mut self,
            initialized: bool,
            spc: &Arc<AddressSpace>,
            off: i64,
            size: i32,
        ) -> Result<(), LowlevelError> {
            let bank = self.banks.get_mut(&spc.space_id()).ok_or_else(|| {
                LowlevelError::with_message(format!("no memory bank for space {}", spc.name()))
            })?;
            bank.set_initialized(off, size, initialized);
            Ok(())
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn state_with_ram(is_big_endian: bool) -> (TestMemoryState, Arc<AddressSpace>) {
        let space = ram_space();
        let mut state = TestMemoryState::new(is_big_endian);
        state.set_memory_bank(Box::new(SinglePageBank::new(space.clone(), is_big_endian, 64)));
        (state, space)
    }

    #[test]
    fn set_value_then_get_value_round_trips_little_endian() {
        let (mut state, space) = state_with_ram(false);
        state.set_value(&space, 0x10, 4, 0x01020304).unwrap();
        let val = state.get_value(&space, 0x10, 4).unwrap();
        assert_eq!(val, 0x01020304);
    }

    #[test]
    fn set_value_encodes_little_endian_bytes_matching_java_constructvalue() {
        // MemoryBank.constructValue/deconstructValue: little-endian byte 0 is the low byte.
        let (mut state, space) = state_with_ram(false);
        state.set_value(&space, 0, 4, 0x01020304).unwrap();
        let mut raw = [0u8; 4];
        state.get_chunk(&mut raw, &space, 0, 4, false).unwrap();
        assert_eq!(raw, [0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn set_value_encodes_big_endian_bytes() {
        let (mut state, space) = state_with_ram(true);
        state.set_value(&space, 0, 4, 0x01020304).unwrap();
        let mut raw = [0u8; 4];
        state.get_chunk(&mut raw, &space, 0, 4, false).unwrap();
        assert_eq!(raw, [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn get_value_unregistered_space_is_error() {
        let mut state = TestMemoryState::new(false);
        let other = AddressSpace::new("OTHER", 32, 1, AddressSpaceType::Ram, 1);
        assert!(state.get_value(&other, 0, 4).is_err());
    }

    #[test]
    fn set_value_register_then_get_value_register_round_trips() {
        let (mut state, space) = state_with_ram(false);
        let reg = Register::new("r0", "general reg 0", Address::new(space, 0x20), 4, false, 0);
        state.set_value_register(&reg.borrow(), 0x11223344).unwrap();
        let val = state.get_value_register(&reg.borrow()).unwrap();
        assert_eq!(val, 0x11223344);
    }

    #[test]
    fn set_value_by_name_then_get_value_by_name_round_trips() {
        let (mut state, space) = state_with_ram(false);
        let reg = Register::new("pc", "program counter", Address::new(space, 0x30), 4, false, 0);
        state.add_register(reg.clone());
        state.set_value_by_name("pc", 0xdeadbeefu32 as i64).unwrap();
        let val = state.get_value_by_name("pc").unwrap();
        assert_eq!(val, 0xdeadbeefu32 as i64);
    }

    #[test]
    fn set_value_varnode_then_get_value_varnode_round_trips() {
        let (mut state, space) = state_with_ram(false);
        let vn = Varnode::new(Address::new(space, 0x40), 2);
        state.set_value_varnode(&vn, 0x1234).unwrap();
        let val = state.get_value_varnode(&vn).unwrap();
        assert_eq!(val, 0x1234);
    }

    #[test]
    fn set_big_value_then_get_big_integer_round_trips() {
        let (mut state, space) = state_with_ram(false);
        state.set_big_value(&space, 0x50, 8, 0x1122334455667788).unwrap();
        let val = state.get_big_integer(&space, 0x50, 8, false).unwrap();
        assert_eq!(val, 0x1122334455667788);
    }

    #[test]
    fn set_initialized_false_makes_get_chunk_stop_early() {
        let (mut state, space) = state_with_ram(false);
        state.set_value(&space, 0, 4, 0x01020304).unwrap();
        state.set_initialized(false, &space, 1, 2).unwrap();

        let mut res = [0u8; 4];
        let n = state.get_chunk(&mut res, &space, 0, 4, true).unwrap();
        // byte 0 remains initialized; bytes [1,3) were just marked uninitialized
        assert_eq!(n, 1);
    }

    #[test]
    fn get_memory_bank_returns_registered_bank() {
        let (state, space) = state_with_ram(false);
        assert!(state.get_memory_bank(&space).is_some());
    }

    #[test]
    fn get_memory_bank_none_for_unregistered_space() {
        let (state, _space) = state_with_ram(false);
        let other = AddressSpace::new("OTHER", 32, 1, AddressSpaceType::Ram, 1);
        assert!(state.get_memory_bank(&other).is_none());
    }
}
