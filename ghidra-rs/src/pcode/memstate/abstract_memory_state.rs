//! Port of `ghidra.pcode.memstate.AbstractMemoryState`.
//!
//! # Port strategy: sibling trait, not an edit to `MemoryState`
//!
//! Java's `AbstractMemoryState` is an abstract class `implements MemoryState` that supplies
//! `final` (i.e. non-overridable) bodies for every "convenience" method declared on the
//! interface -- the `setValue`/`getValue`/`setBigInteger`-family overloads that take a
//! `Varnode`, `Register`, or register name and forward to the primitive `setChunk`/`getChunk`
//! methods (still abstract; concrete `MemoryBank`-backed subclasses implement those).
//!
//! The already-ported [`MemoryState`](super::MemoryState) trait (see `memory_state.rs`) declares
//! *all* of these -- convenience methods included -- as required (non-default) trait methods, so
//! every existing implementor supplies its own body for each of them directly (see that file's
//! `TestMemoryState`). Rather than retrofit those methods into defaults on the shared,
//! already-committed `MemoryState` trait (risking every current and concurrently-in-flight
//! implementor of that trait on this branch), this port keeps `AbstractMemoryState` as an
//! independent trait with its own smaller required core and default bodies for exactly the
//! `final` convenience methods Java's abstract class provides. A type can implement both
//! `MemoryState` and this trait if it wants both surfaces; nothing here depends on `MemoryState`.
//!
//! # Deviation: `Language` narrowed to two capabilities
//!
//! Java stores the whole `final Language language` field, but every method below only ever calls
//! `language.isBigEndian()` or `language.getRegister(String)`. Requiring a full
//! `&dyn Language` (a ~47-method trait) here would force every implementor -- including simple
//! test doubles -- to stand up a complete mock for capabilities this trait never exercises. The
//! required core below narrows this to just [`AbstractMemoryState::is_big_endian`] and
//! [`AbstractMemoryState::get_register_by_name`], matching this crate's "decoupling is
//! first-class" convention of exposing only what's actually used.
//!
//! Java's `language.getRegister(nm)` returns `null` for an unrecognized name, which the
//! `by_name` convenience methods below would then immediately dereference (`reg.getAddress()`),
//! throwing `NullPointerException`. The sibling [`MemoryState`] trait already converts that same
//! unchecked-exception style into a `Result` (see its `TestMemoryState::set_value_by_name`); this
//! port follows that established precedent rather than reproducing the NPE via a panic.
//!
//! # Deprecation
//!
//! Deprecated since Ghidra 12.1 and scheduled for removal, matching Java's
//! `@Deprecated(since = "12.1", forRemoval = true)`.

use std::sync::Arc;

use crate::pcode::error::lowlevel_error::LowlevelError;
use crate::pcode::utils::{
    big_integer_to_bytes, bytes_to_big_integer, bytes_to_long, long_to_bytes,
};
use crate::program::model::address::{AddressSpace, AddressSpaceType};
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::pcode::Varnode;

#[deprecated(since = "12.1", note = "scheduled for removal in a future release")]
pub trait AbstractMemoryState {
    /// Java: `language.isBigEndian()`.
    fn is_big_endian(&self) -> bool;

    /// Java: `language.getRegister(String)`. Returns `None` for an unrecognized name (see the
    /// module docs for how that differs from Java's `null`-then-NPE behavior).
    fn get_register_by_name(&self, name: &str) -> Option<RegisterRef>;

    /// The main interface for setting values for a range of bytes in the `MemoryState`.
    /// Mirrors the (still-abstract in Java) `MemoryState.setChunk`.
    fn set_chunk(
        &mut self,
        val: &[u8],
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
    ) -> Result<(), LowlevelError>;

    /// The main interface for reading a range of bytes from the `MemoryState`. Returns the
    /// number of bytes actually read. Mirrors the (still-abstract in Java)
    /// `MemoryState.getChunk`.
    fn get_chunk(
        &mut self,
        res: &mut [u8],
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
        stop_on_uninitialized: bool,
    ) -> Result<i32, LowlevelError>;

    // ---- final convenience methods (Java: AbstractMemoryState) ----

    /// Java: `final void setValue(Varnode, long)`.
    fn set_value_varnode(&mut self, vn: &Varnode, cval: i64) -> Result<(), LowlevelError> {
        let addr = vn.get_address();
        self.set_value(addr.space(), addr.offset(), vn.get_size(), cval)
    }

    /// Java: `final void setValue(Register, long)`.
    fn set_value_register(&mut self, reg: &Register, cval: i64) -> Result<(), LowlevelError> {
        let space = reg.address_space();
        self.set_value(&space, reg.address().offset(), reg.minimum_byte_size(), cval)
    }

    /// Java: `final void setValue(String, long)`.
    fn set_value_by_name(&mut self, nm: &str, cval: i64) -> Result<(), LowlevelError> {
        let reg = self
            .get_register_by_name(nm)
            .ok_or_else(|| LowlevelError::with_message(format!("unknown register: {nm}")))?;
        let reg = reg.borrow();
        self.set_value_register(&reg, cval)
    }

    /// Java: `final void setValue(AddressSpace, long, int, long)`.
    fn set_value(
        &mut self,
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
        cval: i64,
    ) -> Result<(), LowlevelError> {
        let bytes = long_to_bytes(cval, size as usize, self.is_big_endian());
        self.set_chunk(&bytes, spc, off, size)
    }

    /// Java: `final long getValue(Varnode)`.
    fn get_value_varnode(&mut self, vn: &Varnode) -> Result<i64, LowlevelError> {
        let addr = vn.get_address();
        self.get_value(addr.space(), addr.offset(), vn.get_size())
    }

    /// Java: `final long getValue(Register)`.
    fn get_value_register(&mut self, reg: &Register) -> Result<i64, LowlevelError> {
        let space = reg.address_space();
        let offset = reg.address().offset();
        let size = reg.minimum_byte_size();
        self.get_value(&space, offset, size)
    }

    /// Java: `final long getValue(String)`.
    fn get_value_by_name(&mut self, nm: &str) -> Result<i64, LowlevelError> {
        let reg = self
            .get_register_by_name(nm)
            .ok_or_else(|| LowlevelError::with_message(format!("unknown register: {nm}")))?;
        let reg = reg.borrow();
        self.get_value_register(&reg)
    }

    /// Java: `final long getValue(AddressSpace, long, int)`.
    fn get_value(&mut self, spc: &Arc<AddressSpace>, off: i64, size: i32) -> Result<i64, LowlevelError> {
        if spc.space_type() == AddressSpaceType::Constant {
            return Ok(off);
        }
        let mut bytes = vec![0u8; size as usize];
        self.get_chunk(&mut bytes, spc, off, size, false)?;
        Ok(bytes_to_long(&bytes, size as usize, self.is_big_endian()))
    }

    /// Java: `final void setValue(Varnode, BigInteger)`.
    fn set_big_value_varnode(&mut self, vn: &Varnode, cval: i128) -> Result<(), LowlevelError> {
        let addr = vn.get_address();
        self.set_big_value(addr.space(), addr.offset(), vn.get_size(), cval)
    }

    /// Java: `final void setValue(Register, BigInteger)`.
    fn set_big_value_register(&mut self, reg: &Register, cval: i128) -> Result<(), LowlevelError> {
        let space = reg.address_space();
        self.set_big_value(&space, reg.address().offset(), reg.minimum_byte_size(), cval)
    }

    /// Java: `final void setValue(String, BigInteger)`.
    fn set_big_value_by_name(&mut self, nm: &str, cval: i128) -> Result<(), LowlevelError> {
        let reg = self
            .get_register_by_name(nm)
            .ok_or_else(|| LowlevelError::with_message(format!("unknown register: {nm}")))?;
        let reg = reg.borrow();
        self.set_big_value_register(&reg, cval)
    }

    /// Java: `final void setValue(AddressSpace, long, int, BigInteger)`.
    fn set_big_value(
        &mut self,
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
        cval: i128,
    ) -> Result<(), LowlevelError> {
        let bytes = big_integer_to_bytes(cval, size as usize, self.is_big_endian());
        self.set_chunk(&bytes, spc, off, size)
    }

    /// Java: `final BigInteger getBigInteger(Varnode, boolean)`.
    fn get_big_integer_varnode(
        &mut self,
        vn: &Varnode,
        signed: bool,
    ) -> Result<i128, LowlevelError> {
        let addr = vn.get_address();
        self.get_big_integer(addr.space(), addr.offset(), vn.get_size(), signed)
    }

    /// Java: `final BigInteger getBigInteger(Register)`.
    fn get_big_integer_register(&mut self, reg: &Register) -> Result<i128, LowlevelError> {
        let space = reg.address_space();
        let offset = reg.address().offset();
        let size = reg.minimum_byte_size();
        self.get_big_integer(&space, offset, size, false)
    }

    /// Java: `final BigInteger getBigInteger(String)`.
    fn get_big_integer_by_name(&mut self, nm: &str) -> Result<i128, LowlevelError> {
        let reg = self
            .get_register_by_name(nm)
            .ok_or_else(|| LowlevelError::with_message(format!("unknown register: {nm}")))?;
        let reg = reg.borrow();
        self.get_big_integer_register(&reg)
    }

    /// Java: `final BigInteger getBigInteger(AddressSpace, long, int, boolean)`.
    fn get_big_integer(
        &mut self,
        spc: &Arc<AddressSpace>,
        off: i64,
        size: i32,
        signed: bool,
    ) -> Result<i128, LowlevelError> {
        if spc.space_type() == AddressSpaceType::Constant {
            if !signed && off < 0 {
                // Java: `new BigInteger(1, Utils.longToBytes(off, 8, true))` -- reinterpret the
                // raw 64-bit two's-complement pattern of a negative offset as an unsigned
                // magnitude.
                let be_bytes = long_to_bytes(off, 8, true);
                return Ok(bytes_to_big_integer(&be_bytes, 8, true, false));
            }
            return Ok(off as i128);
        }
        let mut bytes = vec![0u8; size as usize];
        self.get_chunk(&mut bytes, spc, off, size, false)?;
        Ok(bytes_to_big_integer(&bytes, size as usize, self.is_big_endian(), signed))
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpaceType};
    use std::collections::HashMap;

    /// A minimal `AbstractMemoryState` implementor backed by a flat byte map keyed by (space id,
    /// offset), standing in for a real `MemoryBank`-backed subclass. Only `set_chunk`/`get_chunk`
    /// (the "abstract" primitives) and the two narrowed `Language` capabilities are implemented;
    /// every convenience method under test comes from the trait's default bodies.
    struct TestAbstractMemoryState {
        is_big_endian: bool,
        mem: HashMap<(i32, i64), u8>,
        registers: HashMap<String, RegisterRef>,
    }

    impl TestAbstractMemoryState {
        fn new(is_big_endian: bool) -> Self {
            Self { is_big_endian, mem: HashMap::new(), registers: HashMap::new() }
        }

        fn add_register(&mut self, reg: RegisterRef) {
            let name = reg.borrow().name().to_string();
            self.registers.insert(name, reg);
        }
    }

    impl AbstractMemoryState for TestAbstractMemoryState {
        fn is_big_endian(&self) -> bool {
            self.is_big_endian
        }

        fn get_register_by_name(&self, name: &str) -> Option<RegisterRef> {
            self.registers.get(name).cloned()
        }

        fn set_chunk(
            &mut self,
            val: &[u8],
            spc: &Arc<AddressSpace>,
            off: i64,
            size: i32,
        ) -> Result<(), LowlevelError> {
            for i in 0..size as i64 {
                self.mem.insert((spc.space_id(), off + i), val[i as usize]);
            }
            Ok(())
        }

        fn get_chunk(
            &mut self,
            res: &mut [u8],
            spc: &Arc<AddressSpace>,
            off: i64,
            size: i32,
            stop_on_uninitialized: bool,
        ) -> Result<i32, LowlevelError> {
            for i in 0..size as i64 {
                match self.mem.get(&(spc.space_id(), off + i)) {
                    Some(b) => res[i as usize] = *b,
                    None => {
                        if stop_on_uninitialized {
                            return Ok(i as i32);
                        }
                        res[i as usize] = 0;
                    }
                }
            }
            Ok(size)
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn constant_space() -> Arc<AddressSpace> {
        AddressSpace::new("const", 64, 1, AddressSpaceType::Constant, 1)
    }

    #[test]
    fn set_value_then_get_value_round_trips_little_endian() {
        let mut state = TestAbstractMemoryState::new(false);
        let space = ram_space();
        state.set_value(&space, 0x10, 4, 0x01020304).unwrap();
        assert_eq!(state.get_value(&space, 0x10, 4).unwrap(), 0x01020304);
    }

    #[test]
    fn set_value_encodes_little_endian_bytes() {
        let mut state = TestAbstractMemoryState::new(false);
        let space = ram_space();
        state.set_value(&space, 0, 4, 0x01020304).unwrap();
        let mut raw = [0u8; 4];
        state.get_chunk(&mut raw, &space, 0, 4, false).unwrap();
        assert_eq!(raw, [0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn set_value_encodes_big_endian_bytes() {
        let mut state = TestAbstractMemoryState::new(true);
        let space = ram_space();
        state.set_value(&space, 0, 4, 0x01020304).unwrap();
        let mut raw = [0u8; 4];
        state.get_chunk(&mut raw, &space, 0, 4, false).unwrap();
        assert_eq!(raw, [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn get_value_constant_space_returns_offset_directly() {
        let mut state = TestAbstractMemoryState::new(false);
        let space = constant_space();
        // No bytes are ever written for the constant space; getValue must not touch getChunk.
        assert_eq!(state.get_value(&space, 42, 4).unwrap(), 42);
    }

    #[test]
    fn set_value_register_then_get_value_register_round_trips() {
        let mut state = TestAbstractMemoryState::new(false);
        let space = ram_space();
        let reg = Register::new("r0", "general reg 0", Address::new(space, 0x20), 4, false, 0);
        state.set_value_register(&reg.borrow(), 0x11223344).unwrap();
        assert_eq!(state.get_value_register(&reg.borrow()).unwrap(), 0x11223344);
    }

    #[test]
    fn set_value_by_name_then_get_value_by_name_round_trips() {
        let mut state = TestAbstractMemoryState::new(false);
        let space = ram_space();
        let reg = Register::new("pc", "program counter", Address::new(space, 0x30), 4, false, 0);
        state.add_register(reg.clone());
        state.set_value_by_name("pc", 0xdeadbeefu32 as i64).unwrap();
        assert_eq!(state.get_value_by_name("pc").unwrap(), 0xdeadbeefu32 as i64);
    }

    #[test]
    fn value_by_name_for_unknown_register_is_an_error_not_a_panic() {
        // Java: `language.getRegister(nm)` returns null, then `setValue(null, cval)` immediately
        // NPEs dereferencing it. This port converts that into an error instead (see module docs).
        let mut state = TestAbstractMemoryState::new(false);
        assert!(state.set_value_by_name("nope", 1).is_err());
        assert!(state.get_value_by_name("nope").is_err());
        assert!(state.set_big_value_by_name("nope", 1).is_err());
        assert!(state.get_big_integer_by_name("nope").is_err());
    }

    #[test]
    fn set_value_varnode_then_get_value_varnode_round_trips() {
        let mut state = TestAbstractMemoryState::new(false);
        let space = ram_space();
        let vn = Varnode::new(Address::new(space, 0x40), 2);
        state.set_value_varnode(&vn, 0x1234).unwrap();
        assert_eq!(state.get_value_varnode(&vn).unwrap(), 0x1234);
    }

    #[test]
    fn set_big_value_then_get_big_integer_round_trips() {
        let mut state = TestAbstractMemoryState::new(false);
        let space = ram_space();
        state.set_big_value(&space, 0x50, 8, 0x1122334455667788).unwrap();
        assert_eq!(state.get_big_integer(&space, 0x50, 8, false).unwrap(), 0x1122334455667788);
    }

    #[test]
    fn set_big_value_varnode_then_get_big_integer_varnode_round_trips() {
        let mut state = TestAbstractMemoryState::new(true);
        let space = ram_space();
        let vn = Varnode::new(Address::new(space, 0x60), 4);
        state.set_big_value_varnode(&vn, 0x0a0b0c0d).unwrap();
        assert_eq!(state.get_big_integer_varnode(&vn, false).unwrap(), 0x0a0b0c0d);
    }

    #[test]
    fn set_big_value_register_then_get_big_integer_register_round_trips() {
        let mut state = TestAbstractMemoryState::new(false);
        let space = ram_space();
        let reg = Register::new("r1", "general reg 1", Address::new(space, 0x70), 4, false, 0);
        state.set_big_value_register(&reg.borrow(), 99).unwrap();
        assert_eq!(state.get_big_integer_register(&reg.borrow()).unwrap(), 99);
    }

    #[test]
    fn get_big_integer_constant_space_nonnegative_offset_returns_offset() {
        let mut state = TestAbstractMemoryState::new(false);
        let space = constant_space();
        assert_eq!(state.get_big_integer(&space, 7, 8, false).unwrap(), 7);
        // `signed` is irrelevant once `off >= 0`.
        assert_eq!(state.get_big_integer(&space, 7, 8, true).unwrap(), 7);
    }

    #[test]
    fn get_big_integer_constant_space_negative_offset_signed_returns_raw_value() {
        let mut state = TestAbstractMemoryState::new(false);
        let space = constant_space();
        // signed=true skips the reinterpretation branch entirely, so a negative i64 offset comes
        // back as the same negative i128.
        assert_eq!(state.get_big_integer(&space, -1, 8, true).unwrap(), -1);
    }

    #[test]
    fn get_big_integer_constant_space_negative_offset_unsigned_reinterprets_as_magnitude() {
        let mut state = TestAbstractMemoryState::new(false);
        let space = constant_space();
        // Java: `new BigInteger(1, Utils.longToBytes(-1, 8, true))` reinterprets the all-ones
        // 64-bit pattern of -1 as the unsigned magnitude u64::MAX.
        let got = state.get_big_integer(&space, -1, 8, false).unwrap();
        assert_eq!(got, u64::MAX as i128);
    }

    #[test]
    fn get_value_unregistered_bytes_default_to_zero() {
        // set_chunk/get_chunk here treat "never written" as zero-initialized (matching a fresh
        // MemoryBank page), so getValue over untouched memory reads back as 0.
        let mut state = TestAbstractMemoryState::new(false);
        let space = ram_space();
        assert_eq!(state.get_value(&space, 0x1000, 4).unwrap(), 0);
    }
}
