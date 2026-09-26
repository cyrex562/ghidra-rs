//! A breakpoint object. Port of `ghidra.pcode.emulate.BreakCallBack`.
//!
//! # Shape
//!
//! Java's class is concrete, and every breakpoint is an (often anonymous) subclass overriding
//! `pcodeCallback` and/or `addressCallback` -- e.g. `EmulatorHelper`'s
//! `new BreakCallBack() { addressCallback(addr) { emulator.setHalt(true); return true; } }`. Here
//! the struct carries those overrides as closures, set with
//! [`with_pcode_callback`](BreakCallBack::with_pcode_callback) and
//! [`with_address_callback`](BreakCallBack::with_address_callback); an unset callback is the base
//! class's, which returns `false`.
//!
//! Java's overrides reach the emulator through a captured reference (or the `emulate` field). A
//! Rust breakpoint is stored in a table the emulator owns, so it cannot hold the emulator; instead
//! the emulator hands every callback a [`BreakContext`] at call time.

use crate::pcode::pcoderaw::PcodeOpRaw;
use crate::pcode::seam_stubs::Emulate;
use crate::program::model::address::Address;

/// What a breakpoint may do to the emulator in which it fires, given to it at call time.
pub trait BreakContext {
    /// Halt (or un-halt) the emulator: Java's `Emulator.setHalt(boolean)`, which a breakpoint
    /// calls to stop execution at the break.
    fn set_halt(&mut self, halt: bool);

    /// Whether the emulator is halted: Java's `Emulator.getHalt()`.
    fn get_halt(&self) -> bool;
}

/// The override of `pcodeCallback(PcodeOpRaw)`.
pub type PcodeBreakFn = dyn Fn(&PcodeOpRaw, &mut dyn BreakContext) -> bool + Send + Sync;

/// The override of `addressCallback(Address)`.
pub type AddressBreakFn = dyn Fn(&Address, &mut dyn BreakContext) -> bool + Send + Sync;

/// A breakpoint object.
///
/// This is a base class for breakpoint objects in an emulator. The breakpoints are implemented
/// as callback methods, which can be overridden for the particular behavior needed by the emulator.
/// Each breakpoint should override either:
/// - `pcode_callback()`
/// - `address_callback()`
///
/// depending on whether the breakpoint is tailored for a particular pcode op or for
/// a machine address. See the module docs for how overriding is expressed.
///
/// # Deprecation
///
/// This type is deprecated since Ghidra 12.1 and is scheduled for removal.
#[deprecated(since = "12.1", note = "scheduled for removal in a future release")]
pub struct BreakCallBack {
    /// The emulator currently associated with this breakpoint
    emulate: Option<Box<dyn Emulate>>,
    pcode: Option<Box<PcodeBreakFn>>,
    address: Option<Box<AddressBreakFn>>,
}

#[allow(deprecated)]
impl BreakCallBack {
    /// Create a new breakpoint object whose callbacks are the base class's (both return `false`).
    pub fn new() -> Self {
        Self { emulate: None, pcode: None, address: None }
    }

    /// This breakpoint, overriding `pcodeCallback`.
    pub fn with_pcode_callback(
        mut self,
        callback: impl Fn(&PcodeOpRaw, &mut dyn BreakContext) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.pcode = Some(Box::new(callback));
        self
    }

    /// This breakpoint, overriding `addressCallback`.
    pub fn with_address_callback(
        mut self,
        callback: impl Fn(&Address, &mut dyn BreakContext) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.address = Some(Box::new(callback));
        self
    }

    /// This routine is invoked during emulation, if this breakpoint has somehow been associated with
    /// this kind of pcode op. The callback can perform any operation on the emulator context it wants.
    /// It then returns `true` if these actions are intended to replace the action of the pcode op itself.
    /// Or it returns `false` if the pcode op should still have its normal effect on the emulator context.
    ///
    /// # Arguments
    /// * `op` - the particular pcode operation where the break occurs.
    /// * `context` - the emulator in which the break occurs.
    ///
    /// # Returns
    /// `true` if the normal pcode op action should not occur
    pub fn pcode_callback(&self, op: &PcodeOpRaw, context: &mut dyn BreakContext) -> bool {
        self.pcode.as_ref().is_some_and(|f| f(op, context))
    }

    /// This routine is invoked during emulation, if this breakpoint has somehow been associated with
    /// this address. The callback can perform any operation on the emulator context it wants. It then
    /// returns `true` if these actions are intended to replace the action of the entire machine
    /// instruction at this address. Or it returns `false` if the machine instruction should still be
    /// executed normally.
    ///
    /// # Arguments
    /// * `addr` - the address where the break has occurred
    /// * `context` - the emulator in which the break occurs.
    ///
    /// # Returns
    /// `true` if the machine instruction should not be executed
    pub fn address_callback(&self, addr: &Address, context: &mut dyn BreakContext) -> bool {
        self.address.as_ref().is_some_and(|f| f(addr, context))
    }

    /// Associate a particular emulator with this breakpoint.
    ///
    /// # Arguments
    /// * `emu` - the emulator to associate with this breakpoint
    pub fn set_emulate(&mut self, emu: Box<dyn Emulate>) {
        self.emulate = Some(emu);
    }

    /// Get a reference to the associated emulator, if any.
    pub fn emulate(&self) -> Option<&dyn Emulate> {
        self.emulate.as_ref().map(|b| b.as_ref())
    }
}

#[allow(deprecated)]
impl Default for BreakCallBack {
    fn default() -> Self {
        Self::new()
    }
}

/// A [`BreakContext`] over a plain halt flag, for tests and for callers with no emulator at hand.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HaltFlag(pub bool);

impl BreakContext for HaltFlag {
    fn set_halt(&mut self, halt: bool) {
        self.0 = halt;
    }

    fn get_halt(&self) -> bool {
        self.0
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;

    struct MockEmulate;
    impl Emulate for MockEmulate {
        fn dispose(&self) {}

        fn get_language(&self) -> Box<dyn crate::program::model::lang::Language> {
            unimplemented!("test should not call this")
        }
    }

    fn sample_op() -> PcodeOpRaw {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};
        use crate::program::model::pcode::{OpCode, PcodeOp};
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        PcodeOpRaw::from(PcodeOp::with_address_no_inputs(Address::new(space, 0x1000), 0, OpCode::CallOther))
    }

    fn sample_address() -> Address {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};
        Address::new(AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0), 0x1000)
    }

    #[test]
    fn test_new_break_callback() {
        let callback = BreakCallBack::new();
        assert!(callback.emulate().is_none());
    }

    #[test]
    fn test_default_break_callback() {
        let callback = BreakCallBack::default();
        assert!(callback.emulate().is_none());
    }

    #[test]
    fn test_pcode_callback_returns_false() {
        let callback = BreakCallBack::new();
        let mut halt = HaltFlag::default();
        assert!(!callback.pcode_callback(&sample_op(), &mut halt));
        assert!(!halt.get_halt());
    }

    #[test]
    fn test_address_callback_returns_false() {
        let callback = BreakCallBack::new();
        let mut halt = HaltFlag::default();
        assert!(!callback.address_callback(&sample_address(), &mut halt));
        assert!(!halt.get_halt());
    }

    /// `EmulatorHelper`'s address breakpoint: halt the emulator and replace the instruction.
    #[test]
    fn an_address_override_halts_the_emulator() {
        let callback = BreakCallBack::new().with_address_callback(|_addr, emu| {
            emu.set_halt(true);
            true
        });
        let mut halt = HaltFlag::default();
        assert!(callback.address_callback(&sample_address(), &mut halt));
        assert!(halt.get_halt());
        // The other callback is still the base class's.
        assert!(!callback.pcode_callback(&sample_op(), &mut halt));
    }

    #[test]
    fn a_pcode_override_sees_the_op() {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let callback = BreakCallBack::new().with_pcode_callback(move |op, _emu| {
            seen.fetch_add(1, Ordering::SeqCst);
            op.get_address().offset() == 0x1000
        });
        assert!(callback.pcode_callback(&sample_op(), &mut HaltFlag::default()));
        assert_eq!(1, calls.load(Ordering::SeqCst));
        assert!(!callback.address_callback(&sample_address(), &mut HaltFlag::default()));
    }

    #[test]
    fn test_set_emulate() {
        let mut callback = BreakCallBack::new();
        assert!(callback.emulate().is_none());

        let emu = Box::new(MockEmulate);
        callback.set_emulate(emu);
        assert!(callback.emulate().is_some());
    }

    #[test]
    fn test_set_emulate_overwrites_previous() {
        let mut callback = BreakCallBack::new();

        let emu1 = Box::new(MockEmulate);
        callback.set_emulate(emu1);
        assert!(callback.emulate().is_some());

        let emu2 = Box::new(MockEmulate);
        callback.set_emulate(emu2);
        assert!(callback.emulate().is_some());
    }
}
