use crate::pcode::seam_stubs::Emulate;
use crate::pcode::seam_stubs::PcodeOpRaw;
use crate::program::model::address::Address;

/// A breakpoint object
///
/// This is a base class for breakpoint objects in an emulator. The breakpoints are implemented
/// as callback methods, which can be overridden for the particular behavior needed by the emulator.
/// Each derived class should override either:
/// - `pcode_callback()`
/// - `address_callback()`
///
/// depending on whether the breakpoint is tailored for a particular pcode op or for
/// a machine address.
///
/// # Deprecation
///
/// This type is deprecated since Ghidra 12.1 and is scheduled for removal.
#[deprecated(since = "12.1", note = "scheduled for removal in a future release")]
pub struct BreakCallBack {
    /// The emulator currently associated with this breakpoint
    emulate: Option<Box<dyn Emulate>>,
}

impl BreakCallBack {
    /// Create a new breakpoint object.
    pub fn new() -> Self {
        Self { emulate: None }
    }

    /// This routine is invoked during emulation, if this breakpoint has somehow been associated with
    /// this kind of pcode op. The callback can perform any operation on the emulator context it wants.
    /// It then returns `true` if these actions are intended to replace the action of the pcode op itself.
    /// Or it returns `false` if the pcode op should still have its normal effect on the emulator context.
    ///
    /// # Arguments
    /// * `op` - the particular pcode operation where the break occurs.
    ///
    /// # Returns
    /// `true` if the normal pcode op action should not occur
    pub fn pcode_callback(&self, _op: &dyn PcodeOpRaw) -> bool {
        false
    }

    /// This routine is invoked during emulation, if this breakpoint has somehow been associated with
    /// this address. The callback can perform any operation on the emulator context it wants. It then
    /// returns `true` if these actions are intended to replace the action of the entire machine
    /// instruction at this address. Or it returns `false` if the machine instruction should still be
    /// executed normally.
    ///
    /// # Arguments
    /// * `addr` - the address where the break has occurred
    ///
    /// # Returns
    /// `true` if the machine instruction should not be executed
    pub fn address_callback(&self, _addr: &Address) -> bool {
        false
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

impl Default for BreakCallBack {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockEmulate;
    impl Emulate for MockEmulate {
        fn dispose(&self) {}

        fn get_language(&self) -> Box<dyn crate::program::model::lang::Language> {
            unimplemented!("test should not call this")
        }
    }

    struct MockPcodeOpRaw;
    impl PcodeOpRaw for MockPcodeOpRaw {}

    #[test]
    #[allow(deprecated)]
    fn test_new_break_callback() {
        let callback = BreakCallBack::new();
        assert!(callback.emulate().is_none());
    }

    #[test]
    #[allow(deprecated)]
    fn test_default_break_callback() {
        let callback = BreakCallBack::default();
        assert!(callback.emulate().is_none());
    }

    #[test]
    #[allow(deprecated)]
    fn test_pcode_callback_returns_false() {
        let callback = BreakCallBack::new();
        let op = MockPcodeOpRaw;
        assert!(!callback.pcode_callback(&op));
    }

    #[test]
    #[allow(deprecated)]
    fn test_address_callback_returns_false() {
        use crate::program::model::address::AddressSpace;

        let callback = BreakCallBack::new();
        let space = AddressSpace::new("ram", 32, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let addr = Address::new(space, 0x1000);
        assert!(!callback.address_callback(&addr));
    }

    #[test]
    #[allow(deprecated)]
    fn test_set_emulate() {
        let mut callback = BreakCallBack::new();
        assert!(callback.emulate().is_none());

        let emu = Box::new(MockEmulate);
        callback.set_emulate(emu);
        assert!(callback.emulate().is_some());
    }

    #[test]
    #[allow(deprecated)]
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
