use std::collections::BTreeMap;
use std::sync::Arc;

use crate::pcode::emulate::break_callback::BreakCallBack;
use crate::pcode::emulate::break_table::BreakTable;
use crate::pcode::error::lowlevel_error::LowlevelError;
use crate::pcode::seam_stubs::{Emulate, PcodeOpRaw};
use crate::program::model::address::Address;
use crate::program::model::lang::sleigh::symbol::SleighSymbol;
use crate::program::model::lang::sleigh::SleighLanguage;

/// A basic instantiation of a breakpoint table.
///
/// This object allows breakpoints to be registered in the table via either
/// [`register_pcode_callback`](Self::register_pcode_callback) or
/// [`register_address_callback`](Self::register_address_callback).
///
/// Breakpoints are stored in ordered maps keyed by user-defined pcode-op index or by address, and
/// the core [`BreakTable`] methods are implemented to search in these containers.
///
/// Corresponds to `ghidra.pcode.emulate.BreakTableCallBack`.
///
/// # Deprecation
///
/// This type is deprecated since Ghidra 12.1 and is scheduled for removal.
#[deprecated(since = "12.1", note = "scheduled for removal in a future release")]
pub struct BreakTableCallBack {
    language: Arc<SleighLanguage>,
    address_callback: BTreeMap<Address, BreakCallBack>,
    pcode_callback: BTreeMap<i64, BreakCallBack>,
    default_pcode_callback: Option<BreakCallBack>,
}

#[allow(deprecated)]
impl BreakTableCallBack {
    /// The pseudo-name used to register/unregister the *default* pcode-op breakpoint, i.e. one
    /// invoked for every user-defined pcode op that has no breakpoint of its own.
    ///
    /// Port of `BreakTableCallBack.DEFAULT_NAME`.
    pub const DEFAULT_NAME: &'static str = "*";

    /// The break table needs a translator object so user-defined pcode ops can be registered
    /// against by name.
    ///
    /// Port of `new BreakTableCallBack(SleighLanguage)`.
    pub fn new(language: Arc<SleighLanguage>) -> Self {
        Self {
            language,
            address_callback: BTreeMap::new(),
            pcode_callback: BTreeMap::new(),
            default_pcode_callback: None,
        }
    }

    /// Any time the emulator is about to execute a user-defined pcode op with the given name,
    /// the indicated breakpoint is invoked first.
    ///
    /// Port of `registerPcodeCallback(String, BreakCallBack)`.
    ///
    /// # Errors
    /// Returns a [`LowlevelError`] if `name` is not `DEFAULT_NAME` and is not the name of any
    /// user-defined pcode op of this language.
    pub fn register_pcode_callback(
        &mut self,
        name: &str,
        func: BreakCallBack,
    ) -> Result<(), LowlevelError> {
        if name == Self::DEFAULT_NAME {
            self.default_pcode_callback = Some(func);
            return Ok(());
        }
        let num_user_ops = user_defined_op_count(&self.language);
        for i in 0..num_user_ops {
            if user_defined_op_name(&self.language, i) == Some(name) {
                self.pcode_callback.insert(i as i64, func);
                return Ok(());
            }
        }
        let mut names = String::new();
        for i in 0..num_user_ops {
            if let Some(op_name) = user_defined_op_name(&self.language, i) {
                names.push_str(op_name);
            }
            if i < num_user_ops - 1 {
                names.push_str(", ");
            }
        }
        Err(LowlevelError::with_message(format!(
            "Bad userop name: {name}\nMust be one of:\n{names}"
        )))
    }

    /// Unregister the currently registered pcode-op callback handler for the specified name.
    ///
    /// Port of `unregisterPcodeCallback(String)`.
    ///
    /// # Errors
    /// Returns a [`LowlevelError`] if `name` is not `DEFAULT_NAME` and is not the name of any
    /// user-defined pcode op of this language.
    pub fn unregister_pcode_callback(&mut self, name: &str) -> Result<(), LowlevelError> {
        if name == Self::DEFAULT_NAME {
            self.default_pcode_callback = None;
            return Ok(());
        }
        let num_user_ops = user_defined_op_count(&self.language);
        for i in 0..num_user_ops {
            if user_defined_op_name(&self.language, i) == Some(name) {
                self.pcode_callback.remove(&(i as i64));
                return Ok(());
            }
        }
        Err(LowlevelError::with_message(format!("Bad userop name: {name}")))
    }

    /// Any time the emulator is about to execute (the pcode translation of) a particular machine
    /// instruction at this address, the indicated breakpoint is invoked first.
    ///
    /// Port of `registerAddressCallback(Address, BreakCallBack)`.
    pub fn register_address_callback(&mut self, addr: Address, func: BreakCallBack) {
        self.address_callback.insert(addr, func);
    }

    /// Port of `unregisterAddressCallback(Address)`.
    pub fn unregister_address_callback(&mut self, addr: &Address) {
        self.address_callback.remove(addr);
    }
}

#[allow(deprecated)]
impl BreakTable for BreakTableCallBack {
    /// This routine invokes the setEmulate method on each breakpoint currently in the table.
    ///
    /// Port of `setEmulate(Emulate)`.
    ///
    /// [`BreakTable::set_emulate`] only ever hands out a transient `&dyn Emulate` (its lifetime
    /// is not tied to `&mut self`), while [`BreakCallBack::set_emulate`] requires an owned
    /// `Box<dyn Emulate>` and `Emulate` is not `Clone`. So unlike Java -- where `emulate` is just
    /// a shared object reference -- there is no sound way here to retain `emu` for later
    /// registrations or to redistribute it to already-registered breakpoints without changing one
    /// of those two already-ported signatures.
    fn set_emulate(&mut self, _emu: &dyn Emulate) {}

    /// This routine examines the pcode-op based container for any breakpoints associated with the
    /// given op. If one is found, its `pcode_callback` method is invoked.
    ///
    /// Port of `doPcodeOpBreak(PcodeOpRaw)`.
    fn do_pcode_op_break(&self, curop: &dyn PcodeOpRaw) -> bool {
        let val = curop
            .get_input(0)
            .expect("pcode op has no input 0")
            .get_offset();
        match self.pcode_callback.get(&val) {
            Some(callback) => callback.pcode_callback(curop),
            None => self
                .default_pcode_callback
                .as_ref()
                .is_some_and(|cb| cb.pcode_callback(curop)),
        }
    }

    /// This routine examines the address based container for any breakpoints associated with the
    /// given address. If one is found, its `address_callback` method is invoked.
    ///
    /// Port of `doAddressBreak(Address)`.
    fn do_address_break(&self, addr: &Address) -> bool {
        self.address_callback
            .get(addr)
            .is_some_and(|cb| cb.address_callback(addr))
    }
}

/// Port of `SleighLanguage.getNumberOfUserDefinedOpNames()`, which Java delegates to
/// `SymbolTable.getNumberOfUserDefinedOpNames()`.
fn user_defined_op_count(language: &SleighLanguage) -> usize {
    language.get_symbol_table().user_ops.len()
}

/// Port of `SleighLanguage.getUserDefinedOpName(int)`, which Java delegates to
/// `SymbolTable.getUserDefinedOpName(int)`.
fn user_defined_op_name(language: &SleighLanguage, index: usize) -> Option<&str> {
    let symbol_table = language.get_symbol_table();
    let id = *symbol_table.user_ops.get(index)?;
    match symbol_table.find_symbol(id)? {
        SleighSymbol::Userop(userop) => Some(userop.header.name.as_str()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType, DefaultAddressFactory};
    use crate::program::model::pcode::{PackedDecode, Varnode};

    /// Builds a minimal, valid [`SleighLanguage`] (one `ram` space, no symbols) purely so a
    /// [`BreakTableCallBack`] can be constructed; mirrors
    /// `sleigh::tests::test_sleigh_decode_basic`'s hand-built packed encoding.
    fn minimal_sleigh_language() -> SleighLanguage {
        let factory = Arc::new(DefaultAddressFactory::new(vec![]));
        let mut data = vec![];

        data.extend_from_slice(&[0x60, 0xA1]); // <sleigh
        data.extend_from_slice(&[0xE0, 0xA2, 0x21, 4]); // version=4
        data.extend_from_slice(&[0xE0, 0xA3, 0x10]); // bigendian=false

        data.extend_from_slice(&[0x60, 0xA2]); // <spaces defaultspace="ram">
        data.extend_from_slice(&[0xE0, 0xA9, 0x71, 3, b'r', b'a', b'm']);

        data.extend_from_slice(&[0x60, 0xAD, 0xA0, 0xAD]); // <space_other/>

        data.extend_from_slice(&[0x60, 0xA5]); // <space name="ram" size="4" index="1" delay="1"/>
        data.extend_from_slice(&[0xCC, 0x71, 3, b'r', b'a', b'm']);
        data.extend_from_slice(&[0xCF, 0x21, 4]);
        data.extend_from_slice(&[0xC9, 0x21, 1]);
        data.extend_from_slice(&[0xE0, 0xAA, 0x21, 1]);
        data.extend_from_slice(&[0xA0, 0xA5]);

        data.extend_from_slice(&[0xA0, 0xA2]); // </spaces>

        data.extend_from_slice(&[0x60, 0xA6]); // <symbol_table scopesize="1" symbolsize="0">
        data.extend_from_slice(&[0xE0, 0xAD, 0x21, 1]);
        data.extend_from_slice(&[0xE0, 0xAE, 0x21, 0]);
        data.extend_from_slice(&[0x56, 0xC3, 0x41, 0, 0xD6, 0x41, 0, 0x96]); // <scope id=0 parent=0/>
        data.extend_from_slice(&[0xA0, 0xA6]); // </symbol_table>

        data.extend_from_slice(&[0xA0, 0xA1]); // </sleigh>

        let decoder = PackedDecode::new(factory, data);
        SleighLanguage::decode(&decoder, "test".to_string()).unwrap()
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    struct MockPcodeOpRaw {
        inputs: Vec<Varnode>,
    }

    impl PcodeOpRaw for MockPcodeOpRaw {
        fn get_input(&self, index: usize) -> Option<Varnode> {
            self.inputs.get(index).cloned()
        }
    }

    #[test]
    #[allow(deprecated)]
    fn register_pcode_callback_default_name_sets_default_callback() {
        let mut table = BreakTableCallBack::new(Arc::new(minimal_sleigh_language()));
        assert!(table.default_pcode_callback.is_none());

        table
            .register_pcode_callback(BreakTableCallBack::DEFAULT_NAME, BreakCallBack::new())
            .unwrap();

        assert!(table.default_pcode_callback.is_some());
    }

    #[test]
    #[allow(deprecated)]
    fn unregister_pcode_callback_default_name_clears_default_callback() {
        let mut table = BreakTableCallBack::new(Arc::new(minimal_sleigh_language()));
        table
            .register_pcode_callback(BreakTableCallBack::DEFAULT_NAME, BreakCallBack::new())
            .unwrap();

        table
            .unregister_pcode_callback(BreakTableCallBack::DEFAULT_NAME)
            .unwrap();

        assert!(table.default_pcode_callback.is_none());
    }

    #[test]
    #[allow(deprecated)]
    fn register_pcode_callback_unknown_name_reports_bad_userop_name() {
        // Java: `throw new LowlevelError("Bad userop name: " + name + ...)` when the language
        // has no matching user-defined op.
        let mut table = BreakTableCallBack::new(Arc::new(minimal_sleigh_language()));

        let err = table
            .register_pcode_callback("nonexistent", BreakCallBack::new())
            .unwrap_err();

        assert!(err.message().contains("Bad userop name: nonexistent"));
        assert!(table.pcode_callback.is_empty());
    }

    #[test]
    #[allow(deprecated)]
    fn unregister_pcode_callback_unknown_name_reports_bad_userop_name() {
        let mut table = BreakTableCallBack::new(Arc::new(minimal_sleigh_language()));

        let err = table.unregister_pcode_callback("nonexistent").unwrap_err();

        assert_eq!(err.message(), "Bad userop name: nonexistent");
    }

    #[test]
    #[allow(deprecated)]
    fn register_address_callback_then_unregister_removes_entry() {
        let mut table = BreakTableCallBack::new(Arc::new(minimal_sleigh_language()));
        let addr = Address::new(ram_space(), 0x1000);

        table.register_address_callback(addr.clone(), BreakCallBack::new());
        assert_eq!(table.address_callback.len(), 1);

        table.unregister_address_callback(&addr);
        assert!(table.address_callback.is_empty());
    }

    #[test]
    #[allow(deprecated)]
    fn do_address_break_with_no_registered_breakpoint_returns_false() {
        let table = BreakTableCallBack::new(Arc::new(minimal_sleigh_language()));
        let addr = Address::new(ram_space(), 0x1000);

        assert!(!table.do_address_break(&addr));
    }

    #[test]
    #[allow(deprecated)]
    fn do_address_break_dispatches_to_registered_breakpoint_at_address() {
        let mut table = BreakTableCallBack::new(Arc::new(minimal_sleigh_language()));
        let addr = Address::new(ram_space(), 0x1000);
        table.register_address_callback(addr.clone(), BreakCallBack::new());

        // BreakCallBack's base `address_callback` always returns false (it exists to be
        // overridden), so this exercises the found-in-map path rather than the fallback.
        assert!(!table.do_address_break(&addr));
    }

    #[test]
    #[allow(deprecated)]
    fn do_pcode_op_break_uses_input0_offset_to_find_registered_callback() {
        let mut table = BreakTableCallBack::new(Arc::new(minimal_sleigh_language()));
        // Bypass name-based registration (this language declares no user-defined ops) to
        // exercise doPcodeOpBreak's lookup-by-offset behavior directly.
        table.pcode_callback.insert(5, BreakCallBack::new());

        let op = MockPcodeOpRaw {
            inputs: vec![Varnode::new(Address::new(ram_space(), 5), 8)],
        };
        assert!(!table.do_pcode_op_break(&op));
    }

    #[test]
    #[allow(deprecated)]
    fn do_pcode_op_break_falls_back_to_default_when_no_match() {
        let mut table = BreakTableCallBack::new(Arc::new(minimal_sleigh_language()));
        table.pcode_callback.insert(5, BreakCallBack::new());
        table
            .register_pcode_callback(BreakTableCallBack::DEFAULT_NAME, BreakCallBack::new())
            .unwrap();

        let op = MockPcodeOpRaw {
            inputs: vec![Varnode::new(Address::new(ram_space(), 999), 8)],
        };
        assert!(!table.do_pcode_op_break(&op));
    }

    #[test]
    #[allow(deprecated)]
    fn do_pcode_op_break_with_no_match_and_no_default_returns_false() {
        let table = BreakTableCallBack::new(Arc::new(minimal_sleigh_language()));

        let op = MockPcodeOpRaw {
            inputs: vec![Varnode::new(Address::new(ram_space(), 999), 8)],
        };
        assert!(!table.do_pcode_op_break(&op));
    }
}
