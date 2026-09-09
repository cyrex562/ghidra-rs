//! Port of `ghidra.program.database.register.InMemoryRangeMapAdapter`.

use crate::program::database::register::address_range_object_map::AddressRangeObjectMap;
use crate::program::model::address::{Address, AddressRange, AddressRangeIterator};
use crate::program::model::lang::register::RegisterRef;
use crate::program::util::{LanguageTranslator, RangeMapAdapter};
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// A purely in-memory [`RangeMapAdapter`], backed by an [`AddressRangeObjectMap<Vec<u8>>`].
///
/// Port of `ghidra.program.database.register.InMemoryRangeMapAdapter`.
pub struct InMemoryRangeMapAdapter {
    range_map: AddressRangeObjectMap<Vec<u8>>,
}

impl InMemoryRangeMapAdapter {
    /// Constructs a new, empty adapter.
    pub fn new() -> Self {
        Self { range_map: AddressRangeObjectMap::new() }
    }
}

impl Default for InMemoryRangeMapAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl RangeMapAdapter for InMemoryRangeMapAdapter {
    fn get_value(&self, address: &Address) -> Option<Vec<u8>> {
        self.range_map.get_object(address)
    }

    fn move_address_range(
        &mut self,
        from_addr: &Address,
        to_addr: &Address,
        length: u64,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        self.range_map.move_address_range(from_addr, to_addr, length, monitor)
    }

    fn set(&mut self, start: &Address, end: &Address, bytes: &[u8]) {
        self.range_map.set_object(start.clone(), end.clone(), bytes.to_vec());
    }

    fn get_address_range_iterator_in_range(
        &self,
        start: &Address,
        end: &Address,
    ) -> Box<dyn AddressRangeIterator> {
        self.range_map.get_address_range_iterator_in_range(start, end)
    }

    fn get_address_range_iterator(&self) -> Box<dyn AddressRangeIterator> {
        self.range_map.get_address_range_iterator()
    }

    fn clear_range(&mut self, start: &Address, end: &Address) {
        self.range_map.clear_range(start, end);
    }

    fn clear_all(&mut self) {
        self.range_map = AddressRangeObjectMap::new();
    }

    fn is_empty(&self) -> bool {
        self.range_map.is_empty()
    }

    /// Update stored values to reflect a new base register.
    ///
    /// Ports the "register not translated" (clear everything) and "no-op" (same base register,
    /// no value translation required) branches of
    /// `InMemoryRangeMapAdapter.setLanguage` faithfully.
    ///
    /// # TODO(port)
    /// The remaining branch -- re-encoding every stored range's raw bytes by round-tripping them
    /// through a `RegisterValue` (`new RegisterValue(mapReg, oldBytes)`, then
    /// `translator.getNewRegisterValue(...)`, then `RegisterValue.toBytes()`) -- is not
    /// implemented. This crate has no concrete `RegisterValue`: only the object-safe seam trait
    /// `crate::program::seam_stubs::RegisterValue` exists, and it exposes neither a
    /// bytes-constructor nor a `to_bytes()`/serialization method, so there is no way to build the
    /// `RegisterValue` this translation needs or get bytes back out of the translated result.
    /// Rather than guess at a serialization format, this leaves previously stored values
    /// untouched (and un-translated) in that case; callers that hit this branch on a real
    /// language upgrade would see stale register-context bytes.
    fn set_language(
        &mut self,
        translator: &dyn LanguageTranslator,
        map_reg: &RegisterRef,
        _monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        let Some(new_reg) = translator.get_new_register(map_reg) else {
            // register not translated - clear map
            self.clear_all();
            return Ok(());
        };

        if new_reg.borrow().is_base_register() && !translator.is_value_translation_required(map_reg) {
            return Ok(());
        }

        // TODO(port): see doc comment above -- per-range byte translation needs a concrete
        // RegisterValue this crate doesn't have yet. Leaving `range_map` as-is.
        Ok(())
    }

    fn get_value_range_containing(&self, addr: &Address) -> AddressRange {
        self.range_map.get_address_range_containing(addr)
    }

    fn check_writable_state(&self) {
        // Always writable: there is no underlying transaction to validate.
    }

    fn invalidate(&mut self) {
        self.range_map.clear_cache();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::register::Register;
    use crate::program::model::lang::compiler_spec::CompilerSpec;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::seam_stubs::RegisterValue;
    use crate::util::task::DummyMonitor;
    use std::sync::Arc;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("Test", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        space.address(offset)
    }

    fn test_register(space: &Arc<AddressSpace>, name: &str) -> RegisterRef {
        Register::new(name.to_string(), String::new(), addr(space, 0), 4, false, 0)
    }

    /// Minimal `LanguageTranslator` test double. Only the methods `InMemoryRangeMapAdapter`
    /// actually calls (`get_new_register`, `is_value_translation_required`) have interesting
    /// behavior; everything else panics if reached, since a correct `set_language` call should
    /// never need them.
    struct StubTranslator {
        new_register: Option<RegisterRef>,
        value_translation_required: bool,
    }

    impl LanguageTranslator for StubTranslator {
        fn is_valid(&self) -> bool {
            true
        }
        fn get_old_language(&self) -> Arc<dyn Language> {
            unimplemented!("not exercised by these tests")
        }
        fn get_new_language(&self) -> Arc<dyn Language> {
            unimplemented!("not exercised by these tests")
        }
        fn get_old_language_id(&self) -> LanguageID {
            unimplemented!("not exercised by these tests")
        }
        fn get_new_language_id(&self) -> LanguageID {
            unimplemented!("not exercised by these tests")
        }
        fn get_old_version(&self) -> i32 {
            0
        }
        fn get_new_version(&self) -> i32 {
            0
        }
        fn get_new_address_space(&self, _old_space_name: &str) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_old_register(&self, _old_addr: &Address, _size: i32) -> Option<RegisterRef> {
            None
        }
        fn get_old_register_containing(&self, _old_addr: &Address) -> Option<RegisterRef> {
            None
        }
        fn get_old_context_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_new_register(&self, _old_reg: &RegisterRef) -> Option<RegisterRef> {
            self.new_register.clone()
        }
        fn get_new_context_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_new_register_value(&self, _old_value: &dyn RegisterValue) -> Option<Box<dyn RegisterValue>> {
            None
        }
        fn is_value_translation_required(&self, _old_reg: &RegisterRef) -> bool {
            self.value_translation_required
        }
        fn get_new_compiler_spec_id(&self, old_compiler_spec_id: &CompilerSpecID) -> CompilerSpecID {
            old_compiler_spec_id.clone()
        }
        fn get_old_compiler_spec(
            &self,
            _old_compiler_spec_id: &CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpec>, CompilerSpecNotFoundException> {
            unimplemented!("not exercised by these tests")
        }
        fn fixup_instructions(
            &self,
            _program: &mut dyn crate::program::model::listing::Program,
            _old_language: &dyn Language,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), Box<dyn std::error::Error>> {
            unimplemented!("not exercised by these tests")
        }
    }

    #[test]
    fn empty_adapter_reports_empty_and_no_value() {
        let space = space();
        let adapter = InMemoryRangeMapAdapter::new();
        assert!(adapter.is_empty());
        assert_eq!(adapter.get_value(&addr(&space, 0x10)), None);
    }

    #[test]
    fn set_get_round_trip_through_trait() {
        let space = space();
        let mut adapter: Box<dyn RangeMapAdapter> = Box::new(InMemoryRangeMapAdapter::new());

        adapter.set(&addr(&space, 0x1000), &addr(&space, 0x100f), &[1, 2, 3, 4]);
        assert!(!adapter.is_empty());
        assert_eq!(adapter.get_value(&addr(&space, 0x1005)), Some(vec![1, 2, 3, 4]));
        assert_eq!(adapter.get_value(&addr(&space, 0x1010)), None);
    }

    #[test]
    fn clear_range_removes_association() {
        let space = space();
        let mut adapter: Box<dyn RangeMapAdapter> = Box::new(InMemoryRangeMapAdapter::new());
        adapter.set(&addr(&space, 0x1000), &addr(&space, 0x1010), &[0xAB]);
        adapter.clear_range(&addr(&space, 0x1000), &addr(&space, 0x1010));
        assert!(adapter.is_empty());
        assert_eq!(adapter.get_value(&addr(&space, 0x1005)), None);
    }

    #[test]
    fn clear_all_empties_the_map() {
        let space = space();
        let mut adapter: Box<dyn RangeMapAdapter> = Box::new(InMemoryRangeMapAdapter::new());
        adapter.set(&addr(&space, 0x1000), &addr(&space, 0x1010), &[0xAB]);
        adapter.clear_all();
        assert!(adapter.is_empty());
    }

    #[test]
    fn move_address_range_relocates_bytes() {
        let space = space();
        let mut adapter: Box<dyn RangeMapAdapter> = Box::new(InMemoryRangeMapAdapter::new());
        adapter.set(&addr(&space, 0x1000), &addr(&space, 0x100f), &[9, 9]);
        let monitor = DummyMonitor;
        adapter
            .move_address_range(&addr(&space, 0x1000), &addr(&space, 0x2000), 0x10, &monitor)
            .expect("move should succeed");
        assert_eq!(adapter.get_value(&addr(&space, 0x1000)), None);
        assert_eq!(adapter.get_value(&addr(&space, 0x2000)), Some(vec![9, 9]));
    }

    #[test]
    fn get_value_range_containing_returns_stored_range() {
        let space = space();
        let mut adapter: Box<dyn RangeMapAdapter> = Box::new(InMemoryRangeMapAdapter::new());
        adapter.set(&addr(&space, 0x1000), &addr(&space, 0x2000), &[1]);
        let range = adapter.get_value_range_containing(&addr(&space, 0x1500));
        assert_eq!(range.min_address(), &addr(&space, 0x1000));
        assert_eq!(range.max_address(), &addr(&space, 0x2000));
    }

    #[test]
    fn check_writable_state_never_panics() {
        let adapter: Box<dyn RangeMapAdapter> = Box::new(InMemoryRangeMapAdapter::new());
        adapter.check_writable_state();
    }

    #[test]
    fn invalidate_clears_cache_without_losing_data() {
        let space = space();
        let mut adapter: Box<dyn RangeMapAdapter> = Box::new(InMemoryRangeMapAdapter::new());
        adapter.set(&addr(&space, 0x1000), &addr(&space, 0x1010), &[0x42]);
        adapter.invalidate();
        assert_eq!(adapter.get_value(&addr(&space, 0x1005)), Some(vec![0x42]));
    }

    #[test]
    fn set_language_with_untranslated_register_clears_map() {
        let space = space();
        let mut adapter = InMemoryRangeMapAdapter::new();
        adapter.set(&addr(&space, 0x1000), &addr(&space, 0x1010), &[1]);

        let translator = StubTranslator { new_register: None, value_translation_required: false };
        let monitor = DummyMonitor;
        adapter
            .set_language(&translator, &test_register(&space, "r0"), &monitor)
            .expect("not cancelled");

        assert!(adapter.is_empty());
    }

    #[test]
    fn set_language_with_same_base_register_and_no_translation_needed_is_a_no_op() {
        let space = space();
        let mut adapter = InMemoryRangeMapAdapter::new();
        adapter.set(&addr(&space, 0x1000), &addr(&space, 0x1010), &[7]);

        let new_reg = test_register(&space, "r0");
        let translator =
            StubTranslator { new_register: Some(new_reg.clone()), value_translation_required: false };
        let monitor = DummyMonitor;
        adapter
            .set_language(&translator, &new_reg, &monitor)
            .expect("not cancelled");

        assert_eq!(adapter.get_value(&addr(&space, 0x1005)), Some(vec![7]));
    }
}
