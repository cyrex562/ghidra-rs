//! Port of `ghidra.program.model.lang.ProgramProcessorContext`.
//!
//! A [`ProcessorContext`] view of a single, fixed address within a [`ProgramContext`]: every
//! read/write is forwarded to the wrapped `ProgramContext` at that one address (with `start ==
//! end == addr` for the range-based `ProgramContext` methods).

use crate::program::model::address::Address;
use crate::program::model::lang::processor_context::ProcessorContext;
use crate::program::model::lang::processor_context_view::ProcessorContextView;
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::listing::context_change_exception::ContextChangeException;
use crate::program::model::listing::program_context::ProgramContext;
use crate::program::seam_stubs::RegisterValue as RegisterValueTrait;

/// Implementation for the program processor context interface.
///
/// Port of `ghidra.program.model.lang.ProgramProcessorContext`.
pub struct ProgramProcessorContext {
    addr: Address,
    context: Box<dyn ProgramContext>,
}

impl ProgramProcessorContext {
    /// Constructs a new `ProgramProcessorContext` that will have the processor state be the
    /// state of the given `ProgramContext` at the given address.
    ///
    /// Port of `ProgramProcessorContext(ProgramContext, Address)`.
    ///
    /// # Arguments
    /// * `context` - the `ProgramContext` which contains the register state at every address.
    /// * `addr` - the address at which to get the register state.
    pub fn new(context: Box<dyn ProgramContext>, addr: Address) -> Self {
        Self { addr, context }
    }
}

impl ProcessorContextView for ProgramProcessorContext {
    fn get_base_context_register(&self) -> Option<RegisterRef> {
        Some(self.context.get_base_context_register())
    }

    fn get_registers(&self) -> Vec<RegisterRef> {
        self.context.get_registers()
    }

    fn get_register(&self, name: &str) -> Option<RegisterRef> {
        self.context.get_register(name)
    }

    fn get_value(&self, register: &Register, signed: bool) -> Option<i128> {
        self.context.get_value(register, &self.addr, signed)
    }

    fn get_register_value(&self, register: &Register) -> Option<Box<dyn RegisterValueTrait>> {
        self.context.get_register_value(register, &self.addr)
    }

    /// Port of `hasValue(Register)`. Note: Java's implementation always passes `signed = true`
    /// to the underlying `getValue` call, though this makes no observable difference here since
    /// nullness of `getValue`'s result never depends on the `signed` flag (both the signed and
    /// unsigned extraction paths are gated by the same `RegisterValue.hasValue()` check).
    fn has_value(&self, register: &Register) -> bool {
        self.context.get_value(register, &self.addr, true).is_some()
    }
}

impl ProcessorContext for ProgramProcessorContext {
    fn set_value(
        &mut self,
        register: &Register,
        value: i128,
    ) -> Result<(), ContextChangeException> {
        let addr = self.addr.clone();
        self.context.set_value(register, &addr, &addr, Some(value))
    }

    fn set_register_value(
        &mut self,
        value: Box<dyn RegisterValueTrait>,
    ) -> Result<(), ContextChangeException> {
        let addr = self.addr.clone();
        self.context.set_register_value(&addr, &addr, value)
    }

    fn clear_register(&mut self, register: &Register) -> Result<(), ContextChangeException> {
        let addr = self.addr.clone();
        self.context.remove(&addr, &addr, register)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::register::in_memory_range_map_adapter::InMemoryRangeMapAdapter;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::register_value::RegisterValue;
    use crate::program::util::abstract_stored_program_context::test_support::{
        test_language, test_language_with_context,
    };
    use crate::program::util::abstract_stored_program_context::AbstractStoredProgramContext;
    use crate::program::util::RangeMapAdapter;
    use std::sync::Arc;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        space.address(offset)
    }

    fn in_memory_program_context(language: Arc<dyn Language>) -> AbstractStoredProgramContext {
        AbstractStoredProgramContext::new(
            language,
            Box::new(|_reg: &RegisterRef| {
                Box::new(InMemoryRangeMapAdapter::new()) as Box<dyn RangeMapAdapter>
            }),
        )
    }

    #[test]
    fn get_value_reads_through_to_the_program_context_at_the_fixed_address() {
        let lang: Arc<dyn Language> = Arc::new(test_language());
        let mut backing = in_memory_program_context(lang.clone());
        let space = ram_space();
        let eax = lang.get_register_by_name("eax").unwrap();

        ProgramContext::set_register_value(
            &mut backing,
            &addr(&space, 0x1000),
            &addr(&space, 0x2000),
            Box::new(RegisterValue::with_value(eax.clone(), 0xABCD_1234)),
        )
        .unwrap();

        let ctx = ProgramProcessorContext::new(Box::new(backing), addr(&space, 0x1500));
        assert!(ctx.has_value(&eax.borrow()));
        assert_eq!(ctx.get_value(&eax.borrow(), false), Some(0xABCD_1234));
        assert!(ctx.get_register_value(&eax.borrow()).is_some());
    }

    #[test]
    fn get_value_outside_the_set_range_has_no_value() {
        let lang: Arc<dyn Language> = Arc::new(test_language());
        let mut backing = in_memory_program_context(lang.clone());
        let space = ram_space();
        let eax = lang.get_register_by_name("eax").unwrap();

        ProgramContext::set_register_value(
            &mut backing,
            &addr(&space, 0x1000),
            &addr(&space, 0x2000),
            Box::new(RegisterValue::with_value(eax.clone(), 0x42)),
        )
        .unwrap();

        let ctx = ProgramProcessorContext::new(Box::new(backing), addr(&space, 0x5000));
        assert!(!ctx.has_value(&eax.borrow()));
        assert_eq!(ctx.get_value(&eax.borrow(), false), None);
    }

    #[test]
    fn set_value_writes_through_at_the_fixed_address() {
        let lang: Arc<dyn Language> = Arc::new(test_language());
        let backing = in_memory_program_context(lang.clone());
        let space = ram_space();
        let eax = lang.get_register_by_name("eax").unwrap();

        let mut ctx = ProgramProcessorContext::new(Box::new(backing), addr(&space, 0x1000));
        ctx.set_value(&eax.borrow(), 0x99).unwrap();

        assert!(ctx.has_value(&eax.borrow()));
        assert_eq!(ctx.get_value(&eax.borrow(), false), Some(0x99));
    }

    #[test]
    fn set_value_forwards_a_single_point_range_at_the_fixed_address() {
        // `ProgramProcessorContext.setValue` must call `ProgramContext.setValue(register, addr,
        // addr, value)` -- a single-address range, not some other range. Verified directly
        // against a recording `ProgramContext` mock (rather than through
        // `AbstractStoredProgramContext`'s own range semantics) so this test exercises exactly
        // `ProgramProcessorContext`'s own forwarding logic in isolation.
        let lang: Arc<dyn Language> = Arc::new(test_language());
        let space = ram_space();
        let eax = lang.get_register_by_name("eax").unwrap();
        let fixed = addr(&space, 0x1234);

        let recorder = RecordingProgramContext::new(lang.clone());
        let calls = recorder.set_value_calls.clone();
        let mut ctx = ProgramProcessorContext::new(Box::new(recorder), fixed.clone());
        ctx.set_value(&eax.borrow(), 42).unwrap();

        let recorded = calls.borrow();
        assert_eq!(recorded.len(), 1);
        let (start, end, value) = &recorded[0];
        assert_eq!(*start, fixed);
        assert_eq!(*end, fixed);
        assert_eq!(*value, Some(42));
    }

    #[test]
    fn clear_register_forwards_a_single_point_range_at_the_fixed_address() {
        let lang: Arc<dyn Language> = Arc::new(test_language());
        let space = ram_space();
        let eax = lang.get_register_by_name("eax").unwrap();
        let fixed = addr(&space, 0x9999);

        let recorder = RecordingProgramContext::new(lang.clone());
        let calls = recorder.remove_calls.clone();
        let mut ctx = ProgramProcessorContext::new(Box::new(recorder), fixed.clone());
        ctx.clear_register(&eax.borrow()).unwrap();

        let recorded = calls.borrow();
        assert_eq!(recorded.len(), 1);
        let (start, end) = &recorded[0];
        assert_eq!(*start, fixed);
        assert_eq!(*end, fixed);
    }

    #[test]
    fn set_register_value_then_clear_register_round_trips() {
        let lang: Arc<dyn Language> = Arc::new(test_language());
        let backing = in_memory_program_context(lang.clone());
        let space = ram_space();
        let eax = lang.get_register_by_name("eax").unwrap();

        let mut ctx = ProgramProcessorContext::new(Box::new(backing), addr(&space, 0x1000));
        ctx.set_register_value(Box::new(RegisterValue::with_value(eax.clone(), 0x1357)))
            .unwrap();
        assert_eq!(ctx.get_value(&eax.borrow(), false), Some(0x1357));

        ctx.clear_register(&eax.borrow()).unwrap();
        assert!(!ctx.has_value(&eax.borrow()));
    }

    #[test]
    fn get_base_context_register_delegates_to_program_context() {
        let lang: Arc<dyn Language> = Arc::new(test_language_with_context());
        let backing = in_memory_program_context(lang.clone());
        let space = ram_space();

        let ctx = ProgramProcessorContext::new(Box::new(backing), addr(&space, 0x1000));
        let base = ctx.get_base_context_register().unwrap();
        assert_eq!(base.borrow().name(), "contextreg");
    }

    #[test]
    fn get_register_and_get_registers_delegate_to_program_context() {
        let lang: Arc<dyn Language> = Arc::new(test_language());
        let backing = in_memory_program_context(lang.clone());
        let space = ram_space();

        let ctx = ProgramProcessorContext::new(Box::new(backing), addr(&space, 0x1000));
        assert!(ctx.get_register("eax").is_some());
        assert!(ctx.get_register("missing").is_none());
        assert_eq!(ctx.get_registers().len(), 4);
    }

    #[test]
    fn usable_as_trait_object() {
        let lang: Arc<dyn Language> = Arc::new(test_language());
        let backing = in_memory_program_context(lang.clone());
        let space = ram_space();
        let eax = lang.get_register_by_name("eax").unwrap();

        let mut ctx: Box<dyn ProcessorContext> =
            Box::new(ProgramProcessorContext::new(Box::new(backing), addr(&space, 0x1000)));
        ctx.set_value(&eax.borrow(), 5).unwrap();
        assert_eq!(ctx.get_value(&eax.borrow(), false), Some(5));
    }

    /// A `ProgramContext` that records the arguments of every mutating call it receives, so
    /// tests can assert exactly what `ProgramProcessorContext` forwarded (in particular, that
    /// the address range passed through is always the single fixed point `(addr, addr)`).
    /// Read methods are unimplemented (not exercised by the tests that use this mock).
    struct RecordingProgramContext {
        language: Arc<dyn Language>,
        set_value_calls: std::rc::Rc<std::cell::RefCell<Vec<(Address, Address, Option<i128>)>>>,
        remove_calls: std::rc::Rc<std::cell::RefCell<Vec<(Address, Address)>>>,
    }

    impl RecordingProgramContext {
        fn new(language: Arc<dyn Language>) -> Self {
            Self {
                language,
                set_value_calls: std::rc::Rc::new(std::cell::RefCell::new(Vec::new())),
                remove_calls: std::rc::Rc::new(std::cell::RefCell::new(Vec::new())),
            }
        }
    }

    impl ProgramContext for RecordingProgramContext {
        fn has_non_flowing_context(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_flow_value(&self, _value: Box<dyn RegisterValueTrait>) -> Box<dyn RegisterValueTrait> {
            unimplemented!("not exercised by these tests")
        }
        fn get_non_flow_value(
            &self,
            _value: Box<dyn RegisterValueTrait>,
        ) -> Option<Box<dyn RegisterValueTrait>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_register(&self, name: &str) -> Option<RegisterRef> {
            self.language.get_register_by_name(name)
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            self.language.get_registers()
        }
        fn get_registers_with_values(&self) -> Vec<RegisterRef> {
            unimplemented!("not exercised by these tests")
        }
        fn get_value(&self, _register: &Register, _address: &Address, _signed: bool) -> Option<i128> {
            unimplemented!("not exercised by these tests")
        }
        fn get_register_value(
            &self,
            _register: &Register,
            _address: &Address,
        ) -> Option<Box<dyn RegisterValueTrait>> {
            unimplemented!("not exercised by these tests")
        }
        fn set_register_value(
            &mut self,
            _start: &Address,
            _end: &Address,
            _value: Box<dyn RegisterValueTrait>,
        ) -> Result<(), ContextChangeException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_non_default_value(
            &self,
            _register: &Register,
            _address: &Address,
        ) -> Option<Box<dyn RegisterValueTrait>> {
            unimplemented!("not exercised by these tests")
        }
        fn set_value(
            &mut self,
            _register: &Register,
            start: &Address,
            end: &Address,
            value: Option<i128>,
        ) -> Result<(), ContextChangeException> {
            self.set_value_calls
                .borrow_mut()
                .push((start.clone(), end.clone(), value));
            Ok(())
        }
        fn get_register_value_address_ranges(
            &self,
            _register: &Register,
        ) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            unimplemented!("not exercised by these tests")
        }
        fn get_register_value_address_ranges_in_range(
            &self,
            _register: &Register,
            _start: &Address,
            _end: &Address,
        ) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            unimplemented!("not exercised by these tests")
        }
        fn get_register_value_range_containing(
            &self,
            _register: &Register,
            _addr: &Address,
        ) -> crate::program::model::address::AddressRange {
            unimplemented!("not exercised by these tests")
        }
        fn get_default_register_value_address_ranges(
            &self,
            _register: &Register,
        ) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            unimplemented!("not exercised by these tests")
        }
        fn get_default_register_value_address_ranges_in_range(
            &self,
            _register: &Register,
            _start: &Address,
            _end: &Address,
        ) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            unimplemented!("not exercised by these tests")
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            unimplemented!("not exercised by these tests")
        }
        fn remove(
            &mut self,
            start: &Address,
            end: &Address,
            _register: &Register,
        ) -> Result<(), ContextChangeException> {
            self.remove_calls.borrow_mut().push((start.clone(), end.clone()));
            Ok(())
        }
        fn get_register_names(&self) -> Vec<String> {
            unimplemented!("not exercised by these tests")
        }
        fn has_value_over_range(
            &self,
            _reg: &Register,
            _value: i128,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
        ) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_default_value(
            &self,
            _register: &Register,
            _address: &Address,
        ) -> Option<Box<dyn RegisterValueTrait>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_base_context_register(&self) -> RegisterRef {
            self.language
                .get_context_base_register()
                .expect("test language must define a context base register")
        }
        fn get_default_disassembly_context(&self) -> Box<dyn RegisterValueTrait> {
            unimplemented!("not exercised by these tests")
        }
        fn set_default_disassembly_context(&mut self, _value: Box<dyn RegisterValueTrait>) {
            unimplemented!("not exercised by these tests")
        }
        fn get_disassembly_context(&self, _address: &Address) -> Box<dyn RegisterValueTrait> {
            unimplemented!("not exercised by these tests")
        }
    }
}
