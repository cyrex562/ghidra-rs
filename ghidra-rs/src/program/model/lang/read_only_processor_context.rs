//! Port of `ghidra.program.model.lang.ReadOnlyProcessorContext`.
//!
//! Wraps a [`ProcessorContextView`] and forwards every read; every write is a genuine, silent
//! no-op. This is not an approximation: Java's real `setValue`/`setRegisterValue`/`clearRegister`
//! bodies contain nothing but a commented-out `Msg.debug(...)` call and never throw
//! `ContextChangeException`, matching the class's own doc comment ("Any sets to the processor
//! context are ignored"). This port reproduces that faithfully -- writes return `Ok(())` without
//! mutating any state, rather than rejecting with an error.

use crate::program::model::lang::processor_context::ProcessorContext;
use crate::program::model::lang::processor_context_view::ProcessorContextView;
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::listing::context_change_exception::ContextChangeException;
use crate::program::seam_stubs::RegisterValue as RegisterValueTrait;

/// Read only processor context. Any sets to the processor context are ignored.
///
/// Port of `ghidra.program.model.lang.ReadOnlyProcessorContext`.
pub struct ReadOnlyProcessorContext {
    context: Box<dyn ProcessorContextView>,
}

impl ReadOnlyProcessorContext {
    /// Constructs a new `ReadOnlyProcessorContext` wrapping the given view.
    ///
    /// Port of `ReadOnlyProcessorContext(ProcessorContextView)`.
    pub fn new(context: Box<dyn ProcessorContextView>) -> Self {
        Self { context }
    }
}

impl ProcessorContextView for ReadOnlyProcessorContext {
    fn get_base_context_register(&self) -> Option<RegisterRef> {
        self.context.get_base_context_register()
    }

    fn get_register(&self, name: &str) -> Option<RegisterRef> {
        self.context.get_register(name)
    }

    fn get_registers(&self) -> Vec<RegisterRef> {
        self.context.get_registers()
    }

    fn get_value(&self, register: &Register, signed: bool) -> Option<i128> {
        self.context.get_value(register, signed)
    }

    fn get_register_value(&self, register: &Register) -> Option<Box<dyn RegisterValueTrait>> {
        self.context.get_register_value(register)
    }

    fn has_value(&self, register: &Register) -> bool {
        self.context.has_value(register)
    }
}

impl ProcessorContext for ReadOnlyProcessorContext {
    /// Port of `setValue(Register, BigInteger)`: a genuine no-op (matches Java's commented-out
    /// debug logging with no state mutation).
    fn set_value(
        &mut self,
        _register: &Register,
        _value: i128,
    ) -> Result<(), ContextChangeException> {
        Ok(())
    }

    /// Port of `setRegisterValue(RegisterValue)`: a genuine no-op.
    fn set_register_value(
        &mut self,
        _value: Box<dyn RegisterValueTrait>,
    ) -> Result<(), ContextChangeException> {
        Ok(())
    }

    /// Port of `clearRegister(Register)`: a genuine no-op.
    fn clear_register(&mut self, _register: &Register) -> Result<(), ContextChangeException> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::processor_context_impl::ProcessorContextImpl;
    use crate::program::model::lang::language::Language;
    use crate::program::util::abstract_stored_program_context::test_support::test_language;
    use std::sync::Arc;

    fn wrap_backing(backing: ProcessorContextImpl) -> ReadOnlyProcessorContext {
        ReadOnlyProcessorContext::new(Box::new(backing))
    }

    #[test]
    fn reads_are_forwarded_to_the_wrapped_view() {
        let lang: Arc<dyn Language> = Arc::new(test_language());
        let mut backing = ProcessorContextImpl::new(lang.clone());
        let eax = lang.get_register_by_name("eax").unwrap();
        backing.set_value(&eax.borrow(), 0x4242).unwrap();

        let ro = wrap_backing(backing);
        assert!(ro.has_value(&eax.borrow()));
        assert_eq!(ro.get_value(&eax.borrow(), false), Some(0x4242));
        assert!(ro.get_register_value(&eax.borrow()).is_some());
        assert!(ro.get_register("eax").is_some());
        assert_eq!(ro.get_registers().len(), 4);
    }

    #[test]
    fn set_value_is_a_silent_no_op() {
        let lang: Arc<dyn Language> = Arc::new(test_language());
        let backing = ProcessorContextImpl::new(lang.clone());
        let eax = lang.get_register_by_name("eax").unwrap();

        let mut ro = wrap_backing(backing);
        assert!(!ro.has_value(&eax.borrow()));

        // Real Java behavior: succeeds (never throws ContextChangeException) but changes nothing.
        let result = ro.set_value(&eax.borrow(), 999);
        assert!(result.is_ok());
        assert!(!ro.has_value(&eax.borrow()));
        assert_eq!(ro.get_value(&eax.borrow(), false), None);
    }

    #[test]
    fn set_register_value_is_a_silent_no_op() {
        use crate::program::model::lang::register_value::RegisterValue;

        let lang: Arc<dyn Language> = Arc::new(test_language());
        let backing = ProcessorContextImpl::new(lang.clone());
        let eax = lang.get_register_by_name("eax").unwrap();

        let mut ro = wrap_backing(backing);
        let rv: Box<dyn RegisterValueTrait> =
            Box::new(RegisterValue::with_value(eax.clone(), 12345));
        let result = ro.set_register_value(rv);

        assert!(result.is_ok());
        assert!(!ro.has_value(&eax.borrow()));
    }

    #[test]
    fn clear_register_is_a_silent_no_op_and_does_not_affect_existing_values() {
        let lang: Arc<dyn Language> = Arc::new(test_language());
        let mut backing = ProcessorContextImpl::new(lang.clone());
        let eax = lang.get_register_by_name("eax").unwrap();
        backing.set_value(&eax.borrow(), 0x99).unwrap();

        let mut ro = wrap_backing(backing);
        assert!(ro.has_value(&eax.borrow()));

        let result = ro.clear_register(&eax.borrow());
        assert!(result.is_ok());
        // Unlike a real clear, the value is untouched: this is the "ignored" part of
        // ReadOnlyProcessorContext's doc comment.
        assert!(ro.has_value(&eax.borrow()));
        assert_eq!(ro.get_value(&eax.borrow(), false), Some(0x99));
    }

    #[test]
    fn usable_as_trait_object() {
        let lang: Arc<dyn Language> = Arc::new(test_language());
        let backing = ProcessorContextImpl::new(lang.clone());
        let eax = lang.get_register_by_name("eax").unwrap();

        let mut ctx: Box<dyn ProcessorContext> = Box::new(wrap_backing(backing));
        ctx.set_value(&eax.borrow(), 1).unwrap();
        assert!(!ctx.has_value(&eax.borrow()));
    }
}
