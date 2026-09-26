//! Port of `ghidra.program.model.lang.ProcessorContextImpl`.
//!
//! A standalone, in-memory implementation of [`ProcessorContext`] that owns its own storage: a
//! map from each base register's name to that base register's mask/value byte pair (mirroring
//! Java's `Map<Register, byte[]>`). All register-value arithmetic (masking, combining values,
//! clearing bits, signed/unsigned extraction) is delegated to the real, byte-exact
//! [`RegisterValue`] concrete type.

use std::collections::HashMap;
use std::sync::Arc;

use crate::program::model::lang::language::Language;
use crate::program::model::lang::processor_context::ProcessorContext;
use crate::program::model::lang::processor_context_view::ProcessorContextView;
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::lang::register_value::RegisterValue;
use crate::program::model::listing::context_change_exception::ContextChangeException;

/// An implementation of processor context which contains the state of all processor registers.
///
/// Port of `ghidra.program.model.lang.ProcessorContextImpl`.
///
/// Note that [`ContextChangeException`] will never be returned by this implementation of
/// `ProcessorContext` (mirrors the Java class's doc comment).
///
/// `Clone` copies the register values (sharing the language), which is what taking a snapshot of
/// a context means -- e.g. for a
/// [`PseudoInstruction`](crate::app::util::pseudo_instruction::PseudoInstruction), which owns the
/// context it was decoded under.
#[derive(Clone)]
pub struct ProcessorContextImpl {
    /// Keyed by base register name, mirroring Java's `Map<Register, byte[]>` (which is keyed by
    /// `Register`'s `equals`/`hashCode`, effectively identity/name within one `Language`).
    values: HashMap<String, Vec<u8>>,
    language: Arc<dyn Language>,
}

impl ProcessorContextImpl {
    /// Constructs a new `ProcessorContextImpl` for the given language.
    ///
    /// Port of `ProcessorContextImpl(Language)`.
    pub fn new(language: Arc<dyn Language>) -> Self {
        Self {
            values: HashMap::new(),
            language,
        }
    }

    /// Clears all register values held by this context.
    ///
    /// Port of `ProcessorContextImpl.clearAll()`.
    pub fn clear_all(&mut self) {
        self.values.clear();
    }

    /// Resolves an arbitrary `&Register` (as received at a trait-method boundary) to the
    /// [`RegisterRef`] this context's language actually shares child/base links through. A bare
    /// `&Register` cannot be upgraded back into a shared `Rc` handle in this crate's API (see
    /// `register.rs`'s private `self_ref`), so -- matching the identical, already-established
    /// pattern in `AbstractStoredProgramContext::resolve` / `OldProgramContextDB::resolve` --
    /// registers are re-found by name against this context's own language.
    fn resolve(&self, register: &Register) -> RegisterRef {
        self.language
            .get_register_by_name(register.name())
            .unwrap_or_else(|| {
                panic!(
                    "ProcessorContextImpl: register '{}' is not defined by this context's language",
                    register.name()
                )
            })
    }
}

impl ProcessorContextView for ProcessorContextImpl {
    fn get_base_context_register(&self) -> Option<RegisterRef> {
        self.language.get_context_base_register()
    }

    fn get_register(&self, name: &str) -> Option<RegisterRef> {
        self.language.get_register_by_name(name)
    }

    fn get_registers(&self) -> Vec<RegisterRef> {
        self.language.get_registers()
    }

    fn get_register_value(&self, register: &Register) -> Option<RegisterValue> {
        let reg = self.resolve(register);
        let base = reg.get_base_register();
        let key = base.name().to_string();
        let bytes = self.values.get(&key)?;
        Some(RegisterValue::from_bytes(reg, bytes))
    }

    fn get_value(&self, register: &Register, signed: bool) -> Option<i128> {
        let reg = self.resolve(register);
        let base = reg.get_base_register();
        let key = base.name().to_string();
        let bytes = self.values.get(&key)?;
        let value = RegisterValue::from_bytes(reg, bytes);
        if signed {
            value.signed_value()
        } else {
            value.unsigned_value().map(|v| v as i128)
        }
    }

    fn has_value(&self, register: &Register) -> bool {
        self.get_value(register, false).is_some()
    }
}

impl ProcessorContext for ProcessorContextImpl {
    fn set_value(
        &mut self,
        register: &Register,
        value: i128,
    ) -> Result<(), ContextChangeException> {
        let reg = self.resolve(register);
        // Two's-complement bit-pattern reinterpretation, matching this crate's established
        // `i128` <-> `RegisterValue::with_value`'s `u128` convention (see
        // `AbstractStoredProgramContext::set_value`'s identical cast, proven by its
        // `set_value_with_negative_i128_round_trips_via_two_s_complement` test).
        let rv = RegisterValue::with_value(reg, value as u128);
        self.set_register_value(rv)
    }

    fn set_register_value(
        &mut self,
        value: RegisterValue,
    ) -> Result<(), ContextChangeException> {
        let concrete = value;
        let base_register = concrete.register().get_base_register();
        let key = base_register.name().to_string();

        let existing = self.values.get(&key).cloned();
        if let Some(current_bytes) = existing {
            let current_value = RegisterValue::from_bytes(base_register, &current_bytes);
            let combined_value = current_value.combine_values(&concrete);
            self.values.insert(key, combined_value.to_bytes());
        } else {
            self.values.insert(key, concrete.to_bytes());
        }
        Ok(())
    }

    fn clear_register(&mut self, register: &Register) -> Result<(), ContextChangeException> {
        // Unlike the other methods, Java operates directly on the passed-in `Register` object
        // here (`register.getBaseRegister()` / `register.getBaseMask()`) rather than looking
        // anything up in `language` -- both of those are available straight off `&Register`
        // (they resolve via the register's own base-register link, which is populated whenever
        // the register was reached through a live `RegisterRef`), so no `resolve()` is needed.
        let base_register = register.get_base_register();
        let key = base_register.name().to_string();
        if let Some(current_bytes) = self.values.remove(&key) {
            let current_value = RegisterValue::from_bytes(base_register, &current_bytes);
            let cleared_value = current_value.clear_bit_values(&register.base_mask());
            if cleared_value.has_any_value() {
                self.values.insert(key, cleared_value.to_bytes());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::util::abstract_stored_program_context::test_support::{
        test_language, test_language_with_context,
    };

    #[test]
    fn new_context_has_no_values() {
        let lang: Arc<dyn Language> = Arc::new(test_language());
        let ctx = ProcessorContextImpl::new(lang.clone());
        let eax = lang.get_register_by_name("eax").unwrap();
        assert!(!ctx.has_value(&eax));
        assert_eq!(ctx.get_value(&eax, false), None);
        assert!(ctx.get_register_value(&eax).is_none());
    }

    #[test]
    fn set_value_then_get_value_round_trips() {
        let lang: Arc<dyn Language> = Arc::new(test_language());
        let mut ctx = ProcessorContextImpl::new(lang.clone());
        let eax = lang.get_register_by_name("eax").unwrap();

        ctx.set_value(&eax, 0x1234_5678).unwrap();

        assert!(ctx.has_value(&eax));
        assert_eq!(ctx.get_value(&eax, false), Some(0x1234_5678));
        assert_eq!(ctx.get_value(&eax, true), Some(0x1234_5678));
    }

    #[test]
    fn set_value_with_negative_value_round_trips_via_twos_complement() {
        let lang: Arc<dyn Language> = Arc::new(test_language());
        let mut ctx = ProcessorContextImpl::new(lang.clone());
        let eax = lang.get_register_by_name("eax").unwrap();

        ctx.set_value(&eax, -2).unwrap();

        assert_eq!(ctx.get_value(&eax, true), Some(-2));
        assert_eq!(ctx.get_value(&eax, false), Some(0xFFFF_FFFE));
    }

    #[test]
    fn set_value_on_sub_register_is_visible_on_base_register() {
        let lang: Arc<dyn Language> = Arc::new(test_language());
        let mut ctx = ProcessorContextImpl::new(lang.clone());
        let al = lang.get_register_by_name("al").unwrap();
        let eax = lang.get_register_by_name("eax").unwrap();

        ctx.set_value(&al, 0xFF).unwrap();

        // `al` occupies eax's low byte; the rest of eax remains unset (only al's bits combined).
        assert!(ctx.has_value(&al));
        assert!(!ctx.has_value(&eax));
        assert_eq!(ctx.get_value(&al, false), Some(0xFF));
    }

    #[test]
    fn set_register_value_combines_onto_existing_value() {
        let lang: Arc<dyn Language> = Arc::new(test_language());
        let mut ctx = ProcessorContextImpl::new(lang.clone());
        let al = lang.get_register_by_name("al").unwrap();
        let ah = lang.get_register_by_name("ah").unwrap();
        let eax = lang.get_register_by_name("eax").unwrap();

        ctx.set_value(&al, 0x11).unwrap();
        ctx.set_value(&ah, 0x22).unwrap();

        // Both bytes were combined together onto the shared base register's stored bytes: each
        // sub-register still reads back its own value...
        assert!(ctx.has_value(&al));
        assert!(ctx.has_value(&ah));
        assert_eq!(ctx.get_value(&al, false), Some(0x11));
        assert_eq!(ctx.get_value(&ah, false), Some(0x22));

        // ...but `eax` (4 bytes / 32 bits) does *not* have a value, since `al`/`ah` only cover
        // its low 2 bytes -- the upper 2 bytes were never set. This is not a stub gap; it
        // faithfully mirrors `RegisterValue.hasValue()`, which requires every bit within the
        // queried register's own range to be masked "on".
        assert!(!ctx.has_value(&eax));
        assert_eq!(ctx.get_value(&eax, false), None);

        // The raw combined bits are nonetheless present when read back ignoring the mask.
        let combined = ctx.get_register_value(&eax).unwrap();
        assert!(combined.has_any_value());
        assert_eq!(combined.unsigned_value_ignore_mask(), 0x2211);
    }

    #[test]
    fn clear_register_removes_only_that_registers_bits() {
        let lang: Arc<dyn Language> = Arc::new(test_language());
        let mut ctx = ProcessorContextImpl::new(lang.clone());
        let al = lang.get_register_by_name("al").unwrap();
        let ah = lang.get_register_by_name("ah").unwrap();
        let eax = lang.get_register_by_name("eax").unwrap();

        ctx.set_value(&eax, 0x2211).unwrap();
        ctx.clear_register(&al).unwrap();

        assert!(!ctx.has_value(&al));
        assert!(ctx.has_value(&ah));
        assert_eq!(ctx.get_value(&ah, false), Some(0x22));
    }

    #[test]
    fn clear_register_removes_map_entry_entirely_when_no_bits_remain() {
        let lang: Arc<dyn Language> = Arc::new(test_language());
        let mut ctx = ProcessorContextImpl::new(lang.clone());
        let eax = lang.get_register_by_name("eax").unwrap();

        ctx.set_value(&eax, 0x1234_5678).unwrap();
        ctx.clear_register(&eax).unwrap();

        assert!(!ctx.has_value(&eax));
        assert!(ctx.values.is_empty());
    }

    #[test]
    fn clear_all_removes_every_value() {
        let lang: Arc<dyn Language> = Arc::new(test_language());
        let mut ctx = ProcessorContextImpl::new(lang.clone());
        let eax = lang.get_register_by_name("eax").unwrap();
        let r0 = lang.get_register_by_name("r0").unwrap();

        ctx.set_value(&eax, 1).unwrap();
        ctx.set_value(&r0, 2).unwrap();
        ctx.clear_all();

        assert!(!ctx.has_value(&eax));
        assert!(!ctx.has_value(&r0));
    }

    #[test]
    fn get_base_context_register_delegates_to_language() {
        let lang: Arc<dyn Language> = Arc::new(test_language_with_context());
        let ctx = ProcessorContextImpl::new(lang.clone());
        let base = ctx.get_base_context_register().unwrap();
        assert_eq!(base.name(), "contextreg");
    }

    #[test]
    fn get_base_context_register_is_none_without_a_context_register() {
        let lang: Arc<dyn Language> = Arc::new(test_language());
        let ctx = ProcessorContextImpl::new(lang);
        assert!(ctx.get_base_context_register().is_none());
    }

    #[test]
    fn get_register_and_get_registers_delegate_to_language() {
        let lang: Arc<dyn Language> = Arc::new(test_language());
        let ctx = ProcessorContextImpl::new(lang);
        assert!(ctx.get_register("eax").is_some());
        assert!(ctx.get_register("missing").is_none());
        assert_eq!(ctx.get_registers().len(), 4);
    }

    #[test]
    fn usable_as_trait_object() {
        let lang: Arc<dyn Language> = Arc::new(test_language());
        let mut ctx: Box<dyn ProcessorContext> = Box::new(ProcessorContextImpl::new(lang.clone()));
        let eax = lang.get_register_by_name("eax").unwrap();

        ctx.set_value(&eax, 7).unwrap();
        assert_eq!(ctx.get_value(&eax, false), Some(7));
    }
}
