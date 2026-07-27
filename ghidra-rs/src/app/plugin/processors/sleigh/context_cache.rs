use crate::app::seam_stubs::RegisterValueBuilder;
use crate::program::model::address::Address;
use crate::program::model::lang::disassembler_context::DisassemblerContext;
use crate::program::model::lang::processor_context_view::ProcessorContextView;
use crate::program::model::lang::register::{Register, RegisterRef};

/// Caches a language's context register and decodes/encodes its value as SLEIGH context words.
///
/// Port of `ghidra.app.plugin.processors.sleigh.ContextCache`.
///
/// Selected as a dependency-cycle cut-point: consumers (`SleighInstructionPrototype`,
/// `SleighParserContext`, `SleighLanguage`, `SleighDebugLogger`) depend on this trait rather than
/// a concrete implementation, letting those still-unported Java classes be ported independently
/// of each other and of this one.
///
/// Java's `setContext` takes the broader `ProcessorContext` and does nothing unless the argument
/// is (also, dynamically) a `DisassemblerContext`, checked with `instanceof`. Rust trait objects
/// can't be downcast that way without threading `std::any::Any` through the widely-implemented
/// `ProcessorContext` trait (18+ implementors across the crate), so
/// [`ContextCache::set_context`] takes `&mut dyn DisassemblerContext` directly instead -- the
/// only real caller (`SleighParserContext.applyCommits`) is always invoked with a
/// `DisassemblerContext` during disassembly flow analysis, matching the precedent set by
/// `app::util::pseudo_disassembler`.
///
/// Java also constructs the outgoing `RegisterValue` directly
/// (`new RegisterValue(contextBaseRegister, bytes)`); since the real `RegisterValue` class isn't
/// ported yet (only the read-only [`program::seam_stubs::RegisterValue`](crate::program::seam_stubs::RegisterValue)
/// placeholder trait exists), building one is delegated to a [`RegisterValueBuilder`] the caller
/// supplies.
pub trait ContextCache {
    /// Port of `ContextCache.registerVariable(Register)`.
    fn register_variable(&mut self, register: &Register);

    /// Port of `ContextCache.getContextSize()`.
    fn get_context_size(&self) -> i32;

    /// Port of `ContextCache.getContext(ProcessorContextView, int[])`. `buf` should be at least
    /// [`ContextCache::get_context_size`] words long; any extra words are left untouched.
    fn get_context(&mut self, ctx: &dyn ProcessorContextView, buf: &mut [i32]);

    /// Port of `ContextCache.setContext(ProcessorContext, Address, int, int, int)`.
    fn set_context(
        &self,
        ctx: &mut dyn DisassemblerContext,
        builder: &dyn RegisterValueBuilder,
        addr: Address,
        num: i32,
        mask: i32,
        value: i32,
    );
}

/// Default [`ContextCache`] implementation, mirroring the state and logic of Java's concrete
/// `ContextCache` class.
#[derive(Default)]
pub struct DefaultContextCache {
    context_size: i32,
    context_base_register: Option<RegisterRef>,
    /// Port of the `lastValue` one-entry memoization cache.
    last_value: Option<(u128, Vec<i32>)>,
}

impl DefaultContextCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Port of the private `getWords(BigInteger)` helper.
    fn get_words(&mut self, value: u128) -> Vec<i32> {
        if let Some((last_val, last_words)) = &self.last_value {
            if *last_val == value {
                return last_words.clone();
            }
        }

        let context_size = self.context_size as usize;
        let bytes = unsigned_value_to_be_bytes(value);
        let byte_index_diff = context_size as i64 * 4 - bytes.len() as i64;

        let mut words = vec![0i32; context_size];
        for (i, word_slot) in words.iter_mut().enumerate() {
            let byte_index = 4 * i as i64 - byte_index_diff;
            let mut word = get_byte(&bytes, byte_index) as i32;
            for j in 1..4i64 {
                word = (word << 8) | get_byte(&bytes, byte_index + j) as i32;
            }
            *word_slot = word;
        }

        self.last_value = Some((value, words.clone()));
        words
    }
}

impl ContextCache for DefaultContextCache {
    fn register_variable(&mut self, register: &Register) {
        let base = register.get_base_register();
        let min_byte_size = base.borrow().minimum_byte_size();
        self.context_size = (min_byte_size + 3) / 4;
        self.context_base_register = Some(base);
    }

    fn get_context_size(&self) -> i32 {
        self.context_size
    }

    fn get_context(&mut self, ctx: &dyn ProcessorContextView, buf: &mut [i32]) {
        let Some(base_reg) = self.context_base_register.clone() else {
            return;
        };
        let context_reg_value = {
            let reg = base_reg.borrow();
            ctx.get_register_value(&reg)
        };
        let Some(context_reg_value) = context_reg_value else {
            buf.fill(0);
            return;
        };
        let context_value = context_reg_value.get_unsigned_value_ignore_mask();
        let words = self.get_words(context_value);
        for (slot, word) in buf.iter_mut().zip(words.iter()) {
            *slot = *word;
        }
    }

    fn set_context(
        &self,
        ctx: &mut dyn DisassemblerContext,
        builder: &dyn RegisterValueBuilder,
        addr: Address,
        num: i32,
        mask: i32,
        value: i32,
    ) {
        let Some(base_reg) = &self.context_base_register else {
            return;
        };
        let byte_size = (self.context_size * 4) as usize;
        let mut bytes = vec![0u8; 2 * byte_size];
        put_int(&mut bytes, byte_size + num as usize * 4, value);
        put_int(&mut bytes, num as usize * 4, mask);
        let register_value = builder.build_register_value(base_reg.clone(), bytes);
        ctx.set_future_register_value(addr, register_value);
    }
}

/// Port of the private `getByte(byte[], int)` helper. Java's bound check (`index > bytes.length`)
/// is tightened to `>=` here to avoid an out-of-bounds panic; every `index` actually produced by
/// [`DefaultContextCache::get_words`] already stays within `bytes.len() - 1`, so this is not a
/// behavior change, only a defensive fix to an unreachable edge in the original bound.
fn get_byte(bytes: &[u8], index: i64) -> u8 {
    if index < 0 || index as usize >= bytes.len() {
        0
    } else {
        bytes[index as usize]
    }
}

/// Port of the private `putInt(byte[], int, int)` helper.
fn put_int(bytes: &mut [u8], index: usize, mut value: i32) {
    for i in (0..4).rev() {
        bytes[index + i] = value as u8;
        value >>= 8;
    }
}

/// Port of `BigInteger.toByteArray()` as applied to the non-negative value returned by
/// `RegisterValue.getUnsignedValueIgnoreMask()`: the minimal big-endian two's-complement
/// representation, with a leading zero byte prepended when the high bit of the first magnitude
/// byte is set (so the value still reads as non-negative).
fn unsigned_value_to_be_bytes(value: u128) -> Vec<u8> {
    let full = value.to_be_bytes();
    let mut start = 0;
    while start < 15 && full[start] == 0 {
        start += 1;
    }
    let mut bytes = full[start..].to_vec();
    if bytes[0] & 0x80 != 0 {
        let mut with_sign = Vec::with_capacity(bytes.len() + 1);
        with_sign.push(0);
        with_sign.extend_from_slice(&bytes);
        bytes = with_sign;
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::processor_context::ProcessorContext;
    use crate::program::model::listing::context_change_exception::ContextChangeException;
    use crate::program::seam_stubs::RegisterValue;
    use std::cell::RefCell;

    struct MockRegisterValue {
        register: RegisterRef,
        unsigned_value: u128,
    }

    impl RegisterValue for MockRegisterValue {
        fn get_register(&self) -> RegisterRef {
            self.register.clone()
        }

        fn get_register_value(&self, register: &Register) -> Box<dyn RegisterValue> {
            Box::new(MockRegisterValue {
                register: Register::from_register(register),
                unsigned_value: self.unsigned_value,
            })
        }

        fn has_any_value(&self) -> bool {
            true
        }

        fn get_unsigned_value_ignore_mask(&self) -> u128 {
            self.unsigned_value
        }
    }

    struct MockDisassemblerContext {
        base_register: RegisterRef,
        value: Option<u128>,
        future_values: RefCell<Vec<(Address, Vec<u8>)>>,
    }

    impl ProcessorContextView for MockDisassemblerContext {
        fn get_base_context_register(&self) -> Option<RegisterRef> {
            Some(self.base_register.clone())
        }

        fn get_registers(&self) -> Vec<RegisterRef> {
            vec![self.base_register.clone()]
        }

        fn get_register(&self, name: &str) -> Option<RegisterRef> {
            if self.base_register.borrow().name() == name {
                Some(self.base_register.clone())
            } else {
                None
            }
        }

        fn get_value(&self, _register: &Register, _signed: bool) -> Option<i128> {
            None
        }

        fn get_register_value(&self, _register: &Register) -> Option<Box<dyn RegisterValue>> {
            self.value.map(|unsigned_value| {
                Box::new(MockRegisterValue {
                    register: self.base_register.clone(),
                    unsigned_value,
                }) as Box<dyn RegisterValue>
            })
        }

        fn has_value(&self, _register: &Register) -> bool {
            self.value.is_some()
        }
    }

    impl ProcessorContext for MockDisassemblerContext {
        fn set_value(
            &mut self,
            _register: &Register,
            _value: i128,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }

        fn set_register_value(
            &mut self,
            _value: Box<dyn RegisterValue>,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }

        fn clear_register(&mut self, _register: &Register) -> Result<(), ContextChangeException> {
            Ok(())
        }
    }

    impl DisassemblerContext for MockDisassemblerContext {
        fn set_future_register_value(&mut self, address: Address, value: Box<dyn RegisterValue>) {
            let bytes = value
                .get_unsigned_value_ignore_mask()
                .to_be_bytes()
                .to_vec();
            self.future_values.borrow_mut().push((address, bytes));
        }

        fn set_future_register_value_for_flow(
            &mut self,
            _from_addr: Address,
            _to_addr: Address,
            _value: Box<dyn RegisterValue>,
        ) {
        }
    }

    /// Records the exact raw bytes it was asked to build a [`RegisterValue`] from, so the test
    /// can assert on `set_context`'s byte layout without losing length information to a
    /// fixed-width integer round-trip.
    struct MockRegisterValueBuilder {
        built: RefCell<Vec<(RegisterRef, Vec<u8>)>>,
    }

    impl RegisterValueBuilder for MockRegisterValueBuilder {
        fn build_register_value(
            &self,
            register: RegisterRef,
            bytes: Vec<u8>,
        ) -> Box<dyn RegisterValue> {
            self.built
                .borrow_mut()
                .push((register.clone(), bytes.clone()));
            let mut unsigned_value: u128 = 0;
            for b in &bytes {
                unsigned_value = (unsigned_value << 8) | (*b as u128);
            }
            Box::new(MockRegisterValue {
                register,
                unsigned_value,
            })
        }
    }

    fn mock_register(num_bytes: i32) -> RegisterRef {
        let space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 1);
        Register::new(
            "context",
            "Processor context register",
            Address::new(space, 0),
            num_bytes,
            false,
            0,
        )
    }

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 8, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    #[test]
    fn usable_as_trait_object() {
        let cache: Box<dyn ContextCache> = Box::new(DefaultContextCache::new());
        assert_eq!(cache.get_context_size(), 0);
    }

    #[test]
    fn register_variable_computes_context_size_in_words() {
        let mut cache = DefaultContextCache::new();
        // 8-byte context register -> 2 32-bit context words.
        cache.register_variable(&mock_register(8).borrow());
        assert_eq!(cache.get_context_size(), 2);
    }

    #[test]
    fn get_context_decodes_words_and_caches_last_value() {
        let mut cache = DefaultContextCache::new();
        let base_register = mock_register(8);
        cache.register_variable(&base_register.borrow());

        let ctx = MockDisassemblerContext {
            base_register: base_register.clone(),
            value: Some(0xFFFF_FFFF_0000_0001u128),
            future_values: RefCell::new(Vec::new()),
        };

        let mut buf = [0i32; 2];
        cache.get_context(&ctx, &mut buf);
        assert_eq!(buf, [-1, 1]);

        // Exercise the `lastValue` memoization path with a repeat call for the same value.
        let mut buf2 = [0i32; 2];
        cache.get_context(&ctx, &mut buf2);
        assert_eq!(buf2, [-1, 1]);
    }

    #[test]
    fn get_context_zero_fills_when_no_value_is_set() {
        let mut cache = DefaultContextCache::new();
        let base_register = mock_register(4);
        cache.register_variable(&base_register.borrow());

        let ctx = MockDisassemblerContext {
            base_register,
            value: None,
            future_values: RefCell::new(Vec::new()),
        };

        let mut buf = [7i32; 1];
        cache.get_context(&ctx, &mut buf);
        assert_eq!(buf, [0]);
    }

    #[test]
    fn set_context_encodes_mask_and_value_into_future_register_value() {
        let mut cache = DefaultContextCache::new();
        let base_register = mock_register(4);
        cache.register_variable(&base_register.borrow());

        let mut ctx = MockDisassemblerContext {
            base_register,
            value: None,
            future_values: RefCell::new(Vec::new()),
        };
        let builder = MockRegisterValueBuilder {
            built: RefCell::new(Vec::new()),
        };

        cache.set_context(&mut ctx, &builder, mock_address(0x100), 0, 0x0000_00FF, 0x0000_002A);

        let future_values = ctx.future_values.borrow();
        assert_eq!(future_values.len(), 1);
        assert_eq!(future_values[0].0, mock_address(0x100));

        let built = builder.built.borrow();
        assert_eq!(built.len(), 1);
        let (_register, bytes) = &built[0];
        // byte_size = context_size(1) * 4 = 4; layout is [mask (4 bytes)][value (4 bytes)].
        assert_eq!(bytes, &vec![0, 0, 0, 0xFF, 0, 0, 0, 0x2A]);
    }
}
