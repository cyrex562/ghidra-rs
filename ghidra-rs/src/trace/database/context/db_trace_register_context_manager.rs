//! Port of `ghidra.trace.database.context.DBTraceRegisterContextManager`.

use std::sync::Arc;

use crate::program::model::address::{Address, AddressRange, AddressSet, AddressSetView, AddressSpace};
use crate::program::model::lang::{Language, Register};
use crate::program::model::listing::program_context::ProgramContext;
use crate::program::seam_stubs::RegisterValue;
use crate::trace::database::space::db_trace_delegating_manager::DBTraceDelegatingManager;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
use crate::trace::seam_stubs::{DBTraceRegisterContextSpace, TracePlatform, TraceThread};

/// The per-address-space delegate this manager hands out. `Arc`-shared (not owned/boxed), matching
/// [`DBTraceMemorySpace`](crate::trace::seam_stubs::DBTraceMemorySpace)'s established convention
/// for DB-backed, lock-synchronized delegates passed to
/// [`DBTraceDelegatingManager`]'s `delegateXxx` helpers.
pub type RegisterContextSpaceHandle = Arc<dyn DBTraceRegisterContextSpace>;

/// The trace database's register (processor context) manager: per-address-space storage of
/// register values recorded over time, plus language-defined default values.
///
/// Port of `ghidra.trace.database.context.DBTraceRegisterContextManager`, which extends
/// `AbstractDBTraceSpaceBasedManager<DBTraceRegisterContextSpace>` and implements
/// `TraceRegisterContextManager, DBTraceDelegatingManager<DBTraceRegisterContextSpace>`.
///
/// It was selected as a dependency-cycle cut-point.
///
/// [`DBTraceDelegatingManager`]'s `read_lock`/`write_lock`/`get_for_space` are inherited as-is,
/// mirroring `AbstractDBTraceSpaceBasedManager.getForSpace` (widened to public by the concrete
/// class to satisfy the delegating-manager contract) and the class's `readLock`/`writeLock`
/// overrides (`lock.readLock()`/`lock.writeLock()`). This trait adds the handful of members the
/// class needs beyond that supertrait: the active-space enumeration
/// (`AbstractDBTraceSpaceBasedManager.getActiveSpaces()`, which the all-spaces
/// `getRegisterValueAddressRanges`/`hasRegisterValue` overloads reduce over), the by-thread space
/// lookup, and the per-language default-context cache. Every `TraceRegisterContextOperations`
/// method the class implements is then a default method that delegates through these -- via
/// [`DBTraceDelegatingManager`]'s `delegateXxx` helpers -- matching the Java class's own bodies
/// exactly.
///
/// These defaults are `where Self: Sized` (like the `delegateXxx` helpers they call), so they are
/// opted out of the vtable; the handful of required methods above keep the trait usable as
/// `Box<dyn DBTraceRegisterContextManager>`/`Arc<dyn ...>`.
///
/// The constructor and its private, DB-record-backed space-table machinery
/// (`createSpace`/`loadSpaces`, keyed off a `DBCachedObjectStore`) are implementation details
/// private to the concrete class, not part of its cross-package API contract, and
/// `DBCachedObjectStore` itself is not yet ported -- so none of that is represented here.
pub trait DBTraceRegisterContextManager: DBTraceDelegatingManager<RegisterContextSpaceHandle> {
    /// All address spaces with an active register-context delegate. Mirrors
    /// `AbstractDBTraceSpaceBasedManager.getActiveSpaces()`.
    fn get_active_spaces(&self) -> Vec<RegisterContextSpaceHandle>;

    /// Get (or, if `create_if_absent`, create) the register-context space for `thread`'s
    /// (frame-0) register container. Mirrors `getRegisterContextRegisterSpace(TraceThread,
    /// boolean)`, which resolves the container via
    /// `AbstractDBTraceSpaceBasedManager.getForRegisterSpace(TraceThread, int, boolean)`.
    fn get_register_context_register_space(
        &self,
        thread: &dyn TraceThread,
        create_if_absent: bool,
    ) -> Option<RegisterContextSpaceHandle>;

    /// Get (or lazily build and memoize) the language-defined default register context. Mirrors
    /// `getDefaultContext(Language)`, which builds and caches a `ProgramContextImpl(language)`
    /// (with `language.applyContextSettings(...)` applied) per distinct language.
    fn get_default_context(&self, language: &dyn Language) -> Box<dyn ProgramContext>;

    /// Get (or, if `create_if_absent`, create) the register-context space for `space`. Mirrors the
    /// class's public override of `AbstractDBTraceSpaceBasedManager.getForSpace`
    /// (`getRegisterContextSpace(AddressSpace, boolean)`, declared on the `TraceRegisterContextManager`
    /// interface).
    fn get_register_context_space(
        &self,
        space: &Arc<AddressSpace>,
        create_if_absent: bool,
    ) -> Option<RegisterContextSpaceHandle>
    where
        Self: Sized,
    {
        self.get_for_space(space, create_if_absent)
    }

    /// Mirrors `getDefaultValue(Language, Register, Address)`.
    fn get_default_value(
        &self,
        language: &dyn Language,
        register: &Register,
        address: &Address,
    ) -> Option<Box<dyn RegisterValue>>
    where
        Self: Sized,
    {
        self.get_default_context(language).get_default_value(register, address)
    }

    /// Mirrors `setValue(Language, RegisterValue, Lifespan, AddressRange)`.
    fn set_value(
        &self,
        language: &dyn Language,
        value: &dyn RegisterValue,
        lifespan: &dyn Lifespan,
        range: &AddressRange,
    ) where
        Self: Sized,
    {
        let _: Result<(), ()> = self.delegate_write_v(range.space(), |m| {
            m.set_value(language, value, lifespan, range);
            Ok(())
        });
    }

    /// Mirrors `removeValue(Language, Register, Lifespan, AddressRange)`.
    fn remove_value(
        &self,
        language: &dyn Language,
        register: &Register,
        span: &dyn Lifespan,
        range: &AddressRange,
    ) where
        Self: Sized,
    {
        let _: Result<(), ()> = self.delegate_delete_v(range.space(), |m| {
            m.remove_value(language, register, span, range);
            Ok(())
        });
    }

    /// Mirrors `getValue(Language, Register, long, Address)`.
    fn get_value(
        &self,
        language: &dyn Language,
        register: &Register,
        snap: i64,
        address: &Address,
    ) -> Option<Box<dyn RegisterValue>>
    where
        Self: Sized,
    {
        let result: Result<Option<Option<Box<dyn RegisterValue>>>, ()> =
            self.delegate_read(address.space(), |m| Ok(m.get_value(language, register, snap, address)));
        match result {
            Ok(Some(value)) => value,
            _ => None,
        }
    }

    /// Mirrors `getEntry(Language, Register, long, Address)`.
    fn get_entry(
        &self,
        language: &dyn Language,
        register: &Register,
        snap: i64,
        address: &Address,
    ) -> Option<(Box<dyn TraceAddressSnapRange>, Box<dyn RegisterValue>)>
    where
        Self: Sized,
    {
        let result: Result<Option<Option<(Box<dyn TraceAddressSnapRange>, Box<dyn RegisterValue>)>>, ()> =
            self.delegate_read(address.space(), |m| Ok(m.get_entry(language, register, snap, address)));
        match result {
            Ok(Some(entry)) => entry,
            _ => None,
        }
    }

    /// Mirrors `getValueWithDefault(TracePlatform, Register, long, Address)`.
    fn get_value_with_default(
        &self,
        platform: &dyn TracePlatform,
        register: &Register,
        snap: i64,
        address: &Address,
    ) -> Option<Box<dyn RegisterValue>>
    where
        Self: Sized,
    {
        let language = platform.platform_language();
        let Some(host_address) = platform.map_guest_to_host(address.clone()) else {
            return self.get_default_value(language.as_ref(), register, address);
        };
        let result: Result<Option<Box<dyn RegisterValue>>, ()> = self.delegate_read_or(
            host_address.space(),
            |m| Ok(m.get_value_with_default(language.as_ref(), register, snap, &host_address, address)),
            || Ok(self.get_default_value(language.as_ref(), register, address)),
        );
        result.expect("delegate_read_or closures are infallible")
    }

    /// Mirrors `getRegisterValueAddressRanges(Language, Register, long, AddressRange)`.
    fn get_register_value_address_ranges_within(
        &self,
        language: &dyn Language,
        register: &Register,
        snap: i64,
        within: &AddressRange,
    ) -> Box<dyn AddressSetView>
    where
        Self: Sized,
    {
        let result: Result<Box<dyn AddressSetView>, ()> = self.delegate_read_with_default(
            within.space(),
            |m| Ok(m.get_register_value_address_ranges_within(language, register, snap, within)),
            Box::new(AddressSet::new()),
        );
        result.expect("delegate_read_with_default closure is infallible")
    }

    /// Mirrors the all-space overload `getRegisterValueAddressRanges(Language, Register, long)`.
    fn get_register_value_address_ranges(
        &self,
        language: &dyn Language,
        register: &Register,
        snap: i64,
    ) -> Box<dyn AddressSetView>
    where
        Self: Sized,
    {
        let spaces = self.get_active_spaces();
        let result: Result<AddressSet, ()> = self.delegate_address_set(spaces, |m| {
            Ok(AddressSet::from_set(&*m.get_register_value_address_ranges(
                language, register, snap,
            )))
        });
        Box::new(result.expect("delegate_address_set closure is infallible"))
    }

    /// Mirrors `hasRegisterValueInAddressRange(Language, Register, long, AddressRange)`.
    fn has_register_value_in_address_range(
        &self,
        language: &dyn Language,
        register: &Register,
        snap: i64,
        within: &AddressRange,
    ) -> bool
    where
        Self: Sized,
    {
        self.delegate_read_b(
            within.space(),
            |m| m.has_register_value_in_address_range(language, register, snap, within),
            false,
        )
    }

    /// Mirrors the all-space overload `hasRegisterValue(Language, Register, long)`.
    fn has_register_value(&self, language: &dyn Language, register: &Register, snap: i64) -> bool
    where
        Self: Sized,
    {
        let spaces = self.get_active_spaces();
        self.delegate_any(spaces, |m| Ok::<_, ()>(m.has_register_value(language, register, snap)))
            .expect("delegate_any closure is infallible")
    }

    /// Mirrors `clear(Lifespan, AddressRange)`.
    fn clear(&self, span: &dyn Lifespan, range: &AddressRange)
    where
        Self: Sized,
    {
        let _: Result<(), ()> = self.delegate_delete_v(range.space(), |m| {
            m.clear(span, range);
            Ok(())
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpaceType, EmptyAddressRangeIterator};
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::lang::language::ParseError;
    use crate::program::model::lang::language_description::LanguageDescription;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper;
    use crate::program::model::lang::processor_context::ProcessorContext;
    use crate::program::model::lang::register::RegisterRef;
    use crate::program::model::listing::context_change_exception::ContextChangeException;
    use crate::program::model::mem::MemBuffer;
    use crate::program::seam_stubs::{AddressLabelInfo, Processor};
    use crate::trace::model::lifespan::Lifespan as LifespanTrait;
    use crate::util::lock_hold::Lock;
    use std::cell::RefCell;
    use std::sync::Mutex;
    use std::collections::HashMap;

    struct NoopLock;
    impl Lock for NoopLock {
        fn lock(&self) {}
        fn unlock(&self) {}
    }

    struct MockLanguage;
    impl Language for MockLanguage {
        fn get_language_id(&self) -> LanguageID {
            LanguageID::new("mock:LE:32:default").unwrap()
        }
        fn get_language_description(&self) -> Box<dyn LanguageDescription> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_parallel_instruction_helper(&self) -> Option<Box<dyn ParallelInstructionLanguageHelper>> {
            None
        }
        fn get_processor(&self) -> Box<dyn Processor> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_instruction_alignment(&self) -> i32 {
            1
        }
        fn supports_pcode(&self) -> bool {
            true
        }
        fn is_volatile(&self, _addr: &Address) -> bool {
            false
        }
        fn parse(
            &self,
            _buf: &dyn MemBuffer,
            _context: &mut dyn ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<Box<dyn InstructionPrototype>, ParseError> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }
        fn get_registers_at(&self, _address: &Address) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_in_space(
            &self,
            _addrspc: &Arc<AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_register_by_name(&self, _name: &str) -> Option<RegisterRef> {
            None
        }
        fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<RegisterRef> {
            None
        }
        fn get_program_counter(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_base_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_default_memory_blocks(
            &self,
        ) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
            Vec::new()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn AddressLabelInfo>> {
            Vec::new()
        }
        fn get_segmented_space(&self) -> String {
            String::new()
        }
        fn get_volatile_addresses(&self) -> Box<dyn AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn apply_context_settings(
            &self,
            _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext,
        ) {
        }
        fn reload_language(&self, _task_monitor: &dyn crate::util::task::TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(
            &self,
        ) -> Vec<Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>>
        {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
        ) -> Result<
            Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec>,
            crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException,
        > {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_default_compiler_spec(&self) -> Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
        }
        fn has_property(&self, _key: &str) -> bool {
            false
        }
        fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
            default_int
        }
        fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
            default_boolean
        }
        fn get_property_or(&self, _key: &str, default_string: &str) -> String {
            default_string.to_string()
        }
        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }
        fn get_property_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }
        fn has_manual(&self) -> bool {
            false
        }
        fn get_manual_entry(&self, _instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }
        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_addresses(&self) -> Box<dyn AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    struct MockRegisterValue {
        register: RegisterRef,
        value: u128,
    }

    impl RegisterValue for MockRegisterValue {
        fn get_register(&self) -> RegisterRef {
            self.register.clone()
        }
        fn get_register_value(&self, register: &Register) -> Box<dyn RegisterValue> {
            Box::new(MockRegisterValue { register: Register::from_register(register), value: self.value })
        }
        fn has_any_value(&self) -> bool {
            true
        }
        fn get_unsigned_value_ignore_mask(&self) -> u128 {
            self.value
        }
        fn has_value(&self) -> bool {
            self.has_any_value()
        }
        fn combine_values(&self, _other: &dyn RegisterValue) -> Box<dyn RegisterValue> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    #[derive(Clone, Copy)]
    struct MockLifespan {
        min: i64,
        max: i64,
    }

    impl LifespanTrait for MockLifespan {
        fn lmin(&self) -> i64 {
            self.min
        }
        fn lmax(&self) -> i64 {
            self.max
        }
        fn contains(&self, n: i64) -> bool {
            self.min <= n && n <= self.max
        }
        fn with_min(&self, min: i64) -> Box<dyn LifespanTrait> {
            Box::new(MockLifespan { min, max: self.max })
        }
        fn with_max(&self, max: i64) -> Box<dyn LifespanTrait> {
            Box::new(MockLifespan { min: self.min, max })
        }
        fn iter(&self) -> Box<dyn Iterator<Item = i64> + '_> {
            Box::new(self.min..=self.max)
        }
    }

    #[derive(Clone)]
    struct MockSnapRange {
        range: AddressRange,
        lifespan: MockLifespan,
    }

    impl TraceAddressSnapRange for MockSnapRange {
        fn get_lifespan(&self) -> Box<dyn LifespanTrait> {
            Box::new(self.lifespan)
        }
        fn get_range(&self) -> AddressRange {
            self.range.clone()
        }
        fn get_bounds(&self) -> Box<dyn TraceAddressSnapRange> {
            Box::new(self.clone())
        }
        fn immutable(&self, x1: Address, x2: Address, y1: i64, y2: i64) -> Box<dyn TraceAddressSnapRange> {
            Box::new(MockSnapRange { range: AddressRange::new(x1, x2), lifespan: MockLifespan { min: y1, max: y2 } })
        }
    }

    struct MockPlatform {
        language: MockLanguage,
    }

    impl TracePlatform for MockPlatform {
        fn platform_language(&self) -> Box<dyn Language> {
            Box::new(MockLanguage)
        }
        fn map_guest_to_host(&self, address: Address) -> Option<Address> {
            let _ = &self.language;
            Some(address)
        }
    }

    struct MockProgramContext;

    impl ProgramContext for MockProgramContext {
        fn has_non_flowing_context(&self) -> bool {
            false
        }
        fn get_flow_value(&self, value: Box<dyn RegisterValue>) -> Box<dyn RegisterValue> {
            value
        }
        fn get_non_flow_value(&self, _value: Box<dyn RegisterValue>) -> Option<Box<dyn RegisterValue>> {
            None
        }
        fn get_register(&self, _name: &str) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_registers_with_values(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_value(&self, _register: &Register, _address: &Address, _signed: bool) -> Option<i128> {
            None
        }
        fn get_register_value(&self, _register: &Register, _address: &Address) -> Option<Box<dyn RegisterValue>> {
            None
        }
        fn set_register_value(
            &mut self,
            _start: &Address,
            _end: &Address,
            _value: Box<dyn RegisterValue>,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn get_non_default_value(&self, _register: &Register, _address: &Address) -> Option<Box<dyn RegisterValue>> {
            None
        }
        fn set_value(
            &mut self,
            _register: &Register,
            _start: &Address,
            _end: &Address,
            _value: Option<i128>,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn get_register_value_address_ranges(
            &self,
            _register: &Register,
        ) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            Box::new(EmptyAddressRangeIterator)
        }
        fn get_register_value_address_ranges_in_range(
            &self,
            _register: &Register,
            _start: &Address,
            _end: &Address,
        ) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            Box::new(EmptyAddressRangeIterator)
        }
        fn get_register_value_range_containing(&self, _register: &Register, addr: &Address) -> AddressRange {
            AddressRange::new(addr.clone(), addr.clone())
        }
        fn get_default_register_value_address_ranges(
            &self,
            _register: &Register,
        ) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            Box::new(EmptyAddressRangeIterator)
        }
        fn get_default_register_value_address_ranges_in_range(
            &self,
            _register: &Register,
            _start: &Address,
            _end: &Address,
        ) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            Box::new(EmptyAddressRangeIterator)
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn remove(
            &mut self,
            _start: &Address,
            _end: &Address,
            _register: &Register,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn get_register_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn has_value_over_range(&self, _reg: &Register, _value: i128, _addr_set: &dyn AddressSetView) -> bool {
            false
        }
        fn get_default_value(&self, register: &Register, _address: &Address) -> Option<Box<dyn RegisterValue>> {
            Some(Box::new(MockRegisterValue { register: Register::from_register(register), value: 0xdefa17 }))
        }
        fn get_base_context_register(&self) -> RegisterRef {
            panic!("no base context register in mock")
        }
        fn get_default_disassembly_context(&self) -> Box<dyn RegisterValue> {
            Box::new(MockRegisterValue { register: mock_register(), value: 0 })
        }
        fn set_default_disassembly_context(&mut self, _value: Box<dyn RegisterValue>) {}
        fn get_disassembly_context(&self, _address: &Address) -> Box<dyn RegisterValue> {
            Box::new(MockRegisterValue { register: mock_register(), value: 0 })
        }
    }

    /// A minimal in-memory implementor of [`DBTraceRegisterContextSpace`], backed by a single
    /// `(snap, range, value)` slot, sufficient to prove object-safety and exercise real
    /// set/get/clear behavior through the manager's delegate defaults.
    struct MockSpace {
        space: Arc<AddressSpace>,
        entries: Mutex<HashMap<i64, (AddressRange, u128)>>,
    }

    impl DBTraceRegisterContextSpace for MockSpace {
        fn get_address_space(&self) -> Arc<AddressSpace> {
            self.space.clone()
        }
        fn set_value(&self, _language: &dyn Language, value: &dyn RegisterValue, lifespan: &dyn LifespanTrait, range: &AddressRange) {
            self.entries
                .lock()
                .unwrap()
                .insert(lifespan.lmin(), (range.clone(), value.get_unsigned_value_ignore_mask()));
        }
        fn remove_value(&self, _language: &dyn Language, _register: &Register, span: &dyn LifespanTrait, _range: &AddressRange) {
            self.entries.lock().unwrap().remove(&span.lmin());
        }
        fn get_value(&self, _language: &dyn Language, register: &Register, snap: i64, address: &Address) -> Option<Box<dyn RegisterValue>> {
            let entries = self.entries.lock().unwrap();
            let (range, value) = entries.get(&snap)?;
            if !range.contains(address) {
                return None;
            }
            Some(Box::new(MockRegisterValue { register: Register::from_register(register), value: *value }))
        }
        fn get_entry(
            &self,
            _language: &dyn Language,
            register: &Register,
            snap: i64,
            address: &Address,
        ) -> Option<(Box<dyn TraceAddressSnapRange>, Box<dyn RegisterValue>)> {
            let entries = self.entries.lock().unwrap();
            let (range, value) = entries.get(&snap)?;
            if !range.contains(address) {
                return None;
            }
            let snap_range: Box<dyn TraceAddressSnapRange> =
                Box::new(MockSnapRange { range: range.clone(), lifespan: MockLifespan { min: snap, max: snap } });
            let reg_value: Box<dyn RegisterValue> =
                Box::new(MockRegisterValue { register: Register::from_register(register), value: *value });
            Some((snap_range, reg_value))
        }
        fn get_value_with_default(
            &self,
            language: &dyn Language,
            register: &Register,
            snap: i64,
            host_address: &Address,
            _guest_address: &Address,
        ) -> Option<Box<dyn RegisterValue>> {
            self.get_value(language, register, snap, host_address)
        }
        fn get_register_value_address_ranges_within(
            &self,
            _language: &dyn Language,
            _register: &Register,
            snap: i64,
            within: &AddressRange,
        ) -> Box<dyn AddressSetView> {
            let mut set = AddressSet::new();
            if let Some((range, _)) = self.entries.lock().unwrap().get(&snap) {
                if let Some(intersection) = range.intersect(within) {
                    set.add_range_object(&intersection);
                }
            }
            Box::new(set)
        }
        fn get_register_value_address_ranges(&self, _language: &dyn Language, _register: &Register, snap: i64) -> Box<dyn AddressSetView> {
            let mut set = AddressSet::new();
            if let Some((range, _)) = self.entries.lock().unwrap().get(&snap) {
                set.add_range_object(range);
            }
            Box::new(set)
        }
        fn has_register_value_in_address_range(
            &self,
            _language: &dyn Language,
            _register: &Register,
            snap: i64,
            within: &AddressRange,
        ) -> bool {
            self.entries.lock().unwrap().get(&snap).is_some_and(|(range, _)| range.intersects(within))
        }
        fn has_register_value(&self, _language: &dyn Language, _register: &Register, snap: i64) -> bool {
            self.entries.lock().unwrap().contains_key(&snap)
        }
        fn clear(&self, span: &dyn LifespanTrait, _range: &AddressRange) {
            self.entries.lock().unwrap().remove(&span.lmin());
        }
    }

    struct MockManager {
        read_lock: NoopLock,
        write_lock: NoopLock,
        spaces: RefCell<HashMap<String, RegisterContextSpaceHandle>>,
    }

    impl DBTraceDelegatingManager<RegisterContextSpaceHandle> for MockManager {
        fn read_lock(&self) -> &dyn Lock {
            &self.read_lock
        }
        fn write_lock(&self) -> &dyn Lock {
            &self.write_lock
        }
        fn get_for_space(&self, space: &Arc<AddressSpace>, create_if_absent: bool) -> Option<RegisterContextSpaceHandle> {
            let mut spaces = self.spaces.borrow_mut();
            if create_if_absent {
                Some(
                    spaces
                        .entry(space.name().to_string())
                        .or_insert_with(|| Arc::new(MockSpace { space: space.clone(), entries: Mutex::new(HashMap::new()) }))
                        .clone(),
                )
            } else {
                spaces.get(space.name()).cloned()
            }
        }
    }

    impl DBTraceRegisterContextManager for MockManager {
        fn get_active_spaces(&self) -> Vec<RegisterContextSpaceHandle> {
            self.spaces.borrow().values().cloned().collect()
        }
        fn get_register_context_register_space(&self, _thread: &dyn TraceThread, create_if_absent: bool) -> Option<RegisterContextSpaceHandle> {
            self.get_for_space(&ram_space("registers"), create_if_absent)
        }
        fn get_default_context(&self, _language: &dyn Language) -> Box<dyn ProgramContext> {
            // Real Java memoizes this per language (`defaultContexts.computeIfAbsent`); this mock
            // skips the cache since none of this trait's default methods observe identity across
            // calls, only the value `get_default_value` returns.
            Box::new(MockProgramContext)
        }
    }

    fn ram_space(name: &str) -> Arc<AddressSpace> {
        AddressSpace::new(name, 32, 1, AddressSpaceType::Ram, 0)
    }

    fn mock_register() -> RegisterRef {
        let space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 1);
        Register::new("context", "Processor context register", Address::new(space, 0), 4, false, Register::TYPE_NONE)
    }

    fn mock_manager() -> MockManager {
        MockManager { read_lock: NoopLock, write_lock: NoopLock, spaces: RefCell::new(HashMap::new()) }
    }

    #[test]
    fn set_get_and_clear_round_trip_through_delegate_defaults() {
        let mgr = mock_manager();
        let space = ram_space("ram");
        let range = AddressRange::new(Address::new(space.clone(), 0), Address::new(space.clone(), 0xf));
        let addr = Address::new(space.clone(), 4);
        let register = mock_register();
        let language = MockLanguage;
        let lifespan = MockLifespan { min: 0, max: 10 };
        let value = MockRegisterValue { register: register.clone(), value: 0x2a };

        assert!(!mgr.has_register_value(&language, &register.borrow(), 0));

        mgr.set_value(&language, &value, &lifespan, &range);

        assert!(mgr.has_register_value(&language, &register.borrow(), 0));
        assert!(mgr.has_register_value_in_address_range(&language, &register.borrow(), 0, &range));

        let got = mgr.get_value(&language, &register.borrow(), 0, &addr).unwrap();
        assert_eq!(got.get_unsigned_value_ignore_mask(), 0x2a);

        let ranges = mgr.get_register_value_address_ranges(&language, &register.borrow(), 0);
        assert!(ranges.contains(&addr));

        let (entry_range, entry_value) = mgr.get_entry(&language, &register.borrow(), 0, &addr).unwrap();
        assert_eq!(entry_range.get_range(), range);
        assert_eq!(entry_value.get_unsigned_value_ignore_mask(), 0x2a);

        mgr.remove_value(&language, &register.borrow(), &lifespan, &range);
        assert!(!mgr.has_register_value(&language, &register.borrow(), 0));

        mgr.set_value(&language, &value, &lifespan, &range);
        mgr.clear(&lifespan, &range);
        assert!(!mgr.has_register_value(&language, &register.borrow(), 0));
    }

    #[test]
    fn get_default_value_uses_cached_default_context() {
        let mgr = mock_manager();
        let register = mock_register();
        let addr = Address::new(ram_space("ram"), 4);
        let language = MockLanguage;

        let value = mgr.get_default_value(&language, &register.borrow(), &addr).unwrap();
        assert_eq!(value.get_unsigned_value_ignore_mask(), 0xdefa17);
    }

    #[test]
    fn get_value_with_default_falls_back_to_default_when_unset() {
        let mgr = mock_manager();
        let register = mock_register();
        let addr = Address::new(ram_space("ram"), 4);
        let platform = MockPlatform { language: MockLanguage };

        let value = mgr.get_value_with_default(&platform, &register.borrow(), 0, &addr).unwrap();
        assert_eq!(value.get_unsigned_value_ignore_mask(), 0xdefa17);
    }

    /// Proves the required trio (inherited `read_lock`/`write_lock`/`get_for_space`, plus
    /// `get_active_spaces`/`get_register_context_register_space`/`get_default_context`) is
    /// object-safe.
    #[test]
    fn usable_as_trait_object() {
        let mgr = mock_manager();
        let obj: &dyn DBTraceRegisterContextManager = &mgr;
        assert!(obj.get_active_spaces().is_empty());
        obj.write_lock().lock();
        obj.write_lock().unlock();
    }
}
