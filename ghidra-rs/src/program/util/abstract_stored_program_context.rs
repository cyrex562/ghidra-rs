//! Port of `ghidra.program.util.AbstractStoredProgramContext`.
//!
//! Adds persistence-oriented value storage on top of [`AbstractProgramContext`]: a
//! `Register -> RegisterValueStore` map for "current" values and a second one for "default"
//! values, plus the address-range query surface `ProgramContext`/`DefaultProgramContext` expose.
//! Composes [`AbstractProgramContext`] (this session's established "composition over
//! inheritance" convention for a Java `extends`) and fully implements both traits.
//!
//! ## Where the backing store comes from
//!
//! Java's `AbstractStoredProgramContext` declares `createNewRangeMapAdapter` as `abstract`,
//! overridden by the concrete subclass (`ProgramRegisterContextDB` supplies a
//! `DatabaseRangeMapAdapter`). This port takes that as a constructor-supplied closure instead of
//! an abstract method, matching the same idiom already used for pluggable strategies elsewhere in
//! this port.
//!
//! ## `&self` methods that read through a `RegisterValueStore`
//!
//! Several trait methods here are `&self` (e.g. `get_register_value_address_ranges`) but need to
//! flush a store's pending write-cache before iterating it, which
//! [`RegisterValueStore`](crate::program::util::register_value_store::RegisterValueStore)'s own
//! API expresses as `&mut self`. Each stored `RegisterValueStore` is therefore wrapped in a
//! `RefCell` (this session's convention for exactly this shape) so those methods can still borrow
//! mutably through a shared `&self`.
//!
//! ## Known gap: overlay address space redirection
//!
//! Java's `getRegisterValue`/`getDefaultValue` redirect an address in an overlay space to the
//! corresponding address in the overlaid physical space before looking up a *default* value
//! (`address.getAddressSpace().isOverlaySpace()` / `OverlayAddressSpace.translateAddress`). This
//! crate's `Address`/`AddressSpace` (the concrete types actually returned by `Address::space()`)
//! have no overlay concept integrated -- `AddressSpaceType` has no `Overlay` variant, and no
//! `is_overlay_space()`/translation method exists on the concrete `AddressSpace` -- so that
//! redirection is not implemented here. In practice this only matters for addresses in overlay
//! memory blocks, and it degrades gracefully: default-value lookups for such addresses use the
//! overlay address directly rather than being redirected to the physical space's stored default,
//! which just means an overlay-specific address won't inherit a default value set on the
//! underlying physical space. The unrelated `AddressSpaceType::Unknown` branch in
//! `getDefaultValue` *is* implemented, since that variant does exist in this crate's enum.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use crate::program::database::register::in_memory_range_map_adapter::InMemoryRangeMapAdapter;
use crate::program::model::address::{
    Address, AddressRange, AddressRangeIterator, AddressRangeIteratorAdapter, AddressSetView, AddressSpaceType,
};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::lang::register_value::RegisterValue;
use crate::program::model::listing::context_change_exception::ContextChangeException;
use crate::program::model::listing::default_program_context::DefaultProgramContext;
use crate::program::model::listing::program_context::ProgramContext;
use crate::program::seam_stubs::RegisterValue as RegisterValueTrait;
use crate::program::util::abstract_program_context::AbstractProgramContext;
use crate::program::util::register_value_store::RegisterValueStore;
use crate::program::util::RangeMapAdapter;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;
use std::sync::Arc;

/// Shared, real logic for a persistence-oriented processor register context.
///
/// Port of `ghidra.program.util.AbstractStoredProgramContext`.
pub struct AbstractStoredProgramContext {
    base: AbstractProgramContext,
    create_range_map_adapter: Box<dyn Fn(&RegisterRef) -> Box<dyn RangeMapAdapter>>,
    register_value_map: HashMap<String, RefCell<RegisterValueStore>>,
    default_register_value_map: HashMap<String, RefCell<RegisterValueStore>>,
    /// Cached set of register names with at least one value; `None` means "needs recomputing".
    registers_with_values: RefCell<Option<HashSet<String>>>,
}

impl AbstractStoredProgramContext {
    /// Constructs a new context for `language`, using `create_range_map_adapter` to build the
    /// backing store for a base register's "current value" map the first time it is needed.
    pub fn new(
        language: Arc<dyn Language>,
        create_range_map_adapter: Box<dyn Fn(&RegisterRef) -> Box<dyn RangeMapAdapter>>,
    ) -> Self {
        Self {
            base: AbstractProgramContext::new(language),
            create_range_map_adapter,
            register_value_map: HashMap::new(),
            default_register_value_map: HashMap::new(),
            registers_with_values: RefCell::new(None),
        }
    }

    /// Read-only access to the composed [`AbstractProgramContext`], for subclasses/composers
    /// that need the shared bookkeeping directly (mirrors the `protected` fields Java's
    /// subclasses reach into).
    pub fn base(&self) -> &AbstractProgramContext {
        &self.base
    }

    /// Mutable access to the composed [`AbstractProgramContext`].
    pub fn base_mut(&mut self) -> &mut AbstractProgramContext {
        &mut self.base
    }

    /// Resolves a `&Register` (as supplied by every `ProgramContext` trait method) into this
    /// context's own [`RegisterRef`] for the same register, via a language lookup by name.
    fn resolve(&self, register: &Register) -> RegisterRef {
        self.base
            .language()
            .get_register_by_name(register.name())
            .unwrap_or_else(|| panic!("register '{}' not found in this context's language", register.name()))
    }

    fn base_register_key(register: &RegisterRef) -> String {
        register.borrow().get_base_register().borrow().name().to_string()
    }

    /// Flush any cached context not yet written to the backing store.
    ///
    /// Port of `AbstractStoredProgramContext.flushProcessorContextWriteCache()`.
    pub fn flush_processor_context_write_cache(&mut self) {
        let key = Self::base_register_key(&self.base.get_base_context_register());
        if let Some(store) = self.register_value_map.get(&key) {
            store.borrow_mut().flush_write_cache();
        }
    }

    /// Discard any cached context not yet written to the backing store.
    ///
    /// Port of `AbstractStoredProgramContext.invalidateProcessorContextWriteCache()`.
    pub fn invalidate_processor_context_write_cache(&mut self) {
        let key = Self::base_register_key(&self.base.get_base_context_register());
        if let Some(store) = self.register_value_map.get(&key) {
            store.borrow_mut().invalidate_write_cache();
        }
    }

    /// Move all register values within an address range to a new range.
    ///
    /// # Errors
    /// Returns [`CancelledException`] if the user cancelled the operation via `monitor`.
    pub fn move_address_range(
        &mut self,
        from_addr: &Address,
        to_addr: &Address,
        length: u64,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        for store in self.register_value_map.values_mut() {
            store.get_mut().move_address_range(from_addr, to_addr, length, monitor)?;
        }
        Ok(())
    }

    fn ensure_register_value_store(&mut self, base_register: &RegisterRef) -> String {
        let key = base_register.borrow().name().to_string();
        if !self.register_value_map.contains_key(&key) {
            let adapter = (self.create_range_map_adapter)(base_register);
            let enable_cache = base_register.borrow().is_processor_context();
            self.register_value_map
                .insert(key.clone(), RefCell::new(RegisterValueStore::new(base_register, adapter, enable_cache)));
        }
        key
    }

    fn add_register_with_value(set: &mut HashSet<String>, register: &RegisterRef) {
        set.insert(register.borrow().name().to_string());
        for child in register.borrow().child_registers() {
            Self::add_register_with_value(set, &child);
        }
    }

    /// Delete all register values within `[start, end]` and invalidate the read cache.
    ///
    /// Port of `AbstractStoredProgramContext.deleteAddressRange(Address, Address, TaskMonitor)`.
    /// The `monitor` parameter is accepted for signature fidelity but unused, matching Java (the
    /// real method never calls it either).
    pub fn delete_address_range(&mut self, start: &Address, end: &Address, _monitor: &dyn TaskMonitor) {
        for store in self.register_value_map.values() {
            store.borrow_mut().clear_value(start, end, None);
        }
        self.invalidate_read_cache();
    }

    fn get_register_value_internal(
        &self,
        register: &RegisterRef,
        address: &Address,
        map: &HashMap<String, RefCell<RegisterValueStore>>,
    ) -> Option<RegisterValue> {
        // NOTE: Java additionally redirects `address` for overlay-space lookups against the
        // *default* map here; not implemented, see this module's doc comment.
        let key = Self::base_register_key(register);
        let store = map.get(&key)?;
        let store = store.borrow();
        if store.is_empty() {
            return None;
        }
        store.get_value(register, address)
    }

    fn filtered_range_iterator(
        &self,
        register: &RegisterRef,
        map: &HashMap<String, RefCell<RegisterValueStore>>,
        window: Option<(&Address, &Address)>,
    ) -> Box<dyn AddressRangeIterator> {
        let key = Self::base_register_key(register);
        let Some(store_cell) = map.get(&key) else {
            return Box::new(AddressRangeIteratorAdapter::new(Vec::new()));
        };
        let mut store = store_cell.borrow_mut();
        if store.is_empty() {
            return Box::new(AddressRangeIteratorAdapter::new(Vec::new()));
        }
        let raw: Vec<AddressRange> = match window {
            Some((start, end)) => store.get_address_range_iterator_in_range(start, end).collect(),
            None => store.get_address_range_iterator().collect(),
        };
        drop(store);
        let store = store_cell.borrow();

        let mut out = Vec::with_capacity(raw.len());
        for range in raw {
            if let Some(value) = store.get_value(register, range.min_address()) {
                if value.has_any_value() {
                    out.push(range);
                }
            }
        }
        Box::new(AddressRangeIteratorAdapter::new(out))
    }

    fn invalidate_read_cache(&mut self) {
        *self.registers_with_values.borrow_mut() = None;
    }

    fn invalidate_write_cache(&mut self) {
        let key = Self::base_register_key(&self.base.get_base_context_register());
        if let Some(store) = self.register_value_map.get(&key) {
            store.borrow_mut().invalidate_write_cache();
        }
    }

    fn compute_registers_with_values(&self) -> HashSet<String> {
        if let Some(existing) = self.registers_with_values.borrow().as_ref() {
            return existing.clone();
        }
        let mut set = HashSet::new();
        for register in self.base.get_registers() {
            let key = Self::base_register_key(&register);
            let has_current = self.register_value_map.get(&key).is_some_and(|s| !s.borrow().is_empty());
            let has_default = self.default_register_value_map.get(&key).is_some_and(|s| !s.borrow().is_empty());
            if has_current || has_default {
                set.insert(register.borrow().name().to_string());
            }
        }
        *self.registers_with_values.borrow_mut() = Some(set.clone());
        set
    }

    fn get_default_value_impl(&self, register: &Register, address: &Address) -> Option<Box<dyn RegisterValueTrait>> {
        let reg = self.resolve(register);
        let space = address.space();
        if space.space_type() == AddressSpaceType::Unknown {
            return Some(Box::new(RegisterValue::new(reg)));
        }
        // NOTE: overlay-space redirection not implemented; see this module's doc comment.
        self.get_register_value_internal(&reg, address, &self.default_register_value_map)
            .map(|v| Box::new(v) as Box<dyn RegisterValueTrait>)
    }
}

impl ProgramContext for AbstractStoredProgramContext {
    fn has_non_flowing_context(&self) -> bool {
        self.base.has_non_flowing_context()
    }

    fn get_flow_value(&self, value: Box<dyn RegisterValueTrait>) -> Box<dyn RegisterValueTrait> {
        self.base.get_flow_value(value)
    }

    fn get_non_flow_value(&self, value: Box<dyn RegisterValueTrait>) -> Option<Box<dyn RegisterValueTrait>> {
        self.base.get_non_flow_value(value)
    }

    fn get_register(&self, name: &str) -> Option<RegisterRef> {
        self.base.get_register(name)
    }

    fn get_registers(&self) -> Vec<RegisterRef> {
        self.base.get_registers()
    }

    fn get_registers_with_values(&self) -> Vec<RegisterRef> {
        self.compute_registers_with_values()
            .iter()
            .filter_map(|name| self.base.language().get_register_by_name(name))
            .collect()
    }

    fn get_value(&self, register: &Register, address: &Address, signed: bool) -> Option<i128> {
        let boxed = ProgramContext::get_register_value(self, register, address)?;
        let concrete = RegisterValue::from_trait_object(boxed.as_ref());
        if signed { concrete.signed_value() } else { concrete.unsigned_value().map(|v| v as i128) }
    }

    fn get_register_value(&self, register: &Register, address: &Address) -> Option<Box<dyn RegisterValueTrait>> {
        let reg = self.resolve(register);
        let register_value = self.get_register_value_internal(&reg, address, &self.register_value_map);

        if let Some(rv) = &register_value {
            if rv.has_value() {
                return Some(Box::new(rv.clone()));
            }
        }

        let default_register_value = self.get_register_value_internal(&reg, address, &self.default_register_value_map);
        if let Some(drv) = default_register_value {
            let combined = match &register_value {
                Some(rv) => drv.combine_values(rv),
                None => drv,
            };
            return Some(Box::new(combined));
        }
        register_value.map(|v| Box::new(v) as Box<dyn RegisterValueTrait>)
    }

    fn set_register_value(
        &mut self,
        start: &Address,
        end: &Address,
        value: Box<dyn RegisterValueTrait>,
    ) -> Result<(), ContextChangeException> {
        let concrete = RegisterValue::from_trait_object(value.as_ref());
        let base_register = concrete.register().borrow().get_base_register();
        let key = self.ensure_register_value_store(&base_register);
        self.register_value_map.get(&key).expect("just ensured").borrow_mut().set_value(start, end, &concrete);

        let mut cache = self.registers_with_values.borrow_mut();
        if let Some(set) = cache.as_mut() {
            if !set.contains(&key) {
                Self::add_register_with_value(set, &base_register);
            }
        }
        Ok(())
    }

    fn get_non_default_value(&self, register: &Register, address: &Address) -> Option<Box<dyn RegisterValueTrait>> {
        let reg = self.resolve(register);
        self.get_register_value_internal(&reg, address, &self.register_value_map)
            .map(|v| Box::new(v) as Box<dyn RegisterValueTrait>)
    }

    fn set_value(
        &mut self,
        register: &Register,
        start: &Address,
        end: &Address,
        value: Option<i128>,
    ) -> Result<(), ContextChangeException> {
        assert!(start.same_address_space(end), "start and end address must be within the same address space");
        let Some(value) = value else {
            return ProgramContext::remove(self, start, end, register);
        };
        let reg = self.resolve(register);
        let rv = RegisterValue::with_value(reg, value as u128);
        ProgramContext::set_register_value(self, start, end, Box::new(rv))
    }

    fn get_register_value_address_ranges(&self, register: &Register) -> Box<dyn AddressRangeIterator> {
        let reg = self.resolve(register);
        self.filtered_range_iterator(&reg, &self.register_value_map, None)
    }

    fn get_register_value_address_ranges_in_range(
        &self,
        register: &Register,
        start: &Address,
        end: &Address,
    ) -> Box<dyn AddressRangeIterator> {
        let reg = self.resolve(register);
        self.filtered_range_iterator(&reg, &self.register_value_map, Some((start, end)))
    }

    fn get_register_value_range_containing(&self, register: &Register, addr: &Address) -> AddressRange {
        let reg = self.resolve(register);
        let key = Self::base_register_key(&reg);
        let Some(store) = self.register_value_map.get(&key) else {
            return AddressRange::new(addr.clone(), addr.clone());
        };
        let mut store = store.borrow_mut();
        if store.is_empty() {
            return AddressRange::new(addr.clone(), addr.clone());
        }
        store.get_value_range_containing(addr)
    }

    fn get_default_register_value_address_ranges(&self, register: &Register) -> Box<dyn AddressRangeIterator> {
        let reg = self.resolve(register);
        self.filtered_range_iterator(&reg, &self.default_register_value_map, None)
    }

    fn get_default_register_value_address_ranges_in_range(
        &self,
        register: &Register,
        start: &Address,
        end: &Address,
    ) -> Box<dyn AddressRangeIterator> {
        let reg = self.resolve(register);
        self.filtered_range_iterator(&reg, &self.default_register_value_map, Some((start, end)))
    }

    fn get_context_registers(&self) -> Vec<RegisterRef> {
        self.base.get_context_registers()
    }

    fn remove(&mut self, start: &Address, end: &Address, register: &Register) -> Result<(), ContextChangeException> {
        assert!(start.same_address_space(end), "start and end address must be within the same address space");
        let reg = self.resolve(register);
        let key = Self::base_register_key(&reg);
        if let Some(store) = self.register_value_map.get(&key) {
            store.borrow_mut().clear_value(start, end, Some(&reg));
        }
        self.invalidate_read_cache();
        Ok(())
    }

    fn get_register_names(&self) -> Vec<String> {
        self.base.get_register_names()
    }

    fn has_value_over_range(&self, reg: &Register, value: i128, addr_set: &dyn AddressSetView) -> bool {
        let mut it = addr_set.address_ranges();
        for range in &mut it {
            if !self.has_value_over_single_range(reg, value, range.min_address(), range.max_address()) {
                return false;
            }
        }
        true
    }

    fn get_default_value(&self, register: &Register, address: &Address) -> Option<Box<dyn RegisterValueTrait>> {
        self.get_default_value_impl(register, address)
    }

    fn get_base_context_register(&self) -> RegisterRef {
        self.base.get_base_context_register()
    }

    fn get_default_disassembly_context(&self) -> Box<dyn RegisterValueTrait> {
        self.base.get_default_disassembly_context()
    }

    fn set_default_disassembly_context(&mut self, value: Box<dyn RegisterValueTrait>) {
        self.base.set_default_disassembly_context(value);
    }

    fn get_disassembly_context(&self, address: &Address) -> Box<dyn RegisterValueTrait> {
        let base_reg = self.base.get_base_context_register();
        let default_value = self.get_register_value_internal(&base_reg, address, &self.default_register_value_map);
        let current_value = self.get_register_value_internal(&base_reg, address, &self.register_value_map);

        let default_value = match default_value {
            Some(dv) => dv.combine_values(&self.base.default_disassembly_context()),
            None => self.base.default_disassembly_context(),
        };
        let result = match current_value {
            Some(cv) => default_value.combine_values(&cv),
            None => default_value,
        };
        Box::new(result)
    }
}

impl AbstractStoredProgramContext {
    fn has_value_over_single_range(&self, reg: &Register, value: i128, start: &Address, end: &Address) -> bool {
        let mut it = ProgramContext::get_register_value_address_ranges_in_range(self, reg, start, end);
        if let Some(range) = it.next() {
            if range.min_address() == start && range.max_address() == end {
                let reg_value = ProgramContext::get_value(self, reg, start, true);
                return reg_value == Some(value);
            }
        }
        false
    }
}

impl DefaultProgramContext for AbstractStoredProgramContext {
    fn set_default_value(&mut self, register_value: Box<dyn RegisterValueTrait>, start: &Address, end: &Address) {
        assert!(start.same_address_space(end), "start and end address must be within the same address space");
        let concrete = RegisterValue::from_trait_object(register_value.as_ref());
        let base_register = concrete.register().borrow().get_base_register();
        let key = base_register.borrow().name().to_string();
        if !self.default_register_value_map.contains_key(&key) {
            let adapter: Box<dyn RangeMapAdapter> = Box::new(InMemoryRangeMapAdapter::new());
            self.default_register_value_map
                .insert(key.clone(), RefCell::new(RegisterValueStore::new(&base_register, adapter, false)));
        }
        self.default_register_value_map.get(&key).expect("just ensured").borrow_mut().set_value(start, end, &concrete);
        self.invalidate_read_cache();
    }

    fn get_default_value(&self, register: &Register, address: &Address) -> Option<Box<dyn RegisterValueTrait>> {
        self.get_default_value_impl(register, address)
    }
}

#[allow(dead_code)]
fn _keep_invalidate_write_cache_reachable(ctx: &mut AbstractStoredProgramContext) {
    // `invalidate_write_cache` mirrors a real Java method used by `ProgramRegisterContextDB`;
    // referenced here so it is not flagged dead code before that port lands.
    ctx.invalidate_write_cache();
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::program::model::address::{AddressSet, AddressSpace, AddressSpaceType as ASType};
    use crate::program::model::lang::compiler_spec::CompilerSpec;
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
    use crate::program::model::lang::language_description::LanguageDescription;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper;
    use crate::program::model::lang::processor_context::ProcessorContext;
    use crate::program::model::lang::unknown_instruction_exception::UnknownInstructionException;
    use crate::program::model::address::AddressFactory;
    use crate::program::model::mem::MemBuffer;
    use crate::app::plugin::processors::generic::MemoryBlockDefinition;
    use crate::program::model::lang::language::ParseError;
    use crate::program::seam_stubs::{AddressLabelInfo, Processor};
    use crate::program::database::register::database_range_map_adapter::DatabaseRangeMapAdapter;
    use std::collections::HashSet as StdHashSet;

    struct MockProcessor;
    impl Processor for MockProcessor {}

    struct MockCompilerSpecDescription;
    impl CompilerSpecDescription for MockCompilerSpecDescription {
        fn get_compiler_spec_id(&self) -> CompilerSpecID {
            CompilerSpecID::new(Some("gcc"))
        }
        fn get_compiler_spec_name(&self) -> String {
            "GCC".to_string()
        }
        fn get_source(&self) -> String {
            "gcc.cspec".to_string()
        }
    }

    struct MockLanguageDescription;
    impl LanguageDescription for MockLanguageDescription {
        fn get_language_id(&self) -> LanguageID {
            LanguageID::new("test:LE:32:default").unwrap()
        }
        fn get_processor(&self) -> Box<dyn Processor> {
            Box::new(MockProcessor)
        }
        fn get_endian(&self) -> crate::program::model::lang::endian::Endian {
            crate::program::model::lang::endian::Endian::Little
        }
        fn get_instruction_endian(&self) -> crate::program::model::lang::endian::Endian {
            crate::program::model::lang::endian::Endian::Little
        }
        fn get_size(&self) -> i32 {
            32
        }
        fn get_variant(&self) -> String {
            "default".to_string()
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_description(&self) -> String {
            "Test language".to_string()
        }
        fn is_deprecated(&self) -> bool {
            false
        }
        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
            vec![Box::new(MockCompilerSpecDescription)]
        }
        fn get_compiler_spec_description_by_id(
            &self,
            compiler_spec_id: &CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpecDescription>, CompilerSpecNotFoundException> {
            Err(CompilerSpecNotFoundException::new(&self.get_language_id(), compiler_spec_id))
        }
        fn get_external_names(&self, _external_tool: &str) -> Option<Vec<String>> {
            None
        }
    }

    struct MockAddressLabelInfo;
    impl AddressLabelInfo for MockAddressLabelInfo {}

    struct MockMemoryBlockDefinition;
    impl MemoryBlockDefinition for MockMemoryBlockDefinition {}

    struct MockMemBuffer {
        address: Address,
    }
    impl MemBuffer for MockMemBuffer {
        fn get_byte(&self, _offset: i32) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
    }

    struct MockAddressFactory;
    impl AddressFactory for MockAddressFactory {
        fn get_address(&self, _addr_string: &str) -> Option<Address> {
            None
        }
        fn get_all_addresses_case(&self, _addr_string: &str, _case_sensitive: bool) -> Vec<Address> {
            Vec::new()
        }
        fn get_default_address_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_address_spaces(&self) -> Vec<Arc<AddressSpace>> {
            Vec::new()
        }
        fn get_address_space_by_name(&self, _name: &str) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_address_space_by_id(&self, _id: i32) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_all_address_spaces(&self) -> Vec<Arc<AddressSpace>> {
            Vec::new()
        }
        fn get_num_address_spaces(&self) -> usize {
            0
        }
        fn is_valid_address(&self, _address: &Address) -> bool {
            false
        }
        fn get_index(&self, _address: &Address) -> i64 {
            0
        }
        fn get_physical_space(&self, space: &Arc<AddressSpace>) -> Arc<AddressSpace> {
            space.clone()
        }
        fn get_physical_spaces(&self) -> Vec<Arc<AddressSpace>> {
            Vec::new()
        }
        fn address(&self, _space_id: i32, _offset: i64) -> Option<Address> {
            None
        }
        fn get_stack_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_constant_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_unique_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_register_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_constant_address(&self, _offset: i64) -> Option<Address> {
            None
        }
        fn get_address_set_range(&self, _min: &Address, _max: &Address) -> AddressSet {
            AddressSet::new()
        }
        fn get_address_set(&self) -> AddressSet {
            AddressSet::new()
        }
        fn old_get_address_from_long(&self, _value: i64) -> Option<Address> {
            None
        }
        fn has_multiple_memory_spaces(&self) -> bool {
            false
        }
    }

    pub(crate) fn reg_space() -> Arc<AddressSpace> {
        AddressSpace::new("register", 32, 1, ASType::Register, 0)
    }

    pub(crate) fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, ASType::Ram, 1)
    }

    pub(crate) struct TestLanguage {
        context_base: Option<RegisterRef>,
        registers: Vec<RegisterRef>,
    }

    impl Language for TestLanguage {
        fn get_language_id(&self) -> LanguageID {
            LanguageID::new("test:LE:32:default").unwrap()
        }
        fn get_language_description(&self) -> Box<dyn LanguageDescription> {
            Box::new(MockLanguageDescription)
        }
        fn get_parallel_instruction_helper(&self) -> Option<Box<dyn ParallelInstructionLanguageHelper>> {
            None
        }
        fn get_processor(&self) -> Box<dyn Processor> {
            Box::new(MockProcessor)
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            Box::new(MockAddressFactory)
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            ram_space()
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            ram_space()
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
        ) -> Result<Box<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>, ParseError> {
            Err(ParseError::UnknownInstruction(UnknownInstructionException::new()))
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
        fn get_register_in_space(&self, _addrspc: &Arc<AddressSpace>, _offset: i64, _size: i32) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            self.registers.clone()
        }
        fn get_register_names(&self) -> Vec<String> {
            self.registers.iter().map(|r| r.borrow().name().to_string()).collect()
        }
        fn get_register_by_name(&self, name: &str) -> Option<RegisterRef> {
            self.registers.iter().find(|r| r.borrow().name() == name).cloned()
        }
        fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<RegisterRef> {
            None
        }
        fn get_program_counter(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_base_register(&self) -> Option<RegisterRef> {
            self.context_base.clone()
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            match &self.context_base {
                Some(base) => base.borrow().child_registers(),
                None => Vec::new(),
            }
        }
        fn get_default_memory_blocks(&self) -> Vec<Box<dyn MemoryBlockDefinition>> {
            Vec::new()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn AddressLabelInfo>> {
            Vec::new()
        }
        fn get_segmented_space(&self) -> String {
            String::new()
        }
        fn get_volatile_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {}
        fn reload_language(&self, _task_monitor: &dyn TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
            vec![Box::new(MockCompilerSpecDescription)]
        }
        fn get_compiler_spec_by_id(
            &self,
            compiler_spec_id: &CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpec>, CompilerSpecNotFoundException> {
            Err(CompilerSpecNotFoundException::new(&self.get_language_id(), compiler_spec_id))
        }
        fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by these tests")
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
        fn get_property_keys(&self) -> StdHashSet<String> {
            StdHashSet::new()
        }
        fn has_manual(&self) -> bool {
            false
        }
        fn get_manual_entry(&self, _instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> StdHashSet<String> {
            StdHashSet::new()
        }
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }
        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            Some(16)
        }
    }

    /// Base register `eax` (4 bytes) with two byte-aligned children `al` (LSB) and `ah`, plus a
    /// standalone `r0`. No processor-context register (kept simple; context-mask interplay is
    /// covered by `abstract_program_context`'s own tests).
    pub(crate) fn test_language() -> TestLanguage {
        let space = reg_space();
        let eax = Register::new("eax", "", Address::new(space.clone(), 0), 4, false, 0);
        let al = Register::new("al", "", Address::new(space.clone(), 0), 1, false, 0);
        let ah = Register::new("ah", "", Address::new(space.clone(), 1), 1, false, 0);
        let [eax, al, ah]: [Register; 3] =
            crate::program::model::lang::register::test_support::linked(&[&eax, &al, &ah], &[(0, &[1, 2])]).try_into().unwrap();
        let r0 = Register::new("r0", "", Address::new(space, 8), 4, false, 0);

        TestLanguage { context_base: None, registers: vec![eax, al, ah, r0] }
    }

    /// Same as [`test_language`], plus a `contextreg` processor-context base register (no
    /// flowing/non-flowing children -- just present so callers can exercise context-register-only
    /// behavior, e.g. `checkContextWrite` gating).
    pub(crate) fn test_language_with_context() -> TestLanguage {
        let mut lang = test_language();
        let space = reg_space();
        let context_reg =
            Register::new("contextreg", "", Address::new(space, 16), 4, false, Register::TYPE_CONTEXT);
        lang.registers.push(context_reg.clone());
        lang.context_base = Some(context_reg);
        lang
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use super::test_support::*;
    use crate::program::model::address::{AddressSet, AddressSpace, AddressSpaceType as ASType};
    use crate::program::model::lang::compiler_spec::CompilerSpec;
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
    use crate::program::model::lang::language_description::LanguageDescription;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper;
    use crate::program::model::lang::processor_context::ProcessorContext;
    use crate::program::model::lang::unknown_instruction_exception::UnknownInstructionException;
    use crate::program::model::address::AddressFactory;
    use crate::program::model::mem::MemBuffer;
    use crate::app::plugin::processors::generic::MemoryBlockDefinition;
    use crate::program::model::lang::language::ParseError;
    use crate::program::seam_stubs::{AddressLabelInfo, Processor};
    use crate::program::database::register::database_range_map_adapter::DatabaseRangeMapAdapter;
    use std::collections::HashSet as StdHashSet;

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        space.address(offset)
    }

    fn in_memory_context() -> AbstractStoredProgramContext {
        AbstractStoredProgramContext::new(
            Arc::new(test_language()),
            Box::new(|_reg: &RegisterRef| Box::new(InMemoryRangeMapAdapter::new()) as Box<dyn RangeMapAdapter>),
        )
    }

    #[test]
    fn set_then_get_register_value_over_range() {
        let mut ctx = in_memory_context();
        let space = ram_space();
        let eax = ctx.get_register("eax").unwrap();

        let value = RegisterValue::with_value(eax.clone(), 0x1234_5678);
        ProgramContext::set_register_value(&mut ctx, &addr(&space, 0x1000), &addr(&space, 0x2000), Box::new(value))
            .expect("set should succeed");

        let got = ProgramContext::get_register_value(&ctx, &eax.borrow(), &addr(&space, 0x1500)).unwrap();
        assert_eq!(got.get_unsigned_value_ignore_mask(), 0x1234_5678);
        assert!(ProgramContext::get_register_value(&ctx, &eax.borrow(), &addr(&space, 0x5000)).is_none());
    }

    #[test]
    fn setting_narrower_child_register_splits_range_and_preserves_rest() {
        let mut ctx = in_memory_context();
        let space = ram_space();
        let eax = ctx.get_register("eax").unwrap();
        let al = ctx.get_register("al").unwrap();

        let full = RegisterValue::with_value(eax.clone(), 0x1111_1111);
        ProgramContext::set_register_value(&mut ctx, &addr(&space, 0x1000), &addr(&space, 0x2000), Box::new(full)).unwrap();

        let al_val = RegisterValue::with_value(al.clone(), 0xAB);
        ProgramContext::set_register_value(&mut ctx, &addr(&space, 0x1500), &addr(&space, 0x1600), Box::new(al_val)).unwrap();

        let before = ProgramContext::get_register_value(&ctx, &eax.borrow(), &addr(&space, 0x1000)).unwrap();
        assert_eq!(before.get_unsigned_value_ignore_mask(), 0x1111_1111);

        let inside = ProgramContext::get_register_value(&ctx, &eax.borrow(), &addr(&space, 0x1550)).unwrap();
        assert_eq!(inside.get_unsigned_value_ignore_mask(), 0x1111_11AB);

        // Sub-register decomposition: querying `al` directly over the narrower range.
        let al_only = ProgramContext::get_register_value(&ctx, &al.borrow(), &addr(&space, 0x1550)).unwrap();
        assert_eq!(al_only.get_unsigned_value_ignore_mask(), 0xAB);
    }

    #[test]
    fn default_value_used_when_no_explicit_value_set() {
        let mut ctx = in_memory_context();
        let space = ram_space();
        let r0 = ctx.get_register("r0").unwrap();

        let default_val = RegisterValue::with_value(r0.clone(), 0x42);
        DefaultProgramContext::set_default_value(&mut ctx, Box::new(default_val), &addr(&space, 0x0), &addr(&space, 0xFFFF));

        let got = ProgramContext::get_register_value(&ctx, &r0.borrow(), &addr(&space, 0x100)).unwrap();
        assert_eq!(got.get_unsigned_value_ignore_mask(), 0x42);

        // An explicit value takes precedence over the default.
        let explicit = RegisterValue::with_value(r0.clone(), 0x99);
        ProgramContext::set_register_value(&mut ctx, &addr(&space, 0x100), &addr(&space, 0x200), Box::new(explicit)).unwrap();
        let got2 = ProgramContext::get_register_value(&ctx, &r0.borrow(), &addr(&space, 0x150)).unwrap();
        assert_eq!(got2.get_unsigned_value_ignore_mask(), 0x99);

        // Outside the explicit range, the default still applies.
        let got3 = ProgramContext::get_register_value(&ctx, &r0.borrow(), &addr(&space, 0x9000)).unwrap();
        assert_eq!(got3.get_unsigned_value_ignore_mask(), 0x42);
    }

    #[test]
    fn remove_clears_a_range() {
        let mut ctx = in_memory_context();
        let space = ram_space();
        let r0 = ctx.get_register("r0").unwrap();

        let value = RegisterValue::with_value(r0.clone(), 7);
        ProgramContext::set_register_value(&mut ctx, &addr(&space, 0x1000), &addr(&space, 0x2000), Box::new(value)).unwrap();
        ProgramContext::remove(&mut ctx, &addr(&space, 0x1000), &addr(&space, 0x2000), &r0.borrow()).unwrap();

        assert!(ProgramContext::get_register_value(&ctx, &r0.borrow(), &addr(&space, 0x1500)).is_none());
    }

    #[test]
    fn registers_with_values_reflects_current_and_default_maps() {
        let mut ctx = in_memory_context();
        let space = ram_space();
        let eax = ctx.get_register("eax").unwrap();
        let r0 = ctx.get_register("r0").unwrap();

        assert!(ProgramContext::get_registers_with_values(&ctx).is_empty());

        ProgramContext::set_register_value(
            &mut ctx,
            &addr(&space, 0x1000),
            &addr(&space, 0x1010),
            Box::new(RegisterValue::with_value(eax, 1)),
        )
        .unwrap();
        DefaultProgramContext::set_default_value(
            &mut ctx,
            Box::new(RegisterValue::with_value(r0, 1)),
            &addr(&space, 0x0),
            &addr(&space, 0xFFFF),
        );

        let names: Vec<String> = ProgramContext::get_registers_with_values(&ctx).iter().map(|r| r.borrow().name().to_string()).collect();
        assert!(names.contains(&"eax".to_string()));
        assert!(names.contains(&"r0".to_string()));
    }

    #[test]
    fn get_value_supports_signed_and_unsigned() {
        let mut ctx = in_memory_context();
        let space = ram_space();
        let r0 = ctx.get_register("r0").unwrap();

        ProgramContext::set_register_value(
            &mut ctx,
            &addr(&space, 0x1000),
            &addr(&space, 0x1010),
            Box::new(RegisterValue::with_value(r0.clone(), 0xFFFF_FFFF)),
        )
        .unwrap();

        assert_eq!(ProgramContext::get_value(&ctx, &r0.borrow(), &addr(&space, 0x1005), false), Some(0xFFFF_FFFF));
        assert_eq!(ProgramContext::get_value(&ctx, &r0.borrow(), &addr(&space, 0x1005), true), Some(-1));
    }

    #[test]
    fn set_value_with_negative_i128_round_trips_via_two_s_complement() {
        let mut ctx = in_memory_context();
        let space = ram_space();
        let r0 = ctx.get_register("r0").unwrap();

        ProgramContext::set_value(&mut ctx, &r0.borrow(), &addr(&space, 0x1000), &addr(&space, 0x1010), Some(-2)).unwrap();
        assert_eq!(ProgramContext::get_value(&ctx, &r0.borrow(), &addr(&space, 0x1005), true), Some(-2));

        ProgramContext::set_value(&mut ctx, &r0.borrow(), &addr(&space, 0x1000), &addr(&space, 0x1010), None).unwrap();
        assert!(ProgramContext::get_register_value(&ctx, &r0.borrow(), &addr(&space, 0x1005)).is_none());
    }

    #[test]
    fn has_value_over_range_true_only_when_whole_set_matches() {
        let mut ctx = in_memory_context();
        let space = ram_space();
        let r0 = ctx.get_register("r0").unwrap();

        ProgramContext::set_register_value(
            &mut ctx,
            &addr(&space, 0x1000),
            &addr(&space, 0x1010),
            Box::new(RegisterValue::with_value(r0.clone(), 5)),
        )
        .unwrap();

        let mut full = AddressSet::new();
        full.add_range(&addr(&space, 0x1000), &addr(&space, 0x1010));
        assert!(ProgramContext::has_value_over_range(&ctx, &r0.borrow(), 5, &full));
        assert!(!ProgramContext::has_value_over_range(&ctx, &r0.borrow(), 6, &full));

        let mut partial = AddressSet::new();
        partial.add_range(&addr(&space, 0x1000), &addr(&space, 0x2000));
        assert!(!ProgramContext::has_value_over_range(&ctx, &r0.borrow(), 5, &partial));
    }

    #[test]
    fn get_register_value_address_ranges_reports_only_ranges_with_that_registers_bits() {
        let mut ctx = in_memory_context();
        let space = ram_space();
        let eax = ctx.get_register("eax").unwrap();
        let al = ctx.get_register("al").unwrap();
        let ah = ctx.get_register("ah").unwrap();

        // Set only `al`'s bits; `ah` should report no ranges even though the underlying store
        // covers the same address range (shared base register `eax`).
        ProgramContext::set_register_value(
            &mut ctx,
            &addr(&space, 0x1000),
            &addr(&space, 0x1010),
            Box::new(RegisterValue::with_value(al, 0xAB)),
        )
        .unwrap();

        let al_ranges: Vec<AddressRange> = ProgramContext::get_register_value_address_ranges(&ctx, &eax.borrow()).collect();
        assert_eq!(al_ranges.len(), 1);

        let ah_ranges: Vec<AddressRange> = ProgramContext::get_register_value_address_ranges(&ctx, &ah.borrow()).collect();
        assert!(ah_ranges.is_empty());
    }

    #[test]
    fn move_address_range_relocates_values() {
        let mut ctx = in_memory_context();
        let space = ram_space();
        let r0 = ctx.get_register("r0").unwrap();

        ProgramContext::set_register_value(
            &mut ctx,
            &addr(&space, 0x1000),
            &addr(&space, 0x100f),
            Box::new(RegisterValue::with_value(r0.clone(), 77)),
        )
        .unwrap();

        let monitor = crate::util::task::DummyMonitor;
        ctx.move_address_range(&addr(&space, 0x1000), &addr(&space, 0x5000), 0x10, &monitor).unwrap();

        assert!(ProgramContext::get_register_value(&ctx, &r0.borrow(), &addr(&space, 0x1000)).is_none());
        let got = ProgramContext::get_register_value(&ctx, &r0.borrow(), &addr(&space, 0x5000)).unwrap();
        assert_eq!(got.get_unsigned_value_ignore_mask(), 77);
    }

    /// Sanity check that `create_range_map_adapter` is genuinely used to construct a
    /// database-backed store, mirroring how `ProgramRegisterContextDB` will wire this up.
    #[test]
    fn works_with_a_database_backed_range_map_adapter() {
        use crate::framework::db::util::error_handler::ErrorHandler as ErrorHandlerTrait;
        use crate::framework::db::DBHandle;
        use crate::program::database::map::AddressMapDB;
        use crate::program::model::address::DefaultAddressFactory;
        use std::io;
        use std::sync::RwLock;

        struct PanicOnError;
        impl ErrorHandlerTrait for PanicOnError {
            fn db_error(&self, e: io::Error) {
                panic!("unexpected db error: {e}");
            }
        }

        let ram = ram_space();
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let factory = DefaultAddressFactory::new(vec![ram.clone()]);
        let addr_map = Arc::new(RwLock::new(AddressMapDB::new(handle.clone(), Arc::new(factory)).unwrap()));

        let mut ctx = AbstractStoredProgramContext::new(
            Arc::new(test_language()),
            Box::new(move |reg: &RegisterRef| {
                Box::new(
                    DatabaseRangeMapAdapter::new(reg, handle.clone(), addr_map.clone(), Arc::new(PanicOnError))
                        .expect("adapter construction should succeed"),
                ) as Box<dyn RangeMapAdapter>
            }),
        );

        let r0 = ctx.get_register("r0").unwrap();
        ProgramContext::set_register_value(
            &mut ctx,
            &addr(&ram, 0x1000),
            &addr(&ram, 0x1010),
            Box::new(RegisterValue::with_value(r0.clone(), 0xABCD)),
        )
        .unwrap();

        let got = ProgramContext::get_register_value(&ctx, &r0.borrow(), &addr(&ram, 0x1005)).unwrap();
        assert_eq!(got.get_unsigned_value_ignore_mask(), 0xABCD);
    }

    #[test]
    fn get_disassembly_context_combines_default_and_current_context_values() {
        // No processor-context register defined by `test_language()`, so this exercises the
        // fallback path (`self.base.default_disassembly_context()`), still real end-to-end.
        let ctx = in_memory_context();
        let space = ram_space();
        let value = ctx.get_disassembly_context(&addr(&space, 0x1000));
        assert!(!value.has_any_value());
    }
}
