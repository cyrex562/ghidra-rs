//! Port of `ghidra.program.database.register.OldProgramContextDB`.
//!
//! The legacy/migration-path register-context reader: stores each register's value as raw
//! *bytes*, one [`AddressRangeMapDB`] per byte offset within the register space (plus a special
//! per-bit-position offset scheme for single-bit, non-context registers), rather than the
//! coalesced whole-register-value scheme [`RegisterValueStore`](crate::program::util::register_value_store::RegisterValueStore)
//! uses. This does **not** extend/compose [`AbstractStoredProgramContext`](crate::program::util::abstract_stored_program_context::AbstractStoredProgramContext)
//! -- Java's class does not either, it implements `ProgramContext`/`DefaultProgramContext`/
//! `ManagerDB` directly, reading through the older per-byte schema purely for one-time upgrade
//! purposes.
//!
//! ## `ManagerDB` is not literally implemented
//!
//! Same reasoning as [`ProgramRegisterContextDB`](super::program_register_context_db::ProgramRegisterContextDB):
//! this type composes an `Arc<dyn Language>` and [`RegisterRef`] (`Rc<RefCell<Register>>`)
//! state, neither of which is `Send + Sync` in this crate, and `ManagerDB` requires `Send +
//! Sync`. The equivalent methods (`invalidateCache`, `deleteAddressRange`, `moveAddressRange`,
//! `programReady`, `setProgram`) are exposed as regular inherent `pub fn`s instead.
//!
//! ## Deliberately unsupported operations
//!
//! Java's class throws `UnsupportedOperationException` from every *mutating* "current value"
//! operation and a couple of read paths (`get`, `getSigned`, `getValue`, `hasValueOverRange`,
//! `remove`, `set`, `setValue`, `setRegisterValue`, `deleteAddressRange`,
//! `getRegisterValueRangeContaining`, `hasNonFlowingContext`, `getFlowValue`, `getNonFlowValue`)
//! -- this is a read-only reader over old data used strictly during upgrade, not a general
//! `ProgramContext`. This port mirrors that with `panic!` (matching what an uncaught Java
//! `RuntimeException` does to the calling thread) rather than inventing a typed error that would
//! misleadingly suggest the operation is sometimes recoverable.
//!
//! ## Known gap: table enumeration
//!
//! `OldProgramContextDB::old_context_data_exists`/`remove_old_context_data` need to enumerate
//! every table in the database by name prefix (`ProgContext*`). This crate's [`DBHandle`] exposes
//! `get_table(name)` (single lookup) but no "list all tables" method, so both are left as documented
//! `TODO(port)` stubs; see [`ProgramRegisterContextDB`](super::program_register_context_db::ProgramRegisterContextDB)'s
//! module doc comment, which hits the identical gap.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::framework::db::util::ErrorHandler;
use crate::framework::db::{DBHandle, Field, FieldType};
use crate::program::database::map::AddressMapDB;
use crate::program::database::register::in_memory_range_map_adapter::InMemoryRangeMapAdapter;
use crate::program::database::util::AddressRangeMapDB;
use crate::program::model::address::{Address, AddressRange, AddressRangeIterator, AddressRangeIteratorAdapter, AddressSetView};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::lang::register_value::RegisterValue;
use crate::program::model::listing::context_change_exception::ContextChangeException;
use crate::program::model::listing::default_program_context::DefaultProgramContext;
use crate::program::model::listing::program_context::ProgramContext;
use crate::program::seam_stubs::RegisterValue as RegisterValueTrait;
use crate::program::util::register_value_store::RegisterValueStore;
use crate::program::util::RangeMapAdapter;
use crate::util::lock::ReentrantLock;
use crate::util::task::TaskMonitor;

/// Table name prefix used by [`ProgramRegisterContextDB`](super::program_register_context_db::ProgramRegisterContextDB)'s
/// modern per-register storage; used here only as the "how do I know this isn't old data"
/// negative check in Java (not reproduced, see this module's doc comment).
const OLD_CONTEXT_TABLE_PREFIX_SUFFIX: &str = "ProgContext";

/// A single register value over an address range, as reconstructed from the legacy per-byte
/// storage scheme.
///
/// Port of the package-private `ghidra.program.database.register.RegisterValueRange`.
#[derive(Clone)]
pub struct RegisterValueRange {
    start_addr: Address,
    end_addr: Address,
    value: RegisterValue,
}

impl RegisterValueRange {
    pub fn start_address(&self) -> &Address {
        &self.start_addr
    }
    pub fn end_address(&self) -> &Address {
        &self.end_addr
    }
    pub fn value(&self) -> &RegisterValue {
        &self.value
    }
}

/// Legacy/migration-path register-context reader.
///
/// Port of `ghidra.program.database.register.OldProgramContextDB`.
pub struct OldProgramContextDB {
    db_handle: Arc<RwLock<DBHandle>>,
    err_handler: Arc<dyn ErrorHandler>,
    language: Arc<dyn Language>,
    addr_map: Arc<RwLock<AddressMapDB>>,
    lock: ReentrantLock,

    value_maps: RefCell<HashMap<i32, AddressRangeMapDB>>,
    base_context_register: RegisterRef,
    default_register_value_map: HashMap<String, RefCell<RegisterValueStore>>,
    registers_with_values: RefCell<Option<Vec<RegisterRef>>>,
    default_disassembly_context: RegisterValue,
}

impl OldProgramContextDB {
    /// Constructs a new reader over `db_handle`'s legacy per-byte register-value tables.
    pub fn new(
        db_handle: Arc<RwLock<DBHandle>>,
        err_handler: Arc<dyn ErrorHandler>,
        language: Arc<dyn Language>,
        addr_map: Arc<RwLock<AddressMapDB>>,
    ) -> Self {
        let base_context_register = language.get_context_base_register().unwrap_or_else(Register::no_context);
        let default_disassembly_context = RegisterValue::new(base_context_register.clone());

        let mut ctx = Self {
            db_handle,
            err_handler,
            language: language.clone(),
            addr_map,
            lock: ReentrantLock::new("OldProgramContextDB"),
            value_maps: RefCell::new(HashMap::new()),
            base_context_register,
            default_register_value_map: HashMap::new(),
            registers_with_values: RefCell::new(None),
            default_disassembly_context,
        };
        // Port of `initializeDefaultValues(Language)`.
        language.apply_context_settings(&mut ctx as &mut dyn DefaultProgramContext);
        ctx
    }

    /// Returns `true` if any table with the legacy `ProgContext` name prefix exists.
    ///
    /// # TODO(port)
    /// Always returns `false`: this crate's [`DBHandle`] has no table-enumeration method. See
    /// this module's doc comment.
    pub fn old_context_data_exists(_db_handle: &DBHandle) -> bool {
        false
    }

    /// Removes every table with the legacy `ProgContext` name prefix.
    ///
    /// # TODO(port)
    /// A no-op: see [`Self::old_context_data_exists`].
    pub fn remove_old_context_data(_db_handle: &mut DBHandle) -> std::io::Result<()> {
        let _ = OLD_CONTEXT_TABLE_PREFIX_SUFFIX; // referenced so the constant isn't flagged dead
        Ok(())
    }

    /// Port of `OldProgramContextDB.getRegisterOffset(Register)`.
    fn get_register_offset(reg: &Register) -> i32 {
        let mut offset = reg.offset();
        if reg.bit_length() == 1 && !reg.is_processor_context() {
            offset |= reg.least_significant_bit() << 28;
            offset |= 0x90000000u32 as i32;
        }
        offset
    }

    fn get_range_map(&self, offset: i32) -> Option<()> {
        // Presence check only; the real map lives in `self.value_maps`, created on demand via
        // `create_map` because `AddressRangeMapDB::new` can fail (`io::Result`) and this method's
        // Java counterpart swallows that failure by returning `null` -- mirrored here by simply
        // not caching a broken map (see `with_range_map`).
        if self.value_maps.borrow().contains_key(&offset) {
            return Some(());
        }
        self.create_map(offset)
    }

    fn create_map(&self, offset: i32) -> Option<()> {
        let _guard = self.lock.write();
        let table_name = format!("{OLD_CONTEXT_TABLE_PREFIX_SUFFIX}{offset}");
        match AddressRangeMapDB::new(self.db_handle.clone(), self.addr_map.clone(), table_name, FieldType::Byte, false) {
            Ok(map) => {
                self.value_maps.borrow_mut().insert(offset, map);
                Some(())
            }
            Err(e) => {
                self.err_handler.db_error(e);
                None
            }
        }
    }

    fn get_byte(&self, offset: i32, addr: &Address) -> Option<i8> {
        self.get_range_map(offset)?;
        let maps = self.value_maps.borrow();
        let map = maps.get(&offset)?;
        match map.get_value(addr) {
            Ok(Some(Field::Byte(Some(b)))) => Some(b),
            Ok(_) => None,
            Err(e) => {
                self.err_handler.db_error(e);
                None
            }
        }
    }

    /// Port of `OldProgramContextDB.getChangePoints`. `register_length` is accepted for
    /// signature fidelity but unused, matching Java (the real method never reads it either).
    fn get_change_points(&self, start_addr: &Address, end_addr: &Address, register_offset: i32, _register_length: i32) -> Vec<Address> {
        let mut change_points: Vec<Address> = Vec::new();
        if self.get_range_map(register_offset).is_none() {
            return change_points;
        }
        let ranges = {
            let maps = self.value_maps.borrow();
            let map = maps.get(&register_offset).expect("just ensured by get_range_map");
            match map.get_address_ranges(start_addr, end_addr) {
                Ok(r) => r,
                Err(e) => {
                    self.err_handler.db_error(e);
                    Vec::new()
                }
            }
        };

        let mut curr = start_addr.clone();
        for (range, _value) in ranges {
            if curr >= *end_addr {
                break;
            }
            let range_start = range.min_address().clone();
            if range_start != curr {
                push_sorted_unique(&mut change_points, range_start);
            }
            let range_end = range.max_address().clone();
            curr = range_end.add_wrap(1);
            if curr <= *end_addr {
                push_sorted_unique(&mut change_points, curr.clone());
            }
        }
        change_points
    }

    /// Port of `OldProgramContextDB.getRegisterValues(Register, Address, Address)`.
    pub fn get_register_values(&self, reg: &RegisterRef, start: &Address, end: &Address) -> Vec<RegisterValueRange> {
        let offset = Self::get_register_offset(&reg);
        let change_points = self.get_change_points(start, end, offset, reg.minimum_byte_size());

        let mut ranges = Vec::new();
        let mut current_address = start.clone();
        for next_change in &change_points {
            let range_end = next_change.previous().expect("change point cannot be the space minimum here");
            self.add_range(reg, &mut ranges, &current_address, Some(&range_end));
            current_address = next_change.clone();
        }
        self.add_range(reg, &mut ranges, &current_address, Some(end));
        ranges
    }

    fn add_range(&self, reg: &RegisterRef, ranges: &mut Vec<RegisterValueRange>, start: &Address, end: Option<&Address>) {
        let Some(end) = end else {
            let space_max = start.space().max_address();
            self.add_range(reg, ranges, start, Some(&space_max));
            return;
        };
        if start.space() != end.space() {
            let space_max = start.space().max_address();
            self.add_range(reg, ranges, start, Some(&space_max));
            let other_min = end.space().min_address();
            self.add_range(reg, ranges, &other_min, Some(end));
            return;
        }
        let value_range = self.get_register_range(reg, start, end);
        if value_range.value.has_any_value() {
            ranges.push(value_range);
        }
    }

    fn get_register_range(&self, reg: &RegisterRef, start: &Address, end: &Address) -> RegisterValueRange {
        RegisterValueRange {
            start_addr: start.clone(),
            end_addr: end.clone(),
            value: self.get_register_value_concrete(reg, start),
        }
    }

    /// Port of `OldProgramContextDB.getRegisterValue(Register, Address)`.
    fn get_register_value_concrete(&self, register: &RegisterRef, address: &Address) -> RegisterValue {
        let base_reg = register.get_base_register();
        let size = base_reg.minimum_byte_size();
        let offset = Self::get_register_offset(&register);

        let mut bytes = vec![0u8; 2 * size as usize];
        for i in 0..size {
            let index = if register.is_big_endian() { i } else { size - i - 1 };
            match self.get_byte(offset + i, address) {
                Some(b) => {
                    bytes[(size + index) as usize] = b as u8;
                    bytes[index as usize] = 0xFF;
                }
                None => {
                    // ignore byte: leave both mask and value at 0
                }
            }
        }
        RegisterValue::from_bytes(register.clone(), &bytes)
    }

    fn resolve(&self, register: &Register) -> RegisterRef {
        self.language
            .get_register_by_name(register.name())
            .unwrap_or_else(|| panic!("register '{}' not found in this context's language", register.name()))
    }

    /// Clears all data caches.
    ///
    /// Port of `OldProgramContextDB.invalidateCache` (part of `ManagerDB`; see this module's doc
    /// comment for why the trait itself is not implemented).
    pub fn invalidate_cache(&mut self, _all: bool) {
        let _guard = self.lock.write();
        self.value_maps.borrow_mut().clear();
    }

    /// Move all objects within an address range to a new location. A no-op, matching Java (the
    /// real method's body is empty).
    pub fn move_address_range(&mut self, _from_addr: &Address, _to_addr: &Address, _length: u64, _monitor: &dyn TaskMonitor) {}

    /// Callback from program made after the program has completed initialization. A no-op,
    /// matching Java.
    pub fn program_ready(&mut self) {}

    /// Callback from program used to indicate all managers have been created. A no-op, matching
    /// Java (the real method's body is empty).
    pub fn set_program(&mut self) {}

    /// Deletes all objects applied to the given address range.
    ///
    /// # Panics
    /// Always: mirrors `OldProgramContextDB.deleteAddressRange`'s
    /// `UnsupportedOperationException` (see this module's doc comment).
    pub fn delete_address_range(&mut self, _start: &Address, _end: &Address) {
        panic!("OldProgramContextDB.deleteAddressRange: unsupported (read-only legacy context)");
    }
}

fn push_sorted_unique(points: &mut Vec<Address>, addr: Address) {
    if !points.contains(&addr) {
        points.push(addr);
        points.sort();
    }
}

impl ProgramContext for OldProgramContextDB {
    fn has_non_flowing_context(&self) -> bool {
        panic!("OldProgramContextDB.hasNonFlowingContext: unsupported (read-only legacy context)");
    }

    fn get_flow_value(&self, _value: Box<dyn RegisterValueTrait>) -> Box<dyn RegisterValueTrait> {
        panic!("OldProgramContextDB.getFlowValue: unsupported (read-only legacy context)");
    }

    fn get_non_flow_value(&self, _value: Box<dyn RegisterValueTrait>) -> Option<Box<dyn RegisterValueTrait>> {
        panic!("OldProgramContextDB.getNonFlowValue: unsupported (read-only legacy context)");
    }

    fn get_register(&self, name: &str) -> Option<RegisterRef> {
        self.language.get_register_by_name(name)
    }

    fn get_registers(&self) -> Vec<RegisterRef> {
        self.language.get_registers()
    }

    fn get_registers_with_values(&self) -> Vec<RegisterRef> {
        if let Some(cached) = self.registers_with_values.borrow().as_ref() {
            return cached.clone();
        }
        let mut found = Vec::new();
        for register in self.get_registers() {
            let has_current = self.get_register_value_address_ranges(&register).next().is_some();
            let has_default =
                has_current || self.get_default_register_value_address_ranges(&register).next().is_some();
            if has_current || has_default {
                found.push(register);
            }
        }
        *self.registers_with_values.borrow_mut() = Some(found.clone());
        found
    }

    fn get_value(&self, _register: &Register, _address: &Address, _signed: bool) -> Option<i128> {
        panic!("OldProgramContextDB.getValue: unsupported (read-only legacy context)");
    }

    fn get_register_value(&self, register: &Register, address: &Address) -> Option<Box<dyn RegisterValueTrait>> {
        let reg = self.resolve(register);
        Some(Box::new(self.get_register_value_concrete(&reg, address)))
    }

    fn set_register_value(
        &mut self,
        _start: &Address,
        _end: &Address,
        _value: Box<dyn RegisterValueTrait>,
    ) -> Result<(), ContextChangeException> {
        panic!("OldProgramContextDB.setRegisterValue: unsupported (read-only legacy context)");
    }

    fn get_non_default_value(&self, register: &Register, address: &Address) -> Option<Box<dyn RegisterValueTrait>> {
        ProgramContext::get_register_value(self, register, address)
    }

    fn set_value(
        &mut self,
        _register: &Register,
        _start: &Address,
        _end: &Address,
        _value: Option<i128>,
    ) -> Result<(), ContextChangeException> {
        panic!("OldProgramContextDB.setValue: unsupported (read-only legacy context)");
    }

    fn get_register_value_address_ranges(&self, register: &Register) -> Box<dyn AddressRangeIterator> {
        // Port of `getRegisterValueAddressRanges(Register)`: Java scans the full address set
        // known to `addrMap.getAddressFactory()`. This uses the language's address factory
        // instead (this reader has no `AddressMap` reference of its own beyond what it needs for
        // its per-offset tables), which is the same set of memory spaces in practice.
        let set = self.language.get_address_factory().get_address_set();
        match (set.min_address(), set.max_address()) {
            (Some(min), Some(max)) => self.get_register_value_address_ranges_in_range(register, &min, &max),
            _ => Box::new(AddressRangeIteratorAdapter::new(Vec::new())),
        }
    }

    fn get_register_value_address_ranges_in_range(
        &self,
        register: &Register,
        start: &Address,
        end: &Address,
    ) -> Box<dyn AddressRangeIterator> {
        let reg = self.resolve(register);
        let value_ranges = self.get_register_values(&reg, start, end);
        let ranges: Vec<AddressRange> =
            value_ranges.into_iter().map(|vr| AddressRange::new(vr.start_addr, vr.end_addr)).collect();
        Box::new(AddressRangeIteratorAdapter::new(ranges))
    }

    fn get_register_value_range_containing(&self, _register: &Register, _addr: &Address) -> AddressRange {
        panic!("OldProgramContextDB.getRegisterValueRangeContaining: unsupported (read-only legacy context)");
    }

    fn get_default_register_value_address_ranges(&self, register: &Register) -> Box<dyn AddressRangeIterator> {
        let reg = self.resolve(register);
        let key = reg.get_base_register().name().to_string();
        match self.default_register_value_map.get(&key) {
            Some(store) if !store.borrow().is_empty() => store.borrow_mut().get_address_range_iterator(),
            _ => Box::new(AddressRangeIteratorAdapter::new(Vec::new())),
        }
    }

    fn get_default_register_value_address_ranges_in_range(
        &self,
        register: &Register,
        start: &Address,
        end: &Address,
    ) -> Box<dyn AddressRangeIterator> {
        let reg = self.resolve(register);
        let key = reg.get_base_register().name().to_string();
        match self.default_register_value_map.get(&key) {
            Some(store) if !store.borrow().is_empty() => store.borrow_mut().get_address_range_iterator_in_range(start, end),
            _ => Box::new(AddressRangeIteratorAdapter::new(Vec::new())),
        }
    }

    fn get_context_registers(&self) -> Vec<RegisterRef> {
        self.language.get_context_registers()
    }

    fn remove(&mut self, _start: &Address, _end: &Address, _register: &Register) -> Result<(), ContextChangeException> {
        panic!("OldProgramContextDB.remove: unsupported (read-only legacy context)");
    }

    fn get_register_names(&self) -> Vec<String> {
        self.language.get_register_names()
    }

    fn has_value_over_range(&self, _reg: &Register, _value: i128, _addr_set: &dyn crate::program::model::address::AddressSetView) -> bool {
        panic!("OldProgramContextDB.hasValueOverRange: unsupported (read-only legacy context)");
    }

    fn get_default_value(&self, register: &Register, address: &Address) -> Option<Box<dyn RegisterValueTrait>> {
        let reg = self.resolve(register);
        let key = reg.get_base_register().name().to_string();
        let store = self.default_register_value_map.get(&key)?;
        store.borrow().get_value(&reg, address).map(|v| Box::new(v) as Box<dyn RegisterValueTrait>)
    }

    fn get_base_context_register(&self) -> RegisterRef {
        self.base_context_register.clone()
    }

    fn get_default_disassembly_context(&self) -> Box<dyn RegisterValueTrait> {
        Box::new(self.default_disassembly_context.clone())
    }

    fn set_default_disassembly_context(&mut self, value: Box<dyn RegisterValueTrait>) {
        self.default_disassembly_context = RegisterValue::from_trait_object(value.as_ref());
    }

    fn get_disassembly_context(&self, _address: &Address) -> Box<dyn RegisterValueTrait> {
        // Port of `OldProgramContextDB.getDisassemblyContext`: always just the default.
        self.get_default_disassembly_context()
    }
}

impl DefaultProgramContext for OldProgramContextDB {
    fn set_default_value(&mut self, register_value: Box<dyn RegisterValueTrait>, start: &Address, end: &Address) {
        let concrete = RegisterValue::from_trait_object(register_value.as_ref());
        let base_register = concrete.register().get_base_register();
        let key = base_register.name().to_string();
        if !self.default_register_value_map.contains_key(&key) {
            let adapter: Box<dyn RangeMapAdapter> = Box::new(InMemoryRangeMapAdapter::new());
            self.default_register_value_map
                .insert(key.clone(), RefCell::new(RegisterValueStore::new(&base_register, adapter, false)));
        }
        self.default_register_value_map.get(&key).expect("just ensured").borrow_mut().set_value(start, end, &concrete);
    }

    fn get_default_value(&self, register: &Register, address: &Address) -> Option<Box<dyn RegisterValueTrait>> {
        ProgramContext::get_default_value(self, register, address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::util::error_handler::ErrorHandler as ErrorHandlerTrait;
    use crate::program::model::address::{AddressSpace, AddressSpaceType, DefaultAddressFactory};
    use crate::program::util::abstract_stored_program_context::test_support::*;
    use std::io;

    struct PanicOnError;
    impl ErrorHandlerTrait for PanicOnError {
        fn db_error(&self, e: io::Error) {
            panic!("unexpected db error: {e}");
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        space.address(offset)
    }

    fn new_reader(language: Arc<dyn Language>) -> OldProgramContextDB {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let factory = DefaultAddressFactory::new(vec![ram_space()]);
        let addr_map = Arc::new(RwLock::new(AddressMapDB::new(handle.clone(), Arc::new(factory)).unwrap()));
        OldProgramContextDB::new(handle, Arc::new(PanicOnError), language, addr_map)
    }

    #[test]
    fn get_register_value_with_no_stored_bytes_has_no_value() {
        let ctx = new_reader(Arc::new(test_language()));
        let space = ram_space();
        let r0 = ctx.get_register("r0").unwrap();
        let value = ProgramContext::get_register_value(&ctx, &r0, &addr(&space, 0x1000)).unwrap();
        assert!(!value.has_any_value());
    }

    #[test]
    fn default_value_set_then_read_back() {
        let mut ctx = new_reader(Arc::new(test_language()));
        let space = ram_space();
        let r0 = ctx.get_register("r0").unwrap();

        DefaultProgramContext::set_default_value(
            &mut ctx,
            Box::new(RegisterValue::with_value(r0.clone(), 0x77)),
            &addr(&space, 0x0),
            &addr(&space, 0xFFFF),
        );

        let got = ProgramContext::get_default_value(&ctx, &r0, &addr(&space, 0x1000)).unwrap();
        assert_eq!(got.get_unsigned_value_ignore_mask(), 0x77);
    }

    #[test]
    fn get_register_offset_matches_java_algorithm_for_normal_registers() {
        let lang = test_language();
        let r0 = lang.get_register_by_name("r0").unwrap();
        // `r0` is a normal (non-bit, non-context) register: offset is just its own byte offset.
        assert_eq!(OldProgramContextDB::get_register_offset(&r0), r0.offset());
    }

    #[test]
    #[should_panic(expected = "unsupported")]
    fn set_register_value_is_unsupported() {
        let mut ctx = new_reader(Arc::new(test_language()));
        let space = ram_space();
        let r0 = ctx.get_register("r0").unwrap();
        let _ = ProgramContext::set_register_value(
            &mut ctx,
            &addr(&space, 0x1000),
            &addr(&space, 0x1010),
            Box::new(RegisterValue::with_value(r0, 1)),
        );
    }

    #[test]
    #[should_panic(expected = "unsupported")]
    fn has_non_flowing_context_is_unsupported() {
        let ctx = new_reader(Arc::new(test_language()));
        let _ = ProgramContext::has_non_flowing_context(&ctx);
    }

    #[test]
    fn registers_with_values_starts_empty() {
        let ctx = new_reader(Arc::new(test_language()));
        assert!(ProgramContext::get_registers_with_values(&ctx).is_empty());
    }
}
