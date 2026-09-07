//! Test-only [`CodeUnitOwner`] implementation shared by this module's test suites. **Not a port of
//! a Java class** -- Java's `CodeUnitDB` tests build a real `ProgramDB` (and with it a real
//! `CodeManagerDB`, `AddressMapDB`, `CommentsDBAdapter`, `MemoryMapDB` and `DBPropertyMapManager`)
//! on top of a live `DBHandle`. None of that machinery is ported yet, and `CodeUnitOwner` exists
//! precisely so a code unit never names a concrete manager, so this supplies a minimal but
//! *genuinely stateful* stand-in: real bytes in a `Vec<u8>`, real comment [`DBRecord`]s in a
//! `HashMap` keyed by address index, and real property maps -- enough that
//! [`CodeUnitDbBase`](super::code_unit_db::CodeUnitDbBase)'s caching, comment round-tripping and
//! byte-window behaviour can be exercised rather than merely smoke-tested.
//!
//! It is deliberately shared (rather than living inside `code_unit_db.rs`'s `mod tests`) because
//! `InstructionDB`, `DataDB` and `DataComponent` all compose the same `CodeUnitDbBase` and will
//! need the same owner, including its recorded [`CodeUnitOwner::set_flags`] and
//! [`CodeUnitOwner::send_comment_notification`] calls.
//!
//! Callbacks that none of these tests exercise panic with `unimplemented!`, the convention already
//! used by the mock types elsewhere in this crate, rather than inventing behaviour that has no
//! Java original to check against.

use std::any::{Any, TypeId};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io;
use std::sync::{Arc, Mutex, RwLock};

use crate::framework::db::{DBRecord, Field};
use crate::program::database::code::code_unit_owner::CodeUnitOwner;
use crate::program::database::code::comments_db_adapter;
use crate::program::database::map::address_map::AddressMap;
use crate::program::model::address::{
    Address, AddressFactory, AddressRange, AddressRangeIterator, AddressSetView, AddressSpace,
    BoxedAddressIterator, KeyRange,
};
use crate::program::model::data::data_type::DataType;
use crate::program::model::lang::instruction_prototype::InstructionPrototype;
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::lang::ProcessorContextView;
use crate::program::model::listing::context_change_exception::ContextChangeException;
use crate::program::model::listing::instruction::Instruction;
use crate::program::model::listing::program::Program;
use crate::program::model::listing::program_context::ProgramContext;
use crate::program::model::listing::CommentType;
use crate::program::model::mem::{Memory, MemoryAccessException, MemoryBlock};
use crate::program::model::symbol::{
    AddExternalReferenceError, ExternalLocation, MemReferenceImpl, Namespace, Reference,
    ReferenceIterator, ReferenceManager, RefType, SourceType, Symbol, SymbolTable,
};
use crate::program::model::listing::Variable;
use crate::program::model::util::property_map_manager::PropertyMapManager;
use crate::program::model::util::PropertyMap;
use crate::program::seam_stubs::RegisterValue;
use crate::program::util::{
    IntPropertyMap, LongPropertyMap, ObjectPropertyMap, StringPropertyMap, VoidPropertyMap,
};
use crate::util::exception::{
    CancelledException, DuplicateNameException, InvalidInputException, NoValueException,
};
use crate::util::lock::ReentrantLock;
use crate::util::task::TaskMonitor;

const UNEXERCISED: &str = "not exercised by these tests";

// ===========================================================================================
// Program
// ===========================================================================================

/// The bare `Program` a [`TestCodeUnitOwner`] hands back from
/// [`CodeUnitOwner::get_program`].
pub(crate) struct TestProgram;

impl crate::framework::model::DomainObject for TestProgram {}

impl Program for TestProgram {
    fn get_name(&self) -> String {
        "test.bin".to_string()
    }

    fn get_language_id(&self) -> String {
        "test:LE:32:default".to_string()
    }
}

// ===========================================================================================
// Memory
// ===========================================================================================

/// A single named block covering the whole of a [`TestMemory`], so that
/// `CodeUnitDbBase::get_address_string(true, ..)` has a block name to prefix with.
pub(crate) struct TestMemoryBlock {
    name: String,
    start: Address,
    end: Address,
}

impl MemoryBlock for TestMemoryBlock {
    fn get_name(&self) -> &str {
        &self.name
    }

    fn get_start(&self) -> Address {
        self.start.clone()
    }

    fn get_end(&self) -> Address {
        self.end.clone()
    }

    fn get_size(&self) -> u64 {
        (self.end.offset() - self.start.offset() + 1) as u64
    }

    fn is_initialized(&self) -> bool {
        true
    }

    fn get_byte(&self, _addr: &Address) -> Result<u8, MemoryAccessException> {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_bytes(&self, _addr: &Address, _dest: &mut [u8]) -> usize {
        unimplemented!("{UNEXERCISED}")
    }

    fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
        unimplemented!("{UNEXERCISED}")
    }
}

/// A flat, single-block [`Memory`] backed by a real byte vector starting at a configurable base
/// address. Endianness and the (optional) block name are configurable so that
/// `CodeUnitDbBase::is_big_endian` and the block-name branch of `get_address_string` can both be
/// driven from a test.
///
/// The byte vector sits behind a [`RwLock`] rather than being owned outright because the trait
/// hands out `Arc<dyn Memory>`, which cannot be mutated through: tests need to change a byte
/// *behind* a code unit's byte cache in order to prove the cache is real.
pub(crate) struct TestMemory {
    space: Arc<AddressSpace>,
    base_offset: i64,
    bytes: RwLock<Vec<u8>>,
    big_endian: bool,
    block_name: Option<String>,
}

impl TestMemory {
    pub(crate) fn new(space: Arc<AddressSpace>, base_offset: i64, bytes: Vec<u8>) -> Self {
        TestMemory {
            space,
            base_offset,
            bytes: RwLock::new(bytes),
            big_endian: false,
            block_name: Some("text".to_string()),
        }
    }

    /// Overwrite one byte, *without* going through [`Memory::set_bytes`], so a test can change
    /// memory behind a code unit's byte cache.
    pub(crate) fn poke(&self, offset_from_base: usize, value: u8) {
        self.bytes.write().unwrap()[offset_from_base] = value;
    }

    /// The offset of `addr` into the backing vector, if it lies within it.
    fn index_of(&self, addr: &Address) -> Option<usize> {
        if addr.space() != &self.space {
            return None;
        }
        let delta = addr.offset().checked_sub(self.base_offset)?;
        let delta = usize::try_from(delta).ok()?;
        (delta < self.bytes.read().unwrap().len()).then_some(delta)
    }
}

impl Memory for TestMemory {
    fn is_big_endian(&self) -> bool {
        self.big_endian
    }

    fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
        match self.index_of(addr) {
            Some(index) => Ok(self.bytes.read().unwrap()[index]),
            None => Err(MemoryAccessException::new(format!(
                "no bytes at {addr}"
            ))),
        }
    }

    /// Copies as many bytes as are actually available, returning that count -- the same partial
    /// read Java's `MemoryMapDB.getBytes` performs when a request runs off the end of a block.
    fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
        let Some(index) = self.index_of(addr) else {
            return 0;
        };
        let bytes = self.bytes.read().unwrap();
        let n = dest.len().min(bytes.len() - index);
        dest[..n].copy_from_slice(&bytes[index..index + n]);
        n
    }

    fn set_bytes(&mut self, addr: &Address, source: &[u8]) -> Result<(), MemoryAccessException> {
        let index = self
            .index_of(addr)
            .ok_or_else(|| MemoryAccessException::new(format!("no bytes at {addr}")))?;
        let mut bytes = self.bytes.write().unwrap();
        if index + source.len() > bytes.len() {
            return Err(MemoryAccessException::new("write runs past end of memory"));
        }
        bytes[index..index + source.len()].copy_from_slice(source);
        Ok(())
    }

    fn get_block(&self, addr: &Address) -> Option<Arc<dyn MemoryBlock>> {
        let name = self.block_name.clone()?;
        let index = self.index_of(addr)?;
        let _ = index;
        let len = self.bytes.read().unwrap().len() as i64;
        Some(Arc::new(TestMemoryBlock {
            name,
            start: self.space.address(self.base_offset),
            end: self.space.address(self.base_offset + len - 1),
        }))
    }
}

// ===========================================================================================
// AddressMap
// ===========================================================================================

/// Identity mapping between an address's offset and its database key, within a single address
/// space -- the same shape as
/// [`map::test_support::TestAddressMap`](crate::program::database::map), which is private to that
/// module.
pub(crate) struct TestAddressMap {
    space: Arc<AddressSpace>,
}

impl AddressMap for TestAddressMap {
    fn get_key(&self, addr: &Address, _create: bool) -> i64 {
        addr.offset()
    }

    fn get_absolute_encoding(&self, addr: &Address, _create: bool) -> i64 {
        addr.offset()
    }

    fn find_key_range(&self, _key_range_list: &[KeyRange], _addr: Option<&Address>) -> i32 {
        unimplemented!("{UNEXERCISED}")
    }

    fn decode_address(&self, value: i64) -> Address {
        self.space.address(value)
    }

    fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
        None
    }

    fn get_key_ranges_absolute(
        &self,
        start: &Address,
        end: &Address,
        _absolute: bool,
        _create: bool,
    ) -> Vec<KeyRange> {
        vec![KeyRange::new(start.offset(), end.offset())]
    }

    fn get_key_ranges_for_set_absolute(
        &self,
        _set: Option<&dyn AddressSetView>,
        _absolute: bool,
        _create: bool,
    ) -> Vec<KeyRange> {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_old_address_map(&self) -> Box<dyn AddressMap> {
        Box::new(TestAddressMap {
            space: self.space.clone(),
        })
    }

    fn is_upgraded(&self) -> bool {
        false
    }

    fn get_image_base(&self) -> Address {
        self.space.address(0)
    }
}

// ===========================================================================================
// Property maps
// ===========================================================================================

/// Which typed accessor a [`SharedPropertyMap`] answers to, mirroring the way Java's
/// `PropertyMapManager.getIntPropertyMap` refuses (with a `TypeMismatchException`) a map created
/// as some other type.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PropertyKind {
    Int,
    String,
    Void,
}

/// The actual storage behind a property map. Held in an `Arc<Mutex<..>>` so that every
/// `Box<dyn IntPropertyMap>` (etc.) the manager hands out is a *view* onto the same state --
/// without which a write through a returned handle would be dropped on the floor, since the
/// ported `PropertyMapManager` returns owned boxes rather than borrows.
struct SharedPropertyMap {
    name: String,
    kind: PropertyKind,
    ints: BTreeMap<Address, i32>,
    strings: BTreeMap<Address, String>,
    voids: BTreeSet<Address>,
}

impl SharedPropertyMap {
    fn has_property(&self, addr: &Address) -> bool {
        match self.kind {
            PropertyKind::Int => self.ints.contains_key(addr),
            PropertyKind::String => self.strings.contains_key(addr),
            PropertyKind::Void => self.voids.contains(addr),
        }
    }

    fn remove(&mut self, addr: &Address) -> bool {
        match self.kind {
            PropertyKind::Int => self.ints.remove(addr).is_some(),
            PropertyKind::String => self.strings.remove(addr).is_some(),
            PropertyKind::Void => self.voids.remove(addr),
        }
    }

    fn len(&self) -> usize {
        match self.kind {
            PropertyKind::Int => self.ints.len(),
            PropertyKind::String => self.strings.len(),
            PropertyKind::Void => self.voids.len(),
        }
    }
}

/// A handle onto a [`SharedPropertyMap`]. Cloning the handle (which is what the manager's getters
/// do) shares the storage.
pub(crate) struct TestPropertyMap {
    shared: Arc<Mutex<SharedPropertyMap>>,
}

impl PropertyMap for TestPropertyMap {
    fn get_name(&self) -> String {
        self.shared.lock().unwrap().name.clone()
    }

    fn get_value_class(&self) -> Option<TypeId> {
        Some(match self.shared.lock().unwrap().kind {
            PropertyKind::Int => TypeId::of::<i32>(),
            PropertyKind::String => TypeId::of::<String>(),
            PropertyKind::Void => TypeId::of::<bool>(),
        })
    }

    fn clear(&mut self) {
        let mut shared = self.shared.lock().unwrap();
        shared.ints.clear();
        shared.strings.clear();
        shared.voids.clear();
    }

    fn intersects_range(&self, _start: &Address, _end: &Address) -> bool {
        unimplemented!("{UNEXERCISED}")
    }

    fn intersects_set(&self, _set: &dyn AddressSetView) -> bool {
        unimplemented!("{UNEXERCISED}")
    }

    fn remove_range(&mut self, _start: &Address, _end: &Address) -> bool {
        unimplemented!("{UNEXERCISED}")
    }

    fn remove(&mut self, addr: &Address) -> bool {
        self.shared.lock().unwrap().remove(addr)
    }

    fn has_property(&self, addr: &Address) -> bool {
        self.shared.lock().unwrap().has_property(addr)
    }

    fn add(&mut self, addr: &Address, value: Option<Box<dyn Any>>) {
        let mut shared = self.shared.lock().unwrap();
        match value {
            None => {
                shared.remove(addr);
            }
            Some(value) => match shared.kind {
                PropertyKind::Int => {
                    let v = *value.downcast::<i32>().expect("expected i32 value");
                    shared.ints.insert(addr.clone(), v);
                }
                PropertyKind::String => {
                    let v = *value.downcast::<String>().expect("expected String value");
                    shared.strings.insert(addr.clone(), v);
                }
                PropertyKind::Void => {
                    shared.voids.insert(addr.clone());
                }
            },
        }
    }

    fn get(&self, addr: &Address) -> Option<Box<dyn Any>> {
        let shared = self.shared.lock().unwrap();
        match shared.kind {
            PropertyKind::Int => shared.ints.get(addr).map(|v| Box::new(*v) as Box<dyn Any>),
            PropertyKind::String => shared
                .strings
                .get(addr)
                .map(|v| Box::new(v.clone()) as Box<dyn Any>),
            PropertyKind::Void => shared
                .voids
                .contains(addr)
                .then(|| Box::new(true) as Box<dyn Any>),
        }
    }

    fn get_next_property_address(&self, _addr: &Address) -> Option<Address> {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_previous_property_address(&self, _addr: &Address) -> Option<Address> {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_first_property_address(&self) -> Option<Address> {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_last_property_address(&self) -> Option<Address> {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_size(&self) -> usize {
        self.shared.lock().unwrap().len()
    }

    fn get_property_iterator_range(
        &self,
        _start: &Address,
        _end: &Address,
    ) -> BoxedAddressIterator {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_property_iterator_range_ordered(
        &self,
        _start: &Address,
        _end: &Address,
        _forward: bool,
    ) -> BoxedAddressIterator {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_property_iterator(&self) -> BoxedAddressIterator {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_property_iterator_set(&self, _asv: &dyn AddressSetView) -> BoxedAddressIterator {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_property_iterator_set_ordered(
        &self,
        _asv: &dyn AddressSetView,
        _forward: bool,
    ) -> BoxedAddressIterator {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_property_iterator_from(
        &self,
        _start: &Address,
        _forward: bool,
    ) -> BoxedAddressIterator {
        unimplemented!("{UNEXERCISED}")
    }

    fn move_range(&mut self, _start: &Address, _end: &Address, _new_start: &Address) {
        unimplemented!("{UNEXERCISED}")
    }
}

impl IntPropertyMap for TestPropertyMap {
    fn add_int(&mut self, addr: &Address, value: i32) {
        self.shared
            .lock()
            .unwrap()
            .ints
            .insert(addr.clone(), value);
    }

    fn get_int(&self, addr: &Address) -> Result<i32, NoValueException> {
        self.shared
            .lock()
            .unwrap()
            .ints
            .get(addr)
            .copied()
            .ok_or_else(|| NoValueException::with_message("no int property at address"))
    }
}

impl StringPropertyMap for TestPropertyMap {
    fn add_string(&mut self, addr: &Address, value: String) {
        self.shared
            .lock()
            .unwrap()
            .strings
            .insert(addr.clone(), value);
    }

    fn get_string(&self, addr: &Address) -> Result<String, NoValueException> {
        self.shared
            .lock()
            .unwrap()
            .strings
            .get(addr)
            .cloned()
            .ok_or_else(|| NoValueException::with_message("no string property at address"))
    }
}

impl VoidPropertyMap for TestPropertyMap {
    fn add_void(&mut self, addr: &Address) {
        self.shared.lock().unwrap().voids.insert(addr.clone());
    }
}

/// An in-memory [`PropertyMapManager`] whose handed-out maps share their storage with the
/// manager, so writes through a returned `Box<dyn IntPropertyMap>` are visible to a later
/// `get_int_property_map`.
#[derive(Default)]
pub(crate) struct TestPropertyMapManager {
    maps: BTreeMap<String, Arc<Mutex<SharedPropertyMap>>>,
}

impl TestPropertyMapManager {
    fn create(
        &mut self,
        name: &str,
        kind: PropertyKind,
    ) -> Result<TestPropertyMap, DuplicateNameException> {
        if self.maps.contains_key(name) {
            return Err(DuplicateNameException::with_message(format!(
                "property map '{name}' already exists"
            )));
        }
        let shared = Arc::new(Mutex::new(SharedPropertyMap {
            name: name.to_string(),
            kind,
            ints: BTreeMap::new(),
            strings: BTreeMap::new(),
            voids: BTreeSet::new(),
        }));
        self.maps.insert(name.to_string(), shared.clone());
        Ok(TestPropertyMap { shared })
    }

    fn view(&self, name: &str, kind: Option<PropertyKind>) -> Option<TestPropertyMap> {
        let shared = self.maps.get(name)?;
        if let Some(kind) = kind {
            if shared.lock().unwrap().kind != kind {
                return None;
            }
        }
        Some(TestPropertyMap {
            shared: shared.clone(),
        })
    }
}

impl PropertyMapManager for TestPropertyMapManager {
    fn create_int_property_map(
        &mut self,
        property_name: &str,
    ) -> Result<Box<dyn IntPropertyMap>, DuplicateNameException> {
        self.create(property_name, PropertyKind::Int)
            .map(|m| Box::new(m) as Box<dyn IntPropertyMap>)
    }

    fn create_long_property_map(
        &mut self,
        _property_name: &str,
    ) -> Result<Box<dyn LongPropertyMap>, DuplicateNameException> {
        unimplemented!("{UNEXERCISED}")
    }

    fn create_string_property_map(
        &mut self,
        property_name: &str,
    ) -> Result<Box<dyn StringPropertyMap>, DuplicateNameException> {
        self.create(property_name, PropertyKind::String)
            .map(|m| Box::new(m) as Box<dyn StringPropertyMap>)
    }

    fn create_object_property_map(
        &mut self,
        _property_name: &str,
    ) -> Result<Box<dyn ObjectPropertyMap>, DuplicateNameException> {
        unimplemented!("{UNEXERCISED}")
    }

    fn create_void_property_map(
        &mut self,
        property_name: &str,
    ) -> Result<Box<dyn VoidPropertyMap>, DuplicateNameException> {
        self.create(property_name, PropertyKind::Void)
            .map(|m| Box::new(m) as Box<dyn VoidPropertyMap>)
    }

    fn get_property_map(&self, property_name: &str) -> Option<Box<dyn PropertyMap>> {
        self.view(property_name, None)
            .map(|m| Box::new(m) as Box<dyn PropertyMap>)
    }

    fn get_int_property_map(&self, property_name: &str) -> Option<Box<dyn IntPropertyMap>> {
        self.view(property_name, Some(PropertyKind::Int))
            .map(|m| Box::new(m) as Box<dyn IntPropertyMap>)
    }

    fn get_long_property_map(&self, _property_name: &str) -> Option<Box<dyn LongPropertyMap>> {
        None
    }

    fn get_string_property_map(&self, property_name: &str) -> Option<Box<dyn StringPropertyMap>> {
        self.view(property_name, Some(PropertyKind::String))
            .map(|m| Box::new(m) as Box<dyn StringPropertyMap>)
    }

    fn get_object_property_map(&self, _property_name: &str) -> Option<Box<dyn ObjectPropertyMap>> {
        None
    }

    fn get_void_property_map(&self, property_name: &str) -> Option<Box<dyn VoidPropertyMap>> {
        self.view(property_name, Some(PropertyKind::Void))
            .map(|m| Box::new(m) as Box<dyn VoidPropertyMap>)
    }

    fn remove_property_map(&mut self, property_name: &str) -> bool {
        self.maps.remove(property_name).is_some()
    }

    fn property_managers(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.maps.keys().cloned())
    }

    fn remove_all(&mut self, addr: &Address) {
        for shared in self.maps.values() {
            shared.lock().unwrap().remove(addr);
        }
    }

    fn remove_all_range(
        &mut self,
        _start_addr: &Address,
        _end_addr: &Address,
        _monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        unimplemented!("{UNEXERCISED}")
    }
}

// ===========================================================================================
// SymbolTable / ReferenceManager / ProgramContext
// ===========================================================================================

/// An empty symbol table: `getPrimarySymbol`/`getSymbols` legitimately answer "nothing here",
/// which is all `CodeUnitDbBase::get_label` needs to be driven with.
pub(crate) struct TestSymbolTable;

impl SymbolTable for TestSymbolTable {
    fn create_label(
        &mut self,
        _addr: &Address,
        _name: &str,
        _source: SourceType,
    ) -> io::Result<Arc<dyn Symbol>> {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_symbol(&self, _id: i64) -> io::Result<Option<Arc<dyn Symbol>>> {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_symbols(&self, _addr: &Address) -> io::Result<Vec<Arc<dyn Symbol>>> {
        Ok(Vec::new())
    }
}

/// A minimal in-memory reference manager: memory references added through it are stored in a
/// `Vec` and answered back by the "from address" queries, and deleting one removes it.
///
/// Everything a `CodeUnitDB`/`InstructionDB` actually drives is real here -- `InstructionDB`'s
/// fall-through override is *defined* in terms of adding, finding and deleting a
/// `RefType::FALL_THROUGH` reference from the instruction's address, so a manager that always
/// answered "no references" could not exercise it at all. The remaining query methods (variables,
/// destination iterators, counts) stay `unimplemented!`, as they have no code-unit caller.
///
/// One deliberate omission: Java's `ReferenceDBManager.addMemoryReference` calls back into
/// `InstructionDB.fallThroughChanged(ref)` when it adds or removes a `FALL_THROUGH` reference.
/// Nothing here knows about instructions, so that callback is not fired; a test that needs it
/// invokes `InstructionDB::fall_through_changed` itself, standing in for the manager.
#[derive(Default)]
pub(crate) struct TestReferenceManager {
    references: Vec<Arc<dyn Reference>>,
}

impl ReferenceManager for TestReferenceManager {
    fn add_reference(&mut self, _reference: Arc<dyn Reference>) -> Arc<dyn Reference> {
        unimplemented!("{UNEXERCISED}")
    }

    fn add_stack_reference(
        &mut self,
        _from_addr: Address,
        _op_index: i32,
        _stack_offset: i32,
        _ref_type: RefType,
        _source: SourceType,
    ) -> Arc<dyn Reference> {
        unimplemented!("{UNEXERCISED}")
    }

    fn add_register_reference(
        &mut self,
        _from_addr: Address,
        _op_index: i32,
        _register: &Register,
        _ref_type: RefType,
        _source: SourceType,
    ) -> Arc<dyn Reference> {
        unimplemented!("{UNEXERCISED}")
    }

    fn add_memory_reference(
        &mut self,
        from_addr: Address,
        to_addr: Address,
        ref_type: RefType,
        source: SourceType,
        op_index: i32,
    ) -> Arc<dyn Reference> {
        let reference: Arc<dyn Reference> = Arc::new(MemReferenceImpl::new(
            from_addr, to_addr, ref_type, source, op_index, true,
        ));
        self.references.push(reference.clone());
        reference
    }

    fn add_offset_mem_reference(
        &mut self,
        _from_addr: Address,
        _to_addr: Address,
        _to_addr_is_base: bool,
        _offset: i64,
        _ref_type: RefType,
        _source: SourceType,
        _op_index: i32,
    ) -> Arc<dyn Reference> {
        unimplemented!("{UNEXERCISED}")
    }

    fn add_shifted_mem_reference(
        &mut self,
        _from_addr: Address,
        _to_addr: Address,
        _shift_value: i32,
        _ref_type: RefType,
        _source: SourceType,
        _op_index: i32,
    ) -> Arc<dyn Reference> {
        unimplemented!("{UNEXERCISED}")
    }

    fn add_external_reference(
        &mut self,
        _from_addr: Address,
        _library_name: &str,
        _ext_label: Option<&str>,
        _ext_addr: Option<Address>,
        _source: SourceType,
        _op_index: i32,
        _ref_type: RefType,
    ) -> Result<Arc<dyn Reference>, AddExternalReferenceError> {
        unimplemented!("{UNEXERCISED}")
    }

    fn add_external_reference_in_namespace(
        &mut self,
        _from_addr: Address,
        _ext_namespace: Arc<dyn Namespace>,
        _ext_label: Option<&str>,
        _ext_addr: Option<Address>,
        _source: SourceType,
        _op_index: i32,
        _ref_type: RefType,
    ) -> Result<Arc<dyn Reference>, AddExternalReferenceError> {
        unimplemented!("{UNEXERCISED}")
    }

    fn add_external_reference_for_location(
        &mut self,
        _from_addr: Address,
        _op_index: i32,
        _location: Arc<dyn ExternalLocation>,
        _source: SourceType,
        _ref_type: RefType,
    ) -> Result<Arc<dyn Reference>, InvalidInputException> {
        unimplemented!("{UNEXERCISED}")
    }

    fn remove_all_references_from_range(&mut self, _begin_addr: Address, _end_addr: Address) {
        unimplemented!("{UNEXERCISED}")
    }

    fn remove_all_references_from(&mut self, _from_addr: Address) {
        unimplemented!("{UNEXERCISED}")
    }

    fn remove_all_references_to(&mut self, _to_addr: Address) {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_references_to_variable(&self, _var: &dyn Variable) -> Vec<Arc<dyn Reference>> {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_referenced_variable(&self, _reference: &dyn Reference) -> Option<Box<dyn Variable>> {
        unimplemented!("{UNEXERCISED}")
    }

    fn set_primary(&mut self, _reference: Arc<dyn Reference>, _is_primary: bool) {
        // Every reference this manager creates is already primary.
    }

    fn has_flow_references_from(&self, _addr: Address) -> bool {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_flow_references_from(&self, addr: Address) -> Vec<Arc<dyn Reference>> {
        self.references
            .iter()
            .filter(|r| r.from_address() == addr && r.reference_type().is_flow())
            .cloned()
            .collect()
    }

    fn get_external_references(&self) -> Box<dyn ReferenceIterator> {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_references_to(&self, _addr: Address) -> Box<dyn ReferenceIterator> {
        Box::new(crate::program::model::symbol::EmptyReferenceIterator)
    }

    fn get_reference_iterator(&self, _start_addr: Address) -> Box<dyn ReferenceIterator> {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_reference(
        &self,
        from_addr: Address,
        to_addr: Address,
        op_index: i32,
    ) -> Option<Arc<dyn Reference>> {
        self.references
            .iter()
            .find(|r| {
                r.from_address() == from_addr
                    && r.to_address() == to_addr
                    && r.operand_index() == op_index
            })
            .cloned()
    }

    fn get_references_from(&self, addr: Address) -> Vec<Arc<dyn Reference>> {
        self.references
            .iter()
            .filter(|r| r.from_address() == addr)
            .cloned()
            .collect()
    }

    fn get_references_from_operand(
        &self,
        from_addr: Address,
        op_index: i32,
    ) -> Vec<Arc<dyn Reference>> {
        self.references
            .iter()
            .filter(|r| r.from_address() == from_addr && r.operand_index() == op_index)
            .cloned()
            .collect()
    }

    fn has_references_from_operand(&self, _from_addr: Address, _op_index: i32) -> bool {
        unimplemented!("{UNEXERCISED}")
    }

    fn has_references_from(&self, _from_addr: Address) -> bool {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_primary_reference_from(
        &self,
        addr: Address,
        op_index: i32,
    ) -> Option<Arc<dyn Reference>> {
        self.references
            .iter()
            .find(|r| r.from_address() == addr && r.operand_index() == op_index && r.is_primary())
            .cloned()
    }

    fn get_reference_source_iterator(
        &self,
        _start_addr: Address,
        _forward: bool,
    ) -> BoxedAddressIterator {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_reference_source_iterator_in_set(
        &self,
        _addr_set: Option<&dyn AddressSetView>,
        _forward: bool,
    ) -> BoxedAddressIterator {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_reference_destination_iterator(
        &self,
        _start_addr: Address,
        _forward: bool,
    ) -> BoxedAddressIterator {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_reference_destination_iterator_in_set(
        &self,
        _addr_set: Option<&dyn AddressSetView>,
        _forward: bool,
    ) -> BoxedAddressIterator {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_reference_count_to(&self, _to_addr: Address) -> i32 {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_reference_count_from(&self, _from_addr: Address) -> i32 {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_reference_destination_count(&self) -> i32 {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_reference_source_count(&self) -> i32 {
        unimplemented!("{UNEXERCISED}")
    }

    fn has_references_to(&self, _to_addr: Address) -> bool {
        unimplemented!("{UNEXERCISED}")
    }

    fn update_ref_type(
        &mut self,
        _reference: Arc<dyn Reference>,
        _ref_type: RefType,
    ) -> Arc<dyn Reference> {
        unimplemented!("{UNEXERCISED}")
    }

    fn set_association(&mut self, _symbol: Arc<dyn Symbol>, _reference: Arc<dyn Reference>) {
        unimplemented!("{UNEXERCISED}")
    }

    fn remove_association(&mut self, _reference: Arc<dyn Reference>) {
        unimplemented!("{UNEXERCISED}")
    }

    fn delete(&mut self, reference: Arc<dyn Reference>) {
        self.references.retain(|r| {
            r.from_address() != reference.from_address()
                || r.to_address() != reference.to_address()
                || r.operand_index() != reference.operand_index()
        });
    }

    fn get_reference_level(&self, _to_addr: Address) -> i8 {
        unimplemented!("{UNEXERCISED}")
    }
}

/// A program context with no register values defined anywhere.
pub(crate) struct TestProgramContext;

impl ProgramContext for TestProgramContext {
    fn has_non_flowing_context(&self) -> bool {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_flow_value(&self, _value: Box<dyn RegisterValue>) -> Box<dyn RegisterValue> {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_non_flow_value(
        &self,
        _value: Box<dyn RegisterValue>,
    ) -> Option<Box<dyn RegisterValue>> {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_register(&self, _name: &str) -> Option<RegisterRef> {
        None
    }

    fn get_registers(&self) -> Vec<RegisterRef> {
        Vec::new()
    }

    fn get_registers_with_values(&self) -> Vec<RegisterRef> {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_value(&self, _register: &Register, _address: &Address, _signed: bool) -> Option<i128> {
        None
    }

    fn get_register_value(
        &self,
        _register: &Register,
        _address: &Address,
    ) -> Option<Box<dyn RegisterValue>> {
        None
    }

    fn set_register_value(
        &mut self,
        _start: &Address,
        _end: &Address,
        _value: Box<dyn RegisterValue>,
    ) -> Result<(), ContextChangeException> {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_non_default_value(
        &self,
        _register: &Register,
        _address: &Address,
    ) -> Option<Box<dyn RegisterValue>> {
        unimplemented!("{UNEXERCISED}")
    }

    fn set_value(
        &mut self,
        _register: &Register,
        _start: &Address,
        _end: &Address,
        _value: Option<i128>,
    ) -> Result<(), ContextChangeException> {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_register_value_address_ranges(
        &self,
        _register: &Register,
    ) -> Box<dyn AddressRangeIterator> {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_register_value_address_ranges_in_range(
        &self,
        _register: &Register,
        _start: &Address,
        _end: &Address,
    ) -> Box<dyn AddressRangeIterator> {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_register_value_range_containing(
        &self,
        _register: &Register,
        _addr: &Address,
    ) -> AddressRange {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_default_register_value_address_ranges(
        &self,
        _register: &Register,
    ) -> Box<dyn AddressRangeIterator> {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_default_register_value_address_ranges_in_range(
        &self,
        _register: &Register,
        _start: &Address,
        _end: &Address,
    ) -> Box<dyn AddressRangeIterator> {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_context_registers(&self) -> Vec<RegisterRef> {
        unimplemented!("{UNEXERCISED}")
    }

    fn remove(
        &mut self,
        _start: &Address,
        _end: &Address,
        _register: &Register,
    ) -> Result<(), ContextChangeException> {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_register_names(&self) -> Vec<String> {
        unimplemented!("{UNEXERCISED}")
    }

    fn has_value_over_range(
        &self,
        _reg: &Register,
        _value: i128,
        _addr_set: &dyn AddressSetView,
    ) -> bool {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_default_value(
        &self,
        _register: &Register,
        _address: &Address,
    ) -> Option<Box<dyn RegisterValue>> {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_base_context_register(&self) -> RegisterRef {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_default_disassembly_context(&self) -> Box<dyn RegisterValue> {
        unimplemented!("{UNEXERCISED}")
    }

    fn set_default_disassembly_context(&mut self, _value: Box<dyn RegisterValue>) {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_disassembly_context(&self, _address: &Address) -> Box<dyn RegisterValue> {
        unimplemented!("{UNEXERCISED}")
    }
}

// ===========================================================================================
// The owner itself
// ===========================================================================================

/// One recorded `codeMgr.sendNotification(address, commentType, oldValue, comment)` call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommentNotification {
    pub(crate) address: Address,
    pub(crate) comment_type: CommentType,
    pub(crate) old_value: Option<String>,
    pub(crate) new_value: Option<String>,
}

/// An in-memory [`CodeUnitOwner`]: real bytes, real comment records, real property maps, and a
/// record of every `set_flags` / `send_comment_notification` / `db_error` callback made through
/// it.
pub(crate) struct TestCodeUnitOwner {
    space: Arc<AddressSpace>,
    lock: Arc<ReentrantLock>,
    program: Arc<dyn Program>,
    memory: Arc<TestMemory>,
    reference_manager: Arc<Mutex<dyn ReferenceManager>>,
    program_context: Arc<Mutex<dyn ProgramContext>>,
    symbol_table: Arc<dyn SymbolTable>,
    address_map: Arc<dyn AddressMap>,
    property_map_manager: Arc<Mutex<dyn PropertyMapManager>>,
    comments: Mutex<HashMap<i64, DBRecord>>,
    flag_calls: Mutex<Vec<(i64, u8)>>,
    comment_notifications: Mutex<Vec<CommentNotification>>,
    db_errors: Mutex<Vec<String>>,
    /// Backs `codeMgr.getInstructionRecord(addr)`, keyed by address index.
    instruction_records: Mutex<HashMap<i64, DBRecord>>,
    /// Backs `codeMgr.getInstructionPrototype(protoID)`, keyed by prototype id.
    prototypes: Mutex<HashMap<i32, Arc<dyn InstructionPrototype>>>,
    /// Backs `codeMgr.getInstructionAt/After/Before(address)`, keyed by address offset so the
    /// ordered "after"/"before" queries are answerable.
    instructions: Mutex<BTreeMap<i64, Arc<dyn Instruction>>>,
    /// Backs `codeMgr.getDefinedAddressAfter(address)`; `None` (the default) means "nothing is
    /// defined after this address", which is what an instruction at the end of a block sees.
    defined_address_after: Mutex<Option<Address>>,
}

impl TestCodeUnitOwner {
    /// Builds an owner whose memory holds `bytes` starting at `base_offset` in `space`,
    /// little-endian, with a single block named `"text"`.
    pub(crate) fn new(space: Arc<AddressSpace>, base_offset: i64, bytes: Vec<u8>) -> Self {
        let memory = Arc::new(TestMemory::new(space.clone(), base_offset, bytes));
        TestCodeUnitOwner {
            space: space.clone(),
            lock: Arc::new(ReentrantLock::new("test-code-unit")),
            program: Arc::new(TestProgram),
            memory,
            reference_manager: Arc::new(Mutex::new(TestReferenceManager::default())),
            program_context: Arc::new(Mutex::new(TestProgramContext)),
            symbol_table: Arc::new(TestSymbolTable),
            address_map: Arc::new(TestAddressMap { space }),
            property_map_manager: Arc::new(Mutex::new(TestPropertyMapManager::default())),
            comments: Mutex::new(HashMap::new()),
            flag_calls: Mutex::new(Vec::new()),
            comment_notifications: Mutex::new(Vec::new()),
            db_errors: Mutex::new(Vec::new()),
            instruction_records: Mutex::new(HashMap::new()),
            prototypes: Mutex::new(HashMap::new()),
            instructions: Mutex::new(BTreeMap::new()),
            defined_address_after: Mutex::new(None),
        }
    }

    /// Same as [`Self::new`], but big-endian and with no memory block (so
    /// `get_address_string(true, ..)` has no block name to prefix with).
    pub(crate) fn new_big_endian_without_block(
        space: Arc<AddressSpace>,
        base_offset: i64,
        bytes: Vec<u8>,
    ) -> Self {
        let mut owner = Self::new(space.clone(), base_offset, bytes.clone());
        owner.memory = Arc::new(TestMemory {
            space,
            base_offset,
            bytes: RwLock::new(bytes),
            big_endian: true,
            block_name: None,
        });
        owner
    }

    /// An address in this owner's space.
    pub(crate) fn address(&self, offset: i64) -> Address {
        self.space.address(offset)
    }

    /// The backing memory, for poking bytes behind a code unit's byte cache.
    pub(crate) fn memory(&self) -> &Arc<TestMemory> {
        &self.memory
    }

    /// Every `codeMgr.setFlags(addr, flags)` made through this owner, in order.
    pub(crate) fn flag_calls(&self) -> Vec<(i64, u8)> {
        self.flag_calls.lock().unwrap().clone()
    }

    /// Every `codeMgr.sendNotification(..)` made through this owner, in order.
    pub(crate) fn comment_notifications(&self) -> Vec<CommentNotification> {
        self.comment_notifications.lock().unwrap().clone()
    }

    /// Every `codeMgr.dbError(e)` message reported through this owner, in order.
    pub(crate) fn db_errors(&self) -> Vec<String> {
        self.db_errors.lock().unwrap().clone()
    }

    /// The number of comment records currently stored.
    pub(crate) fn comment_record_count(&self) -> usize {
        self.comments.lock().unwrap().len()
    }

    /// Writes a comment record straight into the store, bypassing the code unit -- used to change
    /// the database behind a code unit's comment cache.
    pub(crate) fn put_comment_record_directly(&self, addr: i64, comment_col: usize, comment: &str) {
        let mut record = DBRecord::new(comments_db_adapter::schema(), Field::Long(Some(addr)));
        record.set_field(comment_col, Field::String(Some(comment.to_string())));
        self.comments.lock().unwrap().insert(addr, record);
    }

    /// Reads a comment record straight out of the store, bypassing the code unit.
    pub(crate) fn comment_record_directly(&self, addr: i64) -> Option<DBRecord> {
        self.comments.lock().unwrap().get(&addr).cloned()
    }

    /// Stores the instruction-table record `codeMgr.getInstructionRecord(addr)` should return.
    pub(crate) fn put_instruction_record(&self, addr: i64, record: DBRecord) {
        self.instruction_records.lock().unwrap().insert(addr, record);
    }

    /// Registers a prototype under the id an instruction record refers to it by.
    pub(crate) fn put_instruction_prototype(
        &self,
        proto_id: i32,
        prototype: Arc<dyn InstructionPrototype>,
    ) {
        self.prototypes.lock().unwrap().insert(proto_id, prototype);
    }

    /// Registers an instruction at `offset`, for the `getInstructionAt/After/Before` queries.
    pub(crate) fn put_instruction(&self, offset: i64, instruction: Arc<dyn Instruction>) {
        self.instructions.lock().unwrap().insert(offset, instruction);
    }

    /// Sets what `codeMgr.getDefinedAddressAfter(..)` reports.
    pub(crate) fn set_defined_address_after(&self, address: Option<Address>) {
        *self.defined_address_after.lock().unwrap() = address;
    }
}

impl CodeUnitOwner for TestCodeUnitOwner {
    fn get_lock(&self) -> Arc<ReentrantLock> {
        self.lock.clone()
    }

    fn get_program(&self) -> Arc<dyn Program> {
        self.program.clone()
    }

    fn get_reference_manager(&self) -> Arc<Mutex<dyn ReferenceManager>> {
        self.reference_manager.clone()
    }

    fn get_program_context(&self) -> Arc<Mutex<dyn ProgramContext>> {
        self.program_context.clone()
    }

    fn get_memory(&self) -> Option<Arc<dyn Memory>> {
        Some(self.memory.clone())
    }

    fn get_symbol_table(&self) -> Arc<dyn SymbolTable> {
        self.symbol_table.clone()
    }

    fn get_address_map(&self) -> Arc<dyn AddressMap> {
        self.address_map.clone()
    }

    fn get_property_map_manager(&self) -> Arc<Mutex<dyn PropertyMapManager>> {
        self.property_map_manager.clone()
    }

    fn get_comment_record(&self, addr: i64) -> io::Result<Option<DBRecord>> {
        Ok(self.comments.lock().unwrap().get(&addr).cloned())
    }

    fn create_comment_record(
        &self,
        addr: i64,
        comment_col: i32,
        comment: &str,
    ) -> io::Result<DBRecord> {
        // Mirrors CommentsDBAdapterV1.createRecord: a record keyed by the address index, with the
        // comment written into the column named by the comment type's ordinal.
        let mut record = DBRecord::new(comments_db_adapter::schema(), Field::Long(Some(addr)));
        record.set_field(
            comment_col as usize,
            Field::String(Some(comment.to_string())),
        );
        self.comments.lock().unwrap().insert(addr, record.clone());
        Ok(record)
    }

    fn update_comment_record(&self, record: &DBRecord) -> io::Result<()> {
        let key = record.get_key().get_long_value();
        self.comments.lock().unwrap().insert(key, record.clone());
        Ok(())
    }

    fn delete_comment_record(&self, key: i64) -> io::Result<bool> {
        Ok(self.comments.lock().unwrap().remove(&key).is_some())
    }

    fn send_comment_notification(
        &self,
        address: &Address,
        comment_type: CommentType,
        old_value: Option<&str>,
        new_value: Option<&str>,
    ) {
        self.comment_notifications
            .lock()
            .unwrap()
            .push(CommentNotification {
                address: address.clone(),
                comment_type,
                old_value: old_value.map(str::to_owned),
                new_value: new_value.map(str::to_owned),
            });
    }

    fn db_error(&self, error: io::Error) {
        self.db_errors.lock().unwrap().push(error.to_string());
    }

    fn is_undefined(&self, _address: &Address, _addr: i64) -> bool {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_data_type_for_record(&self, _record: &DBRecord) -> Option<Box<dyn DataType>> {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_data_type_at(&self, _addr: i64) -> Option<Box<dyn DataType>> {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_length_at(&self, _address: &Address) -> i32 {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_defined_address_after(&self, _address: &Address) -> Option<Address> {
        self.defined_address_after.lock().unwrap().clone()
    }

    fn set_flags(&self, addr: i64, flags: u8) {
        self.flag_calls.lock().unwrap().push((addr, flags));
    }

    fn get_instruction_record(&self, addr: i64) -> Option<DBRecord> {
        self.instruction_records.lock().unwrap().get(&addr).cloned()
    }

    fn get_instruction_prototype(&self, proto_id: i32) -> Option<Arc<dyn InstructionPrototype>> {
        self.prototypes.lock().unwrap().get(&proto_id).cloned()
    }

    fn get_original_prototype_context(
        &self,
        _prototype: &dyn InstructionPrototype,
        _base_context_register: Option<RegisterRef>,
    ) -> Option<Arc<dyn ProcessorContextView>> {
        unimplemented!("{UNEXERCISED}")
    }

    fn get_instruction_at(&self, address: &Address) -> Option<Arc<dyn Instruction>> {
        self.instructions
            .lock()
            .unwrap()
            .get(&address.offset())
            .cloned()
    }

    fn get_instruction_after(&self, address: &Address) -> Option<Arc<dyn Instruction>> {
        self.instructions
            .lock()
            .unwrap()
            .range((address.offset() + 1)..)
            .next()
            .map(|(_, instruction)| instruction.clone())
    }

    fn get_instruction_before(&self, address: &Address) -> Option<Arc<dyn Instruction>> {
        self.instructions
            .lock()
            .unwrap()
            .range(..address.offset())
            .next_back()
            .map(|(_, instruction)| instruction.clone())
    }
}
