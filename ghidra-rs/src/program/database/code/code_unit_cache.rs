//! Port of `ghidra.program.database.code.CodeUnitCache`.
//!
//! Java's `CodeUnitCache extends DbCache<CodeUnitDB>`, relying on inheritance to store either an
//! `InstructionDB` or a `DataDB` behind one abstract `CodeUnitDB` supertype and on
//! `DbCache`/`WeakReferenceCache` (a `HashMap` of weak references plus a small `LRUMap` "hard"
//! cache that keeps recently touched entries from being garbage collected) for the actual
//! storage. Two deviations from that, both forced by the surrounding port rather than chosen for
//! convenience:
//!
//! - Rust has no implementation inheritance and `CodeUnitDb` in this crate is a trait, not a
//!   concrete type, so the two possible payloads are named explicitly as [`CodeUnitCacheEntry`],
//!   the cut-point that lets one cache hold either kind.
//! - [`crate::program::database::db_cache::DbCache`] is generic over exactly one concrete
//!   `DbObject` type, which `CodeUnitCacheEntry` (an enum, not a single concrete struct) cannot
//!   satisfy either. This type does not implement that trait; it is a self-contained,
//!   `DbObject`/`DbObjectState`-backed cache purpose-built for the two payload kinds, following
//!   the same "retrieve without the lock, refresh or instantiate under it" contract `DbCache`
//!   documents.
//! - There is no weak-reference layer: Rust has no analogue of Java's GC-driven
//!   `WeakReference`/`ReferenceQueue`, so every live entry is held by a real, strong [`Arc`].
//!   `hard_cache_size` is therefore not "the minimum kept alive against GC pressure" (Java's
//!   documented meaning) but a hard capacity: the least-recently-touched entry is evicted (and
//!   genuinely dropped from the cache) once the count exceeds it. This is observably different
//!   from Java only in that an evicted-but-still-referenced-elsewhere object would keep answering
//!   queries via Java's surviving strong reference outside the cache, whereas here a second
//!   lookup after eviction rebuilds a fresh instance. Neither behavior is reachable from this
//!   cache's own public surface (`get_data`/`get_instruction` always return what is currently
//!   cached or freshly built), so the two are indistinguishable to any of this module's callers.
//!
//! # Cache invalidation without `DbCacheHandle: Send + Sync`
//!
//! [`crate::program::database::db_cache::DbCacheHandle`] -- the handle a [`DbObject`] uses to ask
//! "has my owning cache been invalidated since I was last refreshed" -- is declared `Send + Sync`.
//! `InstructionDB`/`DataDB` are not (see the note on
//! [`DbObject`](crate::program::database::db_object::DbObject) for why: a `Rc`-based `RegisterRef`
//! reaches through both), so a `CodeUnitCache` that directly held those entries could never
//! implement `DbCacheHandle` itself -- the auto-trait bound would fail the moment any entry sat in
//! one of its fields. The fix is to keep the handle and the storage separate:
//! [`CacheModificationHandle`] holds nothing but a shared `i64` counter (trivially `Send + Sync`)
//! and is the object every cached entry's [`DbObject::set_cache`] points at; [`CodeUnitCache`]
//! itself owns the actual [`CodeUnitCacheEntry`] storage and drives that counter's value through
//! [`CodeUnitCache::invalidate`]. This reproduces the real observable behavior (`is_valid()` flips
//! false after an invalidate, `refresh_if_needed` brings it back) without ever needing
//! `CodeUnitCache: Send + Sync`.
//!
//! One consequence: `DbCacheHandle::delete`/`key_changed` -- the callbacks `DbObject::do_refresh`
//! fires on a failed refresh, or that Java's `keyChanged`/`delete(key)` fire directly -- are no-ops
//! on [`CacheModificationHandle`], since it holds no storage to update. A `DbObject` that
//! discovers on refresh that it has been deleted still correctly marks *itself* deleted (via
//! `DbObjectState.deleted`, independent of the handle), so [`DbObject::is_valid`] still reports it
//! correctly; what does not happen automatically is removing the stale `Arc` from this cache's own
//! map. [`CodeUnitCache::delete`]/[`CodeUnitCache::key_changed`] are the inherent, explicit
//! replacements a caller (a future `CodeManagerDB`) is expected to call directly instead.
//!
//! # What could not be ported: `getCachedInstance(long key)`
//!
//! Java's `DbCache.getCachedInstance(Long key)` -- the raw-key overload with no record in hand --
//! falls back to `factory.instantiate(key)` on a cache miss, which for `CodeUnitCache` is
//! `CodeManager.CodeUnitFactory.instantiate(long)`: check the instruction table, then the data
//! table, then fall through to `instantiateUndefinedOrExternalData`, which itself walks
//! `getInstructionContaining`/`getDefinedDataContaining`/external-address handling on the full
//! concrete `CodeManagerDB`. None of that manager exists yet in this crate -- `CodeUnitOwner` (the
//! seam every type in this package depends on instead) exposes no "resolve whichever table this
//! raw key belongs to" callback, only record-shaped and address-shaped queries. This cache
//! therefore only supports instantiate-on-miss from an already-known [`DBRecord`]
//! ([`CodeUnitCache::get_cached_instance_for_record`], and the `get_data`/`get_instruction`
//! convenience wrappers on it) -- exactly the shape `InstructionRecordIterator`/
//! `DataRecordIterator` need, since both already hold a `DBRecord` from their own adapter's record
//! iterator. The raw-key overload is omitted rather than faked.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};

use crate::framework::db::DBRecord;
use crate::program::database::code::code_unit_owner::CodeUnitOwner;
use crate::program::database::code::data_db::DataDB;
use crate::program::database::code::instruction_db::InstructionDB;
use crate::program::database::code::{data_db_adapter, inst_db_adapter};
use crate::program::database::db_cache::DbCacheHandle;
use crate::program::database::db_object::{DbObject, DbObjectState};
use crate::program::model::data::data_type::DataType;

/// A trivially `Send + Sync` [`DbCacheHandle`] backing every entry a [`CodeUnitCache`] hands out.
/// See the module docs for why the handle and the entry storage must be different types.
struct CacheModificationHandle {
    modification_count: AtomicI32,
}

impl DbCacheHandle for CacheModificationHandle {
    fn get_modification_count(&self) -> i32 {
        self.modification_count.load(Ordering::SeqCst)
    }

    fn delete(&self, _key: i64) {
        // No storage here to update -- see the module docs.
    }

    fn key_changed(&self, _old_key: i64, _new_key: i64) {
        // No storage here to update -- see the module docs.
    }
}

/// Either half of the polymorphic `CodeUnitDB` Java's `CodeUnitCache` stores.
///
/// Not a port of a Java type -- the cut-point this crate needs in place of Java's
/// `InstructionDB`/`DataDB` inheriting a shared `CodeUnitDB` supertype. See the module docs.
#[derive(Clone)]
pub enum CodeUnitCacheEntry {
    /// Stands in for a cached `InstructionDB`.
    Instruction(Arc<InstructionDB>),
    /// Stands in for a cached `DataDB`.
    Data(Arc<DataDB>),
}

impl CodeUnitCacheEntry {
    /// The `InstructionDB` this entry holds, or `None` if it holds a `DataDB`.
    pub fn as_instruction(&self) -> Option<Arc<InstructionDB>> {
        match self {
            CodeUnitCacheEntry::Instruction(instruction) => Some(instruction.clone()),
            CodeUnitCacheEntry::Data(_) => None,
        }
    }

    /// The `DataDB` this entry holds, or `None` if it holds an `InstructionDB`.
    pub fn as_data(&self) -> Option<Arc<DataDB>> {
        match self {
            CodeUnitCacheEntry::Data(data) => Some(data.clone()),
            CodeUnitCacheEntry::Instruction(_) => None,
        }
    }
}

impl DbObject for CodeUnitCacheEntry {
    fn state(&self) -> &DbObjectState {
        match self {
            CodeUnitCacheEntry::Instruction(instruction) => instruction.state(),
            CodeUnitCacheEntry::Data(data) => data.state(),
        }
    }

    fn refresh(&self, record: Option<&DBRecord>) -> bool {
        match self {
            CodeUnitCacheEntry::Instruction(instruction) => instruction.refresh(record),
            CodeUnitCacheEntry::Data(data) => data.refresh(record),
        }
    }
}

/// The storage behind a [`CodeUnitCache`], held under one lock so `add`/eviction/lookup are
/// atomic with respect to one another.
struct CacheInner {
    entries: HashMap<i64, CodeUnitCacheEntry>,
    /// Least-recently-touched key at the front, most-recently-touched at the back. Stands in for
    /// the recency order Java's `LRUMap` hard cache maintains.
    lru: VecDeque<i64>,
}

impl CacheInner {
    fn touch(&mut self, key: i64) {
        self.lru.retain(|k| *k != key);
        self.lru.push_back(key);
    }

    fn forget(&mut self, key: i64) {
        self.lru.retain(|k| *k != key);
    }
}

/// Specialized version of a `DbObject` cache for code units. Because the cache has to deal with
/// both instructions and data, it is more convenient to have methods to specifically get an
/// instruction or data when the caller knows which it expects.
///
/// Port of `ghidra.program.database.code.CodeUnitCache`. See the module docs for the shape
/// differences forced by this crate's lack of a concrete `CodeUnitDB`/`DbCache<T>` fit and by
/// `DbCacheHandle`'s `Send + Sync` bound.
pub struct CodeUnitCache {
    owner: Arc<dyn CodeUnitOwner>,
    hard_cache_size: usize,
    handle: Arc<CacheModificationHandle>,
    inner: Mutex<CacheInner>,
}

impl CodeUnitCache {
    /// Constructs a new `CodeUnitCache`. Stands in for `CodeUnitCache(CodeUnitFactory, Lock, int
    /// hardCacheSize)`; the factory and lock are not separate parameters here -- `owner` supplies
    /// everything a from-record instantiation needs (see the module docs on the omitted raw-key
    /// overload), and this port's `CodeUnitCacheEntry` values carry their own locking internally
    /// the same way every other type in this package does.
    pub fn new(owner: Arc<dyn CodeUnitOwner>, hard_cache_size: usize) -> Self {
        CodeUnitCache {
            owner,
            hard_cache_size: hard_cache_size.max(1),
            handle: Arc::new(CacheModificationHandle {
                modification_count: AtomicI32::new(0),
            }),
            inner: Mutex::new(CacheInner {
                entries: HashMap::new(),
                lru: VecDeque::new(),
            }),
        }
    }

    /// The number of objects currently in the cache. Stands in for `DbCache.size()`.
    pub fn size(&self) -> usize {
        self.inner.lock().unwrap().entries.len()
    }

    fn handle(&self) -> Arc<dyn DbCacheHandle> {
        self.handle.clone()
    }

    fn evict_locked(&self, inner: &mut CacheInner) {
        while inner.entries.len() > self.hard_cache_size {
            let Some(oldest) = inner.lru.pop_front() else {
                break;
            };
            inner.entries.remove(&oldest);
        }
    }

    /// Adds the given database object to the cache. Stands in for `DbCache.add(T)`.
    pub fn add(&self, entry: CodeUnitCacheEntry) -> CodeUnitCacheEntry {
        entry.set_cache(self.handle());
        let key = entry.get_key();
        let mut inner = self.inner.lock().unwrap();
        inner.entries.insert(key, entry.clone());
        inner.touch(key);
        self.evict_locked(&mut inner);
        entry
    }

    /// Retrieves the object from the cache, but only if it already exists and is valid. Does not
    /// attempt to refresh or instantiate. Stands in for `DbCache.getIfValid(Long)`.
    pub fn get_if_valid(&self, key: i64) -> Option<CodeUnitCacheEntry> {
        let mut inner = self.inner.lock().unwrap();
        let entry = inner.entries.get(&key)?.clone();
        if !entry.is_valid() {
            return None;
        }
        inner.touch(key);
        Some(entry)
    }

    /// Retrieves the object with the given key directly from the cache without checking validity
    /// or instantiating new instances. Stands in for `DbCache.getRaw(Long)`.
    pub fn get_raw(&self, key: i64) -> Option<CodeUnitCacheEntry> {
        self.inner.lock().unwrap().entries.get(&key).cloned()
    }

    /// Retrieves the database object with the given record's key from the cache, refreshing or
    /// instantiating (from the record) as needed. Stands in for `DbCache.getCachedInstance(
    /// DBRecord)` composed with `CodeUnitCache`'s `CodeUnitFactory.instantiate(DBRecord)`. See the
    /// module docs for why only this record-taking overload -- not the raw-key one -- is ported.
    pub fn get_cached_instance_for_record(&self, record: &DBRecord) -> Option<CodeUnitCacheEntry> {
        let key = record.get_key().get_long_value();
        if let Some(entry) = self.get_if_valid(key) {
            return Some(entry);
        }
        if let Some(entry) = self.get_raw(key) {
            if entry.refresh_if_needed_with_record(Some(record)) {
                let mut inner = self.inner.lock().unwrap();
                inner.touch(key);
                return Some(entry);
            }
        }
        let instantiated = self.instantiate_from_record(record)?;
        Some(self.add(instantiated))
    }

    /// Gets the `Data` object for the given record, or `None` if the record is an instruction
    /// record. Stands in for `CodeUnitCache.getData(DBRecord)`.
    pub fn get_data(&self, record: &DBRecord) -> Option<Arc<DataDB>> {
        self.get_cached_instance_for_record(record)?.as_data()
    }

    /// Gets the `Instruction` object for the given record, or `None` if the record is a data
    /// record. Stands in for `CodeUnitCache.getInstruction(DBRecord)`.
    pub fn get_instruction(&self, record: &DBRecord) -> Option<Arc<InstructionDB>> {
        self.get_cached_instance_for_record(record)?.as_instruction()
    }

    /// Port of `CodeUnitFactory.instantiate(DBRecord)`: dispatches on the record's schema, then
    /// rebuilds the corresponding concrete type using only [`CodeUnitOwner`] callbacks.
    fn instantiate_from_record(&self, record: &DBRecord) -> Option<CodeUnitCacheEntry> {
        if record_has_data_schema(record) {
            self.instantiate_data(record).map(CodeUnitCacheEntry::Data)
        } else {
            self.instantiate_instruction(record)
                .map(CodeUnitCacheEntry::Instruction)
        }
    }

    /// Port of the private `CodeUnitFactory.instantiateInstruction(DBRecord)`.
    fn instantiate_instruction(&self, record: &DBRecord) -> Option<Arc<InstructionDB>> {
        let addr = record.get_key().get_long_value();
        let address = self.owner.get_address_map().decode_address(addr);
        let proto_id = record.get_int(inst_db_adapter::PROTO_ID_COL)?;
        let flags = record.get_byte(inst_db_adapter::FLAGS_COL)? as u8;
        let proto = self.owner.get_instruction_prototype(proto_id)?;
        Some(InstructionDB::new(self.owner.clone(), address, addr, proto, flags))
    }

    /// Port of the private `CodeUnitFactory.instantiateData(DBRecord)`. Java resolves the data
    /// type via `dataManager.getDataType(datatypeID)`; the [`CodeUnitOwner`] seam's
    /// `get_data_type_for_record` is the equivalent already established for `DataDB.refresh`, so
    /// it is reused here rather than reading the type-id column directly.
    fn instantiate_data(&self, record: &DBRecord) -> Option<Arc<DataDB>> {
        let addr = record.get_key().get_long_value();
        let address = self.owner.get_address_map().decode_address(addr);
        let data_type = self
            .owner
            .get_data_type_for_record(record)
            .map(Arc::<dyn DataType>::from);
        Some(Arc::new(DataDB::new(
            self.owner.clone(),
            addr,
            address,
            addr,
            data_type,
        )))
    }

    /// Marks all cached objects as invalid; each will refresh (or discover it has been deleted)
    /// the next time it is validated. Stands in for `DbCache.invalidate()`.
    pub fn invalidate(&self) {
        let count = self.handle.modification_count.fetch_add(1, Ordering::SeqCst) + 1;
        if count < 0 {
            self.handle.modification_count.store(0, Ordering::SeqCst);
        }
    }

    /// The current cache modification counter, corresponding to the number of times the cache has
    /// been invalidated. Stands in for `DbCache.getModificationCount()`.
    pub fn modification_count(&self) -> i32 {
        self.handle.get_modification_count()
    }

    /// Removes the object with the given key from the cache. Stands in for `DbCache.delete(
    /// long)`.
    pub fn delete(&self, key: i64) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(entry) = inner.entries.remove(&key) {
            inner.forget(key);
            entry.set_deleted();
        }
    }

    /// Updates the cache for an object whose key has changed. Stands in for `DbCache.keyChanged(
    /// long, long)`.
    pub fn key_changed(&self, old_key: i64, new_key: i64) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(entry) = inner.entries.remove(&old_key) {
            inner.forget(old_key);
            entry.set_invalid();
            inner.entries.insert(new_key, entry);
            inner.touch(new_key);
        }
    }

    /// Returns every cached object, valid or not. Stands in for `DbCache.getCachedObjects()`.
    pub fn get_cached_objects(&self) -> Vec<CodeUnitCacheEntry> {
        self.inner.lock().unwrap().entries.values().cloned().collect()
    }
}

/// Mirrors `dbRecord.hasSameSchema(DataDBAdapter.DATA_SCHEMA)` from
/// `CodeUnitFactory.instantiate(DBRecord)`. Duplicated (rather than reused) from the equivalent
/// private helpers on `InstructionDB`/`DataDB`, which are not `pub` and are out of this port's
/// scope to modify.
fn record_has_data_schema(record: &DBRecord) -> bool {
    let schema = data_db_adapter::schema();
    if record.get_key().get_type() != schema.get_key_type() {
        return false;
    }
    if record.get_field_count() != schema.get_field_count() {
        return false;
    }
    (0..schema.get_field_count()).all(|i| record.get_field(i).get_type() == schema.get_field_type(i))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::Field;
    use crate::program::database::code::test_support::TestCodeUnitOwner;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::instruction_prototype::{
        GetPseudoParserContextError, InstructionPrototype,
    };
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::{InstructionContext, Mask, ProcessorContextView};
    use crate::program::model::listing::instruction::OperandValue;
    use crate::program::model::mem::MemBuffer;
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::pcode::{PatchEncoder, PcodeOp, PcodeOverride};
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::RefType;
    use crate::program::seam_stubs::ParserContext as SeamParserContext;

    /// A minimal `InstructionPrototype`: a 2-operand, fall-through instruction of a fixed length.
    /// `get_language` is never exercised by these tests (they never reach length-override or
    /// alignment checks), so it is left `unimplemented!()` rather than standing up a full `
    /// Language` mock.
    struct MockPrototype {
        length: i32,
    }

    impl InstructionPrototype for MockPrototype {
        fn get_parser_context(
            &self,
            _buf: &dyn MemBuffer,
            _processor_context: &dyn ProcessorContextView,
        ) -> Result<Box<dyn SeamParserContext>, MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }

        fn get_pseudo_parser_context(
            &self,
            _address: &Address,
            _buffer: &dyn MemBuffer,
            _processor_context: &dyn ProcessorContextView,
        ) -> Result<Box<dyn SeamParserContext>, GetPseudoParserContextError> {
            unimplemented!("not exercised by these tests")
        }

        fn has_delay_slots(&self) -> bool {
            false
        }

        fn has_cross_build_dependency(&self) -> bool {
            false
        }

        fn has_next2_dependency(&self) -> bool {
            false
        }

        fn get_mnemonic(&self, _context: &dyn InstructionContext) -> String {
            "MOV".to_string()
        }

        fn get_length(&self) -> i32 {
            self.length
        }

        fn get_instruction_mask(&self) -> Option<Box<dyn Mask>> {
            None
        }

        fn get_operand_value_mask(&self, _operand_index: i32) -> Option<Box<dyn Mask>> {
            None
        }

        fn get_flow_type(&self, _context: &dyn InstructionContext) -> RefType {
            RefType::FallThrough
        }

        fn get_delay_slot_depth(&self, _context: &dyn InstructionContext) -> i32 {
            0
        }

        fn get_delay_slot_byte_count(&self) -> i32 {
            0
        }

        fn is_in_delay_slot(&self) -> bool {
            false
        }

        fn get_num_operands(&self) -> i32 {
            2
        }

        fn get_op_type(&self, _operand_index: i32, _context: &dyn InstructionContext) -> i32 {
            0
        }

        fn get_fall_through(&self, _context: &dyn InstructionContext) -> Option<Address> {
            None
        }

        fn get_fall_through_offset(&self, _context: &dyn InstructionContext) -> i32 {
            self.length
        }

        fn get_flows(&self, _context: &dyn InstructionContext) -> Option<Vec<Address>> {
            None
        }

        fn get_separator(&self, operand_index: i32) -> Option<String> {
            if operand_index == 0 {
                Some(", ".to_string())
            } else {
                None
            }
        }

        fn get_op_representation_list(
            &self,
            _operand_index: i32,
            _context: &dyn InstructionContext,
        ) -> Option<Vec<OperandValue>> {
            None
        }

        fn get_address(
            &self,
            _operand_index: i32,
            _context: &dyn InstructionContext,
        ) -> Option<Address> {
            None
        }

        fn get_register(
            &self,
            _operand_index: i32,
            _context: &dyn InstructionContext,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }

        fn get_scalar(
            &self,
            _operand_index: i32,
            _context: &dyn InstructionContext,
        ) -> Option<Scalar> {
            None
        }

        fn get_op_objects(
            &self,
            _operand_index: i32,
            _context: &dyn InstructionContext,
        ) -> Vec<OperandValue> {
            Vec::new()
        }

        fn get_operand_ref_type(
            &self,
            _operand_index: i32,
            _context: &dyn InstructionContext,
            _override_: Option<&dyn PcodeOverride>,
        ) -> RefType {
            RefType::Data
        }

        fn has_delimeter(&self, _operand_index: i32) -> bool {
            false
        }

        fn get_input_objects(&self, _context: &dyn InstructionContext) -> Vec<OperandValue> {
            Vec::new()
        }

        fn get_result_objects(&self, _context: &dyn InstructionContext) -> Vec<OperandValue> {
            Vec::new()
        }

        fn get_pcode(
            &self,
            _context: &dyn InstructionContext,
            _override_: Option<&dyn PcodeOverride>,
        ) -> Vec<PcodeOp> {
            Vec::new()
        }

        fn get_pcode_packed(
            &self,
            _encoder: &mut dyn PatchEncoder,
            _context: &dyn InstructionContext,
            _override_: Option<&dyn PcodeOverride>,
        ) -> io::Result<()> {
            Ok(())
        }

        fn get_pcode_for_operand(
            &self,
            _context: &dyn InstructionContext,
            _operand_index: i32,
        ) -> Vec<PcodeOp> {
            Vec::new()
        }

        fn get_language(&self) -> Arc<dyn Language> {
            unimplemented!("not exercised by these tests")
        }
    }

    use std::io;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn owner() -> (Arc<TestCodeUnitOwner>, Arc<dyn CodeUnitOwner>) {
        let owner = Arc::new(TestCodeUnitOwner::new(space(), 0x1000, vec![0u8; 0x100]));
        let dynamic: Arc<dyn CodeUnitOwner> = owner.clone();
        (owner, dynamic)
    }

    fn data_record(addr: i64) -> DBRecord {
        let schema = data_db_adapter::schema();
        let mut record = DBRecord::new(schema, Field::Long(Some(addr)));
        record.set_field(
            crate::program::database::code::data_db_adapter::DATA_TYPE_ID_COL,
            Field::Long(Some(0)),
        );
        record
    }

    fn instruction_record(addr: i64, proto_id: i32) -> DBRecord {
        let schema = inst_db_adapter::schema();
        let mut record = DBRecord::new(schema, Field::Long(Some(addr)));
        record.set_field(inst_db_adapter::PROTO_ID_COL, Field::Int(Some(proto_id)));
        record.set_field(inst_db_adapter::FLAGS_COL, Field::Byte(Some(0)));
        record
    }

    #[test]
    fn get_data_instantiates_on_miss_and_hits_the_cache_thereafter() {
        let (test_owner, dyn_owner) = owner();
        test_owner.set_data_type_at(0x1000, Arc::new(crate::program::database::code::test_support::TestDataType::fixed("dword", 4)));
        let cache = CodeUnitCache::new(dyn_owner, 10);
        let record = data_record(0x1000);

        assert_eq!(cache.size(), 0);
        let first = cache.get_data(&record).expect("miss should instantiate");
        assert_eq!(cache.size(), 1);

        let second = cache.get_data(&record).expect("hit should reuse the cached instance");
        assert!(Arc::ptr_eq(&first, &second), "a cache hit must not rebuild the object");
    }

    #[test]
    fn get_instruction_dispatches_by_schema_and_is_distinct_from_data() {
        let (test_owner, dyn_owner) = owner();
        test_owner.put_instruction_prototype(7, Arc::new(MockPrototype { length: 2 }));
        let cache = CodeUnitCache::new(dyn_owner, 10);
        let record = instruction_record(0x2000, 7);

        let instruction = cache.get_instruction(&record).expect("instruction record should dispatch");
        assert_eq!(instruction.get_key(), 0x2000);
        // The same key, asked for as data, must not match -- proves dispatch actually looked at
        // the record's schema rather than always returning something.
        assert!(cache.get_data(&record).is_none());
    }

    #[test]
    fn eviction_drops_the_least_recently_touched_entry() {
        let (test_owner, dyn_owner) = owner();
        for addr in [0x1000i64, 0x1001, 0x1002] {
            test_owner.set_data_type_at(addr, Arc::new(crate::program::database::code::test_support::TestDataType::fixed("byte", 1)));
        }
        let cache = CodeUnitCache::new(dyn_owner, 2);

        let first = cache.get_data(&data_record(0x1000)).unwrap();
        let _second = cache.get_data(&data_record(0x1001)).unwrap();
        assert_eq!(cache.size(), 2);

        // A third distinct entry pushes the cache over its hard capacity of 2, evicting 0x1000
        // (the least recently touched -- 0x1001 is more recent, and 0x1002 is brand new).
        let _third = cache.get_data(&data_record(0x1002)).unwrap();
        assert_eq!(cache.size(), 2);
        assert!(cache.get_raw(0x1000).is_none(), "the oldest entry should have been evicted");

        // Fetching 0x1000 again is therefore a genuine miss: a *new* instance is built.
        let rebuilt = cache.get_data(&data_record(0x1000)).unwrap();
        assert!(
            !Arc::ptr_eq(&first, &rebuilt),
            "an evicted key must be rebuilt from scratch, not reuse the dropped instance"
        );
    }

    #[test]
    fn touching_an_entry_protects_it_from_eviction() {
        let (test_owner, dyn_owner) = owner();
        for addr in [0x1000i64, 0x1001, 0x1002] {
            test_owner.set_data_type_at(addr, Arc::new(crate::program::database::code::test_support::TestDataType::fixed("byte", 1)));
        }
        let cache = CodeUnitCache::new(dyn_owner, 2);

        let first = cache.get_data(&data_record(0x1000)).unwrap();
        let _second = cache.get_data(&data_record(0x1001)).unwrap();
        // Re-touch 0x1000 so 0x1001 becomes the least-recently-touched entry instead.
        let touched_again = cache.get_data(&data_record(0x1000)).unwrap();
        assert!(Arc::ptr_eq(&first, &touched_again));

        let _third = cache.get_data(&data_record(0x1002)).unwrap();
        assert!(cache.get_raw(0x1000).is_some(), "recently touched entry should survive");
        assert!(cache.get_raw(0x1001).is_none(), "the untouched entry should be evicted instead");
    }

    #[test]
    fn invalidate_marks_entries_invalid_until_refreshed() {
        let (test_owner, dyn_owner) = owner();
        test_owner.set_data_type_at(0x3000, Arc::new(crate::program::database::code::test_support::TestDataType::fixed("dword", 4)));
        let cache = CodeUnitCache::new(dyn_owner, 10);
        let record = data_record(0x3000);

        let first = cache.get_data(&record).unwrap();
        assert!(DbObject::is_valid(&*first));

        cache.invalidate();
        assert_eq!(cache.modification_count(), 1);
        // get_if_valid must not paper over the invalidation.
        assert!(cache.get_if_valid(0x3000).is_none());
        assert!(!DbObject::is_valid(&*first), "the live Arc should observe the invalidation too");

        // A subsequent lookup refreshes (rather than rebuilding) the same instance and it becomes
        // valid again.
        let refreshed = cache.get_data(&record).unwrap();
        assert!(Arc::ptr_eq(&first, &refreshed));
        assert!(DbObject::is_valid(&*refreshed));
    }

    #[test]
    fn delete_removes_the_entry_and_marks_it_deleted() {
        let (test_owner, dyn_owner) = owner();
        test_owner.set_data_type_at(0x4000, Arc::new(crate::program::database::code::test_support::TestDataType::fixed("byte", 1)));
        let cache = CodeUnitCache::new(dyn_owner, 10);
        let record = data_record(0x4000);

        let entry = cache.get_data(&record).unwrap();
        cache.delete(0x4000);

        assert!(cache.get_raw(0x4000).is_none());
        assert!(entry.state().is_deleted_flag());
    }

    #[test]
    fn get_data_returns_none_when_the_data_type_cannot_be_resolved_and_records_no_entry() {
        // No data type registered at this address: `get_data_type_for_record` reports `None`,
        // which is a legitimate "unknown type" answer (mapped to `DataType.DEFAULT`), not a
        // failure -- so this should still succeed and cache a `DataDB` with the default type.
        let (_test_owner, dyn_owner) = owner();
        let cache = CodeUnitCache::new(dyn_owner, 10);
        let record = data_record(0x5000);

        let data = cache.get_data(&record).expect("unknown type maps to DataType.DEFAULT");
        assert_eq!(data.get_key(), 0x5000);
    }
}
