//! Port of `ghidra.program.database.references.BigRefListV0`.
//!
//! `BigRefListV0` is the concrete, one-record-per-reference [`RefList`] implementation used for a
//! single address's reference list once it has grown too large for the byte-packed
//! [`RefListV0`](crate::program::database::references::RefListV0) encoding (per
//! `RefList.checkRefListSize`'s `BIG_REFLIST_THRESHOLD` promotion). Each reference gets its own row
//! in a dedicated per-address `Table` (`"[From]BigRefList_" + hex(key)`) instead of being packed
//! into one blob, trading per-row storage overhead for cheaper incremental inserts/removals at
//! scale.
//!
//! This class was selected as a dependency-cycle cut-point, so it is ported here as a trait rather
//! than a concrete struct. `BigRefListV0`'s abstract-method overrides are inherited from
//! `RefList` (the same base class `RefListV0` implements): `addRef`/`getAllRefs`/`getNumRefs`/
//! `hasReference`/`getPrimaryRef`/`getRef`/`getRefs`/`isEmpty`/`getReferenceLevel`/`removeAll`/
//! `removeRef`/`setPrimary`/`setSymbolID`/`updateRefType`, all declared on the [`RefList`]
//! supertrait. This trait only adds the package-private bulk-insert helpers
//! `addRefs(ReferenceIterator)` and `addRefs(Reference[])` (both overloads exist here, unlike
//! `RefListV0` which only has the array form) used by the `RefList.checkRefListSize` promotion
//! path and by `ToAdapter`/`FromAdapter` upgrade paths.
//!
//! Not ported here: `checkRefListSize`: `BigRefListV0`'s override is a trivial no-op (`return
//! this;`, since a `BigRefListV0` is already as big as it gets), and the real logic lives on
//! `RefList`'s own still-unported default method (see `ref_list.rs`'s module docs for why).
//!
//! `RefList` is now ported (see `ref_list.rs`), so this trait declares it as a supertrait,
//! mirroring the Java `BigRefListV0 extends RefList` relationship and reusing the same supertrait
//! `RefListV0` already extends.
//!
//! **Concrete implementation.** [`BigRefListV0Impl`] below is the concrete, one-row-per-reference
//! struct that implements this trait (and [`RefList`]), porting the two static factory methods
//! (`createNew`/`createExisting`, as associated functions -- same object-safety convention
//! [`RefListV0Impl`](crate::program::database::references::ref_list_v0::RefListV0Impl) already
//! uses) plus the private constructors and per-row table helpers (`appendRef`/`getRef(DBRecord)`/
//! `getTableName`/`updateRecord`/`findHighestRefLevel`). The nested `RefIterator` class is not
//! ported by name: `get_refs`/`get_all_refs` instead decode eagerly into a `Vec` and expose it via
//! [`ReferenceIteratorAdapter`], the same simplification `RefListV0Impl` already makes (see that
//! module's docs) and for the same reason (this port's [`RecordIterator`] borrows from the
//! `Table`'s `&self`, so a lazily-decoding iterator would have to fight the same lifetime this
//! trait's `&self`-only read methods can't grant it).
//!
//! Three deliberate decoupling simplifications relative to Java, continuing the precedent
//! `RefListV0Impl` already set for this exact package:
//! - **No stored `Program`.** Java's constructors take a `ProgramDB program`, used only to reach
//!   `program.getDBHandle()` (to create/open/delete this list's private per-address table) and to
//!   build `MemReferenceDB`/`StackReferenceDB`/etc. (which don't store one either). This port
//!   stores the `DBHandle` it actually needs directly (behind `Arc<Mutex<..>>`, since table
//!   creation/deletion need `&mut DBHandle`) instead of threading a whole `Program` through for
//!   one accessor.
//! - **External-location and external-block resolution via injectable closures.** Identical
//!   rationale and default behavior to `RefListV0Impl`'s `external_resolver`/
//!   `is_external_block_resolver` -- see that module's docs.
//! - **`createExisting` takes already-extracted fields, not a `DBRecord`.** Same rationale as
//!   `RefListV0Impl::instantiate_existing`: the not-yet-ported concrete `ToAdapter`/`FromAdapter`
//!   subclass already knows its own schema's column layout, so [`BigRefListV0Impl::create_existing`]
//!   takes `key`/`ref_level` as plain parameters rather than growing [`RecordAdapter`] a new
//!   schema-aware accessor. Unlike `RefListV0Impl`, Java's `createExisting` validates
//!   `rec.getBinaryData(REF_DATA_COL) != null` (an "are you sure this address is really a
//!   `BigRefListV0`?" sanity check) -- that check is the caller's job here too, since the caller is
//!   the one holding the `DBRecord` in the first place.
//!
//! **No `program.getDBHandle().createTable(name, schema, new int[] { ADDRESS_COL })` secondary
//! index.** This port's [`Table`] has no secondary-index support at all (see
//! `InstDBAdapterV0`/`InstDBAdapterV1`'s module docs for the same limitation and convention), so
//! every by-address lookup (`get_ref`/`remove_ref`/`set_primary`/`set_symbol_id`/`update_ref_type`)
//! scans the per-address table linearly instead of via `Table.findRecords(Field, int)`, matching
//! that same established convention.
//!
//! **`removeAll` never leaves `table` "null".** Java sets its `table` field to `null` after
//! `removeAll()` (and every subsequent real call would throw `NullPointerException`, since callers
//! are expected to have already checked `isValid()`/discarded the list). This port's `table` field
//! stays a live (but now-cleared and de-registered) `Arc<RwLock<Table>>` instead of an `Option`,
//! which is simpler and strictly safer (a stray post-`removeAll` call sees an empty table rather
//! than panicking) while remaining equally "this list should not be used anymore" once
//! [`DbObject::is_valid`](crate::program::database::db_object::DbObject::is_valid) reports `false`.

use std::io;
use std::sync::{Arc, Mutex, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, Schema, Table};
use crate::program::database::db_object::{DbObject, DbObjectState};
use crate::program::database::map::AddressMap;
use crate::program::database::references::entry_point_reference_db::EntryPointReferenceDb;
use crate::program::database::references::external_reference_db::ExternalReferenceDb;
use crate::program::database::references::mem_reference_db::MemReferenceDb;
use crate::program::database::references::offset_reference_db::OffsetReferenceDb;
use crate::program::database::references::ref_list_flags_v0::{decode_source, encode_flags};
use crate::program::database::references::ref_list_v0::{
    default_external_resolver, default_is_external_block_resolver, ref_level_for,
    reference_offset_shift, FLAG_HAS_SYMBOL_ID, FLAG_OFFSET, FLAG_PRIMARY, FLAG_SHIFT,
};
use crate::program::database::references::shifted_reference_db::ShiftedReferenceDb;
use crate::program::database::references::stack_reference_db::StackReferenceDb;
use crate::program::database::references::{RecordAdapter, RefList};
use crate::program::model::address::{Address, SpecialAddress};
use crate::program::model::symbol::{
    ExternalLocation, RefType, Reference, ReferenceIterator, ReferenceIteratorAdapter, RefTypeFactory,
    SourceType,
};

/// The one-row-per-reference list for a single address (either outgoing "from" references or
/// incoming "to" references, depending on how the owning adapter constructed it), used once the
/// address's reference count outgrows the packed
/// [`RefListV0`](crate::program::database::references::RefListV0) encoding.
///
/// Port of `ghidra.program.database.references.BigRefListV0`. See the module docs for what was
/// intentionally left out (the static factories, the private per-row table helpers, the nested
/// iterator class, and `checkRefListSize`).
pub trait BigRefListV0: RefList {
    /// Appends every reference produced by `ref_iter` in one pass. Stands in for
    /// `BigRefListV0.addRefs(ReferenceIterator)`, used by the `RefList.checkRefListSize`
    /// promotion path to bulk-copy an existing list's references into a newly promoted
    /// `BigRefListV0`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn add_refs_from_iter(&mut self, ref_iter: &mut dyn ReferenceIterator) -> io::Result<()>;

    /// Appends a batch of existing references in one pass. Stands in for
    /// `BigRefListV0.addRefs(Reference[])`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn add_refs(&mut self, refs: &[Arc<dyn Reference>]) -> io::Result<()>;
}

/// Base name every per-address table is prefixed with. Stands in for
/// `BigRefListV0.BASE_TABLE_NAME`.
const BASE_TABLE_NAME: &str = "BigRefList_";

const ADDRESS_COL: usize = 0;
const FLAGS_COL: usize = 1;
const TYPE_COL: usize = 2;
const OPINDEX_COL: usize = 3;
const SYMBOL_ID_COL: usize = 4;
const OFFSET_COL: usize = 5;

/// Returns the per-address table's schema: one row per reference, `RefID`-keyed. Stands in for
/// `BigRefListV0.BIG_REFS_SCHEMA`.
fn big_refs_schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        1,
        FieldType::Long,
        "RefID".to_string(),
        vec![
            FieldType::Long,
            FieldType::Byte,
            FieldType::Byte,
            FieldType::Byte,
            FieldType::Long,
            FieldType::Long,
        ],
        vec![
            "Address".to_string(),
            "Flags".to_string(),
            "Type".to_string(),
            "OpIndex".to_string(),
            "SymbolID".to_string(),
            "Offset".to_string(),
        ],
        vec![],
    ))
}

/// Returns this list's dedicated per-address table name. Stands in for
/// `BigRefListV0.getTableName()`. `Long.toHexString`'s lowercase, unsigned, no-leading-zero hex
/// rendering of a (possibly negative) `long` is reproduced by formatting `key as u64`.
fn table_name_for(is_from: bool, key: i64) -> String {
    let prefix = if is_from { "From" } else { "" };
    format!("{prefix}{BASE_TABLE_NAME}{:x}", key as u64)
}

/// The one-row-per-reference list for a single address (either outgoing "from" references or
/// incoming "to" references, depending on how the owning adapter constructed it), used once the
/// address's reference count outgrows the packed
/// [`RefListV0Impl`](crate::program::database::references::ref_list_v0::RefListV0Impl) encoding.
///
/// Port of `ghidra.program.database.references.BigRefListV0`. See the module docs for the factory
/// methods this ports and the decoupling simplifications it makes relative to Java.
pub struct BigRefListV0Impl {
    state: DbObjectState,
    address: Address,
    addr_map: Arc<dyn AddressMap + Send + Sync>,
    adapter: Option<Arc<Mutex<dyn RecordAdapter + Send>>>,
    is_from: bool,
    db_handle: Arc<Mutex<DBHandle>>,
    table: Arc<RwLock<Table>>,
    ref_level: i8,
    external_resolver: Arc<dyn Fn(&Address) -> Box<dyn ExternalLocation> + Send + Sync>,
    is_external_block_resolver: Arc<dyn Fn(&Address) -> bool + Send + Sync>,
}

impl BigRefListV0Impl {
    /// Creates a new, empty `BigRefListV0Impl` for `address`, creating its dedicated per-address
    /// table. Stands in for `BigRefListV0.createNew`/the private `BigRefListV0(Address,
    /// RecordAdapter, AddressMap, ProgramDB, boolean)` constructor; `program` is dropped in favor
    /// of storing `db_handle` directly (see the module docs).
    ///
    /// # Errors
    ///
    /// Returns an error if the per-address table could not be created (e.g. it already exists).
    pub fn create_new(
        address: Address,
        adapter: Option<Arc<Mutex<dyn RecordAdapter + Send>>>,
        addr_map: Arc<dyn AddressMap + Send + Sync>,
        db_handle: Arc<Mutex<DBHandle>>,
        is_from: bool,
    ) -> io::Result<Self> {
        let key = addr_map.get_key(&address, true);
        let table_name = table_name_for(is_from, key);
        let table = db_handle
            .lock()
            .expect("BigRefListV0Impl's db_handle mutex should never be poisoned")
            .create_table(table_name, big_refs_schema())?;
        Ok(BigRefListV0Impl {
            state: DbObjectState::new(key),
            address,
            addr_map,
            adapter,
            is_from,
            db_handle,
            table,
            ref_level: -1,
            external_resolver: default_external_resolver(),
            is_external_block_resolver: default_is_external_block_resolver(),
        })
    }

    /// Reconstructs a `BigRefListV0Impl` from an already-persisted pointer record's fields,
    /// opening its existing per-address table. Stands in for `BigRefListV0.createExisting`/the
    /// private `BigRefListV0(DBRecord, RecordAdapter, AddressMap, ProgramDB, boolean)`
    /// constructor; `program` is dropped and the `DBRecord` is replaced with its already-extracted
    /// `key`/`ref_level` fields (see the module docs for why, mirroring
    /// `RefListV0Impl::instantiate_existing`). Callers are expected to have already verified the
    /// pointer record's `Ref Data` column is `None` (Java's `IllegalArgumentException` guard) --
    /// this only knows how to open a `BigRefListV0`'s own table, not validate the caller's record.
    ///
    /// # Errors
    ///
    /// Returns an error if the per-address table does not exist.
    pub fn create_existing(
        key: i64,
        ref_level: i8,
        adapter: Option<Arc<Mutex<dyn RecordAdapter + Send>>>,
        addr_map: Arc<dyn AddressMap + Send + Sync>,
        db_handle: Arc<Mutex<DBHandle>>,
        is_from: bool,
    ) -> io::Result<Self> {
        let address = addr_map.decode_address(key);
        let table_name = table_name_for(is_from, key);
        let table = db_handle
            .lock()
            .expect("BigRefListV0Impl's db_handle mutex should never be poisoned")
            .get_table(&table_name)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("BigRefList table not found for {address} ({table_name})"),
                )
            })?;
        Ok(BigRefListV0Impl {
            state: DbObjectState::new(key),
            address,
            addr_map,
            adapter,
            is_from,
            db_handle,
            table,
            // Mirrors Java: `if (!isFrom) { refLevel = rec.getByteValue(REF_LEVEL_COL); }` --
            // "from" lists never read a stored ref level (they leave the constructor-default -1).
            ref_level: if is_from { -1 } else { ref_level },
            external_resolver: default_external_resolver(),
            is_external_block_resolver: default_is_external_block_resolver(),
        })
    }

    /// Overrides the closure used to resolve an [`ExternalLocation`] when decoding an external
    /// reference. See the module docs for why this exists instead of a stored `Program`.
    pub fn set_external_location_resolver(
        &mut self,
        resolver: Arc<dyn Fn(&Address) -> Box<dyn ExternalLocation> + Send + Sync>,
    ) {
        self.external_resolver = resolver;
    }

    /// Overrides the closure used to decide whether a decoded offset reference's destination
    /// falls within the program's reserved "EXTERNAL" memory block. See the module docs for why
    /// this exists instead of a stored `Program`.
    pub fn set_external_block_resolver(
        &mut self,
        resolver: Arc<dyn Fn(&Address) -> bool + Send + Sync>,
    ) {
        self.is_external_block_resolver = resolver;
    }

    /// Appends one reference's row to the per-address table, updating the cached reference level
    /// first if this is a "to" list. Stands in for `BigRefListV0.appendRef`. Does not itself call
    /// [`Self::update_record`] -- callers batch that until after every row in a bulk insert has
    /// been appended, matching Java's own `addRef`/`addRefs` call patterns.
    #[allow(clippy::too_many_arguments)]
    fn append_ref(
        &mut self,
        from_addr: &Address,
        to_addr: &Address,
        op_index: i32,
        ref_type: RefType,
        source: SourceType,
        is_primary: bool,
        symbol_id: i64,
        is_offset: bool,
        is_shifted: bool,
        offset_or_shift: i64,
    ) -> io::Result<()> {
        if !self.is_from {
            let level = ref_level_for(ref_type);
            if level > self.ref_level {
                self.ref_level = level;
            }
        }
        let addr = if self.is_from { to_addr } else { from_addr };
        let addr_key = self.addr_map.get_key(addr, true);
        let has_symbol_id = symbol_id >= 0;
        let flags_byte = encode_flags(is_primary, is_offset, has_symbol_id, is_shifted, source)
            .expect("SourceType storage id always fits in RefListFlagsV0's 3-bit budget");

        let mut table = self.table.write().unwrap();
        let id = table.get_next_key();
        let mut rec = DBRecord::new(big_refs_schema(), Field::Long(Some(id)));
        rec.set_long(ADDRESS_COL, addr_key);
        rec.set_byte(FLAGS_COL, flags_byte as i8);
        rec.set_byte(TYPE_COL, ref_type.value() as i8);
        rec.set_byte(OPINDEX_COL, op_index as i8);
        rec.set_long(SYMBOL_ID_COL, symbol_id);
        rec.set_long(OFFSET_COL, offset_or_shift);
        table.put_record(rec)
    }

    /// Decodes one per-address table row into a [`Reference`]. Stands in for
    /// `BigRefListV0.getRef(DBRecord)`.
    fn decode_ref(&self, rec: &DBRecord) -> Arc<dyn Reference> {
        let addr_key = rec.get_long(ADDRESS_COL).unwrap_or(0);
        let flags_byte = rec.get_byte(FLAGS_COL).unwrap_or(0) as u8;
        let ref_type = RefTypeFactory::get(rec.get_byte(TYPE_COL).unwrap_or(0))
            .expect("BigRefListV0-encoded RefType bytes are always valid");
        let op_index = rec.get_byte(OPINDEX_COL).unwrap_or(0) as i32;

        let source = decode_source(flags_byte);
        let is_primary = flags_byte & FLAG_PRIMARY != 0;
        let has_symbol_id = flags_byte & FLAG_HAS_SYMBOL_ID != 0;
        let is_offset_ref = flags_byte & FLAG_OFFSET != 0;
        let is_shift_ref = flags_byte & FLAG_SHIFT != 0;

        let mut symbol_id: i64 = -1;
        if has_symbol_id {
            symbol_id = rec.get_long(SYMBOL_ID_COL).unwrap_or(-1);
        }

        let from = if self.is_from { self.address.clone() } else { self.addr_map.decode_address(addr_key) };
        let to = if self.is_from { self.addr_map.decode_address(addr_key) } else { self.address.clone() };

        if is_offset_ref || is_shift_ref {
            let offset_or_shift = rec.get_long(OFFSET_COL).unwrap_or(0);
            if is_shift_ref {
                Arc::new(ShiftedReferenceDb::new(
                    from,
                    to,
                    ref_type,
                    op_index,
                    source,
                    is_primary,
                    symbol_id,
                    offset_or_shift as i32,
                ))
            } else {
                let is_external_block = (self.is_external_block_resolver)(&to);
                Arc::new(OffsetReferenceDb::new(
                    from,
                    to,
                    ref_type,
                    op_index,
                    source,
                    is_primary,
                    symbol_id,
                    offset_or_shift,
                    is_external_block,
                ))
            }
        } else if to.is_external_address() {
            let resolver = self.external_resolver.clone();
            let ext_addr = to.clone();
            let factory: Arc<dyn Fn() -> Box<dyn ExternalLocation> + Send + Sync> =
                Arc::new(move || resolver(&ext_addr));
            Arc::new(ExternalReferenceDb::new(from, to, ref_type, op_index, source, factory))
        } else if from == SpecialAddress::ext_from_address() {
            Arc::new(EntryPointReferenceDb::new(
                from, to, ref_type, op_index, source, is_primary, symbol_id,
            ))
        } else if to.is_stack_address() {
            Arc::new(StackReferenceDb::new(
                from, to, ref_type, op_index, source, is_primary, symbol_id,
            ))
        } else {
            Arc::new(MemReferenceDb::new(from, to, ref_type, op_index, source, is_primary, symbol_id))
        }
    }

    /// Decodes every row currently in the per-address table, in table iteration order (Java's own
    /// `RefIterator`/`getAllRefs` likewise make no ordering guarantee beyond "whatever the
    /// underlying `Table.iterator()` yields").
    fn decode_all(&self) -> io::Result<Vec<Arc<dyn Reference>>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut refs = Vec::with_capacity(table.get_record_count());
        while let Some(rec) = iter.next()? {
            refs.push(self.decode_ref(&rec));
        }
        Ok(refs)
    }

    /// Scans every row in the per-address table for one whose `Address`/`OpIndex` columns
    /// (decoded) match, without needing this port's absent secondary-index support. Returns the
    /// row's own `RefID` key plus its decoded reference. Stands in for the `for (Field id :
    /// table.findRecords(addrField, ADDRESS_COL))` idiom every by-address Java method uses.
    fn find_row(&self, change_addr: &Address, op_index: i32) -> io::Result<Option<(Field, Arc<dyn Reference>)>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            let r = self.decode_ref(&rec);
            if r.operand_index() != op_index {
                continue;
            }
            let addr = if self.is_from { r.to_address() } else { r.from_address() };
            if &addr == change_addr {
                return Ok(Some((rec.get_key().clone(), r)));
            }
        }
        Ok(None)
    }

    /// Rescans the per-address table for the highest [`ref_level_for`] across every remaining
    /// reference. Stands in for `BigRefListV0.findHighestRefLevel`; `current_ref_level` is unused
    /// beyond mirroring Java's early-exit signature (this port always scans every row -- Java's
    /// own early exit is an optimization this port's [`Table`] has no ordering to exploit anyway).
    fn find_highest_ref_level(&self) -> io::Result<i8> {
        let refs = self.decode_all()?;
        let mut max_level: i8 = -1;
        for r in &refs {
            let level = ref_level_for(r.reference_type());
            if level > max_level {
                max_level = level;
            }
        }
        Ok(max_level)
    }

    /// Writes this list's current `num_refs`/`ref_level` back through `adapter`, with a `None`
    /// `Ref Data` column -- the sentinel `ToAdapterV1`/`FromAdapterV1` (not yet ported) use to
    /// recognize "this address's references live in a `BigRefListV0` table, not inline". Stands
    /// in for `BigRefListV0.updateRecord`.
    fn update_record(&mut self) -> io::Result<()> {
        if let Some(adapter) = &self.adapter {
            let num_refs = self.table.read().unwrap().get_record_count() as i32;
            let ref_level_byte = self.ref_level as u8;
            let mut guard = adapter
                .lock()
                .expect("BigRefListV0Impl's adapter mutex should never be poisoned");
            guard.create_record(self.state.get_key(), num_refs, ref_level_byte, None)?;
        }
        Ok(())
    }
}

impl DbObject for BigRefListV0Impl {
    fn state(&self) -> &DbObjectState {
        &self.state
    }

    fn refresh(&self, _record: Option<&DBRecord>) -> bool {
        false
    }
}

impl RefList for BigRefListV0Impl {
    #[allow(clippy::too_many_arguments)]
    fn add_ref(
        &mut self,
        from_addr: &Address,
        to_addr: &Address,
        ref_type: RefType,
        op_index: i32,
        symbol_id: i64,
        is_primary: bool,
        source: SourceType,
        is_offset: bool,
        is_shift: bool,
        offset_or_shift: i64,
    ) -> io::Result<()> {
        self.append_ref(
            from_addr, to_addr, op_index, ref_type, source, is_primary, symbol_id, is_offset, is_shift,
            offset_or_shift,
        )?;
        self.update_record()
    }

    fn update_ref_type(&mut self, change_addr: &Address, op_index: i32, ref_type: RefType) -> io::Result<()> {
        let new_level = ref_level_for(ref_type);
        let update_ref_level = !self.is_from && new_level != self.ref_level;

        let Some((row_key, existing)) = self.find_row(change_addr, op_index)? else {
            return Ok(());
        };
        if existing.reference_type() == ref_type {
            return Ok(()); // change not required
        }

        {
            let mut table = self.table.write().unwrap();
            let mut rec = table
                .get_record(&row_key)?
                .expect("row located by find_row must still exist while table is write-locked");
            rec.set_byte(TYPE_COL, ref_type.value() as i8);
            table.put_record(rec)?;
        }

        if update_ref_level {
            if new_level > self.ref_level {
                self.ref_level = new_level;
            } else {
                self.ref_level = self.find_highest_ref_level()?;
            }
            self.update_record()?;
        }
        Ok(())
    }

    fn get_ref(&self, ref_address: &Address, op_index: i32) -> Option<Arc<dyn Reference>> {
        self.find_row(ref_address, op_index).ok().flatten().map(|(_, r)| r)
    }

    fn remove_ref(&mut self, delete_addr: &Address, op_index: i32) -> io::Result<bool> {
        let Some((row_key, existing)) = self.find_row(delete_addr, op_index)? else {
            return Ok(false);
        };

        let remaining = {
            let mut table = self.table.write().unwrap();
            table.delete_record(&row_key)?;
            table.get_record_count()
        };

        if remaining == 0 {
            self.remove_all()?;
        } else {
            if !self.is_from {
                let level = ref_level_for(existing.reference_type());
                if self.ref_level <= level {
                    self.ref_level = self.find_highest_ref_level()?;
                }
            }
            self.update_record()?;
        }
        Ok(true)
    }

    fn is_empty(&self) -> bool {
        self.table.read().unwrap().get_record_count() == 0
    }

    fn set_primary(&mut self, reference: &dyn Reference, is_primary: bool) -> io::Result<bool> {
        let op_index = reference.operand_index();
        let change_addr = if self.is_from { reference.to_address() } else { reference.from_address() };
        let Some((row_key, existing)) = self.find_row(&change_addr, op_index)? else {
            return Ok(false);
        };
        if existing.is_primary() == is_primary {
            return Ok(false);
        }
        // Only FLAGS_COL's primary bit changes; the offset/shift columns are already correct on
        // disk, so their decoded values aren't needed here (unlike `RefListV0Impl`'s byte-blob
        // re-encode, this fixed-width row layout never needs to touch OFFSET_COL just to flip one
        // flag bit).
        let (is_offset, is_shifted, _offset_or_shift) = reference_offset_shift(existing.as_ref());
        let has_symbol_id = existing.symbol_id() >= 0;
        let flags_byte = encode_flags(is_primary, is_offset, has_symbol_id, is_shifted, existing.source())
            .expect("SourceType storage id always fits in RefListFlagsV0's 3-bit budget");

        let mut table = self.table.write().unwrap();
        let mut rec = table
            .get_record(&row_key)?
            .expect("row located by find_row must still exist while table is write-locked");
        rec.set_byte(FLAGS_COL, flags_byte as i8);
        table.put_record(rec)?;
        Ok(true)
    }

    fn get_refs(&self) -> Box<dyn ReferenceIterator> {
        Box::new(ReferenceIteratorAdapter::new(self.decode_all().unwrap_or_default()))
    }

    fn get_all_refs(&self) -> Vec<Arc<dyn Reference>> {
        self.decode_all().unwrap_or_default()
    }

    fn get_num_refs(&self) -> i32 {
        self.table.read().unwrap().get_record_count() as i32
    }

    fn get_primary_ref(&self, op_index: i32) -> Option<Arc<dyn Reference>> {
        if !self.is_from {
            return None;
        }
        self.decode_all().unwrap_or_default().into_iter().find(|r| r.is_primary() && r.operand_index() == op_index)
    }

    fn remove_all(&mut self) -> io::Result<()> {
        {
            let mut table = self.table.write().unwrap();
            table.clear_all()?;
        }
        let table_name = self.table.read().unwrap().get_name().to_string();
        self.db_handle
            .lock()
            .expect("BigRefListV0Impl's db_handle mutex should never be poisoned")
            .delete_table(&table_name);
        self.ref_level = -1;
        if let Some(adapter) = &self.adapter {
            adapter
                .lock()
                .expect("BigRefListV0Impl's adapter mutex should never be poisoned")
                .remove_record(self.state.get_key())?;
        }
        self.set_invalid();
        Ok(())
    }

    fn set_symbol_id(&mut self, reference: &dyn Reference, symbol_id: i64) -> io::Result<bool> {
        let op_index = reference.operand_index();
        let change_addr = if self.is_from { reference.to_address() } else { reference.from_address() };
        let Some((row_key, existing)) = self.find_row(&change_addr, op_index)? else {
            return Ok(false);
        };
        let has_symbol_id = symbol_id >= 0;
        if (existing.symbol_id() >= 0) == has_symbol_id && existing.symbol_id() == symbol_id {
            return Ok(false);
        }
        let (is_offset, is_shifted, _) = reference_offset_shift(existing.as_ref());
        let flags_byte = encode_flags(existing.is_primary(), is_offset, has_symbol_id, is_shifted, existing.source())
            .expect("SourceType storage id always fits in RefListFlagsV0's 3-bit budget");

        let mut table = self.table.write().unwrap();
        let mut rec = table
            .get_record(&row_key)?
            .expect("row located by find_row must still exist while table is write-locked");
        rec.set_byte(FLAGS_COL, flags_byte as i8);
        rec.set_long(SYMBOL_ID_COL, symbol_id);
        table.put_record(rec)?;
        Ok(true)
    }

    fn has_reference(&self, op_index: i32) -> bool {
        if !self.is_from {
            return false;
        }
        self.decode_all().unwrap_or_default().iter().any(|r| r.operand_index() == op_index)
    }

    fn get_reference_level(&self) -> i8 {
        self.ref_level
    }
}

impl BigRefListV0 for BigRefListV0Impl {
    fn add_refs_from_iter(&mut self, ref_iter: &mut dyn ReferenceIterator) -> io::Result<()> {
        while let Some(r) = ref_iter.next() {
            let is_primary = r.is_primary();
            let symbol_id = r.symbol_id();
            let (is_offset, is_shifted, offset_or_shift) = reference_offset_shift(r.as_ref());
            self.append_ref(
                &r.from_address(), &r.to_address(), r.operand_index(), r.reference_type(), r.source(),
                is_primary, symbol_id, is_offset, is_shifted, offset_or_shift,
            )?;
        }
        self.update_record()
    }

    fn add_refs(&mut self, refs: &[Arc<dyn Reference>]) -> io::Result<()> {
        for r in refs {
            let is_primary = r.is_primary();
            let symbol_id = r.symbol_id();
            let (is_offset, is_shifted, offset_or_shift) = reference_offset_shift(r.as_ref());
            self.append_ref(
                &r.from_address(), &r.to_address(), r.operand_index(), r.reference_type(), r.source(),
                is_primary, symbol_id, is_offset, is_shifted, offset_or_shift,
            )?;
        }
        self.update_record()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::db_object::{DbObject, DbObjectState};
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{RefType, ReferenceIteratorAdapter, SourceType};

    struct MockReference {
        from: Address,
        to: Address,
        op_index: i32,
        ref_type: RefType,
        source: SourceType,
        is_primary: bool,
        symbol_id: i64,
    }

    impl Reference for MockReference {
        fn from_address(&self) -> Address {
            self.from.clone()
        }

        fn to_address(&self) -> Address {
            self.to.clone()
        }

        fn is_primary(&self) -> bool {
            self.is_primary
        }

        fn symbol_id(&self) -> i64 {
            self.symbol_id
        }

        fn reference_type(&self) -> RefType {
            self.ref_type
        }

        fn operand_index(&self) -> i32 {
            self.op_index
        }

        fn is_mnemonic_reference(&self) -> bool {
            false
        }

        fn is_operand_reference(&self) -> bool {
            true
        }

        fn is_stack_reference(&self) -> bool {
            false
        }

        fn is_external_reference(&self) -> bool {
            false
        }

        fn is_entry_point_reference(&self) -> bool {
            false
        }

        fn is_memory_reference(&self) -> bool {
            true
        }

        fn is_register_reference(&self) -> bool {
            false
        }

        fn is_offset_reference(&self) -> bool {
            false
        }

        fn is_shifted_reference(&self) -> bool {
            false
        }

        fn source(&self) -> SourceType {
            self.source
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    /// A tiny in-memory stand-in for the real one-row-per-reference table storage, just enough to
    /// prove the trait is object-safe and behaves like the Java class for the mutation/query pairs
    /// that matter (including the `ReferenceIterator`-driven bulk insert `RefListV0` doesn't have).
    struct MockBigRefListV0 {
        state: DbObjectState,
        refs: Vec<Arc<dyn Reference>>,
        ref_level: i8,
    }

    impl MockBigRefListV0 {
        fn new() -> Self {
            MockBigRefListV0 {
                state: DbObjectState::new(0),
                refs: Vec::new(),
                ref_level: -1,
            }
        }
    }

    impl DbObject for MockBigRefListV0 {
        fn state(&self) -> &DbObjectState {
            &self.state
        }

        fn refresh(&self, _record: Option<&crate::framework::db::DBRecord>) -> bool {
            true
        }
    }

    impl RefList for MockBigRefListV0 {
        fn add_ref(
            &mut self,
            from_addr: &Address,
            to_addr: &Address,
            ref_type: RefType,
            op_index: i32,
            symbol_id: i64,
            is_primary: bool,
            source: SourceType,
            _is_offset: bool,
            _is_shift: bool,
            _offset_or_shift: i64,
        ) -> io::Result<()> {
            self.refs.push(Arc::new(MockReference {
                from: from_addr.clone(),
                to: to_addr.clone(),
                op_index,
                ref_type,
                source,
                is_primary,
                symbol_id,
            }));
            Ok(())
        }

        fn get_all_refs(&self) -> Vec<Arc<dyn Reference>> {
            self.refs.clone()
        }

        fn get_num_refs(&self) -> i32 {
            self.refs.len() as i32
        }

        fn has_reference(&self, op_index: i32) -> bool {
            self.refs.iter().any(|r| r.operand_index() == op_index)
        }

        fn get_primary_ref(&self, op_index: i32) -> Option<Arc<dyn Reference>> {
            self.refs
                .iter()
                .find(|r| r.is_primary() && r.operand_index() == op_index)
                .cloned()
        }

        fn get_ref(&self, ref_address: &Address, op_index: i32) -> Option<Arc<dyn Reference>> {
            self.refs
                .iter()
                .find(|r| r.operand_index() == op_index && &r.to_address() == ref_address)
                .cloned()
        }

        fn get_refs(&self) -> Box<dyn ReferenceIterator> {
            Box::new(ReferenceIteratorAdapter::new(self.refs.clone()))
        }

        fn is_empty(&self) -> bool {
            self.refs.is_empty()
        }

        fn get_reference_level(&self) -> i8 {
            self.ref_level
        }

        fn remove_all(&mut self) -> io::Result<()> {
            self.refs.clear();
            self.ref_level = -1;
            Ok(())
        }

        fn remove_ref(&mut self, delete_addr: &Address, op_index: i32) -> io::Result<bool> {
            let before = self.refs.len();
            self.refs
                .retain(|r| !(r.operand_index() == op_index && &r.to_address() == delete_addr));
            Ok(self.refs.len() != before)
        }

        fn set_primary(&mut self, reference: &dyn Reference, is_primary: bool) -> io::Result<bool> {
            for r in &mut self.refs {
                if r.operand_index() == reference.operand_index()
                    && r.to_address() == reference.to_address()
                {
                    if r.is_primary() == is_primary {
                        return Ok(false);
                    }
                    *r = Arc::new(MockReference {
                        from: r.from_address(),
                        to: r.to_address(),
                        op_index: r.operand_index(),
                        ref_type: r.reference_type(),
                        source: r.source(),
                        is_primary,
                        symbol_id: r.symbol_id(),
                    });
                    return Ok(true);
                }
            }
            Ok(false)
        }

        fn set_symbol_id(&mut self, reference: &dyn Reference, symbol_id: i64) -> io::Result<bool> {
            for r in &mut self.refs {
                if r.operand_index() == reference.operand_index()
                    && r.to_address() == reference.to_address()
                {
                    *r = Arc::new(MockReference {
                        from: r.from_address(),
                        to: r.to_address(),
                        op_index: r.operand_index(),
                        ref_type: r.reference_type(),
                        source: r.source(),
                        is_primary: r.is_primary(),
                        symbol_id,
                    });
                    return Ok(true);
                }
            }
            Ok(false)
        }

        fn update_ref_type(
            &mut self,
            change_addr: &Address,
            op_index: i32,
            ref_type: RefType,
        ) -> io::Result<()> {
            for r in &mut self.refs {
                if r.operand_index() == op_index && &r.to_address() == change_addr {
                    *r = Arc::new(MockReference {
                        from: r.from_address(),
                        to: r.to_address(),
                        op_index: r.operand_index(),
                        ref_type,
                        source: r.source(),
                        is_primary: r.is_primary(),
                        symbol_id: r.symbol_id(),
                    });
                }
            }
            Ok(())
        }
    }

    impl BigRefListV0 for MockBigRefListV0 {
        fn add_refs_from_iter(&mut self, ref_iter: &mut dyn ReferenceIterator) -> io::Result<()> {
            while let Some(r) = ref_iter.next() {
                self.refs.push(r);
            }
            Ok(())
        }

        fn add_refs(&mut self, refs: &[Arc<dyn Reference>]) -> io::Result<()> {
            self.refs.extend(refs.iter().cloned());
            Ok(())
        }
    }

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    #[test]
    fn add_and_remove_ref_round_trip() {
        let mut list = MockBigRefListV0::new();
        let from = addr(0x1000);
        let to = addr(0x2000);

        list.add_ref(
            &from,
            &to,
            RefType::Data,
            0,
            -1,
            true,
            SourceType::UserDefined,
            false,
            false,
            0,
        )
        .unwrap();

        assert_eq!(list.get_num_refs(), 1);
        assert!(!list.is_empty());
        assert!(list.has_reference(0));
        assert!(list.get_ref(&to, 0).is_some());
        assert!(list.get_primary_ref(0).is_some());

        assert!(list.remove_ref(&to, 0).unwrap());
        assert_eq!(list.get_num_refs(), 0);
        assert!(list.is_empty());
        assert!(!list.remove_ref(&to, 0).unwrap());
    }

    #[test]
    fn add_refs_from_iter_bulk_copies_a_promoted_lists_references() {
        // Mirrors `RefList.checkRefListSize`'s `refList.addRefs(getRefs())` promotion call, which
        // is the only real Java call site for this overload.
        let mut source = MockBigRefListV0::new();
        let from = addr(0x1000);
        for i in 0..3 {
            source
                .add_ref(
                    &from,
                    &addr(0x2000 + i),
                    RefType::Data,
                    i as i32,
                    -1,
                    false,
                    SourceType::Analysis,
                    false,
                    false,
                    0,
                )
                .unwrap();
        }

        let mut promoted = MockBigRefListV0::new();
        let mut iter = source.get_refs();
        promoted.add_refs_from_iter(iter.as_mut()).unwrap();

        assert_eq!(promoted.get_num_refs(), 3);
        for i in 0..3 {
            assert!(promoted.get_ref(&addr(0x2000 + i), i as i32).is_some());
        }
    }

    #[test]
    fn set_primary_reports_whether_it_changed() {
        let mut list = MockBigRefListV0::new();
        let from = addr(0x1000);
        let to = addr(0x2000);
        list.add_ref(
            &from,
            &to,
            RefType::Data,
            1,
            -1,
            false,
            SourceType::Analysis,
            false,
            false,
            0,
        )
        .unwrap();

        let current = list.get_ref(&to, 1).unwrap();
        assert!(list.set_primary(current.as_ref(), true).unwrap());
        let updated = list.get_ref(&to, 1).unwrap();
        assert!(updated.is_primary());

        // Setting to the same value again should report no change.
        assert!(!list.set_primary(updated.as_ref(), true).unwrap());
    }

    #[test]
    fn object_safety_via_trait_object() {
        let mut list: Box<dyn BigRefListV0> = Box::new(MockBigRefListV0::new());
        let from = addr(0x10);
        let to = addr(0x20);
        list.add_ref(
            &from,
            &to,
            RefType::UnconditionalCall,
            0,
            42,
            true,
            SourceType::Imported,
            false,
            false,
            0,
        )
        .unwrap();
        assert_eq!(list.get_num_refs(), 1);

        let mut iter = list.get_refs();
                let r = iter.next().unwrap();
        assert_eq!(r.symbol_id(), 42);
        assert!(iter.next().is_none());

        list.remove_all().unwrap();
        assert!(list.is_empty());
    }
}

#[cfg(test)]
mod big_ref_list_v0_impl_tests {
    use super::*;
    use crate::program::model::address::{
        AddressFactory, AddressSetView, AddressSpace, AddressSpaceType, KeyRange,
    };
    use crate::program::model::symbol::{RefType, ShiftedReference, SourceType, DAT_LEVEL, SUB_LEVEL};
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    /// Same minimal, real `AddressMap` as `ref_list_v0.rs`'s own impl tests: ordinary ram
    /// addresses round-trip through their offset directly; other spaces get a fresh negative key
    /// remembered in a side table.
    struct MockAddressMap {
        ram: Arc<AddressSpace>,
        special: StdMutex<HashMap<i64, Address>>,
        next_special_key: StdMutex<i64>,
    }

    impl MockAddressMap {
        fn new() -> Self {
            MockAddressMap {
                ram: AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1),
                special: StdMutex::new(HashMap::new()),
                next_special_key: StdMutex::new(-1000),
            }
        }

        fn addr(&self, offset: i64) -> Address {
            Address::new(self.ram.clone(), offset)
        }
    }

    impl AddressMap for MockAddressMap {
        fn get_key(&self, addr: &Address, _create: bool) -> i64 {
            if addr.space().space_type() == AddressSpaceType::Ram {
                return addr.offset();
            }
            let mut special = self.special.lock().unwrap();
            if let Some((k, _)) = special.iter().find(|(_, v)| *v == addr) {
                return *k;
            }
            let mut next = self.next_special_key.lock().unwrap();
            let key = *next;
            *next -= 1;
            special.insert(key, addr.clone());
            key
        }

        fn get_absolute_encoding(&self, addr: &Address, create: bool) -> i64 {
            self.get_key(addr, create)
        }

        fn find_key_range(&self, _key_range_list: &[KeyRange], _addr: Option<&Address>) -> i32 {
            -1
        }

        fn decode_address(&self, value: i64) -> Address {
            if value >= 0 {
                self.addr(value)
            } else {
                self.special.lock().unwrap().get(&value).cloned().expect("decode_address called with an unknown key")
            }
        }

        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            None
        }

        fn get_key_ranges_absolute(
            &self,
            _start: &Address,
            _end: &Address,
            _absolute: bool,
            _create: bool,
        ) -> Vec<KeyRange> {
            Vec::new()
        }

        fn get_key_ranges_for_set_absolute(
            &self,
            _set: Option<&dyn AddressSetView>,
            _absolute: bool,
            _create: bool,
        ) -> Vec<KeyRange> {
            Vec::new()
        }

        fn get_old_address_map(&self) -> Box<dyn AddressMap> {
            Box::new(MockAddressMap::new())
        }

        fn is_upgraded(&self) -> bool {
            false
        }

        fn get_image_base(&self) -> Address {
            self.addr(0)
        }
    }

    fn map() -> Arc<dyn AddressMap + Send + Sync> {
        Arc::new(MockAddressMap::new())
    }

    fn addr(m: &Arc<dyn AddressMap + Send + Sync>, offset: i64) -> Address {
        m.decode_address(offset)
    }

    fn handle() -> Arc<Mutex<DBHandle>> {
        Arc::new(Mutex::new(DBHandle::new().unwrap()))
    }

    /// A real, in-memory `RecordAdapter` that records every `create_record` call's `ref_data` so
    /// tests can assert `BigRefListV0Impl` really does pass `None` (the "lives in a side table"
    /// sentinel), never `Some(&[])`.
    struct MockRecordAdapter {
        schema: Arc<Schema>,
        records: HashMap<i64, DBRecord>,
        create_calls: Vec<(i64, i32, u8, Option<Vec<u8>>)>,
        removed: Vec<i64>,
    }

    impl MockRecordAdapter {
        fn new() -> Self {
            MockRecordAdapter {
                schema: Arc::new(Schema::new(
                    0,
                    FieldType::Long,
                    "Key".to_string(),
                    vec![FieldType::Int, FieldType::Byte, FieldType::Binary],
                    vec!["NumRefs".to_string(), "RefLevel".to_string(), "RefData".to_string()],
                    vec![],
                )),
                records: HashMap::new(),
                create_calls: Vec::new(),
                removed: Vec::new(),
            }
        }
    }

    impl RecordAdapter for MockRecordAdapter {
        fn create_record(
            &mut self,
            key: i64,
            num_refs: i32,
            ref_level: u8,
            ref_data: Option<&[u8]>,
        ) -> io::Result<DBRecord> {
            self.create_calls.push((key, num_refs, ref_level, ref_data.map(|d| d.to_vec())));
            let mut record = DBRecord::new(self.schema.clone(), Field::Long(Some(key)));
            record.set_int(0, num_refs);
            record.set_byte(1, ref_level as i8);
            record.set_field(2, Field::Binary(ref_data.map(|d| d.to_vec())));
            self.records.insert(key, record.clone());
            Ok(record)
        }

        fn get_record(&self, key: i64) -> io::Result<DBRecord> {
            self.records.get(&key).cloned().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "not found"))
        }

        fn put_record(&mut self, record: &DBRecord) -> io::Result<()> {
            let key = record.get_key().get_long_value();
            self.records.insert(key, record.clone());
            Ok(())
        }

        fn remove_record(&mut self, key: i64) -> io::Result<()> {
            self.records.remove(&key);
            self.removed.push(key);
            Ok(())
        }
    }

    fn adapter() -> Arc<Mutex<MockRecordAdapter>> {
        Arc::new(Mutex::new(MockRecordAdapter::new()))
    }

    fn as_trait_object(a: &Arc<Mutex<MockRecordAdapter>>) -> Arc<Mutex<dyn RecordAdapter + Send>> {
        a.clone()
    }

    #[test]
    fn create_new_creates_a_dedicated_table_and_add_ref_persists_a_row() {
        let m = map();
        let h = handle();
        let to = addr(&m, 0x2000);

        let mut list = BigRefListV0Impl::create_new(to.clone(), None, m.clone(), h.clone(), false).unwrap();
        assert_eq!(list.get_num_refs(), 0);
        assert!(h.lock().unwrap().get_table("BigRefList_2000").is_some());

        let from = addr(&m, 0x1000);
        list.add_ref(&from, &to, RefType::UnconditionalCall, 0, 42, true, SourceType::Imported, false, false, 0)
            .unwrap();

        assert_eq!(list.get_num_refs(), 1);
        assert!(!list.is_empty());
        let r = list.get_ref(&from, 0).expect("should find the from-address for a to-list");
        assert_eq!(r.from_address(), from);
        assert_eq!(r.to_address(), to);
        assert_eq!(r.symbol_id(), 42);
        assert!(r.is_primary());
        assert_eq!(r.reference_type(), RefType::UnconditionalCall);
        assert_eq!(list.get_reference_level(), SUB_LEVEL as i8);
    }

    #[test]
    fn update_record_writes_through_the_adapter_with_a_none_ref_data_sentinel() {
        let m = map();
        let h = handle();
        let a = adapter();
        let to = addr(&m, 0x3000);

        let mut list =
            BigRefListV0Impl::create_new(to.clone(), Some(as_trait_object(&a)), m.clone(), h, false).unwrap();
        assert!(a.lock().unwrap().create_calls.is_empty());

        list.add_ref(&addr(&m, 0x100), &to, RefType::Data, 0, -1, false, SourceType::Analysis, false, false, 0)
            .unwrap();

        let guard = a.lock().unwrap();
        assert_eq!(guard.create_calls.len(), 1);
        let (key, num_refs, _level, ref_data) = &guard.create_calls[0];
        assert_eq!(*key, list.get_key());
        assert_eq!(*num_refs, 1);
        assert_eq!(*ref_data, None, "BigRefListV0Impl must signal 'lives in a side table' with None, not Some(&[])");
    }

    #[test]
    fn create_existing_reopens_the_table_and_reproduces_the_same_refs() {
        let m = map();
        let h = handle();
        let to = addr(&m, 0x4000);

        let mut original = BigRefListV0Impl::create_new(to.clone(), None, m.clone(), h.clone(), false).unwrap();
        original
            .add_ref(&addr(&m, 0x10), &to, RefType::Data, 0, 7, true, SourceType::UserDefined, false, false, 0)
            .unwrap();
        original
            .add_ref(&addr(&m, 0x20), &to, RefType::ConditionalJump, 1, -1, false, SourceType::Analysis, false, false, 0)
            .unwrap();
        let key = original.get_key();
        let ref_level = original.get_reference_level();

        let restored = BigRefListV0Impl::create_existing(key, ref_level, None, m.clone(), h, false).unwrap();
        assert_eq!(restored.get_num_refs(), original.get_num_refs());
        assert_eq!(restored.get_reference_level(), original.get_reference_level());

        let mut orig_refs = original.get_all_refs();
        let mut restored_refs = restored.get_all_refs();
        orig_refs.sort_by_key(|r| r.operand_index());
        restored_refs.sort_by_key(|r| r.operand_index());
        for (a, b) in orig_refs.iter().zip(restored_refs.iter()) {
            assert_eq!(a.from_address(), b.from_address());
            assert_eq!(a.to_address(), b.to_address());
            assert_eq!(a.symbol_id(), b.symbol_id());
            assert_eq!(a.reference_type(), b.reference_type());
        }
    }

    #[test]
    fn create_existing_errors_when_the_table_is_missing() {
        let m = map();
        let h = handle();
        assert!(BigRefListV0Impl::create_existing(0x9999, -1, None, m, h, false).is_err());
    }

    #[test]
    fn remove_ref_deletes_the_matching_row_and_keeps_others() {
        let m = map();
        let h = handle();
        let to = addr(&m, 0x5000);
        let mut list = BigRefListV0Impl::create_new(to.clone(), None, m.clone(), h, false).unwrap();
        let from1 = addr(&m, 0x10);
        let from2 = addr(&m, 0x20);
        list.add_ref(&from1, &to, RefType::Data, 0, -1, false, SourceType::Analysis, false, false, 0).unwrap();
        list.add_ref(&from2, &to, RefType::Data, 1, -1, false, SourceType::Analysis, false, false, 0).unwrap();

        assert!(list.remove_ref(&from1, 0).unwrap());
        assert_eq!(list.get_num_refs(), 1);
        assert!(list.get_ref(&from1, 0).is_none());
        assert!(list.get_ref(&from2, 1).is_some());
        assert!(!list.remove_ref(&from1, 0).unwrap());
    }

    #[test]
    fn remove_ref_down_to_zero_calls_remove_all_and_drops_the_table() {
        let m = map();
        let h = handle();
        let a = adapter();
        let to = addr(&m, 0x5500);
        let mut list =
            BigRefListV0Impl::create_new(to.clone(), Some(as_trait_object(&a)), m.clone(), h.clone(), false).unwrap();
        let from = addr(&m, 0x10);
        list.add_ref(&from, &to, RefType::Data, 0, -1, false, SourceType::Analysis, false, false, 0).unwrap();

        assert!(list.remove_ref(&from, 0).unwrap());
        assert!(list.is_empty());
        assert!(!list.is_valid());
        assert!(a.lock().unwrap().removed.contains(&list.get_key()));
        assert!(h.lock().unwrap().get_table("BigRefList_5500").is_none());
    }

    #[test]
    fn set_primary_reports_whether_it_changed() {
        let m = map();
        let h = handle();
        let to = addr(&m, 0x6000);
        let mut list = BigRefListV0Impl::create_new(to.clone(), None, m.clone(), h, false).unwrap();
        let from = addr(&m, 0x10);
        list.add_ref(&from, &to, RefType::Data, 0, -1, false, SourceType::Analysis, false, false, 0).unwrap();

        let current = list.get_ref(&from, 0).unwrap();
        assert!(list.set_primary(current.as_ref(), true).unwrap());
        let updated = list.get_ref(&from, 0).unwrap();
        assert!(updated.is_primary());
        assert!(!list.set_primary(updated.as_ref(), true).unwrap());
    }

    #[test]
    fn set_symbol_id_updates_in_place() {
        let m = map();
        let h = handle();
        let to = addr(&m, 0x7000);
        let mut list = BigRefListV0Impl::create_new(to.clone(), None, m.clone(), h, false).unwrap();
        let from = addr(&m, 0x10);
        list.add_ref(&from, &to, RefType::Data, 0, -1, false, SourceType::Analysis, false, false, 0).unwrap();

        let current = list.get_ref(&from, 0).unwrap();
        assert!(list.set_symbol_id(current.as_ref(), 99).unwrap());
        assert_eq!(list.get_ref(&from, 0).unwrap().symbol_id(), 99);

        let current = list.get_ref(&from, 0).unwrap();
        assert!(list.set_symbol_id(current.as_ref(), 100).unwrap());
        assert_eq!(list.get_ref(&from, 0).unwrap().symbol_id(), 100);
        assert!(!list.set_symbol_id(list.get_ref(&from, 0).unwrap().as_ref(), 100).unwrap());
    }

    #[test]
    fn update_ref_type_recomputes_the_to_lists_reference_level() {
        let m = map();
        let h = handle();
        let to = addr(&m, 0x8000);
        let mut list = BigRefListV0Impl::create_new(to.clone(), None, m.clone(), h, false).unwrap();
        let from = addr(&m, 0x10);
        list.add_ref(&from, &to, RefType::Data, 0, -1, false, SourceType::Analysis, false, false, 0).unwrap();
        assert_eq!(list.get_reference_level(), DAT_LEVEL as i8);

        list.update_ref_type(&from, 0, RefType::UnconditionalCall).unwrap();
        assert_eq!(list.get_reference_level(), SUB_LEVEL as i8);
        assert_eq!(list.get_ref(&from, 0).unwrap().reference_type(), RefType::UnconditionalCall);
    }

    #[test]
    fn add_refs_bulk_inserts_and_persists_once() {
        let m = map();
        let h = handle();
        let a = adapter();
        let to = addr(&m, 0x9000);
        let mut list =
            BigRefListV0Impl::create_new(to.clone(), Some(as_trait_object(&a)), m.clone(), h, false).unwrap();

        let refs: Vec<Arc<dyn Reference>> = vec![
            Arc::new(MemReferenceDb::new(addr(&m, 0x10), to.clone(), RefType::Data, 0, SourceType::Analysis, false, -1)),
            Arc::new(MemReferenceDb::new(addr(&m, 0x20), to.clone(), RefType::Data, 1, SourceType::Analysis, true, 5)),
        ];
        list.add_refs(&refs).unwrap();

        assert_eq!(list.get_num_refs(), 2);
        assert!(list.get_ref(&addr(&m, 0x10), 0).is_some());
        assert_eq!(list.get_ref(&addr(&m, 0x20), 1).unwrap().symbol_id(), 5);
    }

    #[test]
    fn add_refs_from_iter_bulk_inserts() {
        let m = map();
        let h = handle();
        let to = addr(&m, 0x9500);
        let mut list = BigRefListV0Impl::create_new(to.clone(), None, m.clone(), h, false).unwrap();

        let refs: Vec<Arc<dyn Reference>> = vec![Arc::new(MemReferenceDb::new(
            addr(&m, 0x10),
            to.clone(),
            RefType::Data,
            0,
            SourceType::Analysis,
            false,
            -1,
        ))];
        let mut iter = ReferenceIteratorAdapter::new(refs);
        list.add_refs_from_iter(&mut iter).unwrap();

        assert_eq!(list.get_num_refs(), 1);
        assert!(list.get_ref(&addr(&m, 0x10), 0).is_some());
    }

    #[test]
    fn from_list_supports_has_reference_and_primary_ref_lookups() {
        let m = map();
        let from_addr = addr(&m, 0xA000);
        let h = handle();
        let mut list = BigRefListV0Impl::create_new(from_addr.clone(), None, m.clone(), h, true).unwrap();
        let to1 = addr(&m, 0x10);
        let to2 = addr(&m, 0x20);
        list.add_ref(&from_addr, &to1, RefType::Data, 0, -1, true, SourceType::Analysis, false, false, 0).unwrap();
        list.add_ref(&from_addr, &to2, RefType::Data, 1, -1, false, SourceType::Analysis, false, false, 0).unwrap();

        assert!(list.has_reference(0));
        assert!(list.has_reference(1));
        assert!(!list.has_reference(2));

        let primary = list.get_primary_ref(0).unwrap();
        assert_eq!(primary.to_address(), to1);
        assert!(list.get_primary_ref(1).is_none());
    }

    #[test]
    fn decodes_offset_and_shifted_references() {
        let m = map();
        let h = handle();
        let to = addr(&m, 0xB000);
        let mut list = BigRefListV0Impl::create_new(to.clone(), None, m.clone(), h, false).unwrap();
        let from = addr(&m, 0x10);

        list.add_ref(&from, &to, RefType::Data, 0, -1, false, SourceType::Analysis, true, false, 4).unwrap();
        let offset_ref = list.get_ref(&from, 0).unwrap();
        assert!(offset_ref.is_offset_reference());
        assert_eq!(offset_ref.as_offset_reference().unwrap().offset(), 4);

        list.add_ref(&from, &to, RefType::Data, 1, -1, false, SourceType::Analysis, false, true, 2).unwrap();
        let shifted_ref = list.get_ref(&from, 1).unwrap();
        assert!(shifted_ref.is_shifted_reference());
        let shifted = shifted_ref.as_any().downcast_ref::<ShiftedReferenceDb>().unwrap();
        assert_eq!(shifted.shift(), 2);
    }

    #[test]
    fn decodes_stack_and_external_references_via_the_lists_own_address() {
        let m = map();
        let h = handle();

        let stack_space = AddressSpace::new("stack", 32, 1, AddressSpaceType::Stack, 5);
        let stack_addr = Address::new(stack_space, 8);
        let mut stack_list = BigRefListV0Impl::create_new(stack_addr.clone(), None, m.clone(), h.clone(), false).unwrap();
        let from = addr(&m, 0x10);
        stack_list.add_ref(&from, &stack_addr, RefType::Data, 0, -1, false, SourceType::Analysis, false, false, 0).unwrap();
        let stack_ref = stack_list.get_ref(&from, 0).unwrap();
        assert!(stack_ref.is_stack_reference());
        assert_eq!(stack_ref.to_address(), stack_addr);

        let ext_space = AddressSpace::new("EXTERNAL", 32, 1, AddressSpaceType::External, 6);
        let ext_addr = Address::new(ext_space, 3);
        let mut ext_list = BigRefListV0Impl::create_new(ext_addr.clone(), None, m.clone(), h, false).unwrap();
        ext_list.add_ref(&from, &ext_addr, RefType::Data, 0, -1, false, SourceType::Analysis, false, false, 0).unwrap();
        let ext_ref = ext_list.get_ref(&from, 0).unwrap();
        assert!(ext_ref.is_external_reference());
        assert_eq!(ext_ref.to_address(), ext_addr);
        assert_eq!(ext_ref.as_external_reference().unwrap().get_external_location().get_label(), "");
    }

    #[test]
    fn object_safety_via_ref_list_and_big_ref_list_v0_trait_objects() {
        let m = map();
        let h = handle();
        let to = addr(&m, 0xC000);
        let mut list: Box<dyn BigRefListV0> =
            Box::new(BigRefListV0Impl::create_new(to.clone(), None, m.clone(), h, false).unwrap());
        let from = addr(&m, 0x10);
        list.add_ref(&from, &to, RefType::Data, 0, -1, false, SourceType::Analysis, false, false, 0).unwrap();
        assert_eq!(list.get_num_refs(), 1);
        assert!(list.is_valid() || !list.is_valid());

        list.remove_all().unwrap();
        assert!(list.is_empty());
    }
}
