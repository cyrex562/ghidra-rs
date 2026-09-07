//! Port of `ghidra.program.database.references.RefListV0`.
//!
//! `RefListV0` is the concrete, byte-packed [`RefList`] implementation used for a single address's
//! reference list (either the "from" list of outgoing references or the "to" list of incoming
//! references, per its `isFrom` flag) before it grows large enough to be promoted to a
//! `BigRefListV0`. It stores every reference for that address as a run of variable-length encoded
//! records in one `byte[]` blob, re-encoding/re-decoding on every mutation and lookup.
//!
//! This class was selected as a dependency-cycle cut-point, so it is ported here as a trait rather
//! than a concrete struct. `RefListV0`'s abstract-method overrides are inherited from `RefList`
//! (`addRef`/`getAllRefs`/`getNumRefs`/`hasReference`/`getPrimaryRef`/`getRef`/`getRefs`/
//! `isEmpty`/`getReferenceLevel`/`removeAll`/`removeRef`/`setPrimary`/`setSymbolID`/
//! `updateRefType`, all declared on the [`RefList`] supertrait), so this trait only adds the
//! package-private bulk-insert helper `addRefs(Reference[])` used by `ToAdapter`/`FromAdapter`
//! upgrade paths and by `RefList.checkRefListSize` when promoting to a `BigRefListV0`.
//!
//! Not ported here: the private byte-encoding helper for `findHighestRefLevel`/`getRefLevel`
//! naming exactly (a `ref_level_for` free function and inherent `find_highest_ref_level` method
//! below implement the same logic under Rust naming), and the nested `RefIterator` class (decoding
//! instead happens eagerly into a `Vec` and is exposed via [`ReferenceIteratorAdapter`]). The
//! package-private `getData()` accessor is also left out of the *trait*: its own doc comment calls
//! it "a little kludgey", and its only callers are the `ToAdapter`/`FromAdapter` static
//! `upgrade(...)` migration paths, which are themselves not yet ported (see `to_adapter.rs`'s
//! module docs for the same convention) -- [`RefListV0Impl`] does expose an equivalent
//! `pub(crate)` accessor ([`RefListV0Impl::raw_ref_data`]) for the concrete adapters that will
//! need it once ported.
//!
//! **Concrete implementation.** [`RefListV0Impl`] below is the concrete, byte-packed struct that
//! implements this trait (and [`RefList`]), porting the three static factory methods
//! (`createTemporary`/`createNew`/`instantiateExisting`, as associated functions since a factory
//! returning `Self` cannot be a trait method without losing object-safety -- the same convention
//! `ToAdapter`'s static factory already uses) plus the private constructors and byte-codec
//! (`appendRef`/`encode`/`decode`/`updateRecord`/`findHighestRefLevel`/`getRefLevel`). Two
//! deliberate decoupling simplifications, consistent with this project's established precedent for
//! this same package (see `offset_reference_db.rs`'s and `external_reference_db.rs`'s own module
//! docs for the same pattern applied to sibling classes):
//! - **No stored `Program`.** Java's constructors take a `ProgramDB program` used only to build
//!   `MemReferenceDB`/`StackReferenceDB`/etc., none of which this port's equivalents store a
//!   `Program` for either (see their own module docs); `program` is therefore dropped entirely
//!   rather than threaded through unused.
//! - **External-location and external-block resolution via injectable closures.** Java's `decode`
//!   calls `program.getExternalManager()...getExtLocation(toAddr)` (for `ExternalReferenceDB`) and
//!   relies on `MemReferenceDB.isExternalBlockReference()` -> `program.getMemory()
//!   .isExternalBlockAddress(toAddr)` (for `OffsetReferenceDB`'s base-address resolution) --  both
//!   live `Program` queries this leaf byte-codec has no business owning. `RefListV0Impl` instead
//!   holds two `Send + Sync` closures (`external_resolver`, `is_external_block_resolver`),
//!   defaulting to a no-op `DefaultExternalLocation` / `false`, overridable via
//!   [`RefListV0Impl::set_external_location_resolver`] /
//!   [`RefListV0Impl::set_external_block_resolver`] once a real `Program`/`ExternalManagerDb` is
//!   available to a caller that wants full fidelity for those two reference kinds.
//! - **`instantiateExisting` takes already-extracted fields, not a `DBRecord`.** Java's version
//!   reads `REF_DATA_COL`/`REF_COUNT_COL`/`REF_LEVEL_COL` directly off the passed-in `DBRecord`
//!   using column constants only the concrete `ToAdapter`/`FromAdapter` subclass (not yet ported)
//!   knows. Rather than growing [`RecordAdapter`] a new schema-aware accessor to claw those fields
//!   back out of an opaque `DBRecord`, [`RefListV0Impl::instantiate_existing`] takes `ref_data`/
//!   `num_refs`/`ref_level` as plain parameters: the future concrete adapter (which already knows
//!   its own schema) reads them itself and passes them straight through.
//!
//! `RefList` is now ported (see `ref_list.rs`), so this trait declares it as a supertrait,
//! mirroring the Java `RefListV0 extends RefList` relationship.

use std::io;
use std::sync::{Arc, Mutex};

use crate::framework::db::DBRecord;
use crate::program::database::db_object::{DbObject, DbObjectState};
use crate::program::database::map::AddressMap;
use crate::program::database::references::entry_point_reference_db::EntryPointReferenceDb;
use crate::program::database::references::external_reference_db::ExternalReferenceDb;
use crate::program::database::references::mem_reference_db::MemReferenceDb;
use crate::program::database::references::offset_reference_db::OffsetReferenceDb;
use crate::program::database::references::ref_list_flags_v0::{decode_source, encode_flags};
use crate::program::database::references::shifted_reference_db::ShiftedReferenceDb;
use crate::program::database::references::stack_reference_db::StackReferenceDb;
use crate::program::database::references::{RecordAdapter, RefList};
use crate::program::model::address::{Address, SpecialAddress};
use crate::program::model::symbol::{
    ExternalLocation, RefType, Reference, ReferenceIterator, ReferenceIteratorAdapter,
    RefTypeFactory, ShiftedReference, SourceType, DAT_LEVEL, EXT_LEVEL, LAB_LEVEL, SUB_LEVEL,
    UNK_LEVEL,
};

/// The packed reference list for a single address (either outgoing "from" references or incoming
/// "to" references, depending on how the owning adapter constructed it).
///
/// Port of `ghidra.program.database.references.RefListV0`. See the module docs for what was
/// intentionally left out (the static factories, the private byte-codec, and the nested
/// iterator class).
pub trait RefListV0: RefList {
    /// Appends a batch of existing references in one pass. Stands in for
    /// `RefListV0.addRefs(Reference[])`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn add_refs(&mut self, refs: &[Arc<dyn Reference>]) -> io::Result<()>;
}

/// Mirrors the `SymbolUtilities`-derived reference levels `RefListV0.getRefLevel(RefType)` (and
/// `BigRefListV0`'s identical private copy) compute, used to decide which reference wins a
/// symbol's primary label.
pub(crate) fn ref_level_for(rt: RefType) -> i8 {
    if rt == RefType::ExternalRef {
        return EXT_LEVEL as i8;
    }
    if rt.is_call() {
        return SUB_LEVEL as i8;
    }
    if rt.is_data() || rt.is_indirect() {
        return DAT_LEVEL as i8;
    }
    if rt.is_flow() {
        return LAB_LEVEL as i8;
    }
    UNK_LEVEL as i8
}

/// Extracts the `(is_offset, is_shifted, offset_or_shift)` triple Java's `addRefs` overloads pull
/// from an `instanceof MemReferenceDB` cast (`memRef.isOffset()`/`isShifted()`/
/// `getOffsetOrShift()`). This port has no single concrete "memory reference" struct to downcast
/// to (offset/shifted references are distinguished by trait, not a shared base class), so this
/// checks [`Reference::as_offset_reference`] first, then falls back to downcasting to
/// [`ShiftedReferenceDb`] (the only [`ShiftedReference`](crate::program::model::symbol::ShiftedReference)
/// implementor in this port) for the shifted case.
fn reference_offset_shift(reference: &dyn Reference) -> (bool, bool, i64) {
    if let Some(offset_ref) = reference.as_offset_reference() {
        return (true, false, offset_ref.offset());
    }
    if reference.is_shifted_reference() {
        if let Some(shifted) = reference.as_any().downcast_ref::<ShiftedReferenceDb>() {
            return (false, true, shifted.shift() as i64);
        }
    }
    (false, false, 0)
}

/// A no-op [`ExternalLocation`] used by [`RefListV0Impl`]'s default `external_resolver`. Every
/// method falls back to [`ExternalLocation`]'s own default implementation, so this is a pure
/// marker with no behavior -- see the module docs for why a resolver closure exists at all.
#[derive(Debug, Default, Clone, Copy)]
struct DefaultExternalLocation;

impl ExternalLocation for DefaultExternalLocation {}

fn default_external_resolver() -> Arc<dyn Fn(&Address) -> Box<dyn ExternalLocation> + Send + Sync>
{
    Arc::new(|_addr: &Address| Box::new(DefaultExternalLocation) as Box<dyn ExternalLocation>)
}

fn default_is_external_block_resolver() -> Arc<dyn Fn(&Address) -> bool + Send + Sync> {
    Arc::new(|_addr: &Address| false)
}

// Bit positions mirror the layout documented in `ref_list_flags_v0`'s module doc comment. That
// module's own constants are private (it only exposes behavior through the `RefListFlagsV0`
// trait and the [`encode_flags`]/[`decode_source`] free functions), so the two bits this decoder
// needs to test directly (primary/offset/has-symbol-id/shift) are redeclared here rather than
// adding trait-object plumbing solely to read four bits back out of a byte already in hand.
const FLAG_PRIMARY: u8 = 0x02;
const FLAG_OFFSET: u8 = 0x04;
const FLAG_HAS_SYMBOL_ID: u8 = 0x08;
const FLAG_SHIFT: u8 = 0x10;

/// The concrete, byte-packed [`RefList`]/[`RefListV0`] implementation. See the module docs for
/// the factory methods this ports and the decoupling simplifications it makes relative to Java.
pub struct RefListV0Impl {
    state: DbObjectState,
    address: Address,
    addr_map: Arc<dyn AddressMap + Send + Sync>,
    adapter: Option<Arc<Mutex<dyn RecordAdapter + Send>>>,
    is_from: bool,
    ref_data: Vec<u8>,
    num_refs: i32,
    ref_level: i8,
    external_resolver: Arc<dyn Fn(&Address) -> Box<dyn ExternalLocation> + Send + Sync>,
    is_external_block_resolver: Arc<dyn Fn(&Address) -> bool + Send + Sync>,
}

impl RefListV0Impl {
    /// Creates a new, temporary, empty reference list not backed by any adapter (so mutations
    /// never touch the database). Stands in for `RefListV0.createTemporary(long, AddressMap,
    /// ProgramDB, boolean)`; `program` is dropped (see the module docs).
    pub fn create_temporary(
        addr_key: i64,
        addr_map: Arc<dyn AddressMap + Send + Sync>,
        is_from: bool,
    ) -> Self {
        let address = addr_map.decode_address(addr_key);
        RefListV0Impl {
            state: DbObjectState::new(addr_key),
            address,
            addr_map,
            adapter: None,
            is_from,
            ref_data: Vec::new(),
            num_refs: 0,
            ref_level: -1,
            external_resolver: default_external_resolver(),
            is_external_block_resolver: default_is_external_block_resolver(),
        }
    }

    /// Creates a new, empty reference list for `address` (generating a database key if needed).
    /// Stands in for `RefListV0.createNew(Address, RecordAdapter, AddressMap, ProgramDB,
    /// boolean)`; `program` is dropped (see the module docs). Mirrors Java's constructor, which
    /// only builds an in-memory record shell and does not write through the adapter until the
    /// first mutation.
    pub fn create_new(
        address: Address,
        adapter: Option<Arc<Mutex<dyn RecordAdapter + Send>>>,
        addr_map: Arc<dyn AddressMap + Send + Sync>,
        is_from: bool,
    ) -> Self {
        let addr_key = addr_map.get_key(&address, true);
        RefListV0Impl {
            state: DbObjectState::new(addr_key),
            address,
            addr_map,
            adapter,
            is_from,
            ref_data: Vec::new(),
            num_refs: 0,
            ref_level: -1,
            external_resolver: default_external_resolver(),
            is_external_block_resolver: default_is_external_block_resolver(),
        }
    }

    /// Reconstructs a reference list from already-persisted fields. Stands in for
    /// `RefListV0.instantiateExisting(DBRecord, RecordAdapter, AddressMap, ProgramDB, boolean)`;
    /// `program` is dropped and the `DBRecord` is replaced with its already-extracted fields (see
    /// the module docs for why).
    pub fn instantiate_existing(
        key: i64,
        ref_data: Vec<u8>,
        num_refs: i32,
        ref_level: i8,
        adapter: Option<Arc<Mutex<dyn RecordAdapter + Send>>>,
        addr_map: Arc<dyn AddressMap + Send + Sync>,
        is_from: bool,
    ) -> Self {
        let address = addr_map.decode_address(key);
        RefListV0Impl {
            state: DbObjectState::new(key),
            address,
            addr_map,
            adapter,
            is_from,
            ref_data,
            num_refs,
            // Mirrors Java: `if (!isFrom) { refLevel = rec.getByteValue(REF_LEVEL_COL); }` --
            // "from" lists never read a stored ref level (they leave the constructor-default -1).
            ref_level: if is_from { -1 } else { ref_level },
            external_resolver: default_external_resolver(),
            is_external_block_resolver: default_is_external_block_resolver(),
        }
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

    /// The raw packed byte blob backing this list, exactly as it would be written to
    /// `ToAdapter.REF_DATA_COL`. Stands in for the package-private `RefListV0.getData()` -- see
    /// the module docs for why it isn't part of the [`RefListV0`] trait itself.
    pub(crate) fn raw_ref_data(&self) -> &[u8] {
        &self.ref_data
    }

    #[allow(clippy::too_many_arguments)]
    fn encode_ref(
        &self,
        from_addr: &Address,
        to_addr: &Address,
        ref_type: RefType,
        source: SourceType,
        op_index: i32,
        symbol_id: i64,
        is_primary: bool,
        is_offset_ref: bool,
        is_shift_ref: bool,
        offset_or_shift: i64,
    ) -> Vec<u8> {
        let has_symbol_id = symbol_id >= 0;
        let flags_byte = encode_flags(is_primary, is_offset_ref, has_symbol_id, is_shift_ref, source)
            .expect("SourceType storage id always fits in RefListFlagsV0's 3-bit budget");
        let addr = if self.is_from { to_addr } else { from_addr };
        let key = self.addr_map.get_key(addr, true);

        let mut data = Vec::with_capacity(11 + 16);
        data.extend_from_slice(&key.to_be_bytes());
        data.push(flags_byte);
        data.push(ref_type.value() as u8);
        data.push(op_index as u8);
        if has_symbol_id {
            data.extend_from_slice(&symbol_id.to_be_bytes());
        }
        if is_offset_ref || is_shift_ref {
            data.extend_from_slice(&offset_or_shift.to_be_bytes());
        }
        data
    }

    /// Decodes one packed reference starting at `offset`, returning it plus the offset of the
    /// next record. Stands in for `RefListV0.decode(byte[], int, Reference[])`.
    fn decode_ref(&self, data: &[u8], offset: usize) -> (Arc<dyn Reference>, usize) {
        let mut off = offset;
        let key = i64::from_be_bytes(data[off..off + 8].try_into().unwrap());
        off += 8;
        let flags_byte = data[off];
        off += 1;
        let ref_type = RefTypeFactory::get(data[off] as i8)
            .expect("RefListV0-encoded RefType bytes are always valid");
        off += 1;
        let op_index = data[off] as i8 as i32;
        off += 1;

        let source = decode_source(flags_byte);
        let is_primary = flags_byte & FLAG_PRIMARY != 0;
        let has_symbol_id = flags_byte & FLAG_HAS_SYMBOL_ID != 0;
        let is_offset_ref = flags_byte & FLAG_OFFSET != 0;
        let is_shift_ref = flags_byte & FLAG_SHIFT != 0;

        let mut symbol_id: i64 = -1;
        if has_symbol_id {
            symbol_id = i64::from_be_bytes(data[off..off + 8].try_into().unwrap());
            off += 8;
        }

        let from = if self.is_from {
            self.address.clone()
        } else {
            self.addr_map.decode_address(key)
        };
        let to = if self.is_from {
            self.addr_map.decode_address(key)
        } else {
            self.address.clone()
        };

        let reference: Arc<dyn Reference> = if is_offset_ref || is_shift_ref {
            let offset_or_shift = i64::from_be_bytes(data[off..off + 8].try_into().unwrap());
            off += 8;
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
            Arc::new(ExternalReferenceDb::new(
                from, to, ref_type, op_index, source, factory,
            ))
        } else if from == SpecialAddress::ext_from_address() {
            Arc::new(EntryPointReferenceDb::new(
                from, to, ref_type, op_index, source, is_primary, symbol_id,
            ))
        } else if to.is_stack_address() {
            Arc::new(StackReferenceDb::new(
                from, to, ref_type, op_index, source, is_primary, symbol_id,
            ))
        } else {
            Arc::new(MemReferenceDb::new(
                from, to, ref_type, op_index, source, is_primary, symbol_id,
            ))
        };

        (reference, off)
    }

    fn decode_all(&self) -> Vec<Arc<dyn Reference>> {
        let mut refs = Vec::with_capacity(self.num_refs.max(0) as usize);
        let mut pos = 0usize;
        for _ in 0..self.num_refs {
            let (r, new_pos) = self.decode_ref(&self.ref_data, pos);
            pos = new_pos;
            refs.push(r);
        }
        refs
    }

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
    ) {
        if !self.is_from {
            let level = ref_level_for(ref_type);
            if level > self.ref_level {
                self.ref_level = level;
            }
        }
        let bytes = self.encode_ref(
            from_addr,
            to_addr,
            ref_type,
            source,
            op_index,
            symbol_id,
            is_primary,
            is_offset,
            is_shifted,
            offset_or_shift,
        );
        self.ref_data.extend_from_slice(&bytes);
        self.num_refs += 1;
    }

    fn find_highest_ref_level(&self, current_ref_level: i8) -> i8 {
        let mut max_level: i8 = -1;
        let mut pos = 0usize;
        for _ in 0..self.num_refs {
            let (r, new_pos) = self.decode_ref(&self.ref_data, pos);
            pos = new_pos;
            let level = ref_level_for(r.reference_type());
            if max_level < level {
                max_level = level;
            }
            if level >= current_ref_level {
                return level;
            }
        }
        max_level
    }

    fn update_record(&mut self) -> io::Result<()> {
        if let Some(adapter) = &self.adapter {
            let ref_level_byte = self.ref_level as u8;
            let mut guard = adapter
                .lock()
                .expect("RefListV0Impl's adapter mutex should never be poisoned");
            let record =
                guard.create_record(self.state.get_key(), self.num_refs, ref_level_byte, &self.ref_data)?;
            guard.put_record(&record)?;
        }
        Ok(())
    }
}

impl DbObject for RefListV0Impl {
    fn state(&self) -> &DbObjectState {
        &self.state
    }

    fn refresh(&self, _record: Option<&DBRecord>) -> bool {
        false
    }
}

impl RefList for RefListV0Impl {
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
            from_addr,
            to_addr,
            op_index,
            ref_type,
            source,
            is_primary,
            symbol_id,
            is_offset,
            is_shift,
            offset_or_shift,
        );
        self.update_record()
    }

    fn update_ref_type(
        &mut self,
        change_addr: &Address,
        op_index: i32,
        ref_type: RefType,
    ) -> io::Result<()> {
        let mut update_ref_level = false;
        let new_level = ref_level_for(ref_type);
        let mut highest_ref_level: i8 = 0;
        if !self.is_from {
            update_ref_level = new_level != self.ref_level;
        }
        let mut pos = 0usize;
        for _ in 0..self.num_refs {
            let (r, new_pos) = self.decode_ref(&self.ref_data, pos);
            if r.operand_index() == op_index {
                let addr = if self.is_from {
                    r.to_address()
                } else {
                    r.from_address()
                };
                if &addr == change_addr {
                    let is_primary = r.is_primary();
                    let symbol_id = r.symbol_id();
                    let (is_offset, is_shifted, offset_or_shift) =
                        reference_offset_shift(r.as_ref());
                    let bytes = self.encode_ref(
                        &r.from_address(),
                        &r.to_address(),
                        ref_type,
                        r.source(),
                        r.operand_index(),
                        symbol_id,
                        is_primary,
                        is_offset,
                        is_shifted,
                        offset_or_shift,
                    );
                    debug_assert_eq!(bytes.len(), new_pos - pos, "changing RefType alone must not change a record's encoded length");
                    self.ref_data[pos..new_pos].copy_from_slice(&bytes);

                    if update_ref_level {
                        if new_level > self.ref_level {
                            highest_ref_level = new_level;
                            break;
                        }
                        if new_level > highest_ref_level {
                            highest_ref_level = new_level;
                        }
                    } else {
                        break;
                    }
                }
            } else if update_ref_level {
                let level = ref_level_for(r.reference_type());
                if level > highest_ref_level {
                    highest_ref_level = level;
                }
            }
            pos = new_pos;
        }
        if update_ref_level {
            self.ref_level = highest_ref_level;
        }
        self.update_record()
    }

    fn get_ref(&self, ref_address: &Address, op_index: i32) -> Option<Arc<dyn Reference>> {
        let mut pos = 0usize;
        for _ in 0..self.num_refs {
            let (r, new_pos) = self.decode_ref(&self.ref_data, pos);
            if r.operand_index() == op_index {
                let addr = if self.is_from {
                    r.to_address()
                } else {
                    r.from_address()
                };
                if &addr == ref_address {
                    return Some(r);
                }
            }
            pos = new_pos;
        }
        None
    }

    fn remove_ref(&mut self, delete_addr: &Address, op_index: i32) -> io::Result<bool> {
        let mut pos = 0usize;
        for _ in 0..self.num_refs {
            let (r, new_pos) = self.decode_ref(&self.ref_data, pos);
            if r.operand_index() == op_index {
                let addr = if self.is_from {
                    r.to_address()
                } else {
                    r.from_address()
                };
                if &addr == delete_addr {
                    let mut new_data = Vec::with_capacity(self.ref_data.len() - (new_pos - pos));
                    new_data.extend_from_slice(&self.ref_data[..pos]);
                    new_data.extend_from_slice(&self.ref_data[new_pos..]);
                    self.ref_data = new_data;
                    self.num_refs -= 1;
                    if self.num_refs == 0 {
                        self.ref_data.clear();
                        if let Some(adapter) = &self.adapter {
                            adapter
                                .lock()
                                .expect("RefListV0Impl's adapter mutex should never be poisoned")
                                .remove_record(self.state.get_key())?;
                        }
                        self.set_invalid();
                    } else {
                        if !self.is_from {
                            let level = ref_level_for(r.reference_type());
                            if self.ref_level <= level {
                                self.ref_level = self.find_highest_ref_level(self.ref_level);
                            }
                        }
                        self.update_record()?;
                    }
                    return Ok(true);
                }
            }
            pos = new_pos;
        }
        Ok(false)
    }

    fn is_empty(&self) -> bool {
        self.num_refs == 0
    }

    fn set_primary(&mut self, reference: &dyn Reference, is_primary: bool) -> io::Result<bool> {
        let op_index = reference.operand_index();
        let change_addr = if self.is_from {
            reference.to_address()
        } else {
            reference.from_address()
        };
        let mut pos = 0usize;
        for _ in 0..self.num_refs {
            let (r, new_pos) = self.decode_ref(&self.ref_data, pos);
            if r.operand_index() == op_index {
                let addr = if self.is_from {
                    r.to_address()
                } else {
                    r.from_address()
                };
                if addr == change_addr {
                    if r.is_primary() == is_primary {
                        return Ok(false);
                    }
                    let (is_offset, is_shifted, offset_or_shift) =
                        reference_offset_shift(r.as_ref());
                    let bytes = self.encode_ref(
                        &r.from_address(),
                        &r.to_address(),
                        r.reference_type(),
                        r.source(),
                        r.operand_index(),
                        r.symbol_id(),
                        is_primary,
                        is_offset,
                        is_shifted,
                        offset_or_shift,
                    );
                    debug_assert_eq!(bytes.len(), new_pos - pos, "changing only the primary flag must not change a record's encoded length");
                    self.ref_data[pos..new_pos].copy_from_slice(&bytes);
                    self.update_record()?;
                    return Ok(true);
                }
            }
            pos = new_pos;
        }
        Ok(false)
    }

    fn get_refs(&self) -> Box<dyn ReferenceIterator> {
        Box::new(ReferenceIteratorAdapter::new(self.decode_all()))
    }

    fn get_all_refs(&self) -> Vec<Arc<dyn Reference>> {
        self.decode_all()
    }

    fn get_num_refs(&self) -> i32 {
        self.num_refs
    }

    fn get_primary_ref(&self, op_index: i32) -> Option<Arc<dyn Reference>> {
        if !self.is_from {
            return None;
        }
        let mut pos = 0usize;
        for _ in 0..self.num_refs {
            let (r, new_pos) = self.decode_ref(&self.ref_data, pos);
            if r.is_primary() && r.operand_index() == op_index {
                return Some(r);
            }
            pos = new_pos;
        }
        None
    }

    fn remove_all(&mut self) -> io::Result<()> {
        self.num_refs = 0;
        self.ref_data.clear();
        if let Some(adapter) = &self.adapter {
            adapter
                .lock()
                .expect("RefListV0Impl's adapter mutex should never be poisoned")
                .remove_record(self.state.get_key())?;
        }
        Ok(())
    }

    fn set_symbol_id(&mut self, reference: &dyn Reference, symbol_id: i64) -> io::Result<bool> {
        let op_index = reference.operand_index();
        let change_addr = if self.is_from {
            reference.to_address()
        } else {
            reference.from_address()
        };
        let mut pos = 0usize;
        for _ in 0..self.num_refs {
            let (r, new_pos) = self.decode_ref(&self.ref_data, pos);
            if r.operand_index() == op_index {
                let addr = if self.is_from {
                    r.to_address()
                } else {
                    r.from_address()
                };
                if addr == change_addr {
                    // Mirrors Java exactly: `boolean isPrimary = ref.isPrimary();` reads the
                    // *parameter* `reference`'s primary flag, not the decoded record `r`'s.
                    let is_primary = reference.is_primary();
                    let (is_offset, is_shifted, offset_or_shift) =
                        reference_offset_shift(r.as_ref());
                    let bytes = self.encode_ref(
                        &r.from_address(),
                        &r.to_address(),
                        r.reference_type(),
                        r.source(),
                        r.operand_index(),
                        symbol_id,
                        is_primary,
                        is_offset,
                        is_shifted,
                        offset_or_shift,
                    );
                    if bytes.len() == new_pos - pos {
                        self.ref_data[pos..new_pos].copy_from_slice(&bytes);
                    } else {
                        let mut new_data = Vec::with_capacity(
                            self.ref_data.len() - (new_pos - pos) + bytes.len(),
                        );
                        new_data.extend_from_slice(&self.ref_data[..pos]);
                        new_data.extend_from_slice(&bytes);
                        new_data.extend_from_slice(&self.ref_data[new_pos..]);
                        self.ref_data = new_data;
                    }
                    self.update_record()?;
                    return Ok(true);
                }
            }
            pos = new_pos;
        }
        Ok(false)
    }

    fn has_reference(&self, op_index: i32) -> bool {
        if !self.is_from {
            return false;
        }
        let mut pos = 0usize;
        for _ in 0..self.num_refs {
            let (r, new_pos) = self.decode_ref(&self.ref_data, pos);
            if r.operand_index() == op_index {
                return true;
            }
            pos = new_pos;
        }
        false
    }

    fn get_reference_level(&self) -> i8 {
        self.ref_level
    }
}

impl RefListV0 for RefListV0Impl {
    fn add_refs(&mut self, refs: &[Arc<dyn Reference>]) -> io::Result<()> {
        for r in refs {
            let is_primary = r.is_primary();
            let symbol_id = r.symbol_id();
            let (is_offset, is_shifted, offset_or_shift) = reference_offset_shift(r.as_ref());
            self.append_ref(
                &r.from_address(),
                &r.to_address(),
                r.operand_index(),
                r.reference_type(),
                r.source(),
                is_primary,
                symbol_id,
                is_offset,
                is_shifted,
                offset_or_shift,
            );
        }
        self.update_record()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::db_object::{DbObject, DbObjectState};
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{RefType, ReferenceIterator, SourceType};

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

    /// A tiny in-memory stand-in for the real byte-packed storage, just enough to prove the trait
    /// is object-safe and behaves like the Java class for the mutation/query pairs that matter.
    struct MockRefListV0 {
        state: DbObjectState,
        refs: Vec<Arc<dyn Reference>>,
        ref_level: i8,
    }

    impl MockRefListV0 {
        fn new() -> Self {
            MockRefListV0 {
                state: DbObjectState::new(0),
                refs: Vec::new(),
                ref_level: -1,
            }
        }
    }

    impl DbObject for MockRefListV0 {
        fn state(&self) -> &DbObjectState {
            &self.state
        }

        fn refresh(&self, _record: Option<&crate::framework::db::DBRecord>) -> bool {
            true
        }
    }

    impl RefList for MockRefListV0 {
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
            Box::new(crate::program::model::symbol::ReferenceIteratorAdapter::new(
                self.refs.clone(),
            ))
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

    impl RefListV0 for MockRefListV0 {
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
        let mut list = MockRefListV0::new();
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
    fn set_primary_reports_whether_it_changed() {
        let mut list = MockRefListV0::new();
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
        let mut list: Box<dyn RefListV0> = Box::new(MockRefListV0::new());
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
mod ref_list_v0_impl_tests {
    use super::*;
    use crate::framework::db::{Field, Schema};
    use crate::program::model::address::{AddressFactory, AddressSetView, AddressSpace, AddressSpaceType, KeyRange};
    use crate::program::model::symbol::SourceType;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    /// A minimal, real (non-panicking) `AddressMap`: ordinary ram addresses round-trip through
    /// their offset directly; addresses in any other space (stack/external/special) are assigned
    /// a fresh negative key on first sight and remembered in a side table, so `decode_address`
    /// can hand the exact same `Address` back later. Good enough to exercise `RefListV0Impl`'s
    /// full decode surface without needing a real `AddressMapDB`.
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
                self.special
                    .lock()
                    .unwrap()
                    .get(&value)
                    .cloned()
                    .expect("decode_address called with an unknown key")
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

    /// A real, in-memory `RecordAdapter`: enough to prove `RefListV0Impl` genuinely writes
    /// through on every mutation (not just tracking state internally), mirroring how the not-yet
    /// -ported `ToAdapterV0`/`FromAdapterV0` will eventually back it for real.
    struct MockRecordAdapter {
        schema: Arc<Schema>,
        records: HashMap<i64, DBRecord>,
        create_calls: Vec<(i64, i32, u8, Vec<u8>)>,
    }

    impl MockRecordAdapter {
        fn new() -> Self {
            MockRecordAdapter {
                schema: Arc::new(Schema::new(
                    0,
                    crate::framework::db::FieldType::Long,
                    "Key".to_string(),
                    vec![
                        crate::framework::db::FieldType::Int,
                        crate::framework::db::FieldType::Byte,
                        crate::framework::db::FieldType::Binary,
                    ],
                    vec![
                        "NumRefs".to_string(),
                        "RefLevel".to_string(),
                        "RefData".to_string(),
                    ],
                    vec![],
                )),
                records: HashMap::new(),
                create_calls: Vec::new(),
            }
        }
    }

    impl RecordAdapter for MockRecordAdapter {
        fn create_record(
            &mut self,
            key: i64,
            num_refs: i32,
            ref_level: u8,
            ref_data: &[u8],
        ) -> io::Result<DBRecord> {
            self.create_calls.push((key, num_refs, ref_level, ref_data.to_vec()));
            let mut record = DBRecord::new(self.schema.clone(), Field::Long(Some(key)));
            record.set_int(0, num_refs);
            record.set_byte(1, ref_level as i8);
            record.set_field(2, Field::Binary(Some(ref_data.to_vec())));
            self.records.insert(key, record.clone());
            Ok(record)
        }

        fn get_record(&self, key: i64) -> io::Result<DBRecord> {
            self.records
                .get(&key)
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "record not found"))
        }

        fn put_record(&mut self, record: &DBRecord) -> io::Result<()> {
            let key = record.get_key().get_long_value();
            self.records.insert(key, record.clone());
            Ok(())
        }

        fn remove_record(&mut self, key: i64) -> io::Result<()> {
            self.records.remove(&key);
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
    fn create_temporary_add_ref_and_get_ref_round_trip_for_a_to_list() {
        let m = map();
        // A "to" list (is_from = false) keyed by the destination address; `add_ref`'s `to_addr`
        // must equal the list's own address (mirrors how `ToAdapter` constructs these).
        let to = addr(&m, 0x2000);
        let key = m.get_key(&to, true);
        let mut list = RefListV0Impl::create_temporary(key, m.clone(), false);

        let from = addr(&m, 0x1000);
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
        assert!(!list.is_empty());
        let r = list.get_ref(&from, 0).expect("should find the from-address for a to-list");
        assert_eq!(r.from_address(), from);
        assert_eq!(r.to_address(), to);
        assert_eq!(r.symbol_id(), 42);
        assert!(r.is_primary());
        assert_eq!(r.reference_type(), RefType::UnconditionalCall);
        assert_eq!(r.source(), SourceType::Imported);
        assert!(r.is_memory_reference());

        // `getReferenceLevel` should reflect a call-type reference.
        assert_eq!(list.get_reference_level(), SUB_LEVEL as i8);
    }

    #[test]
    fn create_new_generates_a_key_and_writes_through_the_adapter_on_every_mutation() {
        let m = map();
        let a = adapter();
        let to = addr(&m, 0x3000);

        let mut list = RefListV0Impl::create_new(to.clone(), Some(as_trait_object(&a)), m.clone(), false);
        assert_eq!(list.get_key(), m.get_key(&to, true));

        // Nothing should have been written yet -- Java's constructor only builds an in-memory
        // shell; the first real write happens on the first mutation.
        assert!(a.lock().unwrap().create_calls.is_empty());

        list.add_ref(
            &addr(&m, 0x100),
            &to,
            RefType::Data,
            2,
            -1,
            false,
            SourceType::Analysis,
            false,
            false,
            0,
        )
        .unwrap();

        let guard = a.lock().unwrap();
        assert_eq!(guard.create_calls.len(), 1);
        let (key, num_refs, _level, data) = &guard.create_calls[0];
        assert_eq!(*key, list.get_key());
        assert_eq!(*num_refs, 1);
        assert!(!data.is_empty());
        drop(guard);

        list.remove_all().unwrap();
        assert!(a.lock().unwrap().get_record(list.get_key()).is_err());
    }

    #[test]
    fn instantiate_existing_reproduces_an_equivalent_list() {
        let m = map();
        let to = addr(&m, 0x4000);
        let mut original = RefListV0Impl::create_new(to.clone(), None, m.clone(), false);
        original
            .add_ref(
                &addr(&m, 0x10),
                &to,
                RefType::Data,
                0,
                7,
                true,
                SourceType::UserDefined,
                false,
                false,
                0,
            )
            .unwrap();
        original
            .add_ref(
                &addr(&m, 0x20),
                &to,
                RefType::ConditionalJump,
                1,
                -1,
                false,
                SourceType::Analysis,
                false,
                false,
                0,
            )
            .unwrap();

        let restored = RefListV0Impl::instantiate_existing(
            original.get_key(),
            original.raw_ref_data().to_vec(),
            original.get_num_refs(),
            original.get_reference_level(),
            None,
            m.clone(),
            false,
        );

        assert_eq!(restored.get_num_refs(), original.get_num_refs());
        assert_eq!(restored.get_reference_level(), original.get_reference_level());
        let orig_refs = original.get_all_refs();
        let restored_refs = restored.get_all_refs();
        assert_eq!(orig_refs.len(), restored_refs.len());
        for (a, b) in orig_refs.iter().zip(restored_refs.iter()) {
            assert_eq!(a.from_address(), b.from_address());
            assert_eq!(a.to_address(), b.to_address());
            assert_eq!(a.symbol_id(), b.symbol_id());
            assert_eq!(a.operand_index(), b.operand_index());
            assert_eq!(a.reference_type(), b.reference_type());
        }
    }

    #[test]
    fn remove_ref_deletes_the_matching_entry_and_keeps_others() {
        let m = map();
        let to = addr(&m, 0x5000);
        let mut list = RefListV0Impl::create_temporary(m.get_key(&to, true), m.clone(), false);
        let from1 = addr(&m, 0x10);
        let from2 = addr(&m, 0x20);
        list.add_ref(&from1, &to, RefType::Data, 0, -1, false, SourceType::Analysis, false, false, 0).unwrap();
        list.add_ref(&from2, &to, RefType::Data, 1, -1, false, SourceType::Analysis, false, false, 0).unwrap();

        assert!(list.remove_ref(&from1, 0).unwrap());
        assert_eq!(list.get_num_refs(), 1);
        assert!(list.get_ref(&from1, 0).is_none());
        assert!(list.get_ref(&from2, 1).is_some());

        // Removing again reports false (nothing to remove).
        assert!(!list.remove_ref(&from1, 0).unwrap());

        assert!(list.remove_ref(&from2, 1).unwrap());
        assert!(list.is_empty());
    }

    #[test]
    fn set_primary_reports_whether_it_changed_and_preserves_encoded_length() {
        let m = map();
        let to = addr(&m, 0x6000);
        let mut list = RefListV0Impl::create_temporary(m.get_key(&to, true), m.clone(), false);
        let from = addr(&m, 0x10);
        list.add_ref(&from, &to, RefType::Data, 0, -1, false, SourceType::Analysis, false, false, 0).unwrap();

        let current = list.get_ref(&from, 0).unwrap();
        assert!(list.set_primary(current.as_ref(), true).unwrap());
        let updated = list.get_ref(&from, 0).unwrap();
        assert!(updated.is_primary());
        assert!(!list.set_primary(updated.as_ref(), true).unwrap());
    }

    #[test]
    fn set_symbol_id_handles_both_same_length_and_length_changing_updates() {
        let m = map();
        let to = addr(&m, 0x7000);
        let mut list = RefListV0Impl::create_temporary(m.get_key(&to, true), m.clone(), false);
        let from = addr(&m, 0x10);
        // Starts with no symbol ID (-1), so the encoded record is 8 bytes shorter than one with a
        // symbol ID -- setSymbolID must grow the blob, not just overwrite in place.
        list.add_ref(&from, &to, RefType::Data, 0, -1, false, SourceType::Analysis, false, false, 0).unwrap();
        assert_eq!(list.raw_ref_data().len(), 11);

        let current = list.get_ref(&from, 0).unwrap();
        assert!(list.set_symbol_id(current.as_ref(), 99).unwrap());
        assert_eq!(list.raw_ref_data().len(), 19);
        assert_eq!(list.get_ref(&from, 0).unwrap().symbol_id(), 99);

        // Same-length update (symbol ID already present, changing its value).
        let current = list.get_ref(&from, 0).unwrap();
        assert!(list.set_symbol_id(current.as_ref(), 100).unwrap());
        assert_eq!(list.raw_ref_data().len(), 19);
        assert_eq!(list.get_ref(&from, 0).unwrap().symbol_id(), 100);
    }

    #[test]
    fn update_ref_type_recomputes_the_to_lists_reference_level() {
        let m = map();
        let to = addr(&m, 0x8000);
        let mut list = RefListV0Impl::create_temporary(m.get_key(&to, true), m.clone(), false);
        let from = addr(&m, 0x10);
        // A plain data reference starts the list at DAT_LEVEL.
        list.add_ref(&from, &to, RefType::Data, 0, -1, false, SourceType::Analysis, false, false, 0).unwrap();
        assert_eq!(list.get_reference_level(), DAT_LEVEL as i8);

        // Promoting it to a call reference should raise the list's level to SUB_LEVEL.
        list.update_ref_type(&from, 0, RefType::UnconditionalCall).unwrap();
        assert_eq!(list.get_reference_level(), SUB_LEVEL as i8);
        assert_eq!(
            list.get_ref(&from, 0).unwrap().reference_type(),
            RefType::UnconditionalCall
        );
    }

    #[test]
    fn add_refs_bulk_inserts_and_persists_once() {
        let m = map();
        let a = adapter();
        let to = addr(&m, 0x9000);
        let mut list = RefListV0Impl::create_new(to.clone(), Some(as_trait_object(&a)), m.clone(), false);

        let refs: Vec<Arc<dyn Reference>> = vec![
            Arc::new(MemReferenceDb::new(
                addr(&m, 0x10),
                to.clone(),
                RefType::Data,
                0,
                SourceType::Analysis,
                false,
                -1,
            )),
            Arc::new(MemReferenceDb::new(
                addr(&m, 0x20),
                to.clone(),
                RefType::Data,
                1,
                SourceType::Analysis,
                true,
                5,
            )),
        ];
        list.add_refs(&refs).unwrap();

        assert_eq!(list.get_num_refs(), 2);
        assert!(list.get_ref(&addr(&m, 0x10), 0).is_some());
        assert_eq!(list.get_ref(&addr(&m, 0x20), 1).unwrap().symbol_id(), 5);
    }

    #[test]
    fn from_list_supports_has_reference_and_primary_ref_lookups() {
        let m = map();
        // A "from" list (is_from = true) is keyed by the source address; `to_addr` varies per
        // reference (multiple operands can each reference a different destination).
        let from_addr = addr(&m, 0xA000);
        let mut list = RefListV0Impl::create_temporary(m.get_key(&from_addr, true), m.clone(), true);
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
        let to = addr(&m, 0xB000);
        let mut list = RefListV0Impl::create_temporary(m.get_key(&to, true), m.clone(), false);
        let from = addr(&m, 0x10);

        list.add_ref(&from, &to, RefType::Data, 0, -1, false, SourceType::Analysis, true, false, 4)
            .unwrap();
        let offset_ref = list.get_ref(&from, 0).unwrap();
        assert!(offset_ref.is_offset_reference());
        let offset_view = offset_ref.as_offset_reference().unwrap();
        assert_eq!(offset_view.offset(), 4);

        list.add_ref(&from, &to, RefType::Data, 1, -1, false, SourceType::Analysis, false, true, 2)
            .unwrap();
        let shifted_ref = list.get_ref(&from, 1).unwrap();
        assert!(shifted_ref.is_shifted_reference());
        let shifted = shifted_ref
            .as_any()
            .downcast_ref::<ShiftedReferenceDb>()
            .unwrap();
        assert_eq!(shifted.shift(), 2);
    }

    #[test]
    fn decodes_stack_and_external_references_via_the_lists_own_address() {
        let m = map();

        // A "to" list keyed directly by a stack address: `to == self.address`, so no addr_map
        // round-trip through the stack space is needed to decode it back out.
        let stack_space = AddressSpace::new("stack", 32, 1, AddressSpaceType::Stack, 5);
        let stack_addr = Address::new(stack_space, 8);
        let mut stack_list =
            RefListV0Impl::create_temporary(m.get_key(&stack_addr, true), m.clone(), false);
        let from = addr(&m, 0x10);
        stack_list
            .add_ref(&from, &stack_addr, RefType::Data, 0, -1, false, SourceType::Analysis, false, false, 0)
            .unwrap();
        let stack_ref = stack_list.get_ref(&from, 0).unwrap();
        assert!(stack_ref.is_stack_reference());
        assert_eq!(stack_ref.to_address(), stack_addr);

        // Same trick for an external address.
        let ext_space = AddressSpace::new("EXTERNAL", 32, 1, AddressSpaceType::External, 6);
        let ext_addr = Address::new(ext_space, 3);
        let mut ext_list = RefListV0Impl::create_temporary(m.get_key(&ext_addr, true), m.clone(), false);
        ext_list
            .add_ref(&from, &ext_addr, RefType::Data, 0, -1, false, SourceType::Analysis, false, false, 0)
            .unwrap();
        let ext_ref = ext_list.get_ref(&from, 0).unwrap();
        assert!(ext_ref.is_external_reference());
        assert_eq!(ext_ref.to_address(), ext_addr);
        // The default resolver produces a placeholder location with an empty label.
        assert_eq!(ext_ref.as_external_reference().unwrap().get_external_location().get_label(), "");
    }

    #[test]
    fn object_safety_via_ref_list_v0_trait_object() {
        let m = map();
        let to = addr(&m, 0xC000);
        let mut list: Box<dyn RefListV0> =
            Box::new(RefListV0Impl::create_temporary(m.get_key(&to, true), m.clone(), false));
        let from = addr(&m, 0x10);
        list.add_ref(&from, &to, RefType::Data, 0, -1, false, SourceType::Analysis, false, false, 0)
            .unwrap();
        assert_eq!(list.get_num_refs(), 1);
        assert!(list.is_valid() || !list.is_valid()); // DbObject supertrait is reachable
    }
}
