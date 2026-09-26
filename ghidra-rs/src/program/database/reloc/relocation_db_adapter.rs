//! Port of `ghidra.program.database.reloc.RelocationDBAdapter`.
//!
//! The Java type is an abstract class whose static factory methods (`getAdapter`,
//! `findReadOnlyAdapter`, `upgrade`) select and migrate between concrete version-specific
//! implementations (`RelocationDBAdapterV1`..`RelocationDBAdapterV6`, `RelocationDBAdapterNoTable`).
//! This trait was originally selected as a dependency-cycle cut-point, modeling only the abstract
//! instance API each version implements. Now that all seven concrete versions exist (see
//! [`RelocationDbAdapterNoTable`](crate::program::database::reloc::RelocationDbAdapterNoTable),
//! [`RelocationDbAdapterV1`](crate::program::database::reloc::RelocationDbAdapterV1)..
//! [`RelocationDbAdapterV6`](crate::program::database::reloc::RelocationDbAdapterV6)), this module
//! also carries the real version-selection/upgrade logic itself: [`get_adapter`] (with
//! `findReadOnlyAdapter`/`upgrade` inlined as private helpers, mirroring how
//! [`bookmark_db_adapter::get_adapter`](crate::program::database::bookmark::bookmark_db_adapter::get_adapter)
//! already handles the identical situation for its own versioned-adapter family) and the
//! [`RelocationAdapterKind`] enum it returns.
//!
//! **Left out: `preV6DataMigrationUpgrade`.** This higher-level migration (invoked by `ProgramDB`
//! *after* a program is fully "ready", to refine `V6`'s default `Status::UNKNOWN`/zero-length
//! placeholder records left behind by the schema-level `upgrade()` below) depends on the unported
//! `Program`/`Memory`/`RelocationManager` types, so it is not ported here -- it belongs with
//! whichever type ends up owning a concrete `Program`. See `RelocationDBAdapter.java`'s own
//! `preV6DataMigrationUpgrade`/`computeOriginalFileBytesLength` for its full logic if/when that
//! becomes available.

use std::io;
use std::sync::Arc;

use crate::framework::data::OpenMode;
use crate::framework::db::{DBHandle, DBRecord, RecordIterator, Schema};
use crate::program::database::map::AddressMap;
use crate::program::database::reloc::relocation_db_adapter_no_table::RelocationDbAdapterNoTable;
use crate::program::database::reloc::relocation_db_adapter_v1::RelocationDbAdapterV1;
use crate::program::database::reloc::relocation_db_adapter_v2::RelocationDbAdapterV2;
use crate::program::database::reloc::relocation_db_adapter_v3::RelocationDbAdapterV3;
use crate::program::database::reloc::relocation_db_adapter_v4::RelocationDbAdapterV4;
use crate::program::database::reloc::relocation_db_adapter_v5::RelocationDbAdapterV5;
use crate::program::database::reloc::relocation_db_adapter_v6::{self, RelocationDbAdapterV6};
use crate::program::model::address::{Address, AddressSetView};
use crate::program::model::reloc::relocation::RelocationStatus;
use crate::util::exception::VersionException;
use crate::util::task::TaskMonitor;

/// DB table name for the relocations table. Stands in for `RelocationDBAdapter.TABLE_NAME`.
pub const TABLE_NAME: &str = "Relocations";

/// Relocation record column index for the address (indexed). Stands in for
/// `RelocationDBAdapter.ADDR_COL`.
pub const ADDR_COL: usize = 0;
/// Relocation record column index for the flags byte (status and optional length). Stands in for
/// `RelocationDBAdapter.FLAGS_COL`.
pub const FLAGS_COL: usize = 1;
/// Relocation record column index for the relocation type. Stands in for
/// `RelocationDBAdapter.TYPE_COL`.
pub const TYPE_COL: usize = 2;
/// Relocation record column index for the binary-coded `long[]` value. Stands in for
/// `RelocationDBAdapter.VALUE_COL`.
pub const VALUE_COL: usize = 3;
/// Relocation record column index for the original bytes (`None`/null defers to FileBytes).
/// Stands in for `RelocationDBAdapter.BYTES_COL`.
pub const BYTES_COL: usize = 4;
/// Relocation record column index for the symbol name. Stands in for
/// `RelocationDBAdapter.SYMBOL_NAME_COL`.
pub const SYMBOL_NAME_COL: usize = 5;

/// Mask isolating the [`RelocationStatus`] value within the flags byte. Stands in for
/// `RelocationDBAdapter.STATUS_FLAGS_MASK`.
pub const STATUS_FLAGS_MASK: u8 = 0x7;
/// Mask isolating the byte-length value within the flags byte (after shifting). Stands in for
/// `RelocationDBAdapter.LENGTH_FLAGS_MASK`.
pub const LENGTH_FLAGS_MASK: u8 = 0xF;
/// Bit position of the byte-length field within the flags byte. Stands in for
/// `RelocationDBAdapter.LENGTH_FLAGS_SHIFT`.
pub const LENGTH_FLAGS_SHIFT: u32 = 3;
/// Maximum byte-length that can be encoded within the flags byte. Stands in for
/// `RelocationDBAdapter.LENGTH_MAX`.
pub const LENGTH_MAX: i32 = 31;

/// Generate flags value for specified status and original bytes length for relocation.
///
/// Port of `RelocationDBAdapter.getFlags(Relocation.Status, int)`.
///
/// # Panics
///
/// Panics if `byte_length` is negative or greater than [`LENGTH_MAX`], mirroring the Java method's
/// `IllegalArgumentException`.
pub fn get_flags(status: RelocationStatus, byte_length: i32) -> u8 {
    if byte_length < 0 || byte_length > LENGTH_MAX {
        panic!("unsupported byte-length: {byte_length}");
    }
    let mut flags = (status.value() as u8) & STATUS_FLAGS_MASK;
    flags |= (byte_length as u8) << LENGTH_FLAGS_SHIFT;
    flags
}

/// Get the status specified by the relocation flags.
///
/// Port of `RelocationDBAdapter.getStatus(byte)`. Returns [`RelocationStatus::Unknown`] if the
/// encoded status value is not recognized, mirroring the Java method's catch-all fallback.
pub fn get_status(flags: u8) -> RelocationStatus {
    RelocationStatus::from_value((flags & STATUS_FLAGS_MASK) as i32)
        .unwrap_or(RelocationStatus::Unknown)
}

/// Get the byte length specified by the relocation flags. This length should only be used if the
/// stored bytes are `None` and the relocation has an appropriate status.
///
/// Port of `RelocationDBAdapter.getByteLength(byte)`.
pub fn get_byte_length(flags: u8) -> i32 {
    ((flags >> LENGTH_FLAGS_SHIFT) & LENGTH_FLAGS_MASK) as i32
}

/// The current relocation table schema. Port of `RelocationDBAdapter.SCHEMA`, which in Java lives
/// on this abstract base class (referencing `RelocationDBAdapterV6.VERSION` for its version
/// number) even though only `V6` ever constructs a table with it; aliased here from
/// [`relocation_db_adapter_v6::schema`] so the two don't drift apart, mirroring how
/// [`bookmark_db_adapter::schema`](crate::program::database::bookmark::bookmark_db_adapter::schema)
/// aliases its own family's current-version schema.
pub fn schema() -> Arc<Schema> {
    relocation_db_adapter_v6::schema()
}

/// Encodes a `long[]` (`&[i64]`) the way Java's `db.BinaryCodedField` would for storage in
/// [`VALUE_COL`]. Only this port's own encoder/decoder pair need agree with each other -- see
/// `FileBytesAdapterV0`'s module docs for the established precedent that exact byte-for-byte
/// parity with Java's on-disk `BinaryCodedField` layout is unnecessary, since both ends of the
/// round-trip live in this port. Format: a big-endian `i32` element count followed by that many
/// big-endian `i64` values.
pub(crate) fn encode_binary_coded_longs(values: &[i64]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + values.len() * 8);
    buf.extend_from_slice(&(values.len() as i32).to_be_bytes());
    for v in values {
        buf.extend_from_slice(&v.to_be_bytes());
    }
    buf
}

/// Decodes bytes produced by [`encode_binary_coded_longs`] back into a `Vec<i64>`. Truncated
/// (too-short) input decodes as many complete trailing values as are present rather than
/// panicking, a defensive read with no equivalent Java code path to mirror (Java's own
/// `BinaryCodedField` is always constructed from a `BinaryField` this port never produces in a
/// truncated form).
pub(crate) fn decode_binary_coded_longs(bytes: &[u8]) -> Vec<i64> {
    if bytes.len() < 4 {
        return Vec::new();
    }
    let count = i32::from_be_bytes(bytes[0..4].try_into().unwrap()).max(0) as usize;
    let mut values = Vec::with_capacity(count);
    let mut offset = 4;
    for _ in 0..count {
        if offset + 8 > bytes.len() {
            break;
        }
        values.push(i64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap()));
        offset += 8;
    }
    values
}

/// Adapter to access the relocations table.
///
/// Port of `ghidra.program.database.reloc.RelocationDBAdapter`.
pub trait RelocationDBAdapter {
    /// Add a new relocation record.
    ///
    /// * `addr` - relocation address
    /// * `flags` - encoded flags (status, length), see [`get_flags`].
    /// * `type_` - relocation type
    /// * `values` - relocation value (e.g., symbol index)
    /// * `bytes` - original memory bytes
    /// * `symbol_name` - symbol name
    fn add(
        &mut self,
        addr: &Address,
        flags: u8,
        type_: i32,
        values: &[i64],
        bytes: Option<&[u8]>,
        symbol_name: Option<&str>,
    ) -> io::Result<()>;

    /// Iterator over all records in address order. Stands in for
    /// `RelocationDBAdapter.iterator()`.
    fn iterator(&self) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Iterator over all relocation records in address order constrained by the specified address
    /// set. Stands in for `RelocationDBAdapter.iterator(AddressSetView)`.
    fn iterator_in_set(&self, set: &dyn AddressSetView) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Iterate over relocation records starting at the specified start address. Stands in for
    /// `RelocationDBAdapter.iterator(Address)`.
    fn iterator_from(&self, start: &Address) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Get the total number of relocation records.
    fn get_record_count(&self) -> i32;

    /// Translate a relocation record to the latest schema format.
    fn adapt_record(&self, rec: DBRecord) -> DBRecord;
}

/// A `RecordIterator` over an eagerly-collected `Vec<DBRecord>`, already translated to the current
/// schema. Shared by every concrete adapter version in this family -- this port's
/// [`Table`](crate::framework::db::Table) has no secondary-index support, so every by-address
/// query is a linear scan/sort collected up front rather than a live cursor crawl, matching the
/// convention already established by `BookmarkDBAdapterV3`/`SymbolDatabaseAdapterV5` and others in
/// this DB-adapter family.
pub(crate) struct VecRelocationRecordIterator {
    records: std::vec::IntoIter<DBRecord>,
}

impl VecRelocationRecordIterator {
    pub(crate) fn new(records: Vec<DBRecord>) -> Self {
        VecRelocationRecordIterator { records: records.into_iter() }
    }
}

impl RecordIterator for VecRelocationRecordIterator {
    fn next(&mut self) -> io::Result<Option<DBRecord>> {
        Ok(self.records.next())
    }

    fn has_next(&self) -> bool {
        self.records.len() > 0
    }
}

/// Whichever concrete relocation table schema is actually in play, selected (and upgraded, if
/// needed) by [`get_adapter`]. A closed `enum` (rather than `Box<dyn RelocationDBAdapter>`) since
/// this port has no need for a `Send`/`Sync` bound on the trait itself yet -- see
/// `BookmarkAdapterKind`'s module docs for the fuller reasoning behind this shape, which would
/// apply equally here if such a bound were ever needed.
pub enum RelocationAdapterKind {
    NoTable(RelocationDbAdapterNoTable),
    V1(RelocationDbAdapterV1),
    V2(RelocationDbAdapterV2),
    V3(RelocationDbAdapterV3),
    V4(RelocationDbAdapterV4),
    V5(RelocationDbAdapterV5),
    V6(RelocationDbAdapterV6),
}

impl RelocationDBAdapter for RelocationAdapterKind {
    fn add(
        &mut self,
        addr: &Address,
        flags: u8,
        type_: i32,
        values: &[i64],
        bytes: Option<&[u8]>,
        symbol_name: Option<&str>,
    ) -> io::Result<()> {
        match self {
            Self::NoTable(a) => a.add(addr, flags, type_, values, bytes, symbol_name),
            Self::V1(a) => a.add(addr, flags, type_, values, bytes, symbol_name),
            Self::V2(a) => a.add(addr, flags, type_, values, bytes, symbol_name),
            Self::V3(a) => a.add(addr, flags, type_, values, bytes, symbol_name),
            Self::V4(a) => a.add(addr, flags, type_, values, bytes, symbol_name),
            Self::V5(a) => a.add(addr, flags, type_, values, bytes, symbol_name),
            Self::V6(a) => a.add(addr, flags, type_, values, bytes, symbol_name),
        }
    }

    fn iterator(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        match self {
            Self::NoTable(a) => a.iterator(),
            Self::V1(a) => a.iterator(),
            Self::V2(a) => a.iterator(),
            Self::V3(a) => a.iterator(),
            Self::V4(a) => a.iterator(),
            Self::V5(a) => a.iterator(),
            Self::V6(a) => a.iterator(),
        }
    }

    fn iterator_in_set(&self, set: &dyn AddressSetView) -> io::Result<Box<dyn RecordIterator + '_>> {
        match self {
            Self::NoTable(a) => a.iterator_in_set(set),
            Self::V1(a) => a.iterator_in_set(set),
            Self::V2(a) => a.iterator_in_set(set),
            Self::V3(a) => a.iterator_in_set(set),
            Self::V4(a) => a.iterator_in_set(set),
            Self::V5(a) => a.iterator_in_set(set),
            Self::V6(a) => a.iterator_in_set(set),
        }
    }

    fn iterator_from(&self, start: &Address) -> io::Result<Box<dyn RecordIterator + '_>> {
        match self {
            Self::NoTable(a) => a.iterator_from(start),
            Self::V1(a) => a.iterator_from(start),
            Self::V2(a) => a.iterator_from(start),
            Self::V3(a) => a.iterator_from(start),
            Self::V4(a) => a.iterator_from(start),
            Self::V5(a) => a.iterator_from(start),
            Self::V6(a) => a.iterator_from(start),
        }
    }

    fn get_record_count(&self) -> i32 {
        match self {
            Self::NoTable(a) => a.get_record_count(),
            Self::V1(a) => a.get_record_count(),
            Self::V2(a) => a.get_record_count(),
            Self::V3(a) => a.get_record_count(),
            Self::V4(a) => a.get_record_count(),
            Self::V5(a) => a.get_record_count(),
            Self::V6(a) => a.get_record_count(),
        }
    }

    fn adapt_record(&self, rec: DBRecord) -> DBRecord {
        match self {
            Self::NoTable(a) => a.adapt_record(rec),
            Self::V1(a) => a.adapt_record(rec),
            Self::V2(a) => a.adapt_record(rec),
            Self::V3(a) => a.adapt_record(rec),
            Self::V4(a) => a.adapt_record(rec),
            Self::V5(a) => a.adapt_record(rec),
            Self::V6(a) => a.adapt_record(rec),
        }
    }
}

/// Selects (and upgrades, if needed) the appropriate relocation table schema for the given
/// database handle and open mode.
///
/// Port of `RelocationDBAdapter.getAdapter(DBHandle, OpenMode, AddressMap, TaskMonitor)`.
///
/// # Errors
/// Returns a [`VersionException`] if the stored schema version is incompatible with `open_mode`.
pub fn get_adapter(
    handle: &mut DBHandle,
    open_mode: OpenMode,
    addr_map: Arc<dyn AddressMap>,
    monitor: &dyn TaskMonitor,
) -> Result<RelocationAdapterKind, VersionException> {
    match RelocationDbAdapterV6::new(handle, addr_map.clone(), open_mode == OpenMode::Create) {
        Ok(v6) => Ok(RelocationAdapterKind::V6(v6)),
        Err(e) => {
            if !e.is_upgradable() || open_mode == OpenMode::Update {
                return Err(e);
            }
            let old_adapter = find_read_only_adapter(handle, addr_map.clone())?;
            if open_mode == OpenMode::Upgrade {
                return upgrade(handle, addr_map, old_adapter, monitor);
            }
            Ok(old_adapter)
        }
    }
}

/// Probes each historical schema version, newest first, returning the first one that opens
/// successfully (or [`RelocationAdapterKind::NoTable`] if none do). Note this final fallback is
/// *not* wrapped in its own error recovery in the original Java either, so a `NoTable` open
/// failure -- i.e. some *other*, unrecognized table shape squatting on [`TABLE_NAME`] -- propagates
/// out of this function rather than being swallowed, matching Java exactly.
///
/// Port of the private `RelocationDBAdapter.findReadOnlyAdapter(DBHandle, AddressMap)`.
fn find_read_only_adapter(
    handle: &mut DBHandle,
    addr_map: Arc<dyn AddressMap>,
) -> Result<RelocationAdapterKind, VersionException> {
    if let Ok(v5) = RelocationDbAdapterV5::new(handle, addr_map.clone()) {
        return Ok(RelocationAdapterKind::V5(v5));
    }
    if let Ok(v4) = RelocationDbAdapterV4::new(handle, addr_map.clone()) {
        return Ok(RelocationAdapterKind::V4(v4));
    }
    if let Ok(v3) = RelocationDbAdapterV3::new(handle, addr_map.clone()) {
        return Ok(RelocationAdapterKind::V3(v3));
    }
    if let Ok(v2) = RelocationDbAdapterV2::new(handle, addr_map.clone()) {
        return Ok(RelocationAdapterKind::V2(v2));
    }
    if let Ok(v1) = RelocationDbAdapterV1::new(handle, addr_map.clone()) {
        return Ok(RelocationAdapterKind::V1(v1));
    }
    Ok(RelocationAdapterKind::NoTable(RelocationDbAdapterNoTable::new(handle)?))
}

/// Upgrades an older relocation schema to the current ([`RelocationDbAdapterV6`]) one in place, via
/// a temporary in-memory database (matching Java's own two-hop copy: old adapter -> temp `V6` ->
/// real `V6`, so that a failure partway through never leaves the real table half-migrated).
///
/// Port of the private `RelocationDBAdapter.upgrade(DBHandle, AddressMap, RelocationDBAdapter,
/// TaskMonitor)`. `monitor` is threaded through for signature parity, but -- faithfully mirroring
/// Java, whose own method body never calls it either, a real quirk in the original rather than an
/// omission here -- is not actually consulted.
fn upgrade(
    handle: &mut DBHandle,
    addr_map: Arc<dyn AddressMap>,
    old_adapter: RelocationAdapterKind,
    monitor: &dyn TaskMonitor,
) -> Result<RelocationAdapterKind, VersionException> {
    let _ = monitor;
    let old_addr_map: Arc<dyn AddressMap> = Arc::from(addr_map.get_old_address_map());
    let map_io_err = |e: io::Error| VersionException::with_message(e.to_string());

    let mut tmp_handle = DBHandle::new().map_err(map_io_err)?;
    let mut tmp_adapter = RelocationDbAdapterV6::new(&mut tmp_handle, addr_map.clone(), true)?;

    let mut iter = old_adapter.iterator().map_err(map_io_err)?;
    while let Some(rec) = iter.next().map_err(map_io_err)? {
        let addr = old_addr_map.decode_address(rec.get_field(ADDR_COL).get_long_value());
        let flags = rec.get_field(FLAGS_COL).get_long_value() as u8;
        let type_ = rec.get_field(TYPE_COL).get_int_value();
        let values = decode_binary_coded_longs(rec.get_field(VALUE_COL).get_binary_data().unwrap_or(&[]));
        let bytes = rec.get_field(BYTES_COL).get_binary_data();
        let symbol_name = rec.get_string(SYMBOL_NAME_COL);
        tmp_adapter
            .add(&addr, flags, type_, &values, bytes, symbol_name)
            .map_err(map_io_err)?;
    }
    drop(iter);

    handle.delete_table(TABLE_NAME);
    let mut new_adapter = RelocationDbAdapterV6::new(handle, addr_map, true)?;

    let mut iter2 = tmp_adapter.iterator().map_err(map_io_err)?;
    while let Some(rec) = iter2.next().map_err(map_io_err)? {
        new_adapter.put(rec).map_err(map_io_err)?;
    }
    Ok(RelocationAdapterKind::V6(new_adapter))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, FieldType, Schema};
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    #[test]
    fn flags_round_trip_status_and_length() {
        // LENGTH_FLAGS_MASK (0xF, 4 bits) only recovers the low 4 bits of the up-to-5-bit value
        // `getFlags`/`get_flags` accepts (bounded by LENGTH_MAX = 31); this asymmetry exists in
        // the original Java encoding, so round-tripping is only exact for lengths 0..15.
        for status in [
            RelocationStatus::Unknown,
            RelocationStatus::Skipped,
            RelocationStatus::Unsupported,
            RelocationStatus::Failure,
            RelocationStatus::Partial,
            RelocationStatus::Applied,
            RelocationStatus::AppliedOther,
        ] {
            for len in [0, 1, 15] {
                let flags = get_flags(status, len);
                assert_eq!(get_status(flags), status);
                assert_eq!(get_byte_length(flags), len);
            }
        }
    }

    #[test]
    fn get_flags_accepts_up_to_length_max_but_only_low_bits_round_trip() {
        // Matches RelocationDBAdapter.getFlags/getByteLength bit-for-bit: encoding LENGTH_MAX (31)
        // does not panic, but decoding truncates to the mask's 4-bit capacity (15).
        let flags = get_flags(RelocationStatus::Unknown, LENGTH_MAX);
        assert_eq!(get_byte_length(flags), 15);
    }

    #[test]
    #[should_panic(expected = "unsupported byte-length")]
    fn get_flags_rejects_out_of_range_length() {
        get_flags(RelocationStatus::Unknown, LENGTH_MAX + 1);
    }

    #[test]
    fn get_status_falls_back_to_unknown_for_unrecognized_value() {
        // STATUS_FLAGS_MASK is 3 bits wide (0..7); all encodable statuses are 0..6, so a raw flags
        // byte cannot itself produce a value outside the recognized status range here. This test
        // instead exercises the fallback path directly via a flags byte whose status bits happen
        // to decode to a defined status, confirming get_status never panics on any masked value.
        for raw in 0u8..=STATUS_FLAGS_MASK {
            let status = RelocationStatus::from_value(raw as i32);
            assert_eq!(get_status(raw), status.unwrap_or(RelocationStatus::Unknown));
        }
    }

    struct MockRecordIterator {
        records: std::vec::IntoIter<DBRecord>,
    }

    impl RecordIterator for MockRecordIterator {
        fn next(&mut self) -> io::Result<Option<DBRecord>> {
            Ok(self.records.next())
        }

        fn has_next(&self) -> bool {
            self.records.len() > 0
        }
    }

    struct MockRelocationDBAdapter {
        schema: Arc<Schema>,
        records: BTreeMap<i64, DBRecord>,
        next_key: i64,
    }

    impl MockRelocationDBAdapter {
        fn new() -> Self {
            let schema = Arc::new(Schema::new(
                6,
                FieldType::Long,
                "Index".to_string(),
                vec![
                    FieldType::Long,
                    FieldType::Byte,
                    FieldType::Int,
                    FieldType::Binary,
                    FieldType::Binary,
                    FieldType::String,
                ],
                vec![
                    "Address".to_string(),
                    "Status".to_string(),
                    "Type".to_string(),
                    "Values".to_string(),
                    "Bytes".to_string(),
                    "Symbol Name".to_string(),
                ],
                vec![],
            ));
            MockRelocationDBAdapter {
                schema,
                records: BTreeMap::new(),
                next_key: 0,
            }
        }
    }

    impl RelocationDBAdapter for MockRelocationDBAdapter {
        fn add(
            &mut self,
            addr: &Address,
            flags: u8,
            type_: i32,
            values: &[i64],
            bytes: Option<&[u8]>,
            symbol_name: Option<&str>,
        ) -> io::Result<()> {
            let key = self.next_key;
            self.next_key += 1;
            let mut rec = DBRecord::new(self.schema.clone(), Field::Long(Some(key)));
            rec.set_field(ADDR_COL, Field::Long(Some(addr.offset())));
            rec.set_field(FLAGS_COL, Field::Byte(Some(flags as i8)));
            rec.set_field(TYPE_COL, Field::Int(Some(type_)));
            let mut encoded = Vec::with_capacity(values.len() * 8);
            for v in values {
                encoded.extend_from_slice(&v.to_be_bytes());
            }
            rec.set_field(VALUE_COL, Field::Binary(Some(encoded)));
            rec.set_field(BYTES_COL, Field::Binary(bytes.map(|b| b.to_vec())));
            rec.set_field(
                SYMBOL_NAME_COL,
                Field::String(symbol_name.map(|s| s.to_string())),
            );
            self.records.insert(key, rec);
            Ok(())
        }

        fn iterator(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            let records: Vec<DBRecord> = self.records.values().cloned().collect();
            Ok(Box::new(MockRecordIterator {
                records: records.into_iter(),
            }))
        }

        fn iterator_in_set(
            &self,
            set: &dyn AddressSetView,
        ) -> io::Result<Box<dyn RecordIterator + '_>> {
            let records: Vec<DBRecord> = self
                .records
                .values()
                .filter(|rec| {
                    if let Field::Long(Some(addr_offset)) = rec.get_field(ADDR_COL) {
                        set.contains(&addr_for_offset(*addr_offset))
                    } else {
                        false
                    }
                })
                .cloned()
                .collect();
            Ok(Box::new(MockRecordIterator {
                records: records.into_iter(),
            }))
        }

        fn iterator_from(&self, start: &Address) -> io::Result<Box<dyn RecordIterator + '_>> {
            let start_offset = start.offset();
            let records: Vec<DBRecord> = self
                .records
                .values()
                .filter(|rec| matches!(rec.get_field(ADDR_COL), Field::Long(Some(o)) if *o >= start_offset))
                .cloned()
                .collect();
            Ok(Box::new(MockRecordIterator {
                records: records.into_iter(),
            }))
        }

        fn get_record_count(&self) -> i32 {
            self.records.len() as i32
        }

        fn adapt_record(&self, rec: DBRecord) -> DBRecord {
            rec
        }
    }

    fn test_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr_for_offset(offset: i64) -> Address {
        test_space().address(offset)
    }

    #[test]
    fn mock_adapter_is_object_safe_and_tracks_records() {
        let space = test_space();
        let mut adapter: Box<dyn RelocationDBAdapter> = Box::new(MockRelocationDBAdapter::new());

        let addr1 = space.address(0x1000);
        let addr2 = space.address(0x2000);

        assert_eq!(adapter.get_record_count(), 0);

        let flags = get_flags(RelocationStatus::Applied, 0);
        adapter
            .add(&addr1, flags, 5, &[1, 2, 3], Some(&[0xde, 0xad]), Some("main"))
            .unwrap();
        adapter
            .add(&addr2, get_flags(RelocationStatus::Unknown, 4), 0, &[], None, None)
            .unwrap();

        assert_eq!(adapter.get_record_count(), 2);

        let count = {
            let mut it = adapter.iterator().unwrap();
            let mut count = 0;
            while it.next().unwrap().is_some() {
                count += 1;
            }
            count
        };
        assert_eq!(count, 2);

        let from_count = {
            let mut it = adapter.iterator_from(&addr2).unwrap();
            let mut count = 0;
            while it.next().unwrap().is_some() {
                count += 1;
            }
            count
        };
        assert_eq!(from_count, 1);

        let rec = {
            let mut it = adapter.iterator().unwrap();
            it.next().unwrap().unwrap()
        };
        assert_eq!(rec.get_field(TYPE_COL), &Field::Int(Some(5)));
        assert_eq!(
            rec.get_field(SYMBOL_NAME_COL),
            &Field::String(Some("main".to_string()))
        );
        let stored_flags = match rec.get_field(FLAGS_COL) {
            Field::Byte(Some(b)) => *b as u8,
            _ => panic!("expected byte field"),
        };
        assert_eq!(get_status(stored_flags), RelocationStatus::Applied);
        assert_eq!(get_byte_length(stored_flags), 0);
    }

    mod factory {
        use super::*;
        use crate::program::database::reloc::test_support::IdentityAddressMap;
        use crate::util::task::DummyMonitor;

        fn test_space() -> Arc<AddressSpace> {
            AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
        }

        fn addr_map() -> Arc<dyn AddressMap> {
            Arc::new(IdentityAddressMap::new(test_space()))
        }

        fn v1_schema() -> Arc<Schema> {
            Arc::new(Schema::new(
                1,
                FieldType::Long,
                "Address".to_string(),
                vec![FieldType::Int],
                vec!["Type".to_string()],
                vec![],
            ))
        }

        #[test]
        fn create_mode_builds_a_working_v6_adapter() {
            let mut handle = DBHandle::new().unwrap();
            let monitor = DummyMonitor;
            let mut adapter = get_adapter(&mut handle, OpenMode::Create, addr_map(), &monitor).unwrap();
            assert!(matches!(adapter, RelocationAdapterKind::V6(_)));

            adapter.add(&test_space().address(0x10), 0, 3, &[], None, None).unwrap();
            assert_eq!(adapter.get_record_count(), 1);
        }

        #[test]
        fn update_mode_reopens_an_existing_v6_table() {
            let mut handle = DBHandle::new().unwrap();
            let monitor = DummyMonitor;
            {
                let mut adapter =
                    get_adapter(&mut handle, OpenMode::Create, addr_map(), &monitor).unwrap();
                adapter.add(&test_space().address(0x10), 0, 0, &[], None, None).unwrap();
            }
            let reopened = get_adapter(&mut handle, OpenMode::Update, addr_map(), &monitor).unwrap();
            assert_eq!(reopened.get_record_count(), 1);
        }

        #[test]
        fn update_mode_rejects_an_older_schema_without_upgrading() {
            let mut handle = DBHandle::new().unwrap();
            handle.create_table(TABLE_NAME.to_string(), v1_schema()).unwrap();
            let monitor = DummyMonitor;
            let result = get_adapter(&mut handle, OpenMode::Update, addr_map(), &monitor);
            assert!(result.is_err());
        }

        #[test]
        fn upgrade_mode_migrates_a_v1_table_into_v6() {
            let mut handle = DBHandle::new().unwrap();
            let table = handle.create_table(TABLE_NAME.to_string(), v1_schema()).unwrap();
            {
                let mut t = table.write().unwrap();
                let mut rec = DBRecord::new(v1_schema(), Field::Long(Some(0x9000)));
                rec.set_field(0, Field::Int(Some(7)));
                t.put_record(rec).unwrap();
            }
            let monitor = DummyMonitor;
            let mut adapter =
                get_adapter(&mut handle, OpenMode::Upgrade, addr_map(), &monitor).unwrap();
            assert!(matches!(adapter, RelocationAdapterKind::V6(_)));
            assert_eq!(adapter.get_record_count(), 1);

            let rec = {
                let mut it = adapter.iterator().unwrap();
                it.next().unwrap().unwrap()
            };
            assert_eq!(rec.get_field(ADDR_COL), &Field::Long(Some(0x9000)));
            assert_eq!(rec.get_field(TYPE_COL), &Field::Int(Some(7)));
            let flags = match rec.get_field(FLAGS_COL) {
                Field::Byte(Some(b)) => *b as u8,
                _ => panic!("expected byte field"),
            };
            // V1 has no status information -- the schema-level upgrade defaults to UNKNOWN,
            // deferring any real status determination to the higher-level (unported)
            // `preV6DataMigrationUpgrade` -- see the module docs.
            assert_eq!(get_status(flags), RelocationStatus::Unknown);

            // The real table now reflects V6, and the temporary migration table is gone.
            assert_eq!(
                handle.get_table(TABLE_NAME).unwrap().read().unwrap().get_schema().get_version(),
                6
            );

            // A fresh add continues from a key sequence independent of the migrated data.
            adapter.add(&test_space().address(0x9100), 0, 0, &[], None, None).unwrap();
            assert_eq!(adapter.get_record_count(), 2);
        }

        #[test]
        fn read_only_open_mode_returns_old_adapter_without_upgrading_the_table() {
            let mut handle = DBHandle::new().unwrap();
            handle.create_table(TABLE_NAME.to_string(), v1_schema()).unwrap();
            let monitor = DummyMonitor;
            let adapter =
                get_adapter(&mut handle, OpenMode::Immutable, addr_map(), &monitor).unwrap();
            assert!(matches!(adapter, RelocationAdapterKind::V1(_)));
            // The real table on disk is untouched -- still V1, not upgraded to V6.
            assert_eq!(
                handle.get_table(TABLE_NAME).unwrap().read().unwrap().get_schema().get_version(),
                1
            );
        }

        #[test]
        fn encode_decode_binary_coded_longs_round_trip() {
            let values = [0i64, 1, -1, i64::MAX, i64::MIN, 42];
            let encoded = encode_binary_coded_longs(&values);
            assert_eq!(decode_binary_coded_longs(&encoded), values.to_vec());
        }

        #[test]
        fn decode_binary_coded_longs_tolerates_truncated_input() {
            assert_eq!(decode_binary_coded_longs(&[]), Vec::<i64>::new());
            assert_eq!(decode_binary_coded_longs(&[0, 0, 0, 2]), Vec::<i64>::new());
        }
    }
}
