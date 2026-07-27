//! Port of `ghidra.program.database.reloc.RelocationDBAdapter`.
//!
//! The Java type is an abstract class whose static factory methods (`getAdapter`,
//! `findReadOnlyAdapter`, `upgrade`) select and migrate between concrete version-specific
//! implementations (`RelocationDBAdapterV1`..`RelocationDBAdapterV6`, `RelocationDBAdapterNoTable`).
//! Those concrete adapters have not been ported yet, so this port only models the abstract
//! instance API each version implements, as an object-safe trait; the version-selection/upgrade
//! logic (and the `preV6DataMigrationUpgrade` migration, which depends on the unported `Program`/
//! `Memory`/`RelocationManager` types) belongs with whichever type ends up owning the concrete
//! adapters. This trait was itself selected as a dependency-cycle cut-point.

use std::io;

use crate::framework::db::{DBRecord, RecordIterator};
use crate::program::model::address::{Address, AddressSetView};
use crate::program::model::reloc::relocation::RelocationStatus;

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
}
