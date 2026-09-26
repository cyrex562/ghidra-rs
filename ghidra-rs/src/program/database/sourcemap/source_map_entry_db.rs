//! Port of `ghidra.program.database.sourcemap.SourceMapEntryDB`.
//!
//! Database-backed implementation of [`SourceMapEntry`]. In Java, the constructor reaches back
//! into the owning `SourceFileManagerDB` for two things: a read lock (pure thread-safety, not
//! needed by this single-threaded construction path) and `manager.getSourceFile(long)`, a
//! package-private helper that resolves the encoded source-file id stored in a record's
//! `FILE_LINE_COL` back to a [`SourceFile`]. `SourceFileManagerDB` in this crate is ported as a
//! trait only (see its module docs), with that private helper deliberately left out as an
//! implementation detail of whichever concrete manager type is added later -- so there is nothing
//! concrete to reach back into yet.
//!
//! Rather than block this port on a concrete `SourceFileManagerDB`, [`SourceMapEntryDB::new`] takes
//! the narrow capability it actually needs -- [`SourceFileLookup`], a small seam trait mapping a
//! source-file id to a [`SourceFile`] -- plus the [`AddressMap`] used to decode the base address.
//! This keeps `SourceMapEntryDB` constructible and testable independent of the not-yet-ported
//! manager, and any future concrete `SourceFileManagerDB` can trivially implement
//! [`SourceFileLookup`] by forwarding to its own source-file cache.

use std::cmp::Ordering;
use std::fmt;

use crate::framework::db::DBRecord;
use crate::program::database::map::AddressMap;
use crate::program::database::sourcemap::source_map_adapter::{BASE_ADDR_COL, FILE_LINE_COL, LENGTH_COL};
use crate::program::database::sourcemap::SourceFile;
use crate::program::model::address::{Address, AddressRange};
use crate::program::model::sourcemap::SourceMapEntry;

/// Resolves a source-file id (as stored, encoded, in a source map record's `FILE_LINE_COL`) back
/// to a [`SourceFile`]. Narrow seam capturing exactly what [`SourceMapEntryDB::new`] needs from the
/// not-yet-ported `SourceFileManagerDB.getSourceFile(long)`/`getSourceFileFromKey(long)`. See the
/// module docs.
pub trait SourceFileLookup {
    /// Returns the [`SourceFile`] registered under `id`, or `None` if there is no such source
    /// file.
    fn get_source_file(&self, id: i64) -> Option<SourceFile>;
}

/// Database implementation of the [`SourceMapEntry`] interface.
///
/// Note: clients should drop and reacquire all `SourceMapEntryDB` objects upon undo/redo and
/// source-map/source-file-removal change events (matches the Java class's own documented caveat).
///
/// Port of `ghidra.program.database.sourcemap.SourceMapEntryDB`. See the module docs for the
/// [`SourceFileLookup`] seam this uses in place of a concrete `SourceFileManagerDB`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceMapEntryDB {
    line_number: i32,
    source_file: SourceFile,
    base_address: Address,
    length: i64,
    range: Option<AddressRange>,
}

impl SourceMapEntryDB {
    /// Creates a new `SourceMapEntryDB` from `record`, resolving its source file via `lookup` and
    /// decoding its base address via `addr_map`.
    ///
    /// # Panics
    ///
    /// Panics if `lookup` has no [`SourceFile`] registered for the id encoded in `record`. This
    /// mirrors real Ghidra's referential-integrity assumption: `SourceFileManagerDB` only ever
    /// creates source map entries for source files it has already registered, so
    /// `manager.getSourceFile(fileAndLine >> 32)` returning `null` here would already indicate
    /// database corruption in Java (the field would just be `null`, deferring the failure to
    /// whatever later code dereferences `getSourceFile()`); panicking immediately surfaces the same
    /// integrity violation instead of deferring it silently.
    pub fn new(lookup: &dyn SourceFileLookup, record: &DBRecord, addr_map: &dyn AddressMap) -> Self {
        let file_and_line = record.get_long(FILE_LINE_COL).unwrap_or(0);
        let line_number = (file_and_line & 0xFFFF_FFFF) as i32;
        let file_id = file_and_line >> 32;
        let source_file = lookup.get_source_file(file_id).unwrap_or_else(|| {
            panic!(
                "SourceMapEntryDB::new: no SourceFile registered for id {file_id} \
                 (referential integrity violated)"
            )
        });

        let encoded_address = record.get_long(BASE_ADDR_COL).unwrap_or(0);
        let base_address = addr_map.decode_address(encoded_address);

        let length = record.get_long(LENGTH_COL).unwrap_or(0);
        let range = if length != 0 {
            let max = base_address
                .add_no_wrap(length - 1)
                .unwrap_or_else(|_| base_address.space().max_address());
            Some(AddressRange::new(base_address.clone(), max))
        } else {
            None
        };

        SourceMapEntryDB {
            line_number,
            source_file,
            base_address,
            length,
            range,
        }
    }
}

impl SourceMapEntry for SourceMapEntryDB {
    fn get_line_number(&self) -> i32 {
        self.line_number
    }

    fn get_source_file(&self) -> SourceFile {
        self.source_file.clone()
    }

    fn get_base_address(&self) -> Address {
        self.base_address.clone()
    }

    fn get_length(&self) -> i64 {
        self.length
    }

    fn get_range(&self) -> Option<AddressRange> {
        self.range.clone()
    }

    fn compare_to(&self, other: &dyn SourceMapEntry) -> Ordering {
        self.source_file
            .cmp(&other.get_source_file())
            .then_with(|| self.line_number.cmp(&other.get_line_number()))
            .then_with(|| self.base_address.cmp(&other.get_base_address()))
            .then_with(|| (self.length as u64).cmp(&(other.get_length() as u64)))
    }
}

impl fmt::Display for SourceMapEntryDB {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} @ {} ({})",
            self.source_file, self.line_number, self.base_address, self.length
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, FieldType, Schema};
    use crate::program::model::address::{AddressFactory, AddressSetView, AddressSpace, AddressSpaceType, KeyRange};
    use std::collections::HashMap;
    use std::sync::Arc;

    struct IdentityAddressMap {
        space: Arc<AddressSpace>,
    }

    impl AddressMap for IdentityAddressMap {
        fn get_key(&self, addr: &Address, _create: bool) -> i64 {
            addr.offset()
        }

        fn get_absolute_encoding(&self, addr: &Address, _create: bool) -> i64 {
            addr.offset()
        }

        fn find_key_range(&self, _key_range_list: &[KeyRange], _addr: Option<&Address>) -> i32 {
            -1
        }

        fn decode_address(&self, value: i64) -> Address {
            self.space.address(value)
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
            Box::new(IdentityAddressMap {
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

    struct MapLookup(HashMap<i64, SourceFile>);

    impl SourceFileLookup for MapLookup {
        fn get_source_file(&self, id: i64) -> Option<SourceFile> {
            self.0.get(&id).cloned()
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr_map() -> IdentityAddressMap {
        IdentityAddressMap { space: ram_space() }
    }

    fn addr(offset: i64) -> Address {
        ram_space().address(offset)
    }

    fn schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "ID".to_string(),
            vec![FieldType::Long, FieldType::Long, FieldType::Long],
            vec!["FileLine".to_string(), "BaseAddr".to_string(), "Length".to_string()],
            vec![],
        ))
    }

    fn make_record(file_id: i64, line: i32, base: i64, length: i64) -> DBRecord {
        let mut rec = DBRecord::new(schema(), Field::Long(Some(1)));
        let file_line = (file_id << 32) | (line as i64 & 0xFFFF_FFFF);
        rec.set_long(FILE_LINE_COL, file_line);
        rec.set_long(BASE_ADDR_COL, base);
        rec.set_long(LENGTH_COL, length);
        rec
    }

    fn lookup_with(id: i64, source_file: SourceFile) -> MapLookup {
        let mut map = HashMap::new();
        map.insert(id, source_file);
        MapLookup(map)
    }

    #[test]
    fn decodes_line_file_address_and_length() {
        let sf = SourceFile::new("/src/main.c").unwrap();
        let lookup = lookup_with(7, sf.clone());
        let rec = make_record(7, 42, 0x1000, 0x10);
        let addr_map = addr_map();

        let entry = SourceMapEntryDB::new(&lookup, &rec, &addr_map);
        assert_eq!(entry.get_line_number(), 42);
        assert_eq!(entry.get_source_file(), sf);
        assert_eq!(entry.get_base_address(), addr(0x1000));
        assert_eq!(entry.get_length(), 0x10);

        let range = entry.get_range().expect("non-zero length has a range");
        assert_eq!(range.min_address(), &addr(0x1000));
        assert_eq!(range.max_address(), &addr(0x100f));
    }

    #[test]
    fn zero_length_entry_has_no_range() {
        let sf = SourceFile::new("/src/main.c").unwrap();
        let lookup = lookup_with(1, sf);
        let rec = make_record(1, 1, 0x2000, 0);
        let addr_map = addr_map();

        let entry = SourceMapEntryDB::new(&lookup, &rec, &addr_map);
        assert_eq!(entry.get_range(), None);
    }

    #[test]
    #[should_panic(expected = "referential integrity violated")]
    fn missing_source_file_panics() {
        let lookup = MapLookup(HashMap::new());
        let rec = make_record(99, 1, 0x1000, 4);
        let addr_map = addr_map();
        let _ = SourceMapEntryDB::new(&lookup, &rec, &addr_map);
    }

    #[test]
    fn compare_to_orders_by_source_file_then_line_then_address_then_length() {
        let sf_a = SourceFile::new("/a.c").unwrap();
        let sf_b = SourceFile::new("/b.c").unwrap();
        let lookup_a = lookup_with(1, sf_a);
        let lookup_b = lookup_with(1, sf_b);
        let addr_map = addr_map();

        let entry_a = SourceMapEntryDB::new(&lookup_a, &make_record(1, 1, 0x1000, 4), &addr_map);
        let entry_b = SourceMapEntryDB::new(&lookup_b, &make_record(1, 1, 0x1000, 4), &addr_map);
        assert_eq!(entry_a.compare_to(&entry_b), Ordering::Less);
        assert_eq!(entry_b.compare_to(&entry_a), Ordering::Greater);

        let sf = SourceFile::new("/same.c").unwrap();
        let lookup = lookup_with(1, sf);
        let low_line = SourceMapEntryDB::new(&lookup, &make_record(1, 1, 0x1000, 4), &addr_map);
        let high_line = SourceMapEntryDB::new(&lookup, &make_record(1, 2, 0x1000, 4), &addr_map);
        assert_eq!(low_line.compare_to(&high_line), Ordering::Less);
    }

    #[test]
    fn to_string_matches_java_format() {
        let sf = SourceFile::new("/src/main.c").unwrap();
        let lookup = lookup_with(1, sf);
        let rec = make_record(1, 10, 0x1000, 4);
        let addr_map = addr_map();
        let entry = SourceMapEntryDB::new(&lookup, &rec, &addr_map);
        assert_eq!(entry.to_string(), format!("/src/main.c:10 @ {} (4)", addr(0x1000)));
    }

    #[test]
    fn equality_and_clone() {
        let sf = SourceFile::new("/src/main.c").unwrap();
        let lookup = lookup_with(1, sf);
        let rec = make_record(1, 10, 0x1000, 4);
        let addr_map = addr_map();
        let entry1 = SourceMapEntryDB::new(&lookup, &rec, &addr_map);
        let entry2 = entry1.clone();
        assert_eq!(entry1, entry2);
    }
}
