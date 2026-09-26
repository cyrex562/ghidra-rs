use crate::framework::db::record::DBRecord;
use crate::framework::db::{DBHandle, Field, FieldType, Schema, Table};
use crate::program::database::map::AddressMapDB;
use crate::program::model::address::{Address, AddressRange, AddressSet};
use std::io;
use std::sync::{Arc, RwLock};

pub struct AddressRangeMapDB {
    /// Kept for structural parity with Java's `AddressRangeMapDB.dbHandle` (and in case a future
    /// method needs it, e.g. a real table-rename); every current method reaches its data purely
    /// through `table`, so this is otherwise unread.
    _db_handle: Arc<RwLock<DBHandle>>,
    addr_map: Arc<RwLock<AddressMapDB>>,
    table: Arc<RwLock<Table>>,
}

impl AddressRangeMapDB {
    pub const TO_COL: usize = 0;
    pub const VALUE_COL: usize = 1;

    /// Prefix applied to every range-map table's name, so range-map tables share a recognizable
    /// namespace and can be probed for existence via [`Self::exists`]. Port of
    /// `AddressRangeMapDB.RANGE_MAP_TABLE_PREFIX`.
    ///
    /// Unlike the Java class (whose constructor takes a bare `name` and internally prepends this
    /// prefix to build `tableName`), this port's [`Self::new`] takes the already-fully-formed
    /// table name -- callers that want the Java naming convention apply the prefix themselves
    /// (see [`crate::program::database::register::DatabaseRangeMapAdapter`]).
    pub const RANGE_MAP_TABLE_PREFIX: &'static str = "Range Map - ";

    pub fn new(
        db_handle: Arc<RwLock<DBHandle>>,
        addr_map: Arc<RwLock<AddressMapDB>>,
        table_name: String,
        value_type: FieldType,
        indexed: bool,
    ) -> io::Result<Self> {
        let schema = Schema::new(
            0,
            FieldType::Long, // Key is start address key
            "Start".to_string(),
            vec![
                FieldType::Long, // End address key
                value_type,      // Value
            ],
            vec!["End".to_string(), "Value".to_string()],
            if indexed { vec![1] } else { vec![] },
        );

        let table = {
            let mut handle = db_handle.write().unwrap();
            handle.create_table(table_name, Arc::new(schema))?
        };

        Ok(Self {
            _db_handle: db_handle,
            addr_map,
            table,
        })
    }

    /// Returns true if a range-map table named `name` already exists in `db_handle`. Port of
    /// `AddressRangeMapDB.exists(DBHandle, String)`. As with [`Self::new`], `name` here is the
    /// already-fully-formed table name (callers apply [`Self::RANGE_MAP_TABLE_PREFIX`]
    /// themselves if they want it).
    pub fn exists(db_handle: &Arc<RwLock<DBHandle>>, name: &str) -> bool {
        db_handle.read().unwrap().get_table(name).is_some()
    }

    /// Returns true if this map has no stored ranges. Port of `AddressRangeMapDB.isEmpty()`.
    pub fn is_empty(&self) -> bool {
        self.table.read().unwrap().get_record_count() == 0
    }

    /// Deletes every stored range. Port of `AddressRangeMapDB.dispose()`.
    ///
    /// Java's `dispose()` deletes the underlying `Table` from its `DBHandle` and nulls out its
    /// own `rangeMapTable` field, leaving the `AddressRangeMapDB` object itself in a state where
    /// any further use throws `NullPointerException` (real Ghidra only ever calls `dispose()`
    /// right before discarding the whole map, except for `DatabaseRangeMapAdapter.clearAll()`,
    /// which calls it and keeps using the same `AddressRangeMapDB` -- relying on the *next*
    /// `paintRange` call to lazily recreate the table via `findTable`/`createTable`).
    ///
    /// This port's `AddressRangeMapDB` has no such lazy-recreate machinery, and deleting the
    /// table from `db_handle`'s registry would not even empty it: `self.table` is a cloned `Arc`
    /// that stays fully live and readable/writable in memory regardless of whether `db_handle`
    /// still knows its name, so a delete-from-registry implementation would silently leave old
    /// records readable while merely detaching the name -- a real correctness bug, not a faithful
    /// reproduction of anything Java does. Clearing the live table's own records in place is both
    /// simpler and actually empties the map, matching every caller's *observable* expectation
    /// (`clearAll()`/[`RangeMapAdapter`](crate::program::util::RangeMapAdapter)'s
    /// "clears all values") without needing an `Option<Table>` + relazy-create dance.
    pub fn dispose(&mut self) -> io::Result<()> {
        self.table.write().unwrap().clear_all()
    }

    /// Notification that something may have changed (undo/redo) and cached state should be
    /// invalidated. Port of `AddressRangeMapDB.invalidate()`.
    ///
    /// A no-op here: unlike Java's `AddressRangeMapDB`, this implementation keeps no internal
    /// `lastValue`-style cache (every query does a fresh table scan), so there is nothing to
    /// invalidate. Kept for API parity with the Java class and [`RangeMapAdapter`](crate::program::util::RangeMapAdapter)'s
    /// `invalidate()`.
    pub fn invalidate(&mut self) {}

    /// Associates `value` with every address in `range`, overwriting whatever value (if any) was
    /// previously associated with any address in that range.
    ///
    /// Stands in for `AddressRangeMapDB.paintRange(Address, Address, Field)`.
    pub fn paint(&mut self, range: &AddressRange, value: Field) -> io::Result<()> {
        self.clear_range(range.min_address(), range.max_address())?;

        let mut table = self.table.write().unwrap();
        let addr_map = self.addr_map.read().unwrap();

        let start_key = addr_map.get_key(range.min_address(), true);
        let end_key = addr_map.get_key(range.max_address(), true);

        let mut rec = DBRecord::new(table.get_schema(), Field::Long(Some(start_key)));
        rec.set_long(Self::TO_COL, end_key);
        rec.set_field(Self::VALUE_COL, value);

        table.put_record(rec)?;
        Ok(())
    }

    pub fn get_value(&self, addr: &Address) -> io::Result<Option<Field>> {
        let table = self.table.read().unwrap();
        let addr_map = self.addr_map.read().unwrap();
        let key = addr_map.get_key(addr, false);

        let mut it = table.get_record_iterator()?;
        while let Some(rec) = it.next()? {
            let start = rec.get_key().get_long_value();
            let end = rec.get_long(Self::TO_COL).unwrap();
            if key >= start && key <= end {
                return Ok(Some(rec.get_field(Self::VALUE_COL).clone()));
            }
        }

        Ok(None)
    }

    /// Removes any value associations for every address in `[start, end]`. Stored ranges that
    /// only partially overlap `[start, end]` are trimmed rather than dropped entirely, keeping
    /// their surviving fragment(s) mapped to the original value.
    ///
    /// Stands in for `AddressRangeMapDB.clearRange(Address, Address)`.
    pub fn clear_range(&mut self, start: &Address, end: &Address) -> io::Result<()> {
        let mut table = self.table.write().unwrap();
        let addr_map = self.addr_map.read().unwrap();

        let qs = addr_map.get_key(start, true);
        let qe = addr_map.get_key(end, true);

        let mut to_delete: Vec<Field> = Vec::new();
        let mut to_insert: Vec<(i64, i64, Field)> = Vec::new();

        {
            let mut it = table.get_record_iterator()?;
            while let Some(rec) = it.next()? {
                let rec_start = rec.get_key().get_long_value();
                let rec_end = rec.get_long(Self::TO_COL).unwrap();
                if rec_end < qs || rec_start > qe {
                    continue; // no overlap
                }
                to_delete.push(rec.get_key().clone());
                let value = rec.get_field(Self::VALUE_COL).clone();
                if rec_start < qs {
                    to_insert.push((rec_start, qs - 1, value.clone()));
                }
                if rec_end > qe {
                    to_insert.push((qe + 1, rec_end, value));
                }
            }
        }

        for key in to_delete {
            table.delete_record(&key)?;
        }
        for (start_key, end_key, value) in to_insert {
            let mut rec = DBRecord::new(table.get_schema(), Field::Long(Some(start_key)));
            rec.set_long(Self::TO_COL, end_key);
            rec.set_field(Self::VALUE_COL, value);
            table.put_record(rec)?;
        }

        Ok(())
    }

    /// Returns every stored `(range, value)` pair, in ascending address order.
    ///
    /// Stands in for the no-argument `AddressRangeMapDB.getAddressRanges()`.
    pub fn get_all_address_ranges(&self) -> io::Result<Vec<(AddressRange, Field)>> {
        let table = self.table.read().unwrap();
        let addr_map = self.addr_map.read().unwrap();

        let mut results = Vec::new();
        let mut it = table.get_record_iterator()?;
        while let Some(rec) = it.next()? {
            let rec_start = rec.get_key().get_long_value();
            let rec_end = rec.get_long(Self::TO_COL).unwrap();
            let value = rec.get_field(Self::VALUE_COL).clone();
            let range =
                AddressRange::new(addr_map.decode_address(rec_start), addr_map.decode_address(rec_end));
            results.push((range, value));
        }
        results.sort_by_key(|(range, _)| range.min_address().clone());
        Ok(results)
    }

    /// Returns the stored `(range, value)` pairs whose ranges overlap `[start, end]`, clipped to
    /// that window, in ascending address order.
    ///
    /// Stands in for `AddressRangeMapDB.getAddressRanges(Address, Address)`.
    pub fn get_address_ranges(
        &self,
        start: &Address,
        end: &Address,
    ) -> io::Result<Vec<(AddressRange, Field)>> {
        let table = self.table.read().unwrap();
        let addr_map = self.addr_map.read().unwrap();

        let qs = addr_map.get_key(start, true);
        let qe = addr_map.get_key(end, true);

        let mut results = Vec::new();
        let mut it = table.get_record_iterator()?;
        while let Some(rec) = it.next()? {
            let rec_start = rec.get_key().get_long_value();
            let rec_end = rec.get_long(Self::TO_COL).unwrap();
            if rec_end < qs || rec_start > qe {
                continue;
            }
            let clipped_start = rec_start.max(qs);
            let clipped_end = rec_end.min(qe);
            let value = rec.get_field(Self::VALUE_COL).clone();
            let range = AddressRange::new(
                addr_map.decode_address(clipped_start),
                addr_map.decode_address(clipped_end),
            );
            results.push((range, value));
        }
        results.sort_by_key(|(range, _)| range.min_address().clone());
        Ok(results)
    }

    /// Returns the set of every address mapped to `value`.
    ///
    /// Stands in for `AddressRangeMapDB.getAddressSet(Field)`.
    pub fn get_address_set(&self, value: &Field) -> io::Result<AddressSet> {
        let table = self.table.read().unwrap();
        let addr_map = self.addr_map.read().unwrap();

        let mut set = AddressSet::new();
        let mut it = table.get_record_iterator()?;
        while let Some(rec) = it.next()? {
            if rec.get_field(Self::VALUE_COL) != value {
                continue;
            }
            let rec_start = rec.get_key().get_long_value();
            let rec_end = rec.get_long(Self::TO_COL).unwrap();
            set.add_range(
                &addr_map.decode_address(rec_start),
                &addr_map.decode_address(rec_end),
            );
        }
        Ok(set)
    }

    /// Returns the bounding address range containing `address` that has a single, consistent
    /// "state": either the stored value-range that covers it, or (if `address` has no stored
    /// value) the maximal gap between whichever stored ranges border it -- clamped to `address`'s
    /// own address space, and never crossing into a range that belongs to a different space.
    ///
    /// Stands in for `AddressRangeMapDB.getAddressRangeContaining(Address)`. Implemented as a
    /// full-table scan (like every other method in this file) rather than the Java class's
    /// B-tree cursor lookups (`getRecordBefore`/`getRecordAfter`), since this port's [`Table`]
    /// has no such "nearest key" cursor API yet.
    pub fn get_address_range_containing(&self, address: &Address) -> io::Result<AddressRange> {
        let table = self.table.read().unwrap();
        let addr_map = self.addr_map.read().unwrap();

        let key = addr_map.get_key(address, false);
        let space_id = address.space().space_id() as i64;

        let mut closest_before_end: Option<i64> = None;
        let mut closest_after_start: Option<i64> = None;

        let mut it = table.get_record_iterator()?;
        while let Some(rec) = it.next()? {
            let rec_start = rec.get_key().get_long_value();
            let rec_end = rec.get_long(Self::TO_COL).unwrap();
            if key >= rec_start && key <= rec_end {
                return Ok(AddressRange::new(
                    addr_map.decode_address(rec_start),
                    addr_map.decode_address(rec_end),
                ));
            }
            // A stored range never spans address spaces (both endpoints share the space encoded
            // in `rec_start`'s upper bits), so this one check is enough to skip ranges that
            // belong to a different space entirely -- they must never influence `address`'s gap
            // boundaries.
            if (rec_start >> 48) != space_id {
                continue;
            }
            if rec_end < key {
                closest_before_end = Some(closest_before_end.map_or(rec_end, |v| v.max(rec_end)));
            }
            if rec_start > key {
                closest_after_start = Some(closest_after_start.map_or(rec_start, |v| v.min(rec_start)));
            }
        }

        let min = match closest_before_end {
            Some(v) => addr_map.decode_address(v + 1),
            None => address.space().min_address(),
        };
        let max = match closest_after_start {
            Some(v) => addr_map.decode_address(v - 1),
            None => address.space().max_address(),
        };
        Ok(AddressRange::new(min, max))
    }
}
