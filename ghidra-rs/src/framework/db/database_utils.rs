use super::db_handle::DBHandle;
use super::field::Field;
use super::table::Table;
use std::io;
use std::sync::{Arc, RwLock};

/// A collection of database-related utilities.
///
/// Port of `db.DatabaseUtils`, a non-instantiable (private constructor) static-utility class,
/// following this crate's convention for such classes (see e.g.
/// [`crate::util::math_utilities::MathUtilities`]) of a fieldless unit struct with an `impl`
/// block of associated functions in place of Java `static` methods.
pub struct DatabaseUtils;

impl DatabaseUtils {
    /// Reassign the long key assigned to a contiguous group of records within a table.
    ///
    /// A shift in the key value is computed as the difference of `old_start` and `new_start`.
    /// Existing records whose keys lie within the new range are removed prior to moving the
    /// target set of records.
    ///
    /// Port of `DatabaseUtils.moveRecords(Table, long, long, long)`. Java stages the move through
    /// a temporary, transaction-wrapped [`DBHandle`]; this port keeps the temporary-table staging
    /// (needed for correctness -- see below) but omits the `startTransaction`/`endTransaction`
    /// bookkeeping around it, since this crate's [`DBHandle`]/[`Table`] mutations are not
    /// currently gated by an active transaction (there is no `DBHandle::start_transaction` to
    /// call), making that bookkeeping a no-op here rather than a load-bearing part of the
    /// operation.
    ///
    /// `old_start + size - 1` and `new_start + size - 1` are computed with wrapping arithmetic,
    /// mirroring Java's `long` addition/subtraction, which silently wraps on overflow (no
    /// exception) rather than being checked; the subsequent `< 0` test is exactly Java's own
    /// (imperfect, but faithfully reproduced) overflow heuristic.
    ///
    /// # Errors
    /// Returns an error if `size <= 0`, if the computed end-of-range for either the old or new
    /// key range is negative (Java's `IllegalArgumentException`s, both surfaced here as
    /// [`io::ErrorKind::InvalidInput`]), or if an I/O error occurs while moving records.
    pub fn move_records(
        table: &Arc<RwLock<Table>>,
        old_start: i64,
        new_start: i64,
        size: i64,
    ) -> io::Result<()> {
        if old_start == new_start {
            return Ok(());
        }
        if size <= 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "size must be > 0"));
        }
        let old_end = old_start.wrapping_add(size).wrapping_sub(1);
        let new_end = new_start.wrapping_add(size).wrapping_sub(1);
        if old_end < 0 || new_end < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Illegal range: end range overflow",
            ));
        }

        let table_schema = table.read().unwrap().get_schema();
        let mut tmp = DBHandle::new()?;
        let tmp_table = tmp.create_table("tmp".to_string(), table_schema)?;

        let key_diff = new_start.wrapping_sub(old_start);

        {
            let src = table.read().unwrap();
            let mut it = src.get_record_iterator_at(&Field::Long(Some(old_start)))?;
            let mut dest = tmp_table.write().unwrap();
            while let Some(mut rec) = it.next()? {
                let key = rec.get_key().get_long_value();
                if key > old_end {
                    break;
                }
                rec.set_key(Field::Long(Some(key.wrapping_add(key_diff))));
                dest.put_record(rec)?;
            }
        }

        {
            let mut dest = table.write().unwrap();
            dest.delete_records(old_start, old_end)?;
            dest.delete_records(new_start, new_end)?;
        }

        {
            let src = tmp_table.read().unwrap();
            let mut it = src.get_record_iterator_at(&Field::Long(Some(new_start)))?;
            let mut dest = table.write().unwrap();
            while let Some(rec) = it.next()? {
                let key = rec.get_key().get_long_value();
                if key > new_end {
                    break;
                }
                dest.put_record(rec)?;
            }
        }

        // Java also calls `tmp.close()` here; this port's `DBHandle` has no explicit `close()`
        // (there is nothing to release beyond the in-memory `BufferMgr` this temporary handle
        // owns), so `tmp` is simply dropped at the end of scope.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::field::FieldType;
    use crate::framework::db::record::DBRecord;
    use crate::framework::db::schema::Schema;

    fn make_table() -> Arc<RwLock<Table>> {
        let mut dbh = DBHandle::new().unwrap();
        let schema = Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::String],
            vec!["Name".to_string()],
            vec![],
        ));
        dbh.create_table("T".to_string(), schema).unwrap()
    }

    fn put(table: &Arc<RwLock<Table>>, key: i64, name: &str) {
        let schema = table.read().unwrap().get_schema();
        let mut rec = DBRecord::new(schema, Field::Long(Some(key)));
        rec.set_field(0, Field::String(Some(name.to_string())));
        table.write().unwrap().put_record(rec).unwrap();
    }

    fn name_at(table: &Arc<RwLock<Table>>, key: i64) -> Option<String> {
        table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(key)))
            .unwrap()
            .map(|r| r.get_field(0).get_string_value().unwrap().to_string())
    }

    #[test]
    fn test_move_records_shifts_keys_up() {
        let table = make_table();
        put(&table, 10, "a");
        put(&table, 11, "b");
        put(&table, 12, "c");

        DatabaseUtils::move_records(&table, 10, 100, 3).unwrap();

        assert!(name_at(&table, 10).is_none());
        assert!(name_at(&table, 11).is_none());
        assert!(name_at(&table, 12).is_none());
        assert_eq!(name_at(&table, 100), Some("a".to_string()));
        assert_eq!(name_at(&table, 101), Some("b".to_string()));
        assert_eq!(name_at(&table, 102), Some("c".to_string()));
    }

    #[test]
    fn test_move_records_removes_existing_records_in_destination_range() {
        let table = make_table();
        put(&table, 0, "old-src");
        put(&table, 100, "old-dest");

        DatabaseUtils::move_records(&table, 0, 100, 1).unwrap();

        assert_eq!(name_at(&table, 100), Some("old-src".to_string()));
        assert_eq!(table.read().unwrap().get_record_count(), 1);
    }

    #[test]
    fn test_move_records_same_start_is_noop() {
        let table = make_table();
        put(&table, 5, "unchanged");
        DatabaseUtils::move_records(&table, 5, 5, 1).unwrap();
        assert_eq!(name_at(&table, 5), Some("unchanged".to_string()));
    }

    #[test]
    fn test_move_records_rejects_non_positive_size() {
        let table = make_table();
        let err = DatabaseUtils::move_records(&table, 0, 10, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_move_records_rejects_overflowing_range() {
        let table = make_table();
        let err = DatabaseUtils::move_records(&table, i64::MAX - 1, 0, i64::MAX).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
