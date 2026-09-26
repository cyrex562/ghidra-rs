//! Port of `ghidra.program.database.symbol.EquateRefDB` as a trait (cycle cut-point).
//!
//! The Java class holds a concrete `EquateManager`, calling back into it for the address map,
//! lock, and re-fetching its own record on refresh (`equateMgr.getEquateRefRecord(key)`) --
//! accessors that [`EquateManager`](crate::program::database::symbol::EquateManager)'s own port
//! (itself a cut-point) deliberately left out as `EquateDB`/`EquateRefDB`-only plumbing. This port
//! models the record-backed getters as an object-safe trait extending
//! [`DbObject`](crate::program::database::db_object::DbObject); a concrete implementor supplies
//! the record snapshot and address decoding.
//!
//! Also re-declares the `EquateRefDBAdapter.EQUATE_ID_COL`/`ADDR_COL`/`OP_INDEX_COL`/`HASH_COL`
//! column indices locally, since
//! [`EquateRefDBAdapter`](crate::program::database::symbol::EquateRefDBAdapter)'s own port
//! intentionally left the table-layout constants out.

use std::sync::Arc;

use crate::framework::db::{DBRecord, Field};
use crate::program::database::db_object::DbObject;
use crate::program::model::address::Address;

/// Column index of the referenced equate's ID. Mirrors `EquateRefDBAdapter.EQUATE_ID_COL`.
pub const EQUATE_ID_COL: usize = 0;
/// Column index of the reference's address (database-key encoding). Mirrors
/// `EquateRefDBAdapter.ADDR_COL`.
pub const ADDR_COL: usize = 1;
/// Column index of the reference's operand index. Mirrors `EquateRefDBAdapter.OP_INDEX_COL`.
pub const OP_INDEX_COL: usize = 2;
/// Column index of the reference's dynamic hash value. Mirrors `EquateRefDBAdapter.HASH_COL`.
pub const HASH_COL: usize = 3;

/// Database object for an equate reference.
///
/// Port of `ghidra.program.database.symbol.EquateRefDB`. See the module docs for what was
/// intentionally left out (the owning `EquateManager` callback, and locking).
pub trait EquateRefDb: DbObject {
    /// Accessor for the backing record snapshot. Stands in for the private `EquateRefDB.record`
    /// field; kept current by [`DbObject::refresh`].
    fn record(&self) -> Arc<DBRecord>;

    /// Accessor standing in for `equateMgr.getAddressMap().decodeAddress(long)`, used to decode
    /// this reference's stored address column. Left required since address decoding depends on
    /// program/database state (the owning `EquateManager`'s `AddressMap`) not modeled by this
    /// trait.
    fn decode_address(&self, raw: i64) -> Address;

    /// Stands in for `EquateRefDB.getEquateID()`.
    fn get_equate_id(&self) -> i64 {
        self.refresh_if_needed();
        self.record().get_long(EQUATE_ID_COL).unwrap_or_default()
    }

    /// Stands in for `EquateRefDB.getAddress()` (the `EquateReference.getAddress()` override).
    ///
    /// Simplification: [`EquateReference::address`](crate::program::model::symbol::EquateReference::address)
    /// in this crate returns `&Address` (a reference into stored state), which a default trait
    /// method computing a fresh `Address` cannot satisfy. A concrete implementor wanting to also
    /// implement `EquateReference` should cache this value (e.g. refreshed alongside the record)
    /// and return a reference to the cached copy.
    fn address(&self) -> Address {
        self.refresh_if_needed();
        self.decode_address(self.record().get_long(ADDR_COL).unwrap_or_default())
    }

    /// Stands in for `EquateRefDB.getOpIndex()`.
    fn op_index(&self) -> i16 {
        self.refresh_if_needed();
        match self.record().get_field(OP_INDEX_COL) {
            Field::Short(Some(v)) => *v,
            _ => 0,
        }
    }

    /// Stands in for `EquateRefDB.getDynamicHashValue()`.
    fn dynamic_hash_value(&self) -> i64 {
        self.refresh_if_needed();
        self.record().get_long(HASH_COL).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{FieldType, Schema};
    use crate::program::database::db_object::DbObjectState;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::sync::{Arc, RwLock};

    fn schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Key".to_string(),
            vec![
                FieldType::Long,
                FieldType::Long,
                FieldType::Short,
                FieldType::Long,
            ],
            vec![
                "Equate ID".to_string(),
                "Equate Reference".to_string(),
                "Operand Index".to_string(),
                "Varnode Hash".to_string(),
            ],
            vec![],
        ))
    }

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    struct MockEquateRefDb {
        state: DbObjectState,
        record: RwLock<Arc<DBRecord>>,
    }

    impl MockEquateRefDb {
        fn new(equate_id: i64, addr: i64, op_index: i16, hash: i64) -> Self {
            let mut record = DBRecord::new(schema(), Field::Long(Some(1)));
            record.set_long(EQUATE_ID_COL, equate_id);
            record.set_long(ADDR_COL, addr);
            record.set_field(OP_INDEX_COL, Field::Short(Some(op_index)));
            record.set_long(HASH_COL, hash);
            MockEquateRefDb {
                state: DbObjectState::new(1),
                record: RwLock::new(Arc::new(record)),
            }
        }
    }

    impl DbObject for MockEquateRefDb {
        fn state(&self) -> &DbObjectState {
            &self.state
        }

        fn refresh(&self, record: Option<&DBRecord>) -> bool {
            if let Some(rec) = record {
                *self.record.write().unwrap() = Arc::new(rec.clone());
            }
            true
        }
    }

    impl EquateRefDb for MockEquateRefDb {
        fn record(&self) -> Arc<DBRecord> {
            self.record.read().unwrap().clone()
        }

        fn decode_address(&self, raw: i64) -> Address {
            Address::new(space(), raw)
        }
    }

    #[test]
    fn getters_read_through_to_record_fields() {
        let ref_db = MockEquateRefDb::new(7, 0x1000, 2, 0xdead);

        assert_eq!(ref_db.get_equate_id(), 7);
        assert_eq!(ref_db.address(), Address::new(space(), 0x1000));
        assert_eq!(ref_db.op_index(), 2);
        assert_eq!(ref_db.dynamic_hash_value(), 0xdead);
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let ref_db: Box<dyn EquateRefDb> = Box::new(MockEquateRefDb::new(1, 0x2000, 0, 0));
        assert_eq!(ref_db.get_equate_id(), 1);
        assert_eq!(ref_db.address(), Address::new(space(), 0x2000));
    }
}
