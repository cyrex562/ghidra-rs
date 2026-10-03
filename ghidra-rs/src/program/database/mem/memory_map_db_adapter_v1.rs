//! Port of the class `ghidra.program.database.mem.MemoryMapDBAdapterV1`.
//!
//! In Java, `MemoryMapDBAdapterV1 extends MemoryMapDBAdapterV0` and consists of exactly one
//! constructor (`MemoryMapDBAdapterV1(DBHandle, MemoryMapDB)`), which does nothing but call
//! `super(handle, memMap, VERSION)` with `VERSION = 1` -- no fields, no method overrides. This
//! port mirrors that precisely: [`open`](MemoryMapDBAdapterV1::open) is the entire "class",
//! delegating straight to [`MemoryMapDBAdapterV0::open`] with `expected_version = 1` (the same
//! parameterized constructor Java's V0 base class exposes specifically so V1 can reuse it). There
//! is no separate `MemoryMapDBAdapterV1` struct/trait impl to speak of, exactly as there is no V1
//! state or behavior to speak of in the original -- introducing a wrapper type here would only
//! add an indirection Java's own class hierarchy doesn't have.
//!
//! The only behavioral difference between V0 and V1 tables lives inside
//! [`MemoryMapDBAdapterV0::parse`](crate::program::database::mem::memory_map_db_adapter_v0::MemoryMapDBAdapterV0)'s
//! own `expected_version` handling (whether the "Segment" column is read), matching Java's
//! `expectedVersion == 1` check in the shared constructor.

use std::sync::{Arc, RwLock};

use crate::framework::db::DBHandle;
use crate::program::database::map::AddressMapDB;
use crate::program::database::mem::memory_map_db_adapter_v0::MemoryMapDBAdapterV0;
use crate::program::model::mem::Memory;
use crate::util::exception::VersionException;

/// Schema version. Mirrors `MemoryMapDBAdapterV1.VERSION`.
pub const VERSION: i32 = 1;

/// Opens the legacy "Memory Block" table as schema version 1. Mirrors
/// `MemoryMapDBAdapterV1(DBHandle, MemoryMapDB)`.
///
/// # Errors
/// Returns a [`VersionException`] if the table is missing or its schema version is not 1.
pub fn open(
    handle: Arc<RwLock<DBHandle>>,
    mem_map: Arc<RwLock<dyn Memory>>,
    addr_map: Arc<RwLock<AddressMapDB>>,
) -> Result<Arc<RwLock<MemoryMapDBAdapterV0>>, VersionException> {
    MemoryMapDBAdapterV0::open(handle, mem_map, addr_map, VERSION)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{DBRecord, Field};
    use crate::program::database::mem::memory_map_db_adapter::MemoryMapDBAdapter;
    use crate::program::database::mem::memory_map_db_adapter_v0::{
        self, BLOCK_TYPE_UNINITIALIZED, V0_IS_READ_COL, V0_LENGTH_COL, V0_NAME_COL, V0_START_ADDR_COL, V0_TABLE_NAME,
        V0_TYPE_COL,
    };
    use crate::program::model::address::{Address, AddressFactory, AddressSpace, AddressSpaceType, DefaultAddressFactory};
    use crate::program::model::mem::MemoryAccessException;

    struct StubMemory;
    impl Memory for StubMemory {
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_byte(&self, _addr: &Address) -> Result<u8, MemoryAccessException> {
            Ok(0)
        }
        fn get_bytes(&self, _addr: &Address, dest: &mut [u8]) -> usize {
            dest.len()
        }
        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            Ok(())
        }
    }

    fn test_space() -> Arc<AddressSpace> {
        AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn setup() -> (Arc<RwLock<DBHandle>>, Arc<RwLock<AddressMapDB>>, Arc<RwLock<dyn Memory>>) {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let factory = DefaultAddressFactory::new(vec![test_space()]);
        let addr_map = Arc::new(RwLock::new(AddressMapDB::new(handle.clone(), Arc::new(factory)).unwrap()));
        let mem_map: Arc<RwLock<dyn Memory>> = Arc::new(RwLock::new(StubMemory));
        (handle, addr_map, mem_map)
    }

    /// Builds a real, full 15-column legacy row via V0's own schema (rather than a fake minimal
    /// one), so `MemoryMapDBAdapterV0::parse`'s column reads (up through `V0_SEGMENT_COL`) are all
    /// in bounds -- matching what a real historical database would actually contain.
    fn write_row(handle: &Arc<RwLock<DBHandle>>, addr_map: &Arc<RwLock<AddressMapDB>>, table_version: i32, name: &str, start: i64) {
        let schema = {
            // Same shape as V0's own `v0_schema()`, but with the version this test wants to
            // simulate on disk (0 to prove V1 rejects it, 1 for the happy path).
            let base = memory_map_db_adapter_v0::v0_schema();
            if base.get_version() == table_version {
                base
            } else {
                use crate::framework::db::{FieldType, Schema};
                Arc::new(Schema::new(
                    table_version,
                    FieldType::Long,
                    "Key".to_string(),
                    (0..base.get_field_count()).map(|i| base.get_field_type(i)).collect(),
                    (0..base.get_field_count()).map(|i| base.get_field_name(i).to_string()).collect(),
                    vec![],
                ))
            }
        };
        let table = {
            let mut h = handle.write().unwrap();
            h.get_table(V0_TABLE_NAME).unwrap_or_else(|| h.create_table(V0_TABLE_NAME.to_string(), schema.clone()).unwrap())
        };
        let key = table.write().unwrap().get_next_key();
        let mut rec = DBRecord::new(schema, Field::Long(Some(key)));
        rec.set_string(V0_NAME_COL, Some(name.to_string()));
        rec.set_bool(V0_IS_READ_COL, true);
        let start_addr = Address::new(test_space(), start);
        let start_key = addr_map.read().unwrap().get_key(&start_addr, true);
        rec.set_long(V0_START_ADDR_COL, start_key);
        rec.set_int(V0_LENGTH_COL, 4);
        rec.set_field(V0_TYPE_COL, Field::Short(Some(BLOCK_TYPE_UNINITIALIZED)));
        table.write().unwrap().put_record(rec).unwrap();
    }

    #[test]
    fn open_rejects_a_version_0_table() {
        let (handle, addr_map, mem_map) = setup();
        write_row(&handle, &addr_map, 0, "x", 0x1000);
        let err = open(handle, mem_map, addr_map).err().unwrap();
        assert!(!err.is_upgradable());
    }

    #[test]
    fn open_with_no_table_at_all_reports_version_exception() {
        let (handle, addr_map, mem_map) = setup();
        assert!(open(handle, mem_map, addr_map).is_err());
    }

    #[test]
    fn opened_v1_adapter_parses_blocks_and_is_read_only_like_v0() {
        let (handle, addr_map, mem_map) = setup();
        write_row(&handle, &addr_map, 1, "blk", 0x2000);

        let adapter = open(handle, mem_map, addr_map).unwrap();
        assert_eq!(adapter.read().unwrap().get_memory_blocks().len(), 1);

        let mut a = adapter.write().unwrap();
        assert_eq!(a.delete_sub_block(0).unwrap_err().kind(), std::io::ErrorKind::Unsupported);
    }
}
