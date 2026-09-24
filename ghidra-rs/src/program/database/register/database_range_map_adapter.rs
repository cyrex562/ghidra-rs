//! Port of `ghidra.program.database.register.DatabaseRangeMapAdapter`.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::util::ErrorHandler;
use crate::framework::db::{DBHandle, Field, FieldType};
use crate::program::database::map::AddressMapDB;
use crate::program::database::util::AddressRangeMapDB;
use crate::program::model::address::{
    Address, AddressRange, AddressRangeIterator, AddressRangeIteratorAdapter,
};
use crate::program::model::lang::register::RegisterRef;
use crate::program::util::{LanguageTranslator, RangeMapAdapter};
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// A [`RangeMapAdapter`] backed by a real database table (via [`AddressRangeMapDB`]).
///
/// Port of `ghidra.program.database.register.DatabaseRangeMapAdapter`.
///
/// Java's constructor additionally takes a `ghidra.util.Lock`, used to guard every mutating
/// `AddressRangeMapDB` call. This port drops it: every mutating method here already requires
/// `&mut self` (see [`RangeMapAdapter`]'s signatures), so Rust's borrow checker already gives the
/// same "no concurrent mutation" guarantee the Java `Lock` existed to enforce at runtime.
pub struct DatabaseRangeMapAdapter {
    map_name: String,
    error_handler: Arc<dyn ErrorHandler>,
    range_map: AddressRangeMapDB,
}

impl DatabaseRangeMapAdapter {
    /// Prefix applied to a register's name to build this adapter's logical map name. Port of
    /// `DatabaseRangeMapAdapter.NAME_PREFIX`.
    pub const NAME_PREFIX: &'static str = "Register_";

    /// Constructs a new adapter for `register`'s values.
    pub fn new(
        register: &RegisterRef,
        db_handle: Arc<RwLock<DBHandle>>,
        addr_map: Arc<RwLock<AddressMapDB>>,
        error_handler: Arc<dyn ErrorHandler>,
    ) -> io::Result<Self> {
        let map_name = format!("{}{}", Self::NAME_PREFIX, register.name());
        let table_name = Self::table_name(&map_name);
        let range_map =
            AddressRangeMapDB::new(db_handle, addr_map, table_name, FieldType::Binary, false)?;
        Ok(Self { map_name, error_handler, range_map })
    }

    fn table_name(map_name: &str) -> String {
        format!("{}{}", AddressRangeMapDB::RANGE_MAP_TABLE_PREFIX, map_name)
    }
}

impl RangeMapAdapter for DatabaseRangeMapAdapter {
    fn get_value(&self, address: &Address) -> Option<Vec<u8>> {
        match self.range_map.get_value(address) {
            Ok(Some(field)) => field.get_binary_data().map(|d| d.to_vec()),
            Ok(None) => None,
            Err(e) => {
                self.error_handler.db_error(e);
                None
            }
        }
    }

    /// Moves every stored value in `[from_addr, from_addr + length - 1]` to the corresponding
    /// offset from `to_addr`.
    ///
    /// Java's `AddressRangeMapDB.moveAddressRange` stages the move through a temporary
    /// `AddressRangeMapDB` on `dbHandle.getScratchPad()` (a second, throwaway `DBHandle`) so a
    /// source/destination overlap can't corrupt data mid-move. This port instead buffers the
    /// collected `(range, value)` pairs in an in-process `Vec` before clearing the source and
    /// repainting the destination -- same non-destructive-staging property, without needing a
    /// scratch-pad `DBHandle` (which this crate's `DBHandle` does not expose).
    fn move_address_range(
        &mut self,
        from_addr: &Address,
        to_addr: &Address,
        length: u64,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        if length == 0 || self.range_map.is_empty() {
            return Ok(());
        }

        let from_end_addr = from_addr
            .add(length as i64 - 1)
            .expect("moveAddressRange: source range end overflowed its address space");

        let ranges = match self.range_map.get_address_ranges(from_addr, &from_end_addr) {
            Ok(r) => r,
            Err(e) => {
                self.error_handler.db_error(e);
                return Ok(());
            }
        };

        let mut collected = Vec::with_capacity(ranges.len());
        for (range, value) in ranges {
            monitor.check_cancelled()?;
            let min_addr = range.min_address().clone();
            let offset = min_addr.subtract(from_addr);
            let new_min = to_addr
                .add(offset)
                .expect("moveAddressRange: destination start overflowed its address space");

            let max_addr = range.max_address().clone();
            let offset = max_addr.subtract(from_addr);
            let new_max = to_addr
                .add(offset)
                .expect("moveAddressRange: destination end overflowed its address space");

            collected.push((new_min, new_max, value));
        }

        if let Err(e) = self.range_map.clear_range(from_addr, &from_end_addr) {
            self.error_handler.db_error(e);
            return Ok(());
        }

        for (min_addr, max_addr, value) in collected {
            monitor.check_cancelled()?;
            let range = AddressRange::new(min_addr, max_addr);
            if let Err(e) = self.range_map.paint(&range, value) {
                self.error_handler.db_error(e);
            }
        }

        Ok(())
    }

    fn set(&mut self, start: &Address, end: &Address, bytes: &[u8]) {
        let range = AddressRange::new(start.clone(), end.clone());
        let field = Field::Binary(Some(bytes.to_vec()));
        if let Err(e) = self.range_map.paint(&range, field) {
            self.error_handler.db_error(e);
        }
    }

    fn get_address_range_iterator_in_range(
        &self,
        start: &Address,
        end: &Address,
    ) -> Box<dyn AddressRangeIterator> {
        match self.range_map.get_address_ranges(start, end) {
            Ok(ranges) => {
                let ranges = ranges.into_iter().map(|(r, _)| r).collect();
                Box::new(AddressRangeIteratorAdapter::new(ranges))
            }
            Err(e) => {
                self.error_handler.db_error(e);
                Box::new(AddressRangeIteratorAdapter::new(Vec::new()))
            }
        }
    }

    fn get_address_range_iterator(&self) -> Box<dyn AddressRangeIterator> {
        match self.range_map.get_all_address_ranges() {
            Ok(ranges) => {
                let ranges = ranges.into_iter().map(|(r, _)| r).collect();
                Box::new(AddressRangeIteratorAdapter::new(ranges))
            }
            Err(e) => {
                self.error_handler.db_error(e);
                Box::new(AddressRangeIteratorAdapter::new(Vec::new()))
            }
        }
    }

    fn clear_range(&mut self, start: &Address, end: &Address) {
        if let Err(e) = self.range_map.clear_range(start, end) {
            self.error_handler.db_error(e);
        }
    }

    fn clear_all(&mut self) {
        if let Err(e) = self.range_map.dispose() {
            self.error_handler.db_error(e);
        }
    }

    fn is_empty(&self) -> bool {
        self.range_map.is_empty()
    }

    /// Update the table name and values to reflect a new base register.
    ///
    /// Ports the "register not translated" (clear everything) and "same base register, no value
    /// translation needed, name unchanged" (no-op) branches of
    /// `DatabaseRangeMapAdapter.setLanguage` faithfully.
    ///
    /// # TODO(port)
    /// Two things are not implemented, and both would be needed together for the remaining
    /// cases (a genuine base-register rename, and/or a value translation):
    ///
    /// 1. **Per-range value translation**: Java rebuilds every stored range by decoding its bytes
    ///    into a `RegisterValue`, translating it via `LanguageTranslator.getNewRegisterValue`,
    ///    and re-encoding the result via `RegisterValue.toBytes()`. This crate has no concrete
    ///    `RegisterValue` -- only the object-safe seam trait `crate::program::seam_stubs::RegisterValue`,
    ///    which exposes neither a bytes constructor nor a serialization method (see the identical
    ///    blocker on [`InMemoryRangeMapAdapter::set_language`](super::in_memory_range_map_adapter::InMemoryRangeMapAdapter)).
    /// 2. **In-place table rename**: Java renames the live database table to
    ///    `NAME_PREFIX + newBaseRegister.getName()` via `AddressRangeMapDB.setName`. This crate's
    ///    [`Table`](crate::framework::db::Table)/[`DBHandle`] expose no rename operation.
    ///
    /// Both cases are left as a no-op: existing values and the table's name are left untouched
    /// rather than guessing at a serialization format or faking a rename that wouldn't actually
    /// relocate the backing table.
    fn set_language(
        &mut self,
        translator: &dyn LanguageTranslator,
        map_reg: &RegisterRef,
        _monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        let Some(new_reg) = translator.get_new_register(map_reg) else {
            // Register not translated - clear map. Java additionally sets `rangeMap = null`
            // here, poisoning the adapter for any further use (`NullPointerException` on the
            // next call); `AddressRangeMapDB::dispose`'s doc comment explains why this port
            // instead leaves a safely-usable, merely-empty map.
            if let Err(e) = self.range_map.dispose() {
                self.error_handler.db_error(e);
            }
            return Ok(());
        };

        let new_base_reg = new_reg.get_base_register();
        let new_map_name = format!("{}{}", Self::NAME_PREFIX, new_base_reg.name());

        let value_translation_required = translator.is_value_translation_required(map_reg);
        if new_reg.is_base_register() && !value_translation_required {
            if self.map_name == new_map_name {
                return Ok(()); // Nothing to change.
            }
            // TODO(port): needs the in-place table rename described above; see item 2.
            return Ok(());
        }

        // TODO(port): needs both the per-range value translation and (if the name also changed)
        // the in-place table rename described above; see items 1 and 2.
        Ok(())
    }

    fn get_value_range_containing(&self, addr: &Address) -> AddressRange {
        match self.range_map.get_address_range_containing(addr) {
            Ok(range) => range,
            Err(e) => {
                self.error_handler.db_error(e);
                AddressRange::new(addr.clone(), addr.clone())
            }
        }
    }

    /// Verify that this adapter is in a writable state.
    ///
    /// # TODO(port)
    /// Java validates `dbHandle.checkTransaction()`, converting a `NoTransactionException` into
    /// `IllegalStateException`. This crate's [`DBHandle`] has no transaction-tracking machinery
    /// yet (`checkTransaction`/`NoTransactionException` are not ported), so there is nothing to
    /// check here; this is always a no-op rather than a faithful "always writable" answer.
    fn check_writable_state(&self) {}

    fn invalidate(&mut self) {
        self.range_map.invalidate();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::util::error_handler::ErrorHandler as ErrorHandlerTrait;
    use crate::program::model::address::{AddressSpace, AddressSpaceType, DefaultAddressFactory};
    use crate::program::model::lang::register::Register;
    use crate::util::task::DummyMonitor;
    use std::sync::Arc;

    struct PanicOnError;
    impl ErrorHandlerTrait for PanicOnError {
        fn db_error(&self, e: io::Error) {
            panic!("unexpected db error: {e}");
        }
    }

    fn test_space() -> Arc<AddressSpace> {
        AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        space.address(offset)
    }

    fn open_adapter(name: &str) -> DatabaseRangeMapAdapter {
        let space = test_space();
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let factory = DefaultAddressFactory::new(vec![space.clone()]);
        let addr_map = Arc::new(RwLock::new(AddressMapDB::new(handle.clone(), Arc::new(factory)).unwrap()));
        let register = Register::new(name.to_string(), String::new(), addr(&space, 0), 4, false, 0);
        DatabaseRangeMapAdapter::new(&register, handle, addr_map, Arc::new(PanicOnError))
            .expect("adapter construction should succeed")
    }

    #[test]
    fn empty_adapter_reports_empty_and_no_value() {
        let space = test_space();
        let adapter = open_adapter("r0");
        assert!(adapter.is_empty());
        assert_eq!(adapter.get_value(&addr(&space, 0x10)), None);
    }

    #[test]
    fn set_get_round_trip_through_trait() {
        let space = test_space();
        let mut adapter: Box<dyn RangeMapAdapter> = Box::new(open_adapter("r0"));

        adapter.set(&addr(&space, 0x1000), &addr(&space, 0x100f), &[1, 2, 3, 4]);
        assert!(!adapter.is_empty());
        assert_eq!(adapter.get_value(&addr(&space, 0x1005)), Some(vec![1, 2, 3, 4]));
        assert_eq!(adapter.get_value(&addr(&space, 0x1010)), None);
    }

    #[test]
    fn overlapping_set_overwrites_only_the_new_range() {
        let space = test_space();
        let mut adapter: Box<dyn RangeMapAdapter> = Box::new(open_adapter("r0"));

        adapter.set(&addr(&space, 0x1000), &addr(&space, 0x2000), &[1]);
        adapter.set(&addr(&space, 0x1500), &addr(&space, 0x1600), &[2]);

        assert_eq!(adapter.get_value(&addr(&space, 0x1000)), Some(vec![1]));
        assert_eq!(adapter.get_value(&addr(&space, 0x1550)), Some(vec![2]));
        assert_eq!(adapter.get_value(&addr(&space, 0x1700)), Some(vec![1]));
    }

    #[test]
    fn clear_range_removes_association() {
        let space = test_space();
        let mut adapter: Box<dyn RangeMapAdapter> = Box::new(open_adapter("r0"));
        adapter.set(&addr(&space, 0x1000), &addr(&space, 0x1010), &[0xAB]);
        adapter.clear_range(&addr(&space, 0x1000), &addr(&space, 0x1010));
        assert!(adapter.is_empty());
        assert_eq!(adapter.get_value(&addr(&space, 0x1005)), None);
    }

    #[test]
    fn clear_all_empties_the_map() {
        let space = test_space();
        let mut adapter: Box<dyn RangeMapAdapter> = Box::new(open_adapter("r0"));
        adapter.set(&addr(&space, 0x1000), &addr(&space, 0x1010), &[0xAB]);
        adapter.clear_all();
        assert!(adapter.is_empty());
        assert_eq!(adapter.get_value(&addr(&space, 0x1005)), None);
    }

    #[test]
    fn move_address_range_relocates_bytes() {
        let space = test_space();
        let mut adapter: Box<dyn RangeMapAdapter> = Box::new(open_adapter("r0"));
        adapter.set(&addr(&space, 0x1000), &addr(&space, 0x100f), &[9, 9]);
        let monitor = DummyMonitor;
        adapter
            .move_address_range(&addr(&space, 0x1000), &addr(&space, 0x2000), 0x10, &monitor)
            .expect("move should succeed");
        assert_eq!(adapter.get_value(&addr(&space, 0x1000)), None);
        assert_eq!(adapter.get_value(&addr(&space, 0x2000)), Some(vec![9, 9]));
    }

    #[test]
    fn get_address_range_iterator_returns_all_stored_ranges() {
        let space = test_space();
        let mut adapter: Box<dyn RangeMapAdapter> = Box::new(open_adapter("r0"));
        adapter.set(&addr(&space, 0x1000), &addr(&space, 0x1010), &[1]);
        adapter.set(&addr(&space, 0x2000), &addr(&space, 0x2010), &[2]);

        let ranges: Vec<AddressRange> = adapter.get_address_range_iterator().collect();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].min_address(), &addr(&space, 0x1000));
        assert_eq!(ranges[1].min_address(), &addr(&space, 0x2000));
    }

    #[test]
    fn get_address_range_iterator_in_range_clips_to_the_window() {
        let space = test_space();
        let mut adapter: Box<dyn RangeMapAdapter> = Box::new(open_adapter("r0"));
        adapter.set(&addr(&space, 0x1000), &addr(&space, 0x2000), &[1]);

        let ranges: Vec<AddressRange> =
            adapter.get_address_range_iterator_in_range(&addr(&space, 0x1500), &addr(&space, 0x1800)).collect();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].min_address(), &addr(&space, 0x1500));
        assert_eq!(ranges[0].max_address(), &addr(&space, 0x1800));
    }

    #[test]
    fn get_value_range_containing_returns_stored_range_or_gap() {
        let space = test_space();
        let mut adapter: Box<dyn RangeMapAdapter> = Box::new(open_adapter("r0"));
        adapter.set(&addr(&space, 0x1000), &addr(&space, 0x2000), &[1]);
        adapter.set(&addr(&space, 0x3000), &addr(&space, 0x4000), &[2]);

        let value_range = adapter.get_value_range_containing(&addr(&space, 0x1500));
        assert_eq!(value_range.min_address(), &addr(&space, 0x1000));
        assert_eq!(value_range.max_address(), &addr(&space, 0x2000));

        let gap_range = adapter.get_value_range_containing(&addr(&space, 0x2500));
        assert_eq!(gap_range.min_address(), &addr(&space, 0x2001));
        assert_eq!(gap_range.max_address(), &addr(&space, 0x2fff));
    }

    #[test]
    fn check_writable_state_never_panics() {
        let adapter: Box<dyn RangeMapAdapter> = Box::new(open_adapter("r0"));
        adapter.check_writable_state();
    }

    #[test]
    fn invalidate_does_not_lose_data() {
        let space = test_space();
        let mut adapter: Box<dyn RangeMapAdapter> = Box::new(open_adapter("r0"));
        adapter.set(&addr(&space, 0x1000), &addr(&space, 0x1010), &[0x42]);
        adapter.invalidate();
        assert_eq!(adapter.get_value(&addr(&space, 0x1005)), Some(vec![0x42]));
    }

}
