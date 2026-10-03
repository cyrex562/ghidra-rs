//! Port of `ghidra.program.database.data.CallingConventionDBAdapterV0`.
//!
//! Version 0 (current, and so far only live-writable) implementation for the Calling
//! Conventions table adapter, backed by a live, writable [`Table`] keyed by a single `Byte`
//! column (the calling convention ID itself; the table's only data column is the convention's
//! `Name`).
//!
//! Newly assigned convention IDs are handed out from a free-key set spanning
//! [`FIRST_CALLING_CONVENTION_ID`]..=127 (`i8::MAX`, matching Java's `Byte.MAX_VALUE`), tracked
//! as a small sorted list of disjoint closed ranges (standing in for Java's Guava
//! `TreeRangeSet<Byte>`). Since there is currently no way to remove an allocated calling
//! convention, ranges only ever shrink from the low end; the range-set machinery exists to
//! correctly resume allocation after gaps (e.g. IDs allocated `2, 3, 5` should offer `4` next,
//! not `6`), matching Java's comment about "sequential until delete is added".
//!
//! Both the name/ID caches and the free-key set are lazily populated on first use and cleared by
//! [`invalidate_cache`](CallingConventionDBAdapter::invalidate_cache), matching Java's
//! `populateCache`/`invalidateCache`. Since [`CallingConventionDBAdapter::get_calling_convention_name`]
//! and [`get_calling_convention_names`](CallingConventionDBAdapter::get_calling_convention_names)
//! take `&self` but populating the cache mutates it, the cache is held behind a `RefCell`.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, Schema, Table};
use crate::program::database::data::calling_convention_db_adapter::{
    CallingConventionDBAdapter, CALLING_CONVENTION_TABLE_NAME, DEFAULT_CALLING_CONVENTION_ID,
    FIRST_CALLING_CONVENTION_ID, UNKNOWN_CALLING_CONVENTION_ID,
};
use crate::program::model::lang::compiler_spec::{
    is_unknown_calling_convention, CALLING_CONVENTION_DEFAULT,
};
use crate::program::model::listing::function::DEFAULT_CALLING_CONVENTION_STRING;
use crate::util::exception::VersionException;

/// Column index of the calling convention's name, as defined by `CallingConventionDBAdapterV0`.
const V0_CALLING_CONVENTION_NAME_COL: usize = 0;

/// Largest usable calling convention ID (matches Java's `Byte.MAX_VALUE`).
const MAX_CALLING_CONVENTION_ID: u8 = i8::MAX as u8;

fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        0,
        FieldType::Byte,
        "ID".to_string(),
        vec![FieldType::String],
        vec!["Name".to_string()],
        vec![],
    ))
}

/// A small set of disjoint, sorted, closed `u8` ranges standing in for Java's Guava
/// `TreeRangeSet<Byte>`. Supports only what this adapter needs: appending ranges in ascending
/// order and removing the lowest available single value.
#[derive(Default)]
struct FreeKeySet {
    /// Sorted, disjoint, non-adjacent closed ranges `(lo, hi)`, `lo <= hi`.
    ranges: Vec<(u8, u8)>,
}

impl FreeKeySet {
    fn add_range(&mut self, lo: u8, hi: u8) {
        if lo <= hi {
            self.ranges.push((lo, hi));
        }
    }

    /// Removes and returns the lowest available key, splitting its range if it has more than
    /// one value left. Returns `None` if no keys remain (allocation capacity exhausted).
    fn remove_first_available(&mut self) -> Option<u8> {
        if self.ranges.is_empty() {
            return None;
        }
        let (lo, hi) = self.ranges.remove(0);
        if lo != hi {
            self.ranges.insert(0, (lo + 1, hi));
        }
        Some(lo)
    }
}

struct Cache {
    name_to_id: HashMap<String, u8>,
    id_to_name: HashMap<u8, String>,
    free_keys: FreeKeySet,
}

/// Version 0 implementation for the calling conventions tables adapter.
///
/// Port of `ghidra.program.database.data.CallingConventionDBAdapterV0`.
pub struct CallingConventionDBAdapterV0 {
    table: Arc<RwLock<Table>>,
    cache: RefCell<Option<Cache>>,
}

impl CallingConventionDBAdapterV0 {
    /// Schema version implemented by this adapter.
    pub const VERSION: i32 = 0;

    /// Gets a version 0 adapter for the calling convention database table.
    ///
    /// `table_prefix` is the prefix to be used with the default table name; if `create` is
    /// `true`, the table is created, otherwise an existing table is opened.
    pub fn new(
        handle: &mut DBHandle,
        table_prefix: &str,
        create: bool,
    ) -> Result<Self, VersionException> {
        let table_name = format!("{table_prefix}{CALLING_CONVENTION_TABLE_NAME}");
        let table = if create {
            handle
                .create_table(table_name, schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?
        } else {
            let table = handle
                .get_table(&table_name)
                .ok_or_else(|| VersionException::with_upgradeable(true))?;
            let version = table.read().unwrap().get_schema().get_version();
            if version != Self::VERSION {
                return Err(VersionException::with_upgradeable(false));
            }
            table
        };
        Ok(CallingConventionDBAdapterV0 {
            table,
            cache: RefCell::new(None),
        })
    }

    /// Populates the name/ID caches and free-key set from the table's current contents, if not
    /// already populated.
    fn populate_cache(&self) -> io::Result<()> {
        if self.cache.borrow().is_some() {
            return Ok(());
        }
        let mut name_to_id = HashMap::new();
        let mut id_to_name = HashMap::new();
        let mut free_keys = FreeKeySet::default();

        let mut next_key: u16 = FIRST_CALLING_CONVENTION_ID as u16;
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            let id = match rec.get_key() {
                Field::Byte(Some(v)) => *v as u8,
                _ => continue,
            };
            let name = match rec.get_field(V0_CALLING_CONVENTION_NAME_COL) {
                Field::String(Some(s)) => s.clone(),
                _ => String::new(),
            };
            id_to_name.insert(id, name.clone());
            name_to_id.insert(name, id);

            if next_key != id as u16 {
                free_keys.add_range(next_key as u8, id.wrapping_sub(1));
            }
            next_key = id as u16 + 1;
        }
        if next_key <= MAX_CALLING_CONVENTION_ID as u16 {
            free_keys.add_range(next_key as u8, MAX_CALLING_CONVENTION_ID);
        }

        *self.cache.borrow_mut() = Some(Cache {
            name_to_id,
            id_to_name,
            free_keys,
        });
        Ok(())
    }
}

impl CallingConventionDBAdapter for CallingConventionDBAdapterV0 {
    fn get_calling_convention_id(
        &mut self,
        name: Option<&str>,
        convention_added: &mut dyn FnMut(&str),
    ) -> io::Result<u8> {
        if is_unknown_calling_convention(name) {
            return Ok(UNKNOWN_CALLING_CONVENTION_ID);
        }
        let name = name.unwrap();
        if name == CALLING_CONVENTION_DEFAULT {
            return Ok(DEFAULT_CALLING_CONVENTION_ID);
        }
        self.populate_cache()?;

        if let Some(&id) = self.cache.borrow().as_ref().unwrap().name_to_id.get(name) {
            return Ok(id);
        }

        let new_id = {
            let mut cache_ref = self.cache.borrow_mut();
            let cache = cache_ref.as_mut().unwrap();
            cache.free_keys.remove_first_available()
        };
        let Some(new_id) = new_id else {
            // Allocation capacity exceeded; matches Java's `Msg.error(...)` + fallback to the
            // unknown convention ID (logging omitted -- no `Msg` seam threaded through this
            // module).
            return Ok(UNKNOWN_CALLING_CONVENTION_ID);
        };

        let mut record = DBRecord::new(schema(), Field::Byte(Some(new_id as i8)));
        record.set_field(
            V0_CALLING_CONVENTION_NAME_COL,
            Field::String(Some(name.to_string())),
        );
        self.table.write().unwrap().put_record(record)?;

        let mut cache_ref = self.cache.borrow_mut();
        let cache = cache_ref.as_mut().unwrap();
        cache.id_to_name.insert(new_id, name.to_string());
        cache.name_to_id.insert(name.to_string(), new_id);
        drop(cache_ref);

        convention_added(name);
        Ok(new_id)
    }

    fn get_calling_convention_name(&self, id: u8) -> io::Result<Option<String>> {
        if id == DEFAULT_CALLING_CONVENTION_ID {
            return Ok(Some(DEFAULT_CALLING_CONVENTION_STRING.to_string()));
        }
        if id == UNKNOWN_CALLING_CONVENTION_ID {
            return Ok(None);
        }
        self.populate_cache()?;
        Ok(self
            .cache
            .borrow()
            .as_ref()
            .unwrap()
            .id_to_name
            .get(&id)
            .cloned())
    }

    fn invalidate_cache(&mut self) {
        *self.cache.borrow_mut() = None;
    }

    fn get_calling_convention_names(&self) -> io::Result<HashSet<String>> {
        self.populate_cache()?;
        Ok(self
            .cache
            .borrow()
            .as_ref()
            .unwrap()
            .name_to_id
            .keys()
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_and_default_names_short_circuit_without_populating_table() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = CallingConventionDBAdapterV0::new(&mut handle, "", true).unwrap();

        assert_eq!(
            adapter
                .get_calling_convention_id(None, &mut |_| panic!("should not be called"))
                .unwrap(),
            UNKNOWN_CALLING_CONVENTION_ID
        );
        assert_eq!(
            adapter
                .get_calling_convention_id(Some(""), &mut |_| panic!("should not be called"))
                .unwrap(),
            UNKNOWN_CALLING_CONVENTION_ID
        );
        assert_eq!(
            adapter
                .get_calling_convention_id(Some("default"), &mut |_| {
                    panic!("should not be called")
                })
                .unwrap(),
            DEFAULT_CALLING_CONVENTION_ID
        );
    }

    #[test]
    fn assigns_sequential_ids_and_calls_back_on_new_conventions() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = CallingConventionDBAdapterV0::new(&mut handle, "", true).unwrap();

        let mut added = Vec::new();
        let id1 = adapter
            .get_calling_convention_id(Some("__stdcall"), &mut |n| added.push(n.to_string()))
            .unwrap();
        let id2 = adapter
            .get_calling_convention_id(Some("__cdecl"), &mut |n| added.push(n.to_string()))
            .unwrap();

        assert_eq!(id1, FIRST_CALLING_CONVENTION_ID);
        assert_eq!(id2, FIRST_CALLING_CONVENTION_ID + 1);
        assert_eq!(added, vec!["__stdcall", "__cdecl"]);

        // Re-requesting the same name returns the same ID and does not call back again.
        let mut called_again = false;
        let id1_again = adapter
            .get_calling_convention_id(Some("__stdcall"), &mut |_| called_again = true)
            .unwrap();
        assert_eq!(id1_again, id1);
        assert!(!called_again);
    }

    #[test]
    fn get_calling_convention_name_round_trips() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = CallingConventionDBAdapterV0::new(&mut handle, "", true).unwrap();
        let id = adapter
            .get_calling_convention_id(Some("__stdcall"), &mut |_| {})
            .unwrap();

        assert_eq!(
            adapter.get_calling_convention_name(id).unwrap(),
            Some("__stdcall".to_string())
        );
        assert_eq!(
            adapter.get_calling_convention_name(DEFAULT_CALLING_CONVENTION_ID).unwrap(),
            Some(DEFAULT_CALLING_CONVENTION_STRING.to_string())
        );
        assert_eq!(
            adapter
                .get_calling_convention_name(UNKNOWN_CALLING_CONVENTION_ID)
                .unwrap(),
            None
        );
        assert_eq!(adapter.get_calling_convention_name(120).unwrap(), None);
    }

    #[test]
    fn get_calling_convention_names_excludes_default_and_unknown() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = CallingConventionDBAdapterV0::new(&mut handle, "", true).unwrap();
        adapter
            .get_calling_convention_id(Some("__stdcall"), &mut |_| {})
            .unwrap();
        adapter
            .get_calling_convention_id(Some("__cdecl"), &mut |_| {})
            .unwrap();
        // These should not appear as stored names.
        adapter
            .get_calling_convention_id(Some("default"), &mut |_| {})
            .unwrap();
        adapter
            .get_calling_convention_id(None, &mut |_| {})
            .unwrap();

        let names = adapter.get_calling_convention_names().unwrap();
        assert_eq!(
            names,
            HashSet::from(["__stdcall".to_string(), "__cdecl".to_string()])
        );
    }

    #[test]
    fn invalidate_cache_forces_repopulation() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = CallingConventionDBAdapterV0::new(&mut handle, "", true).unwrap();
        adapter
            .get_calling_convention_id(Some("__stdcall"), &mut |_| {})
            .unwrap();
        adapter.invalidate_cache();
        assert!(adapter.cache.borrow().is_none());

        // Still works correctly after invalidation.
        assert_eq!(
            adapter.get_calling_convention_names().unwrap(),
            HashSet::from(["__stdcall".to_string()])
        );
    }

    #[test]
    fn opening_an_existing_table_resumes_allocation_after_the_highest_used_id() {
        let mut handle = DBHandle::new().unwrap();
        {
            let mut adapter = CallingConventionDBAdapterV0::new(&mut handle, "", true).unwrap();
            adapter
                .get_calling_convention_id(Some("__stdcall"), &mut |_| {})
                .unwrap();
            adapter
                .get_calling_convention_id(Some("__cdecl"), &mut |_| {})
                .unwrap();
        }
        let mut adapter = CallingConventionDBAdapterV0::new(&mut handle, "", false).unwrap();
        let id = adapter
            .get_calling_convention_id(Some("__thiscall"), &mut |_| {})
            .unwrap();
        assert_eq!(id, FIRST_CALLING_CONVENTION_ID + 2);
    }

    #[test]
    fn opening_missing_table_without_create_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        assert!(CallingConventionDBAdapterV0::new(&mut handle, "", false).is_err());
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter: Box<dyn CallingConventionDBAdapter> =
            Box::new(CallingConventionDBAdapterV0::new(&mut handle, "", true).unwrap());
        assert_eq!(
            adapter.get_calling_convention_id(None, &mut |_| {}).unwrap(),
            UNKNOWN_CALLING_CONVENTION_ID
        );
    }
}
