//! Port of `ghidra.program.database.symbol.NamespaceManager`.
//!
//! Manages the mapping from addresses to the namespace whose "body" (the set of addresses it
//! spans, e.g. a `Function`'s extent) contains them. Composition, not inheritance: the Java class
//! holds a `SymbolManager` back-reference (set via `setProgram`) purely to resolve a namespace ID
//! to its `Namespace` object and to enumerate a namespace's child symbols; storing that as a field
//! here would create a reference cycle with [`SymbolManagerDB`](crate::program::database::symbol::symbol_manager::SymbolManagerDB),
//! which already owns a `NamespaceManagerDB`. Instead, every method that needs a symbol lookup
//! takes `symbol_table: &dyn SymbolTable` as an explicit parameter, mirroring the
//! `get_body_via_namespace_manager`-style dependency-injection convention used elsewhere in this
//! crate (see [`GhidraClassDb`](crate::program::database::symbol::ghidra_class_db::GhidraClassDb)).
//!
//! Left out: the Java class's `LRUMap`-bounded body cache (10 entries) is instead an unbounded
//! `HashMap` keyed by namespace ID (rather than `Namespace` object identity, since [`Namespace`]
//! trait objects are neither `Hash` nor `Eq`); functionally equivalent for correctness, just
//! without the eviction bound.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex, RwLock};

use crate::framework::db::{DBHandle, Field, FieldType};
use crate::program::database::map::AddressMapDB;
use crate::program::database::util::AddressRangeMapDB;
use crate::program::database::ManagerDB;
use crate::program::model::address::{Address, AddressOverflowException, AddressRange, AddressSet, AddressSetView};
use crate::program::model::symbol::{Namespace, SymbolTable};

/// Error produced by [`NamespaceManagerDB::set_body`], mirroring
/// `NamespaceManager.setBody(Namespace, AddressSetView)`'s
/// `throws OverlappingNamespaceException`.
#[derive(Debug, thiserror::Error)]
#[error("Namespace body [{min}, {max}] overlaps an existing namespace")]
pub struct OverlappingNamespaceError {
    pub min: Address,
    pub max: Address,
}

/// Class to manage namespaces.
///
/// Port of `ghidra.program.database.symbol.NamespaceManager`.
pub struct NamespaceManagerDB {
    namespace_map: AddressRangeMapDB,
    body_cache: Mutex<HashMap<i64, AddressSet>>,
}

impl NamespaceManagerDB {
    pub const NAMESPACE_MAP_NAME: &'static str = "SCOPE ADDRESSES";

    pub fn new(
        db_handle: Arc<RwLock<DBHandle>>,
        addr_map: Arc<RwLock<AddressMapDB>>,
    ) -> io::Result<Self> {
        let namespace_map = AddressRangeMapDB::new(
            db_handle,
            addr_map,
            Self::NAMESPACE_MAP_NAME.to_string(),
            FieldType::Long, // Stores Namespace ID
            true,
        )?;

        Ok(Self {
            namespace_map,
            body_cache: Mutex::new(HashMap::new()),
        })
    }

    fn clear_cache(&self) {
        self.body_cache.lock().unwrap().clear();
    }

    pub fn get_namespace_id(&self, addr: &Address) -> io::Result<i64> {
        if let Some(field) = self.namespace_map.get_value(addr)? {
            Ok(field.get_long_value())
        } else {
            Ok(0) // Global namespace ID
        }
    }

    pub fn set_namespace_id(&mut self, range: &AddressRange, id: i64) -> io::Result<()> {
        self.namespace_map.paint(range, Field::Long(Some(id)))
    }

    /// Sets the body of a namespace.
    ///
    /// Stands in for `NamespaceManager.setBody(Namespace, AddressSetView)`.
    ///
    /// # Errors
    ///
    /// Returns [`OverlappingNamespaceError`] if `set` overlaps another namespace's body (in which
    /// case the namespace's previous body is restored, matching the Java method's rollback).
    pub fn set_body(
        &mut self,
        namespace: &dyn Namespace,
        set: &dyn AddressSetView,
    ) -> io::Result<Result<(), OverlappingNamespaceError>> {
        let old_body = self.remove_body(namespace)?;
        if let Some(range) = self.overlaps_namespace(set)? {
            self.do_set_body(namespace, &old_body)?;
            return Ok(Err(OverlappingNamespaceError {
                min: range.min_address().clone(),
                max: range.max_address().clone(),
            }));
        }
        self.do_set_body(namespace, set)?;
        self.clear_cache();
        Ok(Ok(()))
    }

    fn do_set_body(&mut self, namespace: &dyn Namespace, set: &dyn AddressSetView) -> io::Result<()> {
        let field = Field::Long(Some(namespace.get_id()));
        let mut it = set.address_ranges();
        while let Some(range) = it.next() {
            self.namespace_map
                .paint(&AddressRange::new(range.min_address().clone(), range.max_address().clone()), field.clone())?;
        }
        Ok(())
    }

    /// Removes any associated body with the given namespace, returning the old body.
    ///
    /// Stands in for `NamespaceManager.removeBody(Namespace)`.
    pub fn remove_body(&mut self, namespace: &dyn Namespace) -> io::Result<AddressSet> {
        let set = self.get_address_set_by_id(namespace.get_id())?;
        let mut it = set.address_ranges();
        while let Some(range) = it.next() {
            self.namespace_map
                .clear_range(range.min_address(), range.max_address())?;
        }
        self.clear_cache();
        Ok(set)
    }

    /// Get the namespace containing the given address, or `global_namespace` if none is defined.
    ///
    /// Stands in for `NamespaceManager.getNamespaceContaining(Address)`.
    pub fn get_namespace_containing(
        &self,
        addr: &Address,
        symbol_table: &dyn SymbolTable,
        global_namespace: &Arc<dyn Namespace>,
    ) -> io::Result<Arc<dyn Namespace>> {
        if let Some(field) = self.namespace_map.get_value(addr)? {
            if let Some(symbol) = symbol_table.get_symbol(field.get_long_value())? {
                if let Some(ns) = symbol.as_namespace() {
                    return Ok(ns);
                }
            }
        }
        Ok(global_namespace.clone())
    }

    /// Checks if an existing namespace's address set intersects with the given set. If so,
    /// returns the first overlapping range.
    ///
    /// Stands in for `NamespaceManager.overlapsNamespace(AddressSetView)`.
    pub fn overlaps_namespace(&self, set: &dyn AddressSetView) -> io::Result<Option<AddressRange>> {
        let mut it = set.address_ranges();
        while let Some(range) = it.next() {
            let existing = self
                .namespace_map
                .get_address_ranges(range.min_address(), range.max_address())?;
            if let Some((existing_range, _)) = existing.into_iter().next() {
                return Ok(Some(existing_range));
            }
        }
        Ok(None)
    }

    /// Get all namespaces whose body overlaps the specified address set.
    ///
    /// Stands in for `NamespaceManager.getNamespacesOverlapping(AddressSetView)`.
    pub fn get_namespaces_overlapping(
        &self,
        set: &dyn AddressSetView,
        symbol_table: &dyn SymbolTable,
    ) -> io::Result<Vec<Arc<dyn Namespace>>> {
        let mut ids: Vec<i64> = Vec::new();
        let mut it = set.address_ranges();
        while let Some(range) = it.next() {
            let overlaps = self
                .namespace_map
                .get_address_ranges(range.min_address(), range.max_address())?;
            for (_, value) in overlaps {
                let id = value.get_long_value();
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
        }

        let mut list = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(symbol) = symbol_table.get_symbol(id)? {
                if let Some(ns) = symbol.as_namespace() {
                    list.push(ns);
                }
            }
        }
        // Matches the Java method's (likely incidental) side effect of clearing the body cache.
        self.clear_cache();
        Ok(list)
    }

    /// Gets the body for the given namespace.
    ///
    /// Stands in for `NamespaceManager.getAddressSet(Namespace)`.
    pub fn get_address_set(
        &self,
        namespace: &dyn Namespace,
        symbol_table: &dyn SymbolTable,
    ) -> io::Result<AddressSet> {
        let id = namespace.get_id();
        if let Some(cached) = self.body_cache.lock().unwrap().get(&id) {
            return Ok(cached.clone());
        }

        let my_set = self.get_address_set_by_id(id)?;
        let mut set = AddressSet::from_set(&my_set);
        for symbol in symbol_table.get_symbols_in_namespace(id)? {
            if let Some(child_ns) = symbol.as_namespace() {
                set.add_set(&*child_ns.get_body());
            }
        }

        self.body_cache.lock().unwrap().insert(id, set.clone());
        Ok(set)
    }

    fn get_address_set_by_id(&self, namespace_id: i64) -> io::Result<AddressSet> {
        self.namespace_map.get_address_set(&Field::Long(Some(namespace_id)))
    }

    /// Update the address in all records to reflect the movement of a symbol address.
    ///
    /// Stands in for `NamespaceManager.moveAddressRange(Address, Address, long, TaskMonitor)`.
    ///
    /// # Errors
    ///
    /// Returns an error if `length` addresses starting at `from_addr` overflow the address space,
    /// or if a database error occurs.
    pub fn move_namespaces(
        &mut self,
        from_addr: &Address,
        to_addr: &Address,
        length: u64,
    ) -> Result<(), AddressOverflowException> {
        if length == 0 {
            return Ok(());
        }
        let range_end = from_addr.add_no_wrap(length as i64 - 1)?;

        let mut addr_set = AddressSet::from_start_end(from_addr.clone(), range_end.clone());
        let mut moves: Vec<(i64, AddressRange)> = Vec::new();

        let overlapping = self
            .namespace_map
            .get_address_ranges(from_addr, &range_end)
            .map_err(|_| AddressOverflowException::default())?;
        for (_, field) in overlapping {
            if addr_set.is_empty() {
                break;
            }
            let namespace_id = field.get_long_value();
            let full_ns_set = self
                .get_address_set_by_id(namespace_id)
                .map_err(|_| AddressOverflowException::default())?;
            let intersection = addr_set.intersect(&full_ns_set);

            let mut it = intersection.address_ranges();
            while let Some(r) = it.next() {
                let offset_start = r.min_address().subtract(from_addr);
                let start_addr = to_addr.add(offset_start)?;
                let offset_end = r.max_address().subtract(from_addr);
                let end_addr = to_addr.add(offset_end)?;
                moves.push((namespace_id, AddressRange::new(start_addr, end_addr)));
            }
            addr_set = addr_set.subtract(&intersection);
        }

        self.namespace_map
            .clear_range(from_addr, &range_end)
            .map_err(|_| AddressOverflowException::default())?;
        for (namespace_id, range) in moves {
            self.namespace_map
                .paint(&range, Field::Long(Some(namespace_id)))
                .map_err(|_| AddressOverflowException::default())?;
        }
        self.clear_cache();
        Ok(())
    }
}

impl ManagerDB for NamespaceManagerDB {
    fn invalidate_cache(&mut self, _all: bool) -> io::Result<()> {
        self.clear_cache();
        Ok(())
    }

    fn delete_address_range(
        &mut self,
        start_addr: &Address,
        end_addr: &Address,
    ) -> io::Result<()> {
        self.namespace_map.clear_range(start_addr, end_addr)?;
        self.clear_cache();
        Ok(())
    }

    fn move_address_range(
        &mut self,
        from_addr: &Address,
        to_addr: &Address,
        length: u64,
    ) -> io::Result<()> {
        self.move_namespaces(from_addr, to_addr, length)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::symbol::symbol_db::SymbolDB;
    use crate::program::model::address::{AddressSpace, AddressSpaceType, DefaultAddressFactory};
    use crate::program::model::symbol::{SourceType, Symbol, SymbolType};
    use std::sync::Arc;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn new_manager() -> (NamespaceManagerDB, Arc<AddressSpace>) {
        let space = ram_space();
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let factory = Arc::new(DefaultAddressFactory::new(vec![space.clone()]));
        let addr_map = Arc::new(RwLock::new(AddressMapDB::new(handle.clone(), factory).unwrap()));
        let mgr = NamespaceManagerDB::new(handle, addr_map).unwrap();
        (mgr, space)
    }

    /// Minimal [`Namespace`] test double, standing in for a `NamespaceDB` backed by a real
    /// symbol/namespace ID.
    struct MockNamespace {
        id: i64,
        symbol: Arc<dyn Symbol>,
    }

    impl Namespace for MockNamespace {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            self.symbol.clone()
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
    }

    struct MockSymbolTable {
        namespaces: std::collections::HashMap<i64, Arc<dyn Namespace>>,
    }

    impl SymbolTable for MockSymbolTable {
        fn create_label(
            &mut self,
            _addr: &Address,
            _name: &str,
            _source: SourceType,
        ) -> io::Result<Arc<dyn Symbol>> {
            unimplemented!()
        }
        fn get_symbol(&self, id: i64) -> io::Result<Option<Arc<dyn Symbol>>> {
            Ok(self.namespaces.get(&id).map(|ns| ns.get_symbol()))
        }
        fn get_symbols(&self, _addr: &Address) -> io::Result<Vec<Arc<dyn Symbol>>> {
            Ok(Vec::new())
        }
    }

    fn mock_symbol(id: i64) -> Arc<dyn Symbol> {
        Arc::new(SymbolDB::new(
            id,
            format!("ns{id}"),
            crate::program::model::address::Address::new(ram_space(), 0),
            SymbolType::Namespace,
            -1,
            true,
            SourceType::UserDefined,
        ))
    }

    /// A [`Symbol`] test double whose [`Symbol::as_namespace`] actually reports the given
    /// [`Namespace`], unlike the plain [`SymbolDB`] test symbols (whose `as_namespace` defaults
    /// to `None`). Needed because `get_namespace_containing`/`get_namespaces_overlapping` resolve
    /// a namespace ID to a symbol and then narrow it via `as_namespace`, mirroring
    /// `Symbol.getObject() instanceof Namespace` in the Java original.
    struct NamespaceSymbol {
        inner: Arc<dyn Symbol>,
        ns: Arc<dyn Namespace>,
    }
    impl Symbol for NamespaceSymbol {
        fn get_address(&self) -> Address {
            self.inner.get_address()
        }
        fn get_name(&self) -> &str {
            self.inner.get_name()
        }
        fn get_symbol_type(&self) -> SymbolType {
            self.inner.get_symbol_type()
        }
        fn get_source(&self) -> SourceType {
            self.inner.get_source()
        }
        fn is_primary(&self) -> bool {
            self.inner.is_primary()
        }
        fn get_id(&self) -> i64 {
            self.inner.get_id()
        }
        fn get_parent_id(&self) -> i64 {
            self.inner.get_parent_id()
        }
        fn as_namespace(&self) -> Option<Arc<dyn Namespace>> {
            Some(self.ns.clone())
        }
    }

    /// Builds a namespace-reporting symbol paired with a [`MockNamespace`] of the given ID, ready
    /// to insert into a [`MockSymbolTable`].
    fn namespace_with_symbol(id: i64) -> Arc<dyn Namespace> {
        let ns = Arc::new(MockNamespace { id, symbol: mock_symbol(id) }) as Arc<dyn Namespace>;
        let wrapped: Arc<dyn Symbol> = Arc::new(NamespaceSymbol {
            inner: mock_symbol(id),
            ns: ns.clone(),
        });
        Arc::new(MockNamespace { id, symbol: wrapped })
    }

    #[test]
    fn set_get_namespace_id_round_trips_via_manager_db() {
        let (mut mgr, space) = new_manager();
        let range = AddressRange::new(space.address(0x1000), space.address(0x1010));

        assert_eq!(mgr.get_namespace_id(&space.address(0x1005)).unwrap(), 0);
        mgr.set_namespace_id(&range, 7).unwrap();
        assert_eq!(mgr.get_namespace_id(&space.address(0x1005)).unwrap(), 7);
        assert_eq!(mgr.get_namespace_id(&space.address(0x2000)).unwrap(), 0);

        ManagerDB::delete_address_range(&mut mgr, &space.address(0x1000), &space.address(0x1010))
            .unwrap();
        assert_eq!(mgr.get_namespace_id(&space.address(0x1005)).unwrap(), 0);
    }

    #[test]
    fn set_body_detects_overlap_and_restores_old_body() {
        let (mut mgr, space) = new_manager();

        let ns1 = MockNamespace { id: 1, symbol: mock_symbol(1) };
        let ns2 = MockNamespace { id: 2, symbol: mock_symbol(2) };

        let body1 = AddressSet::from_start_end(space.address(0x1000), space.address(0x1010));
        assert!(mgr.set_body(&ns1, &body1).unwrap().is_ok());

        // ns2's requested body overlaps ns1's existing body.
        let overlapping_body =
            AddressSet::from_start_end(space.address(0x1008), space.address(0x1020));
        let result = mgr.set_body(&ns2, &overlapping_body).unwrap();
        assert!(result.is_err());

        // ns1's body must be intact (restored) after the failed ns2 assignment.
        let symtab = MockSymbolTable { namespaces: std::collections::HashMap::new() };
        let ns1_body = mgr.get_address_set(&ns1, &symtab).unwrap();
        assert!(ns1_body.contains(&space.address(0x1000)));
        assert!(ns1_body.contains(&space.address(0x1010)));
        assert!(!ns1_body.contains(&space.address(0x1020)));
    }

    #[test]
    fn get_namespace_containing_resolves_via_symbol_table() {
        let (mut mgr, space) = new_manager();

        let mut namespaces = std::collections::HashMap::new();
        namespaces.insert(1i64, namespace_with_symbol(1));
        let symtab = MockSymbolTable { namespaces };

        let range = AddressRange::new(space.address(0x3000), space.address(0x3010));
        mgr.set_namespace_id(&range, 1).unwrap();

        let global: Arc<dyn Namespace> = Arc::new(MockNamespace { id: 0, symbol: mock_symbol(0) });
        let found = mgr
            .get_namespace_containing(&space.address(0x3005), &symtab, &global)
            .unwrap();
        assert_eq!(found.get_id(), 1);

        let not_found = mgr
            .get_namespace_containing(&space.address(0x4000), &symtab, &global)
            .unwrap();
        assert_eq!(not_found.get_id(), 0);
    }

    #[test]
    fn overlaps_namespace_and_get_namespaces_overlapping() {
        let (mut mgr, space) = new_manager();
        let range = AddressRange::new(space.address(0x1000), space.address(0x1010));
        mgr.set_namespace_id(&range, 42).unwrap();

        let query = AddressSet::from_start_end(space.address(0x1005), space.address(0x1020));
        let overlap = mgr.overlaps_namespace(&query).unwrap();
        assert!(overlap.is_some());

        let no_overlap_query =
            AddressSet::from_start_end(space.address(0x5000), space.address(0x5010));
        assert!(mgr.overlaps_namespace(&no_overlap_query).unwrap().is_none());

        let symtab = MockSymbolTable {
            namespaces: {
                let mut m = std::collections::HashMap::new();
                m.insert(42i64, namespace_with_symbol(42));
                m
            },
        };
        let overlapping = mgr.get_namespaces_overlapping(&query, &symtab).unwrap();
        assert_eq!(overlapping.len(), 1);
        assert_eq!(overlapping[0].get_id(), 42);
    }

    #[test]
    fn move_address_range_shifts_namespace_ids() {
        let (mut mgr, space) = new_manager();
        let range = AddressRange::new(space.address(0x1000), space.address(0x1010));
        mgr.set_namespace_id(&range, 99).unwrap();

        ManagerDB::move_address_range(&mut mgr, &space.address(0x1000), &space.address(0x2000), 0x11)
            .unwrap();

        assert_eq!(mgr.get_namespace_id(&space.address(0x1005)).unwrap(), 0);
        assert_eq!(mgr.get_namespace_id(&space.address(0x2005)).unwrap(), 99);
        assert_eq!(mgr.get_namespace_id(&space.address(0x2010)).unwrap(), 99);
    }
}
