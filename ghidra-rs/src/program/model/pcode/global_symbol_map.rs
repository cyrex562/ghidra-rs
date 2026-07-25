use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::pcode::Varnode;
use crate::program::seam_stubs::HighSymbol;

/// A container for global symbols in the decompiler's model of a function. It contains
/// `HighSymbol` objects for any symbol accessed by the particular function that is in either the
/// global scope or some other global namespace.
///
/// Port of `ghidra.program.model.pcode.GlobalSymbolMap`, cut to a trait at this cycle
/// break-point: the real class is constructed from a `HighFunction`, whose own port will need to
/// hold a `GlobalSymbolMap`, and `HighSymbol`/`HighCodeSymbol` (constructed here from the
/// function's `DataTypeManager`) are themselves views onto `HighFunction`. The constructor and the
/// private `insertSymbol` id/address bookkeeping helper are therefore not modeled here: a
/// concrete implementation owns that state (the `HashMap<Address, HighSymbol>` /
/// `HashMap<Long, HighSymbol>` / next-synthetic-id fields) and the `HighFunction` back-reference
/// needed to build symbols, and provides real bodies for the lookup-building methods below.
/// `HighSymbol` is not yet ported; a minimal placeholder lives in
/// [`crate::program::seam_stubs`]. `HighCodeSymbol` is likewise not yet ported; `new_symbol`'s
/// Java return type of the stronger `HighCodeSymbol` is narrowed to `HighSymbol` here, since
/// `HighCodeSymbol` needs its own placeholder/port before that distinction can be represented.
pub trait GlobalSymbolMap {
    /// Create a `HighSymbol` based on the id of the underlying Ghidra `Symbol`. The `Symbol` is
    /// looked up in the `SymbolTable` and then a `HighSymbol` is created with the name and
    /// data-type associated with the `Symbol`. If a `Symbol` cannot be found, `None` is returned.
    ///
    /// # Arguments
    /// * `id` - the database id of the `CodeSymbol`
    /// * `data_type` - the recovered data-type of the symbol
    /// * `sz` - the size in bytes of the desired symbol
    fn populate_symbol(
        &mut self,
        id: i64,
        data_type: Option<Box<dyn DataType>>,
        sz: i32,
    ) -> Option<Arc<dyn HighSymbol>>;

    /// Some Varnode annotations refer to global symbols. Check if there is a symbol at the
    /// Varnode address and, if there is, create a corresponding `HighSymbol`.
    fn populate_annotation(&mut self, vn: &Varnode);

    /// Create a `HighSymbol` corresponding to an underlying Data object. The name of the symbol
    /// is generated dynamically.
    ///
    /// # Arguments
    /// * `id` - the id to associate with the new symbol
    /// * `addr` - the address of the Data object
    /// * `data_type` - the recovered data-type of the symbol, or `None` to use the default
    ///   data-type (in which case `sz` is treated as `1`)
    /// * `sz` - the size in bytes of the symbol
    fn new_symbol(
        &mut self,
        id: i64,
        addr: Address,
        data_type: Option<Box<dyn DataType>>,
        sz: i32,
    ) -> Arc<dyn HighSymbol>;

    /// Retrieve a `HighSymbol` based on an id.
    fn get_symbol_by_id(&self, id: i64) -> Option<Arc<dyn HighSymbol>>;

    /// Retrieve a `HighSymbol` based on an `Address`.
    fn get_symbol_by_address(&self, addr: &Address) -> Option<Arc<dyn HighSymbol>>;

    /// Get an iterator over all `HighSymbol`s in this container.
    fn get_symbols(&self) -> Box<dyn Iterator<Item = Arc<dyn HighSymbol>> + '_>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::collections::HashMap;

    struct MockHighSymbol {
        id: i64,
    }

    impl HighSymbol for MockHighSymbol {
        fn get_id(&self) -> i64 {
            self.id
        }

        fn get_high_function(&self) -> Arc<dyn crate::program::model::pcode::high_function::HighFunction> {
            unimplemented!("not needed for this smoke test")
        }
    }

    /// Mirrors `GlobalSymbolMap`'s real fields (`addrMappedSymbols`, `symbolMap`,
    /// `uniqueSymbolId`) and the id-reconciliation behavior of its private `insertSymbol` helper,
    /// to prove the trait is object-safe and its methods compose into working lookup behavior.
    #[derive(Default)]
    struct MockGlobalSymbolMap {
        addr_mapped_symbols: HashMap<Address, Arc<dyn HighSymbol>>,
        symbol_map: HashMap<i64, Arc<dyn HighSymbol>>,
        unique_symbol_id: i64,
    }

    const ID_BASE: i64 = 0x40 << 56;

    impl MockGlobalSymbolMap {
        fn insert_symbol(&mut self, sym: Arc<dyn HighSymbol>, addr: Address) {
            let unique_id = sym.get_id();
            if (unique_id >> 56) == (ID_BASE >> 56) {
                let val = unique_id & 0x7fffffff;
                if val > self.unique_symbol_id {
                    self.unique_symbol_id = val;
                }
            }
            self.symbol_map.insert(unique_id, sym.clone());
            self.addr_mapped_symbols.insert(addr, sym);
        }
    }

    impl GlobalSymbolMap for MockGlobalSymbolMap {
        fn populate_symbol(
            &mut self,
            _id: i64,
            _data_type: Option<Box<dyn DataType>>,
            _sz: i32,
        ) -> Option<Arc<dyn HighSymbol>> {
            None
        }

        fn populate_annotation(&mut self, vn: &Varnode) {
            let addr = vn.get_address().clone();
            if self.addr_mapped_symbols.contains_key(&addr) {
                return;
            }
            let sym: Arc<dyn HighSymbol> = Arc::new(MockHighSymbol { id: ID_BASE | 7 });
            self.insert_symbol(sym, addr);
        }

        fn new_symbol(
            &mut self,
            id: i64,
            addr: Address,
            data_type: Option<Box<dyn DataType>>,
            sz: i32,
        ) -> Arc<dyn HighSymbol> {
            let _ = (data_type, sz);
            let sym: Arc<dyn HighSymbol> = Arc::new(MockHighSymbol { id });
            self.insert_symbol(sym.clone(), addr);
            sym
        }

        fn get_symbol_by_id(&self, id: i64) -> Option<Arc<dyn HighSymbol>> {
            self.symbol_map.get(&id).cloned()
        }

        fn get_symbol_by_address(&self, addr: &Address) -> Option<Arc<dyn HighSymbol>> {
            self.addr_mapped_symbols.get(addr).cloned()
        }

        fn get_symbols(&self) -> Box<dyn Iterator<Item = Arc<dyn HighSymbol>> + '_> {
            Box::new(self.symbol_map.values().cloned())
        }
    }

    fn ram_addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    fn new_symbol_is_looked_up_by_id_and_address() {
        let mut map: Box<dyn GlobalSymbolMap> = Box::new(MockGlobalSymbolMap::default());
        let addr = ram_addr(0x1000);

        let created = map.new_symbol(42, addr.clone(), None, 4);
        assert_eq!(created.get_id(), 42);

        let by_id = map.get_symbol_by_id(42).expect("symbol should be found by id");
        assert_eq!(by_id.get_id(), 42);

        let by_addr = map
            .get_symbol_by_address(&addr)
            .expect("symbol should be found by address");
        assert_eq!(by_addr.get_id(), 42);

        assert!(map.get_symbol_by_id(99).is_none());
        assert_eq!(map.get_symbols().count(), 1);
    }

    #[test]
    fn populate_annotation_is_idempotent_per_address() {
        let mut map = MockGlobalSymbolMap::default();
        let addr = ram_addr(0x2000);
        let vn = Varnode::new(addr.clone(), 4);

        map.populate_annotation(&vn);
        assert_eq!(map.get_symbols().count(), 1);
        let first_id = map.get_symbol_by_address(&addr).unwrap().get_id();

        // Calling again for the same address must not create a second entry.
        map.populate_annotation(&vn);
        assert_eq!(map.get_symbols().count(), 1);
        assert_eq!(map.get_symbol_by_address(&addr).unwrap().get_id(), first_id);
    }
}
