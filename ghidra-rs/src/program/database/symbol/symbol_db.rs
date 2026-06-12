use crate::program::model::address::Address;
use crate::program::model::symbol::{SourceType, Symbol, SymbolType};

pub struct SymbolDB {
    pub id: i64,
    pub name: String,
    pub address: Address,
    pub symbol_type: SymbolType,
    pub parent_id: i64,
    pub is_primary: bool,
    pub source: SourceType,
}

impl SymbolDB {
    pub fn new(
        id: i64,
        name: String,
        address: Address,
        symbol_type: SymbolType,
        parent_id: i64,
        is_primary: bool,
        source: SourceType,
    ) -> Self {
        Self {
            id,
            name,
            address,
            symbol_type,
            parent_id,
            is_primary,
            source,
        }
    }
}

impl Symbol for SymbolDB {
    fn get_address(&self) -> Address {
        self.address.clone()
    }

    fn get_name(&self) -> &str {
        &self.name
    }

    fn get_symbol_type(&self) -> SymbolType {
        self.symbol_type
    }

    fn get_source(&self) -> SourceType {
        self.source
    }

    fn is_primary(&self) -> bool {
        self.is_primary
    }

    fn get_id(&self) -> i64 {
        self.id
    }

    fn get_parent_id(&self) -> i64 {
        self.parent_id
    }
}
