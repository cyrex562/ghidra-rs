use crate::program::model::address::{Address, AddressSet, SpecialAddress};
use crate::program::model::symbol::{SourceType, Symbol, SymbolType};

pub const GLOBAL_NAMESPACE_NAME: &str = "Global";
pub const GLOBAL_SYMBOL_NAME: &str = "global";
pub const GLOBAL_NAMESPACE_ID: i64 = 0;

/// Global namespace implementation.
///
/// Java's `GlobalNamespace` obtains its body from `Memory`.  The current Rust
/// memory trait does not expose address ranges, so this port stores the body
/// address set directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalNamespace {
    body: AddressSet,
}

impl GlobalNamespace {
    pub fn new(body: AddressSet) -> Self {
        Self { body }
    }

    pub fn empty() -> Self {
        Self::new(AddressSet::new())
    }

    pub fn name(&self) -> &'static str {
        GLOBAL_NAMESPACE_NAME
    }

    pub fn id(&self) -> i64 {
        GLOBAL_NAMESPACE_ID
    }

    pub fn parent_namespace_id(&self) -> Option<i64> {
        None
    }

    pub fn body(&self) -> &AddressSet {
        &self.body
    }

    pub fn is_external(&self) -> bool {
        false
    }

    pub fn symbol(&self) -> GlobalSymbol {
        GlobalSymbol::new(self.clone())
    }

    pub fn set_parent_namespace(&self) -> Result<(), String> {
        Err("Can't parent this namespace".to_string())
    }
}

impl std::fmt::Display for GlobalNamespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Global symbol implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalSymbol {
    namespace: GlobalNamespace,
}

impl GlobalSymbol {
    pub fn new(namespace: GlobalNamespace) -> Self {
        Self { namespace }
    }

    pub fn namespace(&self) -> &GlobalNamespace {
        &self.namespace
    }

    pub fn path(&self) -> Vec<String> {
        Vec::new()
    }

    pub fn is_deleted(&self) -> bool {
        false
    }

    pub fn is_external(&self) -> bool {
        false
    }

    pub fn is_descendant(&self) -> bool {
        true
    }

    pub fn is_valid_parent(&self) -> bool {
        false
    }

    pub fn reference_count(&self) -> usize {
        0
    }

    pub fn has_references(&self) -> bool {
        false
    }

    pub fn is_pinned(&self) -> bool {
        false
    }

    pub fn is_dynamic(&self) -> bool {
        false
    }

    pub fn is_external_entry_point(&self) -> bool {
        false
    }

    pub fn is_global(&self) -> bool {
        true
    }

    pub fn set_name(&self, _new_name: &str) -> Result<(), String> {
        Err("Setting the name of the Global symbol is not allowed.".to_string())
    }

    pub fn delete(&self) -> bool {
        false
    }

    pub fn set_pinned(&self, _pinned: bool) -> Result<(), String> {
        Err("Can't pin the global symbol".to_string())
    }

    pub fn set_namespace(&self) -> Result<(), String> {
        Err("Cannot change the Global namespace".to_string())
    }
}

impl Symbol for GlobalSymbol {
    fn get_address(&self) -> Address {
        SpecialAddress::no_address()
    }

    fn get_name(&self) -> &str {
        GLOBAL_SYMBOL_NAME
    }

    fn get_symbol_type(&self) -> SymbolType {
        SymbolType::Global
    }

    fn get_source(&self) -> SourceType {
        SourceType::Default
    }

    fn is_primary(&self) -> bool {
        true
    }

    fn get_id(&self) -> i64 {
        GLOBAL_NAMESPACE_ID
    }

    fn get_parent_id(&self) -> i64 {
        GLOBAL_NAMESPACE_ID
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSetView, AddressSpace, AddressSpaceType};

    #[test]
    fn global_namespace_matches_java_constants() {
        let namespace = GlobalNamespace::empty();

        assert_eq!(namespace.name(), "Global");
        assert_eq!(namespace.id(), 0);
        assert_eq!(namespace.parent_namespace_id(), None);
        assert!(!namespace.is_external());
        assert_eq!(namespace.to_string(), "Global");
        assert!(namespace.set_parent_namespace().is_err());
    }

    #[test]
    fn global_namespace_preserves_body_set() {
        let ram = AddressSpace::new("ram", 8, 1, AddressSpaceType::Ram, 1);
        let body = AddressSet::from_start_end(ram.address(0x10), ram.address(0x1f));
        let namespace = GlobalNamespace::new(body);

        assert!(namespace
            .body()
            .contains_range(&ram.address(0x10), &ram.address(0x1f)));
    }

    #[test]
    fn global_symbol_matches_java_contract_available_in_rust_trait() {
        let namespace = GlobalNamespace::empty();
        let symbol = namespace.symbol();

        assert_eq!(symbol.get_address(), SpecialAddress::no_address());
        assert_eq!(symbol.get_name(), "global");
        assert_eq!(symbol.get_symbol_type(), SymbolType::Global);
        assert_eq!(symbol.get_source(), SourceType::Default);
        assert!(symbol.is_primary());
        assert_eq!(symbol.get_id(), 0);
        assert_eq!(symbol.get_parent_id(), 0);
        assert!(symbol.is_global());
        assert!(!symbol.is_deleted());
        assert!(!symbol.is_external());
        assert!(symbol.is_descendant());
        assert!(!symbol.is_valid_parent());
        assert_eq!(symbol.reference_count(), 0);
        assert!(!symbol.has_references());
        assert!(!symbol.is_pinned());
        assert!(!symbol.is_dynamic());
        assert!(!symbol.is_external_entry_point());
        assert!(symbol.path().is_empty());
    }

    #[test]
    fn global_symbol_rejects_mutation() {
        let symbol = GlobalNamespace::empty().symbol();

        assert!(symbol.set_name("new").is_err());
        assert!(!symbol.delete());
        assert!(symbol.set_pinned(true).is_err());
        assert!(symbol.set_namespace().is_err());
    }
}
