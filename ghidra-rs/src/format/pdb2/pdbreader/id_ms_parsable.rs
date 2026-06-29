/// Trait for PDB items that carry a unique identifier.
///
/// Implementors override [`pdb_id`](IdMsParsable::pdb_id) to return the unique PDB identifier
/// for their item type. The default implementation panics, mirroring Java's
/// `UnsupportedOperationException` default.
pub trait IdMsParsable {
    /// Returns the unique PDB identifier for this item type.
    fn pdb_id(&self) -> i32 {
        panic!("pdb_id not implemented for this type");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ConcreteItem;
    impl IdMsParsable for ConcreteItem {
        fn pdb_id(&self) -> i32 {
            0x1234
        }
    }

    struct DefaultItem;
    impl IdMsParsable for DefaultItem {}

    #[test]
    fn overridden_pdb_id_returns_value() {
        assert_eq!(ConcreteItem.pdb_id(), 0x1234);
    }

    #[test]
    #[should_panic]
    fn default_pdb_id_panics() {
        DefaultItem.pdb_id();
    }
}
