//! Mirrors `ghidra.program.model.symbol.DataRefType`, the `RefType` subclass describing
//! memory-access reference types (read/write/indirect) as opposed to control-flow reference
//! types.
//!
//! [`RefType`](crate::program::model::symbol::RefType) already folds `DataRefType`'s behavior
//! into its own `is_data`/`is_read`/`is_write`/`is_indirect` query methods (see that module's
//! docs), so this trait is not wired into `RefType`'s own implementation. It exists as a
//! standalone seam: `DataRefType` was selected as a cut-point for a dependency cycle, so its
//! public API is ported as an object-safe trait that other, not-yet-ported code can depend on
//! without depending on `RefType` concretely.

/// Query methods for a data (memory-access) reference type. Mirrors `DataRefType`'s public API:
/// `isData()`, `isRead()`, `isWrite()`, `isIndirect()`.
pub trait DataRefType {
    /// Always `true` for a data reference type. Stands in for `DataRefType.isData()`.
    fn is_data(&self) -> bool {
        true
    }

    /// Stands in for `DataRefType.isRead()`.
    fn is_read(&self) -> bool;

    /// Stands in for `DataRefType.isWrite()`.
    fn is_write(&self) -> bool;

    /// Stands in for `DataRefType.isIndirect()`.
    fn is_indirect(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirrors `DataRefType`'s private `access` bitmask (`READX`/`WRITEX`/`INDX`) and its
    /// constructor, proving the trait is object-safe and that a real implementation can derive
    /// its query methods from stored access flags the way the Java class does.
    struct MockDataRefType {
        access: u8,
    }

    const READX: u8 = 1;
    const WRITEX: u8 = 2;
    const INDX: u8 = 4;

    impl MockDataRefType {
        fn new(access: u8) -> Self {
            MockDataRefType { access }
        }
    }

    impl DataRefType for MockDataRefType {
        fn is_read(&self) -> bool {
            (self.access & READX) == READX
        }

        fn is_write(&self) -> bool {
            (self.access & WRITEX) == WRITEX
        }

        fn is_indirect(&self) -> bool {
            (self.access & INDX) == INDX
        }
    }

    #[test]
    fn read_write_indirect_flags_match_access_bitmask() {
        let read_ind: Box<dyn DataRefType> = Box::new(MockDataRefType::new(READX | INDX));
        assert!(read_ind.is_data());
        assert!(read_ind.is_read());
        assert!(!read_ind.is_write());
        assert!(read_ind.is_indirect());

        let read_write: Box<dyn DataRefType> = Box::new(MockDataRefType::new(READX | WRITEX));
        assert!(read_write.is_read());
        assert!(read_write.is_write());
        assert!(!read_write.is_indirect());

        let plain: Box<dyn DataRefType> = Box::new(MockDataRefType::new(0));
        assert!(!plain.is_read());
        assert!(!plain.is_write());
        assert!(!plain.is_indirect());
    }
}
