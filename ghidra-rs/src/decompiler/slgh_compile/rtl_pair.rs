//! A pair of a p-code section and its associated symbol scope.
//!
//! Models `ghidra.pcodeCPort.slgh_compile.RtlPair`.

use crate::program::model::lang::sleigh::symbol::SymbolScope;
use crate::program::model::lang::sleigh::template::ConstructTpl;
use std::fmt;
use std::sync::Arc;

/// A pair consisting of a p-code section and its associated symbol scope.
///
/// This structure is used during SLEIGH compilation to associate a constructor's
/// p-code template with the symbol scope in which it was defined.
#[derive(Clone)]
pub struct RtlPair {
    /// A p-code section, or None if not set.
    pub section: Option<ConstructTpl>,
    /// The associated symbol scope, or None if not set.
    pub scope: Option<Arc<SymbolScope>>,
}

impl fmt::Debug for RtlPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtlPair")
            .field("section", &self.section)
            .field("scope", &self.scope.as_ref().map(|s| s.id))
            .finish()
    }
}

impl RtlPair {
    /// Creates a new RtlPair with both fields set to None.
    ///
    /// Mirrors the Java `RtlPair()` no-arg constructor.
    pub fn new() -> Self {
        Self {
            section: None,
            scope: None,
        }
    }

    /// Creates a new RtlPair with the given section and scope.
    ///
    /// Mirrors the Java `RtlPair(ConstructTpl, SymbolScope)` constructor.
    pub fn with_section_and_scope(section: ConstructTpl, scope: Arc<SymbolScope>) -> Self {
        Self {
            section: Some(section),
            scope: Some(scope),
        }
    }
}

impl Default for RtlPair {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_empty_pair() {
        let pair = RtlPair::new();
        assert!(pair.section.is_none());
        assert!(pair.scope.is_none());
    }

    #[test]
    fn default_creates_empty_pair() {
        let pair = RtlPair::default();
        assert!(pair.section.is_none());
        assert!(pair.scope.is_none());
    }

    #[test]
    fn with_section_and_scope_sets_both_fields() {
        let section = ConstructTpl::new();
        let scope = Arc::new(SymbolScope {
            id: 0,
            parent_id: None,
            symbols: Default::default(),
        });
        let pair = RtlPair::with_section_and_scope(section.clone(), scope.clone());

        assert!(pair.section.is_some());
        assert!(pair.scope.is_some());
        assert_eq!(pair.section.as_ref().unwrap().num_labels, section.num_labels);
        assert_eq!(pair.scope.as_ref().unwrap().id, scope.id);
    }

    #[test]
    fn clone_copies_all_fields() {
        let section = ConstructTpl::new();
        let scope = Arc::new(SymbolScope {
            id: 5,
            parent_id: None,
            symbols: Default::default(),
        });
        let pair1 = RtlPair::with_section_and_scope(section.clone(), scope.clone());
        let pair2 = pair1.clone();

        assert!(pair2.section.is_some());
        assert!(pair2.scope.is_some());
        assert_eq!(pair1.section, pair2.section);
        assert_eq!(pair1.scope, pair2.scope);
    }
}
