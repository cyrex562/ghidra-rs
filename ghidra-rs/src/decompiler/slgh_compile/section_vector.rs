//! A vector of p-code sections indexed by name.
//!
//! Models `ghidra.pcodeCPort.slgh_compile.SectionVector`.

use crate::decompiler::slgh_compile::RtlPair;
use crate::generic::stl::vector_stl::VectorStl;
use crate::program::model::lang::sleigh::symbol::SymbolScope;
use crate::program::model::lang::sleigh::template::ConstructTpl;
use std::sync::Arc;

/// A container for a main p-code section and zero or more named sections.
///
/// Manages a collection of `RtlPair`s during SLEIGH compilation, with a single
/// primary section and a growable vector of named sections indexed by integer IDs.
#[derive(Clone)]
pub struct SectionVector {
    next_index: i32,
    main: RtlPair,
    named: VectorStl<RtlPair>,
}

impl SectionVector {
    /// Creates a new SectionVector with the given main section.
    ///
    /// Initializes the main section with the provided p-code template and symbol scope,
    /// and creates an empty vector for named sections.
    ///
    /// Mirrors the Java `SectionVector(ConstructTpl, SymbolScope)` constructor.
    pub fn new(rtl: ConstructTpl, scope: Arc<SymbolScope>) -> Self {
        Self {
            next_index: -1,
            main: RtlPair::with_section_and_scope(rtl, scope),
            named: VectorStl::new(),
        }
    }

    /// Returns the p-code template of the main section.
    pub fn get_main_section(&self) -> Option<&ConstructTpl> {
        self.main.section.as_ref()
    }

    /// Returns the p-code template of the named section at the given index.
    ///
    /// # Panics
    /// Panics if the index is out of bounds.
    pub fn get_named_section(&self, index: usize) -> Option<&ConstructTpl> {
        self.named.get(index).section.as_ref()
    }

    /// Returns a reference to the main RtlPair.
    pub fn get_main_pair(&self) -> &RtlPair {
        &self.main
    }

    /// Returns a reference to the named RtlPair at the given index.
    ///
    /// # Panics
    /// Panics if the index is out of bounds.
    pub fn get_named_pair(&self, i: usize) -> &RtlPair {
        self.named.get(i)
    }

    /// Sets the index for the next named section to be appended.
    pub fn set_next_index(&mut self, i: i32) {
        self.next_index = i;
    }

    /// Returns the maximum number of named sections.
    ///
    /// Mirrors the Java `getMaxId()` method, which returns `named.size()`.
    pub fn get_max_id(&self) -> usize {
        self.named.size()
    }

    /// Appends a new named section at the position indicated by the next index.
    ///
    /// Grows the named vector with empty sections if necessary to ensure there is
    /// an element at the position indicated by the current `next_index`, then replaces
    /// that position with a new section containing the given p-code template and scope.
    ///
    /// # Panics
    /// Panics if `next_index` is negative.
    pub fn append(&mut self, rtl: ConstructTpl, scope: Arc<SymbolScope>) {
        let index = self.next_index as usize;
        while self.named.size() <= index {
            self.named.push_back(RtlPair::new());
        }
        self.named.set(index, RtlPair::with_section_and_scope(rtl, scope));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_initializes_with_main_section() {
        let rtl = ConstructTpl::new();
        let scope = Arc::new(SymbolScope {
            id: 0,
            parent_id: None,
            symbols: Default::default(),
        });
        let section_vector = SectionVector::new(rtl.clone(), scope.clone());

        assert_eq!(section_vector.next_index, -1);
        assert!(section_vector.get_main_section().is_some());
        assert_eq!(section_vector.get_max_id(), 0);
    }

    #[test]
    fn get_main_pair_returns_main() {
        let rtl = ConstructTpl::new();
        let scope = Arc::new(SymbolScope {
            id: 1,
            parent_id: None,
            symbols: Default::default(),
        });
        let section_vector = SectionVector::new(rtl, scope.clone());

        let main_pair = section_vector.get_main_pair();
        assert!(main_pair.section.is_some());
        assert!(main_pair.scope.is_some());
        assert_eq!(main_pair.scope.as_ref().unwrap().id, 1);
    }

    #[test]
    fn set_next_index_updates_index() {
        let rtl = ConstructTpl::new();
        let scope = Arc::new(SymbolScope {
            id: 0,
            parent_id: None,
            symbols: Default::default(),
        });
        let mut section_vector = SectionVector::new(rtl, scope);

        section_vector.set_next_index(3);
        assert_eq!(section_vector.next_index, 3);
    }

    #[test]
    fn append_fills_gaps_and_sets_section() {
        let rtl = ConstructTpl::new();
        let scope1 = Arc::new(SymbolScope {
            id: 1,
            parent_id: None,
            symbols: Default::default(),
        });
        let mut section_vector = SectionVector::new(rtl, scope1);

        section_vector.set_next_index(2);

        let rtl2 = ConstructTpl::new();
        let scope2 = Arc::new(SymbolScope {
            id: 2,
            parent_id: None,
            symbols: Default::default(),
        });
        section_vector.append(rtl2, scope2);

        assert_eq!(section_vector.get_max_id(), 3);

        let pair_at_0 = section_vector.get_named_pair(0);
        assert!(pair_at_0.section.is_none());

        let pair_at_1 = section_vector.get_named_pair(1);
        assert!(pair_at_1.section.is_none());

        let pair_at_2 = section_vector.get_named_pair(2);
        assert!(pair_at_2.section.is_some());
        assert_eq!(pair_at_2.scope.as_ref().unwrap().id, 2);
    }

    #[test]
    fn get_named_section_returns_template() {
        let rtl = ConstructTpl::new();
        let scope1 = Arc::new(SymbolScope {
            id: 1,
            parent_id: None,
            symbols: Default::default(),
        });
        let mut section_vector = SectionVector::new(rtl, scope1);

        section_vector.set_next_index(0);
        let rtl2 = ConstructTpl::new();
        let scope2 = Arc::new(SymbolScope {
            id: 2,
            parent_id: None,
            symbols: Default::default(),
        });
        section_vector.append(rtl2, scope2);

        let section = section_vector.get_named_section(0);
        assert!(section.is_some());
    }

    #[test]
    fn get_named_pair_returns_pair() {
        let rtl = ConstructTpl::new();
        let scope1 = Arc::new(SymbolScope {
            id: 1,
            parent_id: None,
            symbols: Default::default(),
        });
        let mut section_vector = SectionVector::new(rtl, scope1);

        section_vector.set_next_index(1);
        let rtl2 = ConstructTpl::new();
        let scope2 = Arc::new(SymbolScope {
            id: 3,
            parent_id: None,
            symbols: Default::default(),
        });
        section_vector.append(rtl2, scope2);

        let pair = section_vector.get_named_pair(1);
        assert!(pair.scope.is_some());
        assert_eq!(pair.scope.as_ref().unwrap().id, 3);
    }

    #[test]
    fn clone_copies_all_fields() {
        let rtl = ConstructTpl::new();
        let scope1 = Arc::new(SymbolScope {
            id: 1,
            parent_id: None,
            symbols: Default::default(),
        });
        let mut section_vector1 = SectionVector::new(rtl, scope1);
        section_vector1.set_next_index(2);

        let section_vector2 = section_vector1.clone();

        assert_eq!(section_vector2.next_index, 2);
        assert_eq!(section_vector2.get_max_id(), section_vector1.get_max_id());
    }
}
