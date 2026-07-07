use crate::program::model::symbol::SourceType;
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClearType {
    Instructions,
    Data,
    Symbols,
    Comments,
    Properties,
    Functions,
    Registers,
    Equates,
    UserReferences,
    AnalysisReferences,
    ImportReferences,
    DefaultReferences,
    Bookmarks,
}

impl ClearType {
    pub fn values() -> &'static [ClearType] {
        &[
            ClearType::Instructions,
            ClearType::Data,
            ClearType::Symbols,
            ClearType::Comments,
            ClearType::Properties,
            ClearType::Functions,
            ClearType::Registers,
            ClearType::Equates,
            ClearType::UserReferences,
            ClearType::AnalysisReferences,
            ClearType::ImportReferences,
            ClearType::DefaultReferences,
            ClearType::Bookmarks,
        ]
    }
}

/// Configuration for what items to clear from a program.
#[derive(Debug, Clone)]
pub struct ClearOptions {
    types_to_clear_set: HashSet<ClearType>,
}

impl ClearOptions {
    /// Default constructor that will clear everything!
    pub fn new() -> Self {
        Self::with_default_state(true)
    }

    /// Constructor with optional initialization.
    pub fn with_default_state(default_clear_state: bool) -> Self {
        let mut types_to_clear_set = HashSet::new();
        if default_clear_state {
            for &clear_type in ClearType::values() {
                types_to_clear_set.insert(clear_type);
            }
        }
        ClearOptions { types_to_clear_set }
    }

    /// Set whether a specific clear type should be cleared.
    pub fn set_should_clear(&mut self, clear_type: ClearType, should_clear: bool) {
        if should_clear {
            self.types_to_clear_set.insert(clear_type);
        } else {
            self.types_to_clear_set.remove(&clear_type);
        }
    }

    /// Returns whether a specific clear type should be cleared.
    pub fn should_clear(&self, clear_type: ClearType) -> bool {
        self.types_to_clear_set.contains(&clear_type)
    }

    /// Returns the set of reference source types to clear.
    pub fn get_reference_source_types_to_clear(&self) -> HashSet<SourceType> {
        let mut source_types_to_clear = HashSet::new();

        if self.should_clear(ClearType::UserReferences) {
            source_types_to_clear.insert(SourceType::UserDefined);
        }
        if self.should_clear(ClearType::DefaultReferences) {
            source_types_to_clear.insert(SourceType::Default);
        }
        if self.should_clear(ClearType::ImportReferences) {
            source_types_to_clear.insert(SourceType::Imported);
        }
        if self.should_clear(ClearType::AnalysisReferences) {
            source_types_to_clear.insert(SourceType::Analysis);
        }

        source_types_to_clear
    }

    /// Returns whether any clear type should be cleared.
    pub fn clear_any(&self) -> bool {
        !self.types_to_clear_set.is_empty()
    }
}

impl Default for ClearOptions {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_constructor_clears_everything() {
        let options = ClearOptions::new();

        for &clear_type in ClearType::values() {
            assert!(
                options.should_clear(clear_type),
                "Default constructor should clear {:?}",
                clear_type
            );
        }
    }

    #[test]
    fn with_default_state_false_clears_nothing() {
        let options = ClearOptions::with_default_state(false);

        for &clear_type in ClearType::values() {
            assert!(
                !options.should_clear(clear_type),
                "Constructor with false should not clear {:?}",
                clear_type
            );
        }
    }

    #[test]
    fn set_should_clear_adds_type() {
        let mut options = ClearOptions::with_default_state(false);

        options.set_should_clear(ClearType::Instructions, true);
        assert!(options.should_clear(ClearType::Instructions));
    }

    #[test]
    fn set_should_clear_removes_type() {
        let mut options = ClearOptions::new();

        options.set_should_clear(ClearType::Instructions, false);
        assert!(!options.should_clear(ClearType::Instructions));
    }

    #[test]
    fn clear_any_returns_true_when_types_present() {
        let mut options = ClearOptions::with_default_state(false);
        assert!(!options.clear_any());

        options.set_should_clear(ClearType::Data, true);
        assert!(options.clear_any());
    }

    #[test]
    fn clear_any_returns_false_when_no_types() {
        let options = ClearOptions::with_default_state(false);
        assert!(!options.clear_any());
    }

    #[test]
    fn get_reference_source_types_to_clear_user() {
        let mut options = ClearOptions::with_default_state(false);
        options.set_should_clear(ClearType::UserReferences, true);

        let source_types = options.get_reference_source_types_to_clear();
        assert!(source_types.contains(&SourceType::UserDefined));
        assert!(!source_types.contains(&SourceType::Analysis));
    }

    #[test]
    fn get_reference_source_types_to_clear_default() {
        let mut options = ClearOptions::with_default_state(false);
        options.set_should_clear(ClearType::DefaultReferences, true);

        let source_types = options.get_reference_source_types_to_clear();
        assert!(source_types.contains(&SourceType::Default));
    }

    #[test]
    fn get_reference_source_types_to_clear_imported() {
        let mut options = ClearOptions::with_default_state(false);
        options.set_should_clear(ClearType::ImportReferences, true);

        let source_types = options.get_reference_source_types_to_clear();
        assert!(source_types.contains(&SourceType::Imported));
    }

    #[test]
    fn get_reference_source_types_to_clear_analysis() {
        let mut options = ClearOptions::with_default_state(false);
        options.set_should_clear(ClearType::AnalysisReferences, true);

        let source_types = options.get_reference_source_types_to_clear();
        assert!(source_types.contains(&SourceType::Analysis));
    }

    #[test]
    fn get_reference_source_types_to_clear_multiple() {
        let mut options = ClearOptions::with_default_state(false);
        options.set_should_clear(ClearType::UserReferences, true);
        options.set_should_clear(ClearType::AnalysisReferences, true);

        let source_types = options.get_reference_source_types_to_clear();
        assert_eq!(source_types.len(), 2);
        assert!(source_types.contains(&SourceType::UserDefined));
        assert!(source_types.contains(&SourceType::Analysis));
    }

    #[test]
    fn clone_produces_independent_copy() {
        let mut options1 = ClearOptions::new();
        options1.set_should_clear(ClearType::Instructions, false);

        let options2 = options1.clone();

        let mut options1_mut = options1;
        options1_mut.set_should_clear(ClearType::Data, false);

        assert!(!options2.should_clear(ClearType::Instructions));
        assert!(options2.should_clear(ClearType::Data));
    }
}
