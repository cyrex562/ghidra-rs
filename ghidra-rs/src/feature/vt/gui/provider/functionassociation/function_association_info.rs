use std::cmp::Ordering;

/// Tracks whether a function is part of a version-tracking association and
/// caches filter-relevance data for efficient table filtering.
///
/// Equality and ordering are determined solely by the function ID.
#[derive(Clone, Debug)]
pub struct FunctionAssociationInfo {
    function_id: i64,
    is_in_association: bool,
    is_in_accepted_association: bool,
    is_filter_info_initialized: bool,
}

impl FunctionAssociationInfo {
    /// Creates a new instance for the function with the given ID.
    pub fn new(function_id: i64) -> Self {
        Self {
            function_id,
            is_in_association: false,
            is_in_accepted_association: false,
            is_filter_info_initialized: false,
        }
    }

    /// Returns the function ID this info record is keyed on.
    pub fn get_function_id(&self) -> i64 {
        self.function_id
    }

    /// Returns `true` if this function participates in any VT association.
    pub fn is_in_association(&self) -> bool {
        self.is_in_association
    }

    /// Returns `true` if this function participates in an *accepted* VT association.
    pub fn is_in_accepted_association(&self) -> bool {
        self.is_in_accepted_association
    }

    /// Returns `true` once [`set_filter_data`] has been called at least once.
    pub fn is_filter_initialized(&self) -> bool {
        self.is_filter_info_initialized
    }

    /// Stores filter-relevance data and marks this record as initialized.
    pub fn set_filter_data(&mut self, is_in_association: bool, is_in_accepted_association: bool) {
        self.is_in_association = is_in_association;
        self.is_in_accepted_association = is_in_accepted_association;
        self.is_filter_info_initialized = true;
    }
}

impl PartialEq for FunctionAssociationInfo {
    fn eq(&self, other: &Self) -> bool {
        self.function_id == other.function_id
    }
}

impl Eq for FunctionAssociationInfo {}

impl std::hash::Hash for FunctionAssociationInfo {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Mirror Java's hashCode(): (int) functionID
        (self.function_id as i32).hash(state);
    }
}

impl PartialOrd for FunctionAssociationInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FunctionAssociationInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        self.function_id.cmp(&other.function_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    fn hash_of(info: &FunctionAssociationInfo) -> u64 {
        let mut h = DefaultHasher::new();
        info.hash(&mut h);
        h.finish()
    }

    #[test]
    fn new_is_uninitialized() {
        let info = FunctionAssociationInfo::new(42);
        assert_eq!(info.get_function_id(), 42);
        assert!(!info.is_in_association());
        assert!(!info.is_in_accepted_association());
        assert!(!info.is_filter_initialized());
    }

    #[test]
    fn set_filter_data_marks_initialized() {
        let mut info = FunctionAssociationInfo::new(1);
        info.set_filter_data(true, false);
        assert!(info.is_filter_initialized());
        assert!(info.is_in_association());
        assert!(!info.is_in_accepted_association());
    }

    #[test]
    fn set_filter_data_both_true() {
        let mut info = FunctionAssociationInfo::new(1);
        info.set_filter_data(true, true);
        assert!(info.is_in_association());
        assert!(info.is_in_accepted_association());
    }

    #[test]
    fn equality_based_on_function_id() {
        let a = FunctionAssociationInfo::new(10);
        let mut b = FunctionAssociationInfo::new(10);
        b.set_filter_data(true, true);
        assert_eq!(a, b);

        let c = FunctionAssociationInfo::new(11);
        assert_ne!(a, c);
    }

    #[test]
    fn hash_consistent_with_equality() {
        let a = FunctionAssociationInfo::new(99);
        let mut b = FunctionAssociationInfo::new(99);
        b.set_filter_data(true, false);
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn ordering() {
        let low = FunctionAssociationInfo::new(1);
        let high = FunctionAssociationInfo::new(2);
        assert!(low < high);
        assert!(high > low);

        let same = FunctionAssociationInfo::new(1);
        assert_eq!(low.cmp(&same), std::cmp::Ordering::Equal);
    }

    #[test]
    fn negative_ids_order_correctly() {
        let neg = FunctionAssociationInfo::new(-5);
        let pos = FunctionAssociationInfo::new(5);
        assert!(neg < pos);
    }

    #[test]
    fn clone_is_independent() {
        let mut original = FunctionAssociationInfo::new(7);
        original.set_filter_data(true, true);
        let mut cloned = original.clone();
        cloned.set_filter_data(false, false);
        assert!(original.is_in_association());
        assert!(!cloned.is_in_association());
    }
}
