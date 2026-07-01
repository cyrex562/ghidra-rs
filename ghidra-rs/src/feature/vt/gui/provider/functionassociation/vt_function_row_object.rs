use super::function_association_info::FunctionAssociationInfo;
use std::cmp::Ordering;

/// A row in the VT function-association table, wrapping `FunctionAssociationInfo`.
///
/// Equality and comparison are delegated to the wrapped `FunctionAssociationInfo`.
#[derive(Clone, Debug)]
pub struct VtFunctionRowObject {
    info: FunctionAssociationInfo,
}

impl VtFunctionRowObject {
    /// Creates a new row object wrapping the given `FunctionAssociationInfo`.
    pub fn new(info: FunctionAssociationInfo) -> Self {
        Self { info }
    }

    /// Returns a reference to the wrapped `FunctionAssociationInfo`.
    pub fn get_info(&self) -> &FunctionAssociationInfo {
        &self.info
    }
}

impl PartialEq for VtFunctionRowObject {
    fn eq(&self, other: &Self) -> bool {
        self.info == other.info
    }
}

impl Eq for VtFunctionRowObject {}

impl std::hash::Hash for VtFunctionRowObject {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.info.hash(state);
    }
}

impl PartialOrd for VtFunctionRowObject {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VtFunctionRowObject {
    fn cmp(&self, other: &Self) -> Ordering {
        self.info.cmp(&other.info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    fn hash_of(obj: &VtFunctionRowObject) -> u64 {
        let mut h = DefaultHasher::new();
        obj.hash(&mut h);
        h.finish()
    }

    #[test]
    fn new_wraps_info() {
        let info = FunctionAssociationInfo::new(42);
        let obj = VtFunctionRowObject::new(info);
        assert_eq!(obj.get_info().get_function_id(), 42);
    }

    #[test]
    fn get_info_returns_reference() {
        let info = FunctionAssociationInfo::new(10);
        let obj = VtFunctionRowObject::new(info);
        assert_eq!(obj.get_info().get_function_id(), 10);
    }

    #[test]
    fn equality_based_on_info() {
        let info_a = FunctionAssociationInfo::new(10);
        let info_b = FunctionAssociationInfo::new(10);
        let obj_a = VtFunctionRowObject::new(info_a);
        let obj_b = VtFunctionRowObject::new(info_b);
        assert_eq!(obj_a, obj_b);
    }

    #[test]
    fn inequality_different_ids() {
        let info_a = FunctionAssociationInfo::new(10);
        let info_b = FunctionAssociationInfo::new(11);
        let obj_a = VtFunctionRowObject::new(info_a);
        let obj_b = VtFunctionRowObject::new(info_b);
        assert_ne!(obj_a, obj_b);
    }

    #[test]
    fn hash_consistent_with_equality() {
        let info_a = FunctionAssociationInfo::new(99);
        let info_b = FunctionAssociationInfo::new(99);
        let obj_a = VtFunctionRowObject::new(info_a);
        let obj_b = VtFunctionRowObject::new(info_b);
        assert_eq!(obj_a, obj_b);
        assert_eq!(hash_of(&obj_a), hash_of(&obj_b));
    }

    #[test]
    fn hash_differs_for_different_ids() {
        let info_a = FunctionAssociationInfo::new(10);
        let info_b = FunctionAssociationInfo::new(11);
        let obj_a = VtFunctionRowObject::new(info_a);
        let obj_b = VtFunctionRowObject::new(info_b);
        assert_ne!(hash_of(&obj_a), hash_of(&obj_b));
    }

    #[test]
    fn ordering_delegates_to_info() {
        let info_low = FunctionAssociationInfo::new(1);
        let info_high = FunctionAssociationInfo::new(2);
        let obj_low = VtFunctionRowObject::new(info_low);
        let obj_high = VtFunctionRowObject::new(info_high);
        assert!(obj_low < obj_high);
        assert!(obj_high > obj_low);
    }

    #[test]
    fn equal_objects_cmp_equal() {
        let info_a = FunctionAssociationInfo::new(5);
        let info_b = FunctionAssociationInfo::new(5);
        let obj_a = VtFunctionRowObject::new(info_a);
        let obj_b = VtFunctionRowObject::new(info_b);
        assert_eq!(obj_a.cmp(&obj_b), Ordering::Equal);
    }

    #[test]
    fn clone_is_independent() {
        let info = FunctionAssociationInfo::new(7);
        let obj = VtFunctionRowObject::new(info);
        let cloned = obj.clone();
        assert_eq!(obj, cloned);
    }

    #[test]
    fn hash_in_collection() {
        use std::collections::HashSet;
        let info_a = FunctionAssociationInfo::new(1);
        let info_b = FunctionAssociationInfo::new(2);
        let info_c = FunctionAssociationInfo::new(1);
        let obj_a = VtFunctionRowObject::new(info_a);
        let obj_b = VtFunctionRowObject::new(info_b);
        let obj_c = VtFunctionRowObject::new(info_c);

        let mut set = HashSet::new();
        set.insert(obj_a);
        set.insert(obj_b);
        set.insert(obj_c);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn ordering_in_sort() {
        let info_3 = FunctionAssociationInfo::new(3);
        let info_1 = FunctionAssociationInfo::new(1);
        let info_2 = FunctionAssociationInfo::new(2);
        let mut objs = vec![
            VtFunctionRowObject::new(info_3),
            VtFunctionRowObject::new(info_1),
            VtFunctionRowObject::new(info_2),
        ];
        objs.sort();
        assert_eq!(objs[0].get_info().get_function_id(), 1);
        assert_eq!(objs[1].get_info().get_function_id(), 2);
        assert_eq!(objs[2].get_info().get_function_id(), 3);
    }
}
