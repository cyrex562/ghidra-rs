/// Marker for a service-consumption point, mirroring Java's `@AutoServiceConsumed`
/// runtime annotation.
///
/// In Java this annotation is placed on fields or methods so that the plugin-tool
/// framework can automatically inject the matching service instance at runtime.
/// It carries no attributes — its mere presence on a member is the signal.
///
/// In Rust, where there is no reflective annotation system, the same marker role
/// is played by this unit struct. Code that needs to record "this member consumes
/// a service" stores or registers an `AutoServiceConsumed` value through the
/// framework's registration API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AutoServiceConsumed;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_be_constructed() {
        let _ = AutoServiceConsumed;
    }

    #[test]
    fn two_instances_are_equal() {
        assert_eq!(AutoServiceConsumed, AutoServiceConsumed);
    }

    #[test]
    fn clone_produces_equal_instance() {
        let a = AutoServiceConsumed;
        assert_eq!(a.clone(), a);
    }

    #[test]
    fn copy_semantics_work() {
        let a = AutoServiceConsumed;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn debug_output_contains_type_name() {
        let s = format!("{:?}", AutoServiceConsumed);
        assert!(s.contains("AutoServiceConsumed"));
    }

    #[test]
    fn hash_is_stable() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(AutoServiceConsumed);
        set.insert(AutoServiceConsumed);
        assert_eq!(set.len(), 1);
    }
}
