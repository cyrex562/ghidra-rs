/// Represents the computational category of Java values during bytecode emulation.
/// Categories are used to classify values in the JVM computational type system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JavaComputationalCategory {
    /// Category 1: Single-word values (int, float, reference, returnAddress).
    Cat1,
    /// Category 2: Double-word values (long, double).
    Cat2,
    /// Void category: used for methods that return no value.
    Void,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_format() {
        assert_eq!(format!("{:?}", JavaComputationalCategory::Cat1), "Cat1");
        assert_eq!(format!("{:?}", JavaComputationalCategory::Cat2), "Cat2");
        assert_eq!(format!("{:?}", JavaComputationalCategory::Void), "Void");
    }

    #[test]
    fn test_clone() {
        let cat = JavaComputationalCategory::Cat1;
        let cloned = cat.clone();
        assert_eq!(cat, cloned);
    }

    #[test]
    fn test_copy() {
        let cat1 = JavaComputationalCategory::Cat2;
        let cat2 = cat1;
        assert_eq!(cat1, cat2);
    }

    #[test]
    fn test_equality() {
        assert_eq!(JavaComputationalCategory::Cat1, JavaComputationalCategory::Cat1);
        assert_ne!(JavaComputationalCategory::Cat1, JavaComputationalCategory::Cat2);
        assert_ne!(JavaComputationalCategory::Cat1, JavaComputationalCategory::Void);
        assert_ne!(JavaComputationalCategory::Cat2, JavaComputationalCategory::Void);
    }

    #[test]
    fn test_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(JavaComputationalCategory::Cat1);
        set.insert(JavaComputationalCategory::Cat2);
        set.insert(JavaComputationalCategory::Void);

        assert_eq!(set.len(), 3);
        assert!(set.contains(&JavaComputationalCategory::Cat1));
        assert!(set.contains(&JavaComputationalCategory::Cat2));
        assert!(set.contains(&JavaComputationalCategory::Void));
    }

    #[test]
    fn test_as_match_patterns() {
        let cat = JavaComputationalCategory::Cat1;
        match cat {
            JavaComputationalCategory::Cat1 => assert!(true),
            JavaComputationalCategory::Cat2 => assert!(false),
            JavaComputationalCategory::Void => assert!(false),
        }
    }
}
